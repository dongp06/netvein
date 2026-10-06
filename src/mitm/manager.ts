import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { ErrorCode } from "../errors.js";
import { VERSION } from "../version.js";
import { captureStamp } from "../project.js";

export interface StartOptions {
  port?: number;
  caDir?: string;
  allowHosts?: string[];
  attachBrowser?: boolean;
  /** Directory for the auto-captured flows jsonl; the daemon appends while running. */
  captureDir?: string;
}

export interface Endpoint {
  proxyPort: number;
  spki: string | null;
  attachBrowser: boolean;
}

export interface Stats {
  running: boolean;
  flows: number;
  held: string[];
  breakpoints: number;
  uptimeS: number;
  spki: string | null;
}

function addonPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // dist/mitm/ and src/mitm/ both sit two levels under the repo root.
  return path.resolve(here, "..", "..", "python", "netvein_addon.py");
}

/** Chrome args that route a netvein-launched browser through the daemon. */
export function buildProxyArgs(endpoint: Endpoint | null, extraArgs: string[] = []): string[] {
  const args = [...extraArgs];
  if (endpoint && endpoint.attachBrowser) {
    args.push(`--proxy-server=127.0.0.1:${endpoint.proxyPort}`);
    if (endpoint.spki) args.push(`--ignore-certificate-errors-spki-list=${endpoint.spki}`);
  }
  return args;
}

/** PATH lookup without a dependency: scan PATH like `which`. */
function whichBinary(binary: string): string | null {
  const dirs = (process.env.PATH ?? "").split(path.delimiter);
  for (const dir of dirs) {
    if (!dir) continue;
    const candidate = path.join(dir, binary);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      // not here; keep scanning
    }
  }
  return null;
}

async function portFree(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (free: boolean) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(free);
    };
    socket.setTimeout(400);
    socket.once("connect", () => done(false));
    socket.once("timeout", () => done(true));
    socket.once("error", () => done(true));
  });
}

export class MitmError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "MitmError";
    this.code = code;
  }
}

/** Daemon error strings map onto registry codes; everything else is a loss. */
function mapDaemonError(text: string): ErrorCode {
  if (/not found|no flow/i.test(text)) return "ERR_MITM_FLOW_NOT_FOUND";
  if (/pattern|regex|compile/i.test(text)) return "ERR_MITM_BAD_PATTERN";
  return "ERR_MITM_LOST";
}

export class MitmManager {
  private proc: ChildProcessByStdio<null, Readable, Readable> | null = null;
  private ctlSocket: net.Socket | null = null;
  private pending = new Map<number, { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }>();
  private nextId = 1;
  private buffer = "";
  private info: { proxyPort: number; confDir: string; spki: string | null; attachBrowser: boolean; captureFile: string | null } | null = null;
  /** Survives daemon death on purpose: the file remains readable after a crash. */
  private captureFile: string | null = null;
  private lastStats: Stats | null = null;
  private died = false;
  private stopping = false;
  private starting: Promise<{ proxyPort: number; spki: string | null; confDir: string; alreadyRunning: boolean }> | null = null;
  private exitHooked = false;

  get pid(): number | undefined {
    return this.proc?.pid;
  }

  state(): "stopped" | "running" | "dead" {
    if (this.info && !this.died) return "running";
    if (this.died) return "dead";
    return "stopped";
  }

  running(): boolean {
    return this.state() === "running";
  }

  endpoint(): Endpoint | null {
    if (!this.info || this.died) return null;
    return { proxyPort: this.info.proxyPort, spki: this.info.spki, attachBrowser: this.info.attachBrowser };
  }

  /** Auto-capture target for the current or most recent daemon run. */
  captureInfo(): { file: string; exists: boolean; bytes: number } | null {
    const file = this.captureFile;
    if (!file) return null;
    try {
      const stat = fs.statSync(file);
      return { file, exists: true, bytes: stat.size };
    } catch {
      return { file, exists: false, bytes: 0 };
    }
  }

  async start(options: StartOptions = {}): Promise<{ proxyPort: number; spki: string | null; confDir: string; alreadyRunning: boolean }> {
    if (this.running()) {
      return { proxyPort: this.info!.proxyPort, spki: this.info!.spki, confDir: this.info!.confDir, alreadyRunning: true };
    }
    // Concurrent traffic_start calls must share one spawn, not race two daemons.
    if (this.starting) return this.starting;
    this.starting = this.startInner(options).finally(() => {
      this.starting = null;
    });
    return this.starting;
  }

  private async startInner(options: StartOptions): Promise<{ proxyPort: number; spki: string | null; confDir: string; alreadyRunning: boolean }> {
    if (!fs.existsSync(addonPath())) {
      throw new MitmError("ERR_MITM_UNAVAILABLE", `Addon missing at ${addonPath()}.`);
    }
    const binary = whichBinary("mitmdump");
    if (!binary) {
      throw new MitmError("ERR_MITM_UNAVAILABLE", "mitmdump was not found on PATH.");
    }
    const port = options.port ?? 8080;
    if (!(await portFree("127.0.0.1", port))) {
      throw new MitmError("ERR_MITM_PORT_BUSY", `127.0.0.1:${port} is already in use.`);
    }
    const confDir = options.caDir ?? fs.mkdtempSync(path.join(os.tmpdir(), "netvein-mitm-"));
    const portFile = path.join(confDir, "ctl.port");
    fs.rmSync(portFile, { force: true });
    let captureFile: string | null = null;
    if (options.captureDir) {
      fs.mkdirSync(options.captureDir, { recursive: true });
      captureFile = path.join(options.captureDir, captureStamp());
      this.captureFile = captureFile;
    }

    const args = ["--listen-host", "127.0.0.1", "--listen-port", String(port), "--set", `confdir=${confDir}`, "-s", addonPath(), "--quiet"];
    if (options.allowHosts?.length) {
      args.push("--allow-hosts", options.allowHosts.join("|"));
    }

    const proc = spawn(binary, args, {
      env: { ...process.env, NETVEIN_CONFDIR: confDir, NETVEIN_CTL_PORT: "0", NETVEIN_PORTFILE: portFile, NETVEIN_VERSION: VERSION, ...(captureFile ? { NETVEIN_CAPTURE: captureFile } : {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.proc = proc;
    this.died = false;
    this.stopping = false;
    proc.on("exit", () => {
      this.proc = null;
      if (this.stopping) {
        this.stopping = false;
        this.died = false;
      } else {
        this.died = true;
      }
      this.info = null;
      this.rejectAllPending(new MitmError("ERR_MITM_LOST", "The traffic daemon exited unexpectedly."));
    });
    proc.stderr.on("data", () => {}); // drained; startup failure detail surfaces via the portfile timeout
    proc.stdout.on("data", () => {});
    this.ensureExitHook();

    try {
      const ctlPort = await this.waitForPortFile(portFile, 15000);
      await this.connectControl(ctlPort);
      // Bootstrap info before the handshake command: command() guards on running().
      this.info = { proxyPort: port, confDir, spki: null, attachBrowser: options.attachBrowser ?? true, captureFile };
      const stats = await this.command("stats");
      this.info.spki = (stats.spki as string | null) ?? null;
      return { proxyPort: port, spki: this.info.spki, confDir, alreadyRunning: false };
    } catch (error) {
      this.proc?.kill("SIGKILL");
      this.proc = null;
      this.info = null;
      this.died = false;
      throw error;
    }
  }

  private async waitForPortFile(portFile: string, timeoutMs: number): Promise<number> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (this.proc === null) {
        throw new MitmError("ERR_MITM_LOST", "mitmdump exited before the control socket came up.");
      }
      try {
        const raw = fs.readFileSync(portFile, "utf8").trim();
        if (/^\d+$/.test(raw)) return Number(raw);
      } catch {
        // portfile not written yet
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new MitmError("ERR_MITM_LOST", "mitmdump did not open its control socket within 15s.");
  }

  private connectControl(port: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host: "127.0.0.1", port });
      const onErr = (error: Error) => reject(new MitmError("ERR_MITM_LOST", error.message));
      socket.once("error", onErr);
      socket.once("connect", () => {
        socket.removeListener("error", onErr);
        socket.on("data", (chunk) => this.onData(chunk));
        socket.on("error", () => {}); // ECONNRESET after SIGKILL is expected; close/exit drives state
        socket.on("close", () => this.onClose());
        this.ctlSocket = socket;
        resolve();
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer += chunk.toString("utf8");
    let cut = this.buffer.indexOf("\n");
    while (cut !== -1) {
      const line = this.buffer.slice(0, cut);
      this.buffer = this.buffer.slice(cut + 1);
      cut = this.buffer.indexOf("\n");
      let msg: { id?: number; ok?: boolean; error?: string } & Record<string, unknown>;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      if (typeof msg.id !== "number") continue; // unsolicited lines are ignored; held state is polled
      const waiter = this.pending.get(msg.id);
      if (!waiter) continue;
      this.pending.delete(msg.id);
      if (msg.ok) waiter.resolve(msg);
      else waiter.reject(new MitmError(mapDaemonError(String(msg.error ?? "")), String(msg.error ?? "daemon error")));
    }
  }

  private onClose(): void {
    this.ctlSocket = null;
    if (this.proc && !this.stopping) this.died = true;
    this.rejectAllPending(new MitmError("ERR_MITM_LOST", "Control socket closed."));
  }

  private rejectAllPending(error: Error): void {
    for (const [, waiter] of this.pending) waiter.reject(error);
    this.pending.clear();
  }

  async command(cmd: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    if (this.state() === "dead") throw new MitmError("ERR_MITM_LOST", "The traffic daemon died; call traffic_start again.");
    if (!this.running() || !this.ctlSocket) throw new MitmError("ERR_MITM_NOT_RUNNING", "The traffic daemon is not running.");
    const id = this.nextId++;
    const line = JSON.stringify({ id, cmd, args }) + "\n";
    return new Promise((resolve, reject) => {
      const settle = (fn: () => void) => {
        clearTimeout(timer);
        fn();
      };
      this.pending.set(id, {
        resolve: (v) => settle(() => resolve(v)),
        reject: (e) => settle(() => reject(e)),
      });
      this.ctlSocket!.write(line);
      const timer = setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new MitmError("ERR_MITM_LOST", `Command ${cmd} timed out after 20s.`));
        }
      }, 20000);
      timer.unref?.();
    });
  }

  async stats(): Promise<Stats | null> {
    if (!this.running()) return null;
    const reply = await this.command("stats");
    const stats = {
      running: true,
      flows: Number(reply.flows) || 0,
      held: (reply.held as string[]) ?? [],
      breakpoints: Number(reply.breakpoints) || 0,
      uptimeS: Number(reply.uptimeS) || 0,
      spki: (reply.spki as string | null) ?? null,
    };
    this.lastStats = stats;
    return stats;
  }

  async held(): Promise<string[]> {
    const stats = await this.stats();
    return stats?.held ?? [];
  }

  lastStatsSnapshot(): Stats | null {
    return this.lastStats;
  }

  async stop(): Promise<void> {
    if (!this.running()) return;
    this.stopping = true;
    try {
      await this.command("stop");
    } catch {
      // the daemon exits as part of stop; a lost socket is expected
    }
    await this.waitForExit(3000);
    if (this.proc) {
      this.proc.kill("SIGKILL");
      await this.waitForExit(2000);
    }
    if (this.proc === null) return; // exit handler already ran and settled state
    // Exit event somehow missing: settle state by hand.
    this.info = null;
    this.died = false;
    this.stopping = false;
    this.ctlSocket = null;
  }

  /**
   * A netvein-owned daemon must not outlive netvein: hard-kill the live child
   * when this process goes away (crash safety net; index.ts shutdown() covers
   * the clean path). Registered once per manager, reads the current proc.
   */
  private ensureExitHook(): void {
    if (this.exitHooked) return;
    this.exitHooked = true;
    process.once("exit", () => {
      try {
        this.proc?.kill("SIGKILL");
      } catch {
        // already gone
      }
    });
  }

  private waitForExit(timeoutMs: number): Promise<void> {
    const proc = this.proc;
    if (!proc) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(done, timeoutMs);
      proc.once("exit", done);
    });
  }
}

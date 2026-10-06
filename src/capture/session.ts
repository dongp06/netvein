import * as fs from "node:fs";
import * as path from "node:path";
import type { MitmManager } from "../mitm/manager.js";
import type { CaptureSessionConfig } from "./types.js";

function sanitizeName(name: string): string {
  return name.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "capture";
}

function timeStamp(): string {
  const d = new Date();
  return d.toISOString().replace(/[:.]/g, "-").replace("T", "_").replace("Z", "");
}

function countLines(filePath: string): number {
  try {
    if (!fs.existsSync(filePath)) return 0;
    const content = fs.readFileSync(filePath, "utf8");
    let count = 0;
    for (let i = 0; i < content.length; i++) {
      if (content[i] === "\n") count++;
    }
    return count;
  } catch {
    return 0;
  }
}

export class CaptureSessionManager {
  private active: CaptureSessionConfig | null = null;
  private rootDir: string;

  constructor(workspaceDir?: string) {
    this.rootDir = workspaceDir ? path.resolve(workspaceDir) : process.cwd();
  }

  get workspaceDir(): string {
    return this.rootDir;
  }

  updateRootDir(newDir: string): void {
    this.rootDir = path.resolve(newDir);
  }

  get activeSession(): CaptureSessionConfig | null {
    if (!this.active) return null;
    return {
      ...this.active,
      flowCount: countLines(this.active.flowsFile),
    };
  }

  private getCapturesBaseDir(): string {
    const netveinDir = path.join(this.rootDir, ".netvein");
    if (fs.existsSync(netveinDir)) {
      return path.join(netveinDir, "captures");
    }
    return path.join(this.rootDir, "captures");
  }

  async start(
    mitm: MitmManager,
    options: {
      name?: string;
      focus?: string[];
      dropTelemetry?: boolean;
      keepSecrets?: boolean;
      storeBodies?: boolean;
      port?: number;
    } = {},
  ): Promise<CaptureSessionConfig> {
    if (this.active) {
      await this.stop(mitm);
    }

    const baseDir = this.getCapturesBaseDir();
    fs.mkdirSync(baseDir, { recursive: true });

    const rawName = options.name || "session";
    const name = sanitizeName(rawName);
    const id = `${name}-${timeStamp()}`;
    const sessionDir = path.join(baseDir, id);
    const bodiesDir = path.join(sessionDir, "bodies");
    const flowsFile = path.join(sessionDir, "flows.jsonl");

    fs.mkdirSync(sessionDir, { recursive: true });
    if (options.storeBodies !== false) {
      fs.mkdirSync(bodiesDir, { recursive: true });
    }

    const config: CaptureSessionConfig = {
      id,
      name,
      dir: sessionDir,
      flowsFile,
      bodiesDir,
      startTime: new Date().toISOString(),
      focus: options.focus,
      dropTelemetry: options.dropTelemetry ?? true,
      keepSecrets: options.keepSecrets ?? true,
      storeBodies: options.storeBodies !== false,
      status: "active",
      flowCount: 0,
    };

    fs.writeFileSync(path.join(sessionDir, "session.json"), JSON.stringify(config, null, 2), "utf8");

    // Configure the mitm daemon: if already running, apply dynamic config; otherwise start it
    if (mitm.running()) {
      await mitm.captureConfig({
        focus: config.focus,
        dropTelemetry: config.dropTelemetry,
        keepSecrets: config.keepSecrets,
        bodiesDir: config.storeBodies ? config.bodiesDir : "",
        capturePath: config.flowsFile,
      });
    } else {
      await mitm.start({
        port: options.port ?? 8080,
        focus: config.focus,
        dropTelemetry: config.dropTelemetry,
        keepSecrets: config.keepSecrets,
        bodiesDir: config.storeBodies ? config.bodiesDir : undefined,
        captureDir: sessionDir,
      });
      // Point the live capture file directly to our session's flows.jsonl
      await mitm.captureConfig({
        capturePath: config.flowsFile,
        bodiesDir: config.storeBodies ? config.bodiesDir : "",
      });
    }

    this.active = config;
    return config;
  }

  async stop(mitm?: MitmManager): Promise<CaptureSessionConfig | null> {
    if (!this.active) return null;
    const session = this.active;
    session.status = "stopped";
    session.endTime = new Date().toISOString();
    session.flowCount = countLines(session.flowsFile);

    try {
      fs.writeFileSync(path.join(session.dir, "session.json"), JSON.stringify(session, null, 2), "utf8");
    } catch {
      // Best-effort write
    }

    if (mitm && mitm.running()) {
      try {
        await mitm.captureConfig({
          focus: [],
          dropTelemetry: false,
          keepSecrets: true,
          bodiesDir: "",
          capturePath: "",
        });
      } catch {
        // Daemon may have stopped
      }
    }

    this.active = null;
    return session;
  }

  listSessions(): CaptureSessionConfig[] {
    const baseDir = this.getCapturesBaseDir();
    if (!fs.existsSync(baseDir)) return [];

    const results: CaptureSessionConfig[] = [];
    try {
      const entries = fs.readdirSync(baseDir);
      for (const entry of entries) {
        const fullPath = path.join(baseDir, entry);
        if (!fs.statSync(fullPath).isDirectory()) continue;
        const metaPath = path.join(fullPath, "session.json");
        const flowsPath = path.join(fullPath, "flows.jsonl");

        if (fs.existsSync(metaPath)) {
          try {
            const data = JSON.parse(fs.readFileSync(metaPath, "utf8")) as CaptureSessionConfig;
            data.flowCount = countLines(data.flowsFile || flowsPath);
            results.push(data);
            continue;
          } catch {
            // malformed session.json, fall back to directory inspection
          }
        }

        if (fs.existsSync(flowsPath)) {
          results.push({
            id: entry,
            name: entry,
            dir: fullPath,
            flowsFile: flowsPath,
            bodiesDir: path.join(fullPath, "bodies"),
            startTime: fs.statSync(flowsPath).birthtime.toISOString(),
            status: "stopped",
            flowCount: countLines(flowsPath),
          });
        }
      }
    } catch {
      return [];
    }

    results.sort((a, b) => b.startTime.localeCompare(a.startTime));
    return results;
  }
}

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { MitmManager } from "../mitm/manager.js";
import type { ProxiedExecOptions, ProxiedExecResult } from "./types.js";

function getShimPath(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const distShim = path.resolve(here, "..", "shims", "node-proxy.mjs");
    if (fs.existsSync(distShim)) return distShim;
    const parentShim = path.resolve(here, "..", "..", "src", "shims", "node-proxy.mjs");
    if (fs.existsSync(parentShim)) return parentShim;
    return distShim;
  } catch {
    return "";
  }
}

export function buildProxyEnvironment(
  proxyPort: number,
  confDir?: string | null,
  focus?: string[],
  extraEnv?: Record<string, string>,
): Record<string, string> {
  const proxyUrl = `http://127.0.0.1:${proxyPort}`;
  const env: Record<string, string> = {
    ...process.env as Record<string, string>,
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    ALL_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    all_proxy: proxyUrl,
    NETVEIN_PROXY_URL: proxyUrl,
  };

  if (focus && focus.length > 0) {
    env.NETVEIN_FOCUS = focus.join(",");
  }

  if (confDir) {
    const caCert = path.join(confDir, "mitmproxy-ca-cert.pem");
    if (fs.existsSync(caCert)) {
      env.SSL_CERT_FILE = caCert;
      env.NODE_EXTRA_CA_CERTS = caCert;
      env.REQUESTS_CA_BUNDLE = caCert;
      env.CURL_CA_BUNDLE = caCert;
    }
  }

  // Prepend node proxy shim into NODE_OPTIONS so Node.js fetch / undici traffic is captured
  const shim = getShimPath();
  if (shim && fs.existsSync(shim)) {
    const shimArg = `--import "${shim.replace(/\\/g, "/")}"`;
    env.NODE_OPTIONS = env.NODE_OPTIONS ? `${shimArg} ${env.NODE_OPTIONS}` : shimArg;
  }

  if (extraEnv) {
    Object.assign(env, extraEnv);
  }

  return env;
}

export async function runProxiedCommand(
  mitm: MitmManager,
  options: ProxiedExecOptions,
): Promise<ProxiedExecResult> {
  // Ensure the traffic daemon is running
  if (!mitm.running()) {
    await mitm.start();
  }

  const endpoint = mitm.endpoint();
  if (!endpoint) {
    throw new Error("Traffic daemon endpoint is not available.");
  }

  const statsBefore = (await mitm.stats())?.flows ?? 0;
  const env = buildProxyEnvironment(endpoint.proxyPort, mitm.confDir, options.focus, options.env);
  const timeoutMs = options.timeoutMs ?? 60000;
  const maxChars = options.maxChars ?? 20000;
  const cwd = options.cwd ? path.resolve(options.cwd) : process.cwd();

  const isWin = process.platform === "win32";
  const start = Date.now();

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    // Use shell on Windows or fallback
    const child = spawn(options.command, options.args ?? [], {
      cwd,
      env,
      shell: isWin,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill("SIGKILL");
      } catch {}
    }, timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      if (stdout.length < maxChars) {
        stdout += chunk.toString("utf8");
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      if (stderr.length < maxChars) {
        stderr += chunk.toString("utf8");
      }
    });

    child.on("close", async (code) => {
      clearTimeout(timer);
      const durationMs = Date.now() - start;

      // Small pause to allow in-flight socket flows to register in daemon
      await new Promise((r) => setTimeout(r, 200));
      const statsAfter = (await mitm.stats())?.flows ?? statsBefore;
      const flowsCaptured = Math.max(0, statsAfter - statsBefore);

      if (timedOut) {
        stderr += `\n[netvein] Command timed out after ${timeoutMs}ms.`;
      }

      if (stdout.length >= maxChars) {
        stdout = stdout.slice(0, maxChars) + "\n... [truncated]";
      }
      if (stderr.length >= maxChars) {
        stderr = stderr.slice(0, maxChars) + "\n... [truncated]";
      }

      resolve({
        command: options.command + (options.args?.length ? " " + options.args.join(" ") : ""),
        exitCode: code,
        stdout,
        stderr,
        durationMs,
        flowsBefore: statsBefore,
        flowsAfter: statsAfter,
        flowsCaptured,
      });
    });

    child.on("error", async (err) => {
      clearTimeout(timer);
      const durationMs = Date.now() - start;
      const statsAfter = (await mitm.stats())?.flows ?? statsBefore;

      resolve({
        command: options.command,
        exitCode: -1,
        stdout,
        stderr: `Failed to execute: ${err.message}`,
        durationMs,
        flowsBefore: statsBefore,
        flowsAfter: statsAfter,
        flowsCaptured: 0,
      });
    });
  });
}

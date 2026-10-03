import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";

export interface LaunchOptions {
  executablePath?: string;
  host?: string;
  port?: number;
  userDataDir?: string;
  headless?: boolean;
  targetUrl?: string;
  extraArgs?: string[];
}

export interface LaunchResult {
  alreadyRunning: boolean;
  executable?: string;
  pid?: number;
  host: string;
  port: number;
  userDataDir?: string;
  message: string;
}

/**
 * Find Chrome, Edge, Brave or Chromium executable across Windows, macOS, and Linux.
 */
export function findBrowserExecutable(preferredPath?: string): string | null {
  if (preferredPath && fs.existsSync(preferredPath)) {
    return preferredPath;
  }

  const platform = process.platform;

  if (platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || "";
    const programFiles = process.env["ProgramFiles"] || "C:\\Program Files";
    const programFilesX86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";

    const candidates = [
      path.join(programFiles, "Google\\Chrome\\Application\\chrome.exe"),
      path.join(programFilesX86, "Google\\Chrome\\Application\\chrome.exe"),
      path.join(localAppData, "Google\\Chrome\\Application\\chrome.exe"),
      path.join(programFilesX86, "Microsoft\\Edge\\Application\\msedge.exe"),
      path.join(programFiles, "Microsoft\\Edge\\Application\\msedge.exe"),
      path.join(localAppData, "Microsoft\\Edge\\Application\\msedge.exe"),
      path.join(programFiles, "BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
      path.join(programFilesX86, "BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
      path.join(localAppData, "BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }
  } else if (platform === "darwin") {
    const candidates = [
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }
  } else {
    // Linux
    const candidates = [
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/microsoft-edge",
      "/usr/bin/brave-browser",
      "/snap/bin/chromium",
    ];

    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) return candidate;
    }
  }

  return null;
}

/**
 * Check if the CDP HTTP endpoint is already listening and responsive.
 */
export function isCdpPortOpen(host = "127.0.0.1", port = 9222, timeoutMs = 600): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(
      {
        host,
        port,
        path: "/json/version",
        timeout: timeoutMs,
      },
      (res) => {
        resolve(res.statusCode === 200);
      },
    );

    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });

    req.on("error", () => {
      resolve(false);
    });
  });
}

/**
 * Launch Chromium with CDP remote debugging flags and wait until port is responsive.
 */
export async function launchBrowser(options: LaunchOptions = {}): Promise<LaunchResult> {
  const host = options.host || "127.0.0.1";
  const port = options.port || 9222;

  // 1. Check if already open
  const isOpen = await isCdpPortOpen(host, port, 800);
  if (isOpen) {
    return {
      alreadyRunning: true,
      host,
      port,
      message: `CDP endpoint is already active and responsive at http://${host}:${port}`,
    };
  }

  // 2. Discover browser executable
  const executable = findBrowserExecutable(options.executablePath);
  if (!executable) {
    throw new Error(
      "Could not automatically locate Chrome, Edge, or Brave executable. Please install Chrome or specify BROWSER_PATH environment variable.",
    );
  }

  // 3. Prepare dedicated user profile directory
  const userDataDir = options.userDataDir || path.join(os.tmpdir(), "reverse-engineering-browser-profile");
  if (!fs.existsSync(userDataDir)) {
    fs.mkdirSync(userDataDir, { recursive: true });
  }

  const args = [
    `--remote-debugging-port=${port}`,
    `--remote-debugging-address=${host}`,
    `--user-data-dir=${userDataDir}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-domain-reliability",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
  ];

  if (options.headless) {
    args.push("--headless=new");
  }

  if (options.extraArgs) {
    args.push(...options.extraArgs);
  }

  args.push(options.targetUrl || "about:blank");

  // 4. Spawn independent background process
  const child = spawn(executable, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: false,
  });

  child.unref();

  // 5. Poll until port opens (up to 15 seconds)
  const startTime = Date.now();
  const maxWaitMs = 15_000;
  let ready = false;

  while (Date.now() - startTime < maxWaitMs) {
    await new Promise((r) => setTimeout(r, 250));
    if (await isCdpPortOpen(host, port, 400)) {
      ready = true;
      break;
    }
  }

  if (!ready) {
    throw new Error(
      `Launched browser at "${executable}" with PID ${child.pid}, but CDP port ${port} did not become responsive within 15 seconds.`,
    );
  }

  return {
    alreadyRunning: false,
    executable,
    pid: child.pid,
    host,
    port,
    userDataDir,
    message: `Successfully launched browser (${path.basename(executable)}) with CDP active on http://${host}:${port}`,
  };
}

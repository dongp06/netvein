#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CdpSession } from "./cdp.js";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";
import { checkForUpdate, defaultUpdateDeps, isUpdateCheckEnabled } from "./updater.js";
import { VERSION } from "./version.js";

function printHelp(): void {
  console.log(`
Netvein MCP v${VERSION}
The reverse-engineer's browser MCP: Chrome DevTools Protocol session plus a wire-level
traffic daemon for web reverse engineering and dynamic analysis.

Usage:
  netvein [command] [options]
  netvein-mcp [command] [options]

Commands:
  serve [options]                     Start Netvein as an MCP server (--mcp)
  init [dir] [--force]                Create a .netvein workspace (same as the netvein_init tool)
  status [dir]                        Show workspace config and newest captures (same as netvein_project)
  install [--target <agents>] [--force] Install Netvein MCP into AI agents (Claude, Cursor, Antigravity, Codex)
  uninstall [--target <agents>]        Remove Netvein MCP from AI agents

Options:
  --mcp               Explicit flag indicating MCP stdio mode (used with serve)
  --project <dir>     .netvein workspace directory (else NETVEIN_PROJECT env, else discovered from cwd)
  --host <string>     CDP endpoint host (default: 127.0.0.1 or CDP_HOST env)
  --port <number>     CDP endpoint port (default: 9222 or CDP_PORT env)
  -v, --version       Display version
  -h, --help          Show this help message

Environment Variables:
  CDP_HOST            Chrome DevTools host (default: 127.0.0.1)
  CDP_PORT            Chrome DevTools port (default: 9222)
  NETVEIN_PROJECT     Explicit .netvein workspace directory (overrides upward discovery)
  LOG_LEVEL           Logging verbosity (debug, info, warn, error)
  NETVEIN_UPDATE_CHECK           Set to 0 to disable the start-up update check
  NETVEIN_UPDATE_INTERVAL_HOURS  Hours between checks (default: 24)
  `.trim());
}

/**
 * Non-blocking start-up update check. The report goes through MCP logging, with
 * stderr as the fallback — never stdout, which is the JSON-RPC channel and would
 * be corrupted by a stray line. Nothing here modifies the working tree.
 */
async function announceUpdateCheck(server: McpServer): Promise<void> {
  if (!isUpdateCheckEnabled()) return;
  try {
    const result = await checkForUpdate(defaultUpdateDeps());
    if (result.status !== "update-available") return;
    const message = `A newer release is available: ${result.localVersion} -> ${result.remoteVersion}. ${result.updateUrl}`;
    const host = server as unknown as {
      server?: { sendLoggingMessage?: (params: unknown) => Promise<void> };
    };
    if (typeof host.server?.sendLoggingMessage === "function") {
      await host.server.sendLoggingMessage({ level: "info", logger: "update-check", data: message });
    } else {
      console.error(`[netvein-mcp] ${message}`);
    }
  } catch {
    // A failed check is never fatal and is never worth a line on stdout.
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    printHelp();
    process.exit(0);
  }
  if (args.includes("-v") || args.includes("--version")) {
    console.log(VERSION);
    process.exit(0);
  }

  const config = loadConfig();

  // Parse CLI overrides if supplied
  const hostIdx = args.indexOf("--host");
  if (hostIdx !== -1 && args[hostIdx + 1]) {
    config.host = args[hostIdx + 1];
  }
  const portIdx = args.indexOf("--port");
  if (portIdx !== -1 && args[portIdx + 1]) {
    config.port = Number(args[portIdx + 1]) || config.port;
  }

  const argv = process.argv.slice(2);
  const projectIdx = argv.indexOf("--project");
  const projectDir = projectIdx !== -1 && argv[projectIdx + 1] ? argv[projectIdx + 1] : undefined;

  const sub = argv[0];
  if (sub === "install" || sub === "uninstall") {
    const { installAgents, uninstallAgents } = await import("./installer.js");
    const targetIdx = argv.indexOf("--target");
    const targets = targetIdx !== -1 && argv[targetIdx + 1] ? argv[targetIdx + 1].split(",").map((s) => s.trim()) : undefined;
    const force = argv.includes("--force");

    if (sub === "install") {
      console.log(`Installing Netvein MCP v${VERSION} into AI agents...`);
      const results = installAgents({ targets, force });
      for (const r of results) {
        const mark = r.action === "installed" || r.action === "updated" ? "✓" : r.action === "already-configured" ? "•" : "x";
        console.log(`  [${mark}] ${r.target}: ${r.action} (${r.path})`);
        if (r.error) console.log(`      Error: ${r.error}`);
      }
    } else {
      console.log("Uninstalling Netvein MCP from AI agents...");
      const results = uninstallAgents({ targets });
      for (const r of results) {
        const mark = r.action === "removed" ? "✓" : "•";
        console.log(`  [${mark}] ${r.target}: ${r.action} (${r.path})`);
        if (r.error) console.log(`      Error: ${r.error}`);
      }
    }
    process.exit(0);
  }

  if (sub === "init" || sub === "status") {
    const { initProject, findProjectDir, loadWorkspace, listCaptures, ProjectExistsError } = await import("./project.js");
    const dir = (await import("node:path")).resolve(argv[1] && !argv[1].startsWith("--") ? argv[1] : process.cwd());
    if (sub === "init") {
      try {
        const r = initProject(dir, argv.includes("--force"));
        console.log(`workspace: ${r.dir}`);
        for (const c of r.created) console.log(`  created ${c}`);
        if (r.created.length === 0) console.log("  (nothing missing — workspace already complete)");
      } catch (e) {
        if (e instanceof ProjectExistsError) {
          console.error(`${e.message} Re-run with --force to add any missing files.`);
          process.exit(1);
        }
        throw e;
      }
    } else {
      const found = findProjectDir(dir);
      if (!found) {
        console.log(`no .netvein workspace at or above ${dir}`);
        console.log("create one: netvein init");
        process.exit(1);
      }
      const ws = loadWorkspace(found);
      console.log(`workspace: ${ws.dir}`);
      console.log(`config:    ${JSON.stringify(ws.config)}`);
      const caps = listCaptures(ws);
      console.log(`captures:  ${caps.length ? "" : "(none)"}`);
      for (const c of caps) console.log(`  ${c.mtime}  ${c.bytes}B  ${c.file}`);
    }
    process.exit(0);
  }

  // If invoked with "serve", strip it so subsequent args are clean
  if (sub === "serve") {
    argv.shift();
  }

  const session = new CdpSession({ host: config.host, port: config.port, projectDir });
  const server = createServer(session);
  const transport = new StdioServerTransport();

  const shutdown = async () => {
    try {
      await session.disconnect();
    } catch (_) {}
    try {
      // The traffic daemon is netvein-owned: it must not outlive us.
      await session.mitm.stop();
    } catch (_) {}
    try {
      await server.close();
    } catch (_) {}
    process.exit(0);
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  process.on("unhandledRejection", (reason) => {
    // Avoid crashing on uncaught CDP background socket disconnects
    console.error("[netvein-mcp] Unhandled promise rejection:", reason);
  });

  await server.connect(transport);
  // Deliberately not awaited: the client is already served while this runs.
  void announceUpdateCheck(server);
}

main().catch((error) => {
  console.error("[netvein-mcp] Fatal server error:", error);
  process.exit(1);
});

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
  netvein-mcp [options]

Options:
  --host <string>     CDP endpoint host (default: 127.0.0.1 or CDP_HOST env)
  --port <number>     CDP endpoint port (default: 9222 or CDP_PORT env)
  -v, --version       Display version
  -h, --help          Show this help message

Environment Variables:
  CDP_HOST            Chrome DevTools host (default: 127.0.0.1)
  CDP_PORT            Chrome DevTools port (default: 9222)
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

  const session = new CdpSession({ host: config.host, port: config.port });
  const server = createServer(session);
  const transport = new StdioServerTransport();

  const shutdown = async () => {
    try {
      await session.disconnect();
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

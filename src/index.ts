#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CdpSession } from "./cdp.js";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

function printHelp(): void {
  console.log(`
Reverse Engineering MCP Server v0.2.0
An advanced Chrome DevTools Protocol (CDP) server for web reverse engineering and dynamic analysis.

Usage:
  reverse-engineering-mcp [options]

Options:
  --host <string>     CDP endpoint host (default: 127.0.0.1 or CDP_HOST env)
  --port <number>     CDP endpoint port (default: 9222 or CDP_PORT env)
  -v, --version       Display version
  -h, --help          Show this help message

Environment Variables:
  CDP_HOST            Chrome DevTools host (default: 127.0.0.1)
  CDP_PORT            Chrome DevTools port (default: 9222)
  LOG_LEVEL           Logging verbosity (debug, info, warn, error)
  `.trim());
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("-h") || args.includes("--help")) {
    printHelp();
    process.exit(0);
  }
  if (args.includes("-v") || args.includes("--version")) {
    console.log("0.2.0");
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
    console.error("[reverse-engineering-mcp] Unhandled promise rejection:", reason);
  });

  await server.connect(transport);
}

main().catch((error) => {
  console.error("[reverse-engineering-mcp] Fatal server error:", error);
  process.exit(1);
});

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CdpSession } from "./cdp.js";

/**
 * Register MCP resources for live inspection of browser state without executing active tools.
 */
export function registerResources(server: McpServer, session: CdpSession): void {
  server.registerResource(
    "session-status",
    "netvein://session/status",
    {
      description: "Current CDP connection status, attached page URL, pause state, and active counters.",
      mimeType: "application/json",
    },
    async (uri) => {
      const status = session.status();
      const currentUrl = await session.getCurrentUrl().catch(() => null);
      return {
        contents: [
          {
            uri: uri.toString(),
            mimeType: "application/json",
            text: JSON.stringify({ ...status, currentUrl }, null, 2),
          },
        ],
      };
    },
  );

  server.registerResource(
    "console-logs",
    "netvein://session/console",
    {
      description: "Captured browser console messages, errors, warnings, and unhandled exceptions.",
      mimeType: "text/plain",
    },
    async (uri) => {
      const logs = session.getConsole(200);
      const formatted = logs
        .map((l) => `[${l.timestamp}] [${l.type}] ${l.args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a ?? ""))).join(" ")}`)
        .join("\n");
      return {
        contents: [
          {
            uri: uri.toString(),
            mimeType: "text/plain",
            text: formatted || "No console messages captured yet.",
          },
        ],
      };
    },
  );

  server.registerResource(
    "timeline-events",
    "netvein://session/timeline",
    {
      description: "Chronological timeline of network requests, debugger pauses, and hook invocations.",
      mimeType: "application/json",
    },
    async (uri) => {
      const events = session.getTimeline(200);
      return {
        contents: [
          {
            uri: uri.toString(),
            mimeType: "application/json",
            text: JSON.stringify(events, null, 2),
          },
        ],
      };
    },
  );
}

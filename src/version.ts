/**
 * Single source of truth for the advertised version. `package.json` is the
 * release version; this constant is what the MCP handshake and the CLI report,
 * so the three cannot drift apart silently.
 */
export const VERSION = "0.3.0";

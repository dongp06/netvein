export interface ServerConfig {
  host: string;
  port: number;
  logLevel: "debug" | "info" | "warn" | "error";
  maxStoredText: number;
  maxConsoleEvents: number;
  maxNetworkRecords: number;
  maxSocketEvents: number;
  maxHookEvents: number;
  maxTimelineEvents: number;
}

export function loadConfig(env = process.env): ServerConfig {
  return {
    host: env.CDP_HOST || "127.0.0.1",
    port: Number(env.CDP_PORT) || 9222,
    logLevel: (env.LOG_LEVEL as ServerConfig["logLevel"]) || "info",
    maxStoredText: Number(env.MAX_STORED_TEXT) || 20_000,
    maxConsoleEvents: Number(env.MAX_CONSOLE_EVENTS) || 1_000,
    maxNetworkRecords: Number(env.MAX_NETWORK_RECORDS) || 1_000,
    maxSocketEvents: Number(env.MAX_SOCKET_EVENTS) || 2_000,
    maxHookEvents: Number(env.MAX_HOOK_EVENTS) || 2_000,
    maxTimelineEvents: Number(env.MAX_TIMELINE_EVENTS) || 5_000,
  };
}

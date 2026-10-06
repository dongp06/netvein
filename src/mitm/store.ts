export interface FlowSummary {
  id: string;
  ts: string;
  method: string;
  host: string;
  path: string;
  /** null while a held/in-flight flow has no response yet. */
  status: number | null;
  bytes: number;
  durationMs: number;
  held: boolean;
  expired: boolean;
  scheme: string;
}

export interface FlowFilters {
  host?: string;
  pathContains?: string;
  method?: string;
  status?: number;
  since?: string;
  heldOnly?: boolean;
  limit?: number;
}

export interface FlowDetail {
  summary: FlowSummary;
  request: { headers: Record<string, string>; body: string | null };
  response: { headers: Record<string, string>; body: string | null; status: number | null } | null;
  wsFrames?: Array<{ dir: "up" | "down"; ts: string; payload: string }>;
}

export const KEEP_REQUEST_HEADERS = [
  "content-type", "content-length", "user-agent", "referer", "cookie", "authorization",
  "accept", "accept-language", "origin", "x-requested-with",
];

export const KEEP_RESPONSE_HEADERS = [
  "content-type", "content-length", "set-cookie", "server", "cache-control",
];

/** Keep only the curated headers, lower-cased keys. Hop-by-hop noise disappears. */
export function stripHeaders(headers: Record<string, string>, kind: "request" | "response"): Record<string, string> {
  const keep = kind === "request" ? KEEP_REQUEST_HEADERS : KEEP_RESPONSE_HEADERS;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    const lower = key.toLowerCase();
    if (keep.includes(lower)) out[lower] = value;
  }
  return out;
}

export function filterFlows(flows: readonly FlowSummary[], filters: FlowFilters): FlowSummary[] {
  const sinceMs = filters.since ? Date.parse(filters.since) : null;
  const out = flows.filter((flow) => {
    if (filters.host && !flow.host.toLowerCase().includes(filters.host.toLowerCase())) return false;
    if (filters.pathContains && !flow.path.includes(filters.pathContains)) return false;
    if (filters.method && flow.method.toUpperCase() !== filters.method.toUpperCase()) return false;
    if (filters.status !== undefined && flow.status !== filters.status) return false;
    if (filters.heldOnly && !flow.held) return false;
    if (sinceMs !== null && !Number.isNaN(sinceMs) && Date.parse(flow.ts) < sinceMs) return false;
    return true;
  });
  const limit = Math.max(1, Math.min(filters.limit ?? 50, 500));
  return out.slice(-limit);
}

export function formatFlowList(flows: readonly FlowSummary[]): string {
  const lines = [`${flows.length} flows (newest last)`];
  for (const flow of flows) {
    const status = flow.status === null ? "-" : String(flow.status);
    const marks = flow.held ? ` [HELD${flow.expired ? " expired" : ""}]` : "";
    lines.push(`${flow.id} ${flow.method} ${flow.host}${flow.path} -> ${status} ${flow.bytes}B ${flow.durationMs}ms${marks}`);
  }
  return lines.join("\n");
}

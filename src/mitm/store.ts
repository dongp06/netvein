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

/** Pretty JSON when parseable, binary marker when not, truncated to maxChars. */
export function beautifyBody(body: string | null, contentType: string | null, maxChars: number): string {
  if (body === null || body === undefined) return "";
  const isText = contentType === null || /json|text|xml|urlencoded|javascript|html/.test(contentType);
  if (!isText) return `[binary ${Buffer.byteLength(body)} bytes]`;
  let out = body;
  if (contentType && contentType.includes("json")) {
    try {
      out = JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      // Not valid JSON after all; keep the raw text.
    }
  }
  if (out.length > maxChars) return `${out.slice(0, maxChars)}…[truncated]`;
  return out;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Ready-to-run curl from a captured flow. Curated headers unless full. */
export function buildCurl(detail: FlowDetail, fullHeaders = false): string {
  const headers = fullHeaders
    ? detail.request.headers
    : stripHeaders(detail.request.headers, "request");
  const argv = ["curl", "-X", detail.summary.method, shellQuote(detail.summary.scheme + "://" + detail.summary.host + detail.summary.path)];
  for (const [key, value] of Object.entries(headers)) {
    argv.push("-H", shellQuote(`${key}: ${value}`));
  }
  if (detail.request.body !== null && detail.request.body !== undefined) {
    argv.push("--data-raw", shellQuote(detail.request.body));
  }
  return argv.join(" ");
}

export interface ReplayResponse {
  status: number | null;
  headers: Record<string, string>;
  body: string | null;
  error?: string;
}

function flatten(value: unknown, prefix = ""): Record<string, unknown> {
  if (value === null || typeof value !== "object") return { [prefix || "$"]: value };
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (child !== null && typeof child === "object") Object.assign(out, flatten(child, path));
    else out[path] = child;
  }
  return out;
}

function safeJson(body: string | null): unknown {
  if (body === null || body === undefined) return undefined;
  try {
    const parsed = JSON.parse(body);
    return parsed !== null && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Bounded, path-level comparison of an original flow body against a replay. */
export function diffReplay(
  original: { status: number | null; body: string | null; headers: Record<string, string> },
  replay: ReplayResponse,
  maxEntries: number,
): { statusChanged: boolean; statusFrom: number | null; statusTo: number | null; body: { changed: string[]; added: string[]; removed: string[] } | null; truncated: boolean } {
  const before = flatten(safeJson(original.body));
  const after = flatten(safeJson(replay.body));
  const changed: string[] = [];
  const added: string[] = [];
  const removed: string[] = [];
  for (const [path, value] of Object.entries(after)) {
    if (!(path in before)) added.push(path);
    else if (!sameValue(before[path], value)) changed.push(path);
  }
  for (const path of Object.keys(before)) {
    if (!(path in after)) removed.push(path);
  }
  const truncated = changed.length + added.length + removed.length > maxEntries;
  const cap = (list: string[]) => list.slice(0, maxEntries);
  const parseable = safeJson(original.body) !== undefined || safeJson(replay.body) !== undefined;
  return {
    statusChanged: original.status !== replay.status,
    statusFrom: original.status,
    statusTo: replay.status,
    body: parseable ? { changed: cap(changed), added: cap(added), removed: cap(removed) } : null,
    truncated,
  };
}

export type FlowPart = "request" | "response" | "both" | "ws";

/** Shaping for traffic_flow: curated headers, beautified bodies, per-part view. */
export function shapeFlowDetail(detail: FlowDetail, part: FlowPart, maxChars: number): Record<string, unknown> {
  const out: Record<string, unknown> = { id: detail.summary.id, summary: detail.summary };
  if (part === "request" || part === "both") {
    out.request = {
      headers: stripHeaders(detail.request.headers, "request"),
      body: beautifyBody(detail.request.body, detail.request.headers["content-type"] ?? null, maxChars),
    };
  }
  if (part === "response" || part === "both") {
    out.response = detail.response
      ? {
          headers: stripHeaders(detail.response.headers, "response"),
          body: beautifyBody(detail.response.body, detail.response.headers["content-type"] ?? null, maxChars),
          status: detail.response.status,
        }
      : null;
  }
  if (part === "ws") out.wsFrames = detail.wsFrames ?? [];
  return out;
}

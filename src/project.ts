import * as fs from "node:fs";
import * as path from "node:path";

export const PROJECT_DIR_NAME = ".netvein";

export interface TrafficProjectConfig {
  port?: number;
  caDir?: string;
  allowHosts?: string[];
  attachBrowser?: boolean;
  capture?: boolean;
}

export interface ProjectConfig {
  cdp?: { host?: string; port?: number };
  traffic?: TrafficProjectConfig;
}

export interface Workspace {
  /** Absolute path of the `.netvein` directory. */
  dir: string;
  config: ProjectConfig;
  captureDir: string;
  notesDir: string;
}

export interface CaptureEntry {
  file: string;
  bytes: number;
  mtime: string;
}

export class ProjectExistsError extends Error {
  constructor(public readonly dir: string) {
    super(`A netvein workspace already exists at ${dir}.`);
    this.name = "ProjectExistsError";
  }
}

/** Walk up from startPath looking for a `.netvein` directory (workspace discovery). */
export function findProjectDir(startPath: string): string | null {
  let current = path.resolve(startPath);
  for (;;) {
    const candidate = path.join(current, PROJECT_DIR_NAME);
    try {
      if (fs.statSync(candidate).isDirectory()) return candidate;
    } catch {
      // absent at this level
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function pickString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function pickNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function pickBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

/** Parse + sanitize: wrong-typed keys are dropped, never thrown over. */
export function parseProjectConfig(raw: string): ProjectConfig {
  const parsed: unknown = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("netvein config must be a JSON object");
  }
  const top = parsed as Record<string, unknown>;
  const out: ProjectConfig = {};
  if (top.cdp && typeof top.cdp === "object") {
    const cdp = top.cdp as Record<string, unknown>;
    const host = pickString(cdp.host);
    const port = pickNumber(cdp.port);
    if (host || port !== undefined) out.cdp = { ...(host ? { host } : {}), ...(port !== undefined ? { port } : {}) };
  }
  if (top.traffic && typeof top.traffic === "object") {
    const t = top.traffic as Record<string, unknown>;
    const traffic: TrafficProjectConfig = {};
    const port = pickNumber(t.port);
    const caDir = pickString(t.caDir);
    const attachBrowser = pickBoolean(t.attachBrowser);
    const capture = pickBoolean(t.capture);
    if (port !== undefined) traffic.port = port;
    if (caDir) traffic.caDir = caDir;
    if (Array.isArray(t.allowHosts) && t.allowHosts.every((x) => typeof x === "string")) traffic.allowHosts = t.allowHosts as string[];
    if (attachBrowser !== undefined) traffic.attachBrowser = attachBrowser;
    if (capture !== undefined) traffic.capture = capture;
    if (Object.keys(traffic).length > 0) out.traffic = traffic;
  }
  return out;
}

export function loadWorkspace(dir: string): Workspace {
  const resolved = path.resolve(dir);
  let config: ProjectConfig = {};
  const configPath = path.join(resolved, "config.json");
  if (fs.existsSync(configPath)) {
    config = parseProjectConfig(fs.readFileSync(configPath, "utf8"));
  }
  return {
    dir: resolved,
    config,
    captureDir: path.join(resolved, "capture"),
    notesDir: path.join(resolved, "notes"),
  };
}

const CONFIG_TEMPLATE = `{
  "cdp": { "host": "127.0.0.1", "port": 9222 },
  "traffic": { "port": 8080, "capture": true, "attachBrowser": true }
}
`;

const GITIGNORE_TEMPLATE = `# netvein local analysis state — add this directory to git.
# config.json may be committed when a team wants to share it; artifacts are not.
capture/
notes/
`;

const README_TEMPLATE = `# .netvein — netvein-mcp project workspace
 
Discovered by walking up from the process working directory. When present, netvein-mcp:

- applies \`config.json\` (cdp + traffic defaults) after CLI flags and
  \`NETVEIN_*\` env vars but before built-in defaults;
- auto-captures traffic daemon flows into \`capture/flows-<utc>.jsonl\`
  (one JSON line per finished flow; websocket flows get a second, frame-complete
  line at close — **last occurrence of an id wins**);
- keeps manual exports in \`capture/\` as the default destination.

\`capture/\` and \`notes/\` are scratch: gitignore them (a \`.gitignore\` is
provided here). Commit \`config.json\` only if the settings are team-shared.
`;

export interface InitResult {
  dir: string;
  created: string[];
}

/**
 * Create the `.netvein` skeleton under startPath. Never destructive: existing
 * files are left alone; `force` only bypasses the already-exists refusal.
 */
export function initProject(startPath: string, force = false): InitResult {
  const root = path.resolve(startPath);
  const dir = path.join(root, PROJECT_DIR_NAME);
  const exists = fs.existsSync(dir);
  if (exists && !force) throw new ProjectExistsError(dir);
  const created: string[] = [];
  const files: Array<[string, string]> = [
    ["config.json", CONFIG_TEMPLATE],
    [".gitignore", GITIGNORE_TEMPLATE],
    ["README.md", README_TEMPLATE],
  ];
  fs.mkdirSync(dir, { recursive: true });
  for (const sub of ["capture", "notes"]) {
    const p = path.join(dir, sub);
    if (!fs.existsSync(p)) {
      fs.mkdirSync(p);
      created.push(sub + "/");
    }
  }
  for (const [rel, contents] of files) {
    const p = path.join(dir, rel);
    if (!fs.existsSync(p)) {
      fs.writeFileSync(p, contents);
      created.push(rel);
    }
  }
  return { dir, created };
}

/** Newest-first capture artifacts (daemon captures + manual exports). */
export function listCaptures(workspace: Workspace, limit = 10): CaptureEntry[] {
  let names: string[];
  try {
    names = fs.readdirSync(workspace.captureDir);
  } catch {
    return [];
  }
  const entries: CaptureEntry[] = [];
  for (const name of names) {
    if (!/^(flows|export)-.*\.(jsonl|har)$/.test(name)) continue;
    try {
      const stat = fs.statSync(path.join(workspace.captureDir, name));
      if (!stat.isFile()) continue;
      entries.push({ file: name, bytes: stat.size, mtime: stat.mtime.toISOString() });
    } catch {
      // raced away; skip
    }
  }
  entries.sort((a, b) => b.mtime.localeCompare(a.mtime));
  return entries.slice(0, limit);
}

/** `flows-2026-10-06T02-53-12-123Z.jsonl` — sortable, filesystem-safe. */
export function captureStamp(date = new Date()): string {
  return `flows-${date.toISOString().replace(/[:.]/g, "-")}.jsonl`;
}

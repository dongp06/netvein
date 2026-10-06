import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { VERSION } from "./version.js";

/**
 * Read-only update *checking*. Nothing in this module writes to the repository,
 * replaces files, or executes remote content. It compares the locally reported
 * version against the tags on the git remote and reports the difference. The
 * decision to update stays with the operator.
 */

export type UpdateStatus = "update-available" | "up-to-date" | "ahead" | "unknown" | "throttled";

export interface UpdateResult {
  status: UpdateStatus;
  localVersion: string;
  remoteVersion?: string;
  updateUrl?: string;
  checkedAt?: string;
  detail?: string;
  /** Head of the tracked remote branch, when the branch probe is available. */
  remoteBranchHead?: string;
  /** Local HEAD, when the branch probe is available. */
  localHead?: string;
  /** True when both heads were read and differ. Absent when either was unavailable. */
  branchDiffers?: boolean;
}

export interface UpdateDeps {
  localVersion: string;
  runLsRemote: () => Promise<string[]>;
  readCache: () => Promise<{ checkedAt: string } | null>;
  writeCache: (value: { checkedAt: string }) => Promise<void>;
  now: () => string;
  intervalMs?: number;
  force?: boolean;
  repoUrl?: string;
  /**
   * Optional branch probe. The repository carries no release tags, so the tag
   * comparison alone can never report anything; comparing the tracked branch
   * head against local HEAD is what actually answers "has the remote moved".
   * Without a fetch we cannot order the two heads, so the result reports
   * `branchDiffers` rather than claiming a direction.
   */
  runLsRemoteBranch?: () => Promise<string | null>;
  readLocalHead?: () => Promise<string | null>;
  remoteBranch?: string;
}

export const DEFAULT_INTERVAL_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_REPO_URL = "https://github.com/dongp06/netvein-mcp";

/** Parse `v0.4.0`, `0.4.0` or `1.2` into a comparable triple. Null for anything else. */
export function parseVersion(tag: string): [number, number, number] | null {
  const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(tag.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

/** Numeric semver ordering. Missing components count as zero. */
export function compareVersions(a: readonly number[], b: readonly number[]): number {
  const length = Math.max(a.length, b.length, 3);
  for (let index = 0; index < length; index++) {
    const left = a[index] ?? 0;
    const right = b[index] ?? 0;
    if (left !== right) return left > right ? 1 : -1;
  }
  return 0;
}

/**
 * Compare the local version against every parsable tag and report the highest.
 * Unparsable tags are ignored; if none parse, the answer is `unknown` rather
 * than a guess.
 */
export function classifyUpdate(
  localVersion: string,
  tags: readonly string[],
): { status: UpdateStatus; remoteVersion?: string } {
  const local = parseVersion(localVersion);
  if (!local) return { status: "unknown" };

  let highest: [number, number, number] | null = null;
  let highestLabel: string | null = null;
  for (const tag of tags) {
    const parsed = parseVersion(tag);
    if (!parsed) continue;
    if (!highest || compareVersions(parsed, highest) > 0) {
      highest = parsed;
      highestLabel = tag.trim().replace(/^v/, "");
    }
  }

  if (!highest || !highestLabel) return { status: "unknown" };
  const order = compareVersions(highest, local);
  if (order > 0) return { status: "update-available", remoteVersion: highestLabel };
  if (order === 0) return { status: "up-to-date", remoteVersion: highestLabel };
  return { status: "ahead", remoteVersion: highestLabel };
}

/** An unreadable or unparsable timestamp counts as due, so a corrupt cache cannot wedge checking. */
export function isCheckDue(
  lastCheckedAt: string | null | undefined,
  nowIso: string,
  intervalMs: number,
): boolean {
  if (!lastCheckedAt) return true;
  const last = Date.parse(lastCheckedAt);
  const now = Date.parse(nowIso);
  if (Number.isNaN(last) || Number.isNaN(now)) return true;
  return now - last >= intervalMs;
}

async function quiet<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

/**
 * Run one check. Every failure path returns a result instead of throwing, so
 * the caller can log it without guarding. Cache read/write failures are
 * swallowed: a broken cache must not break the check.
 */
export async function checkForUpdate(deps: UpdateDeps): Promise<UpdateResult> {
  const intervalMs = deps.intervalMs ?? DEFAULT_INTERVAL_MS;
  const repoUrl = deps.repoUrl ?? DEFAULT_REPO_URL;
  const base: UpdateResult = { status: "unknown", localVersion: deps.localVersion };

  if (!deps.force) {
    const cache = await quiet(() => deps.readCache(), null);
    if (!isCheckDue(cache?.checkedAt ?? null, deps.now(), intervalMs)) {
      return { ...base, status: "throttled", ...(cache?.checkedAt ? { checkedAt: cache.checkedAt } : {}) };
    }
  }

  let refs: string[];
  try {
    refs = await deps.runLsRemote();
  } catch (error) {
    return { ...base, status: "unknown", detail: error instanceof Error ? error.message : String(error) };
  }

  const tags = refs
    .map((line) => {
      const parts = line.trim().split(/\s+/);
      return (parts[parts.length - 1] ?? "").replace(/^refs\/tags\//, "");
    })
    .filter((tag) => tag.length > 0);

  const checkedAt = deps.now();
  await quiet(() => deps.writeCache({ checkedAt }), undefined);

  const classification = classifyUpdate(deps.localVersion, tags);

  const branch: Pick<UpdateResult, "remoteBranchHead" | "localHead" | "branchDiffers"> = {};
  if (deps.runLsRemoteBranch && deps.readLocalHead) {
    const probeBranch = deps.runLsRemoteBranch;
    const probeLocal = deps.readLocalHead;
    const remote = await quiet(() => probeBranch(), null);
    const local = await quiet(() => probeLocal(), null);
    if (remote) {
      branch.remoteBranchHead = remote;
    }
    if (local) {
      branch.localHead = local;
    }
    // Only claim a difference when both sides were actually read.
    if (remote && local) {
      branch.branchDiffers = remote !== local;
    }
  }

  return {
    status: classification.status,
    localVersion: deps.localVersion,
    ...(classification.remoteVersion ? { remoteVersion: classification.remoteVersion } : {}),
    updateUrl: repoUrl,
    checkedAt,
    ...branch,
  };
}

/** Use a URL rather than the `origin` remote so the check does not depend on cwd. */
export function runGitLsRemote(repoUrl: string, timeoutMs = 3000): Promise<string[]> {
  return new Promise((resolve, reject) => {
    execFile("git", ["ls-remote", "--tags", "--refs", repoUrl], { timeout: timeoutMs }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(
        String(stdout)
          .split("\n")
          .filter((line) => line.trim().length > 0),
      );
    });
  });
}

export function defaultCachePath(): string {
  return path.join(os.tmpdir(), "netvein-mcp-update-check.json");
}

/** The checkout this module was loaded from, not the client's cwd. */
function packageRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

/** Head SHA of the tracked remote branch, or null when it cannot be read. */
export function runGitLsRemoteBranch(repoUrl: string, branch: string, timeoutMs = 3000): Promise<string | null> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      ["ls-remote", "--heads", repoUrl, `refs/heads/${branch}`],
      { timeout: timeoutMs },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        const sha = (String(stdout).trim().split("\n")[0] ?? "").split(/\s+/)[0] ?? "";
        resolve(/^[0-9a-f]{40}$/.test(sha) ? sha : null);
      },
    );
  });
}

/** Local HEAD of the checkout this module ships in, or null when it is not a git repo. */
export function readLocalHeadGit(cwd = packageRoot(), timeoutMs = 3000): Promise<string | null> {
  return new Promise((resolve, reject) => {
    execFile("git", ["rev-parse", "HEAD"], { cwd, timeout: timeoutMs }, (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }
      const sha = String(stdout).trim();
      resolve(/^[0-9a-f]{40}$/.test(sha) ? sha : null);
    });
  });
}

export function defaultRemoteBranch(env: NodeJS.ProcessEnv = process.env): string {
  const configured = readEnvWithFallback(env, "NETVEIN_UPDATE_BRANCH", "REVERSE_MCP_UPDATE_BRANCH")?.trim();
  return configured && configured.length > 0 ? configured : "main";
}

const deprecatedEnvWarned = new Set<string>();

/**
 * Read NETVEIN_* first, falling back to the pre-rename REVERSE_MCP_* names. The
 * deprecated read warns once per variable, to stderr only — stdout is the
 * JSON-RPC channel.
 */
function readEnvWithFallback(env: NodeJS.ProcessEnv, newName: string, oldName: string): string | undefined {
  if (env[newName] !== undefined) return env[newName];
  if (env[oldName] !== undefined) {
    if (!deprecatedEnvWarned.has(oldName)) {
      deprecatedEnvWarned.add(oldName);
      console.error(`[netvein-mcp] ${oldName} is deprecated; use ${newName} instead. Both work for now.`);
    }
    return env[oldName];
  }
  return undefined;
}

export function isUpdateCheckEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = readEnvWithFallback(env, "NETVEIN_UPDATE_CHECK", "REVERSE_MCP_UPDATE_CHECK");
  if (raw === undefined) return true;
  return !["0", "false", "off", "no"].includes(raw.trim().toLowerCase());
}

export function updateIntervalMs(env: NodeJS.ProcessEnv = process.env): number {
  const hours = Number(readEnvWithFallback(env, "NETVEIN_UPDATE_INTERVAL_HOURS", "REVERSE_MCP_UPDATE_INTERVAL_HOURS"));
  if (!Number.isFinite(hours) || hours <= 0) return DEFAULT_INTERVAL_MS;
  return hours * 3600_000;
}

export function defaultUpdateDeps(overrides: Partial<UpdateDeps> = {}): UpdateDeps {
  const cachePath = defaultCachePath();
  const branch = defaultRemoteBranch();
  return {
    localVersion: VERSION,
    runLsRemote: () => runGitLsRemote(DEFAULT_REPO_URL),
    runLsRemoteBranch: () => runGitLsRemoteBranch(DEFAULT_REPO_URL, branch),
    readLocalHead: () => readLocalHeadGit(),
    readCache: async () => {
      try {
        return JSON.parse(await fs.readFile(cachePath, "utf8")) as { checkedAt: string };
      } catch {
        return null;
      }
    },
    writeCache: async (value) => {
      try {
        await fs.writeFile(cachePath, JSON.stringify(value), "utf8");
      } catch {
        // A cache we cannot write just means the next check is unthrottled.
      }
    },
    now: () => new Date().toISOString(),
    intervalMs: updateIntervalMs(),
    ...overrides,
  };
}

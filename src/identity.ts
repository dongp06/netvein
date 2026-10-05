import * as net from "node:net";
import type { CookieRecord } from "./types.js";

export interface IdentityRecord {
  name: string;
  browserContextId: string | null;
  proxy?: string;
  seed: number;
  createdAt: string;
  usable: boolean;
}

const PROXY_PATTERN = /^(?:[a-z0-9]+:\/\/)?([a-z0-9.\-]+):(\d{1,5})$/i;

/**
 * Normalise a proxy string to the "host:port" form that
 * Target.createBrowserContext expects. Throws on anything malformed so the
 * caller can surface ERR_PROXY_UNREACHABLE before a context is created.
 */
export function parseProxyServer(proxy: string): string {
  const match = PROXY_PATTERN.exec(proxy.trim());
  if (!match) {
    throw new Error(`Proxy must be in host:port form (optionally scheme://host:port), received "${proxy}".`);
  }
  const port = Number(match[2]);
  if (port < 1 || port > 65535) {
    throw new Error(`Proxy must be in host:port form with a port between 1 and 65535, received "${proxy}".`);
  }
  return `${match[1]}:${port}`;
}

/** Resolve when a TCP connection to host:port completes within the timeout. */
export function probeProxy(proxy: string, timeoutMs = 3000): Promise<void> {
  return new Promise((resolve, reject) => {
    const normalized = parseProxyServer(proxy);
    const separator = normalized.lastIndexOf(":");
    const host = normalized.slice(0, separator);
    const port = Number(normalized.slice(separator + 1));

    const socket = net.connect({ host, port });
    const finish = (error?: Error): void => {
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish());
    socket.once("timeout", () =>
      finish(new Error(`Proxy ${normalized} did not accept a connection within ${timeoutMs}ms.`)),
    );
    socket.once("error", (error: Error) => finish(new Error(`Proxy ${normalized} is unreachable: ${error.message}`)));
  });
}

export interface IdentityPayload {
  version: 1;
  name: string;
  proxy?: string;
  exportedAt: string;
  cookies: CookieRecord[];
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
}

export function serializeIdentity(
  name: string,
  proxy: string | undefined,
  cookies: CookieRecord[],
  localStorage: Record<string, string>,
  sessionStorage: Record<string, string>,
): IdentityPayload {
  const payload: IdentityPayload = {
    version: 1,
    name,
    exportedAt: new Date().toISOString(),
    cookies,
    localStorage,
    sessionStorage,
  };
  if (proxy !== undefined) payload.proxy = proxy;
  return payload;
}

/**
 * Validate an exported identity payload. Throws with an actionable message so
 * the caller can return an envelope error without applying anything partially.
 */
export function parseIdentityPayload(json: string): IdentityPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new Error(`Identity payload is not valid JSON: ${error instanceof Error ? error.message : String(error)}.`);
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Identity payload must be a JSON object.");
  }

  const candidate = parsed as Partial<IdentityPayload>;

  if (typeof candidate.name !== "string" || candidate.name.length === 0) {
    throw new Error("Identity payload is missing a non-empty name field.");
  }
  if (!Array.isArray(candidate.cookies)) {
    throw new Error("Identity payload is missing a cookies array.");
  }
  if (candidate.localStorage !== undefined && typeof candidate.localStorage !== "object") {
    throw new Error("Identity payload localStorage must be an object when present.");
  }
  if (candidate.sessionStorage !== undefined && typeof candidate.sessionStorage !== "object") {
    throw new Error("Identity payload sessionStorage must be an object when present.");
  }

  return {
    version: 1,
    name: candidate.name,
    ...(candidate.proxy !== undefined ? { proxy: candidate.proxy } : {}),
    exportedAt: candidate.exportedAt ?? new Date().toISOString(),
    cookies: candidate.cookies as CookieRecord[],
    localStorage: (candidate.localStorage as Record<string, string>) ?? {},
    sessionStorage: (candidate.sessionStorage as Record<string, string>) ?? {},
  };
}

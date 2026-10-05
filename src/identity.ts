import * as net from "node:net";

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

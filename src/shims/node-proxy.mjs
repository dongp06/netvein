// netvein node-proxy shim
// Injected via NODE_OPTIONS="--import .../node-proxy.mjs" to route
// fetch, undici, http, and https through Netvein's capture proxy.

const proxyUrl =
  process.env.NETVEIN_PROXY_URL ||
  process.env.HTTPS_PROXY ||
  process.env.https_proxy ||
  process.env.HTTP_PROXY ||
  process.env.http_proxy ||
  process.env.ALL_PROXY ||
  process.env.all_proxy;

const proxyOnlyRaw = process.env.NETVEIN_FOCUS || process.env.CAPTURE_KIT_FOCUS || "";
const proxyOnlyHosts = proxyOnlyRaw
  .split(",")
  .map((entry) => entry.trim().toLowerCase())
  .filter(Boolean);

function hostMatchesAllowlist(hostname, allowlist) {
  if (!allowlist || allowlist.length === 0) return true;
  const h = (hostname || "").toLowerCase();
  for (const entry of allowlist) {
    if (entry === "*") return true;
    if (h === entry) return true;
    if (h.endsWith(`.${entry}`)) return true;
    if (h.includes(entry)) return true;
  }
  return false;
}

function resolveHostname(input) {
  if (!input) return "";
  if (typeof input === "string") {
    try {
      return new URL(input).hostname;
    } catch {
      return "";
    }
  }
  if (input instanceof URL) return input.hostname;
  return input.hostname || "";
}

if (proxyUrl) {
  try {
    const { ProxyAgent, setGlobalDispatcher, fetch: undiciFetch } = await import("undici");
    const proxyDispatcher = new ProxyAgent(proxyUrl);

    if (proxyOnlyHosts.length === 0) {
      setGlobalDispatcher(proxyDispatcher);
    }

    if (typeof globalThis.fetch === "function") {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (input, init = undefined) => {
        const hostname = resolveHostname(typeof input === "object" && input && "url" in input ? input.url : input);
        if (hostMatchesAllowlist(hostname, proxyOnlyHosts)) {
          const opts = init ? { ...init, dispatcher: proxyDispatcher } : { dispatcher: proxyDispatcher };
          return undiciFetch(input, opts);
        }
        return originalFetch(input, init);
      };
    }
  } catch {
    // Undici optional; continue to standard http/https agent
  }
}

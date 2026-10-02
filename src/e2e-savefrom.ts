import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface, type Interface } from "node:readline";

type JsonRpcMessage = {
  id?: number;
  result?: any;
  error?: { code?: number; message?: string; data?: unknown };
  method?: string;
};

type ToolResult = Record<string, any> | any[];

const DEFAULT_PAGE_URL = "https://en1.savefrom.net/19wr/";
const DEFAULT_SOURCE_URL = "https://vt.tiktok.com/ZSb5aNRof/";

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(value, minimum), maximum);
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) continue;
    const equalIndex = item.indexOf("=");
    if (equalIndex > 2) {
      args[item.slice(2, equalIndex)] = item.slice(equalIndex + 1);
      continue;
    }
    const key = item.slice(2);
    const next = argv[index + 1];
    if (next && !next.startsWith("--")) {
      args[key] = next;
      index += 1;
    } else {
      args[key] = true;
    }
  }
  return args;
}

function stringArg(args: Record<string, string | boolean>, name: string, fallback: string): string {
  return typeof args[name] === "string" && args[name].length > 0 ? args[name] as string : fallback;
}

function numberArg(args: Record<string, string | boolean>, name: string, fallback: number, minimum: number, maximum: number): number {
  const parsed = typeof args[name] === "string" ? Number(args[name]) : fallback;
  return Number.isFinite(parsed) ? clamp(Math.trunc(parsed), minimum, maximum) : fallback;
}

function parseToolText(response: any): unknown {
  const text = response?.content?.find((item: any) => item.type === "text")?.text;
  if (typeof text !== "string") return response;
  try { return JSON.parse(text); } catch (_) { return text; }
}

class McpStdioClient {
  private readonly child: ChildProcessWithoutNullStreams;
  private readonly lines: Interface;
  private readonly pending = new Map<number, { resolve: (message: JsonRpcMessage) => void; reject: (error: Error) => void }>();
  private nextId = 1;
  private stderr = "";

  constructor(projectRoot: string) {
    this.child = spawn(process.execPath, [resolve(projectRoot, "dist/index.js")], {
      cwd: projectRoot,
      env: { ...process.env, CDP_HOST: process.env.CDP_HOST ?? "127.0.0.1", CDP_PORT: process.env.CDP_PORT ?? "9222" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.lines = createInterface({ input: this.child.stdout });
    this.lines.on("line", (line) => {
      if (!line.trim()) return;
      let message: JsonRpcMessage;
      try { message = JSON.parse(line) as JsonRpcMessage; } catch (_) { return; }
      if (message.id === undefined) return;
      const waiter = this.pending.get(message.id);
      if (!waiter) return;
      this.pending.delete(message.id);
      waiter.resolve(message);
    });
    this.child.stderr.on("data", (chunk: Buffer) => {
      this.stderr += chunk.toString();
      if (this.stderr.length > 20_000) this.stderr = this.stderr.slice(-20_000);
    });
    this.child.on("exit", (code, signal) => {
      const suffix = this.stderr ? `\nMCP stderr:\n${this.stderr}` : "";
      for (const waiter of this.pending.values()) waiter.reject(new Error(`MCP exited (${code ?? "?"}/${signal ?? "?"})${suffix}`));
      this.pending.clear();
    });
  }

  request(method: string, params?: Record<string, unknown>): Promise<JsonRpcMessage> {
    const id = this.nextId++;
    const message = { jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) };
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, { resolve: resolvePromise, reject });
      this.child.stdin.write(`${JSON.stringify(message)}\n`);
    });
  }

  notify(method: string, params?: Record<string, unknown>): void {
    const message = { jsonrpc: "2.0", method, ...(params === undefined ? {} : { params }) };
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  async tool(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    const response = await this.request("tools/call", { name, arguments: args });
    if (response.error) throw new Error(`${name}: ${response.error.message ?? JSON.stringify(response.error)}`);
    const result = response.result;
    const value = parseToolText(result);
    if (result?.isError) {
      const message = typeof value === "object" && value !== null && "error" in value ? (value as any).error : value;
      throw new Error(`${name}: ${typeof message === "string" ? message : JSON.stringify(message)}`);
    }
    return value as ToolResult;
  }

  async close(): Promise<void> {
    this.lines.close();
    if (!this.child.killed) this.child.kill();
  }
}

function collectHttpUrls(value: unknown, output = new Set<string>(), depth = 0): Set<string> {
  if (output.size >= 300 || depth > 6 || value === null || value === undefined) return output;
  if (typeof value === "string") {
    for (const match of value.match(/https?:\/\/[^\s"'<>\\]+/gi) ?? []) {
      output.add(match.replace(/[),.;\]}]+$/g, "").slice(0, 4_000));
      if (output.size >= 300) break;
    }
    return output;
  }
  if (typeof value !== "object") return output;
  if (Array.isArray(value)) {
    for (const child of value) collectHttpUrls(child, output, depth + 1);
    return output;
  }
  for (const child of Object.values(value as Record<string, unknown>)) collectHttpUrls(child, output, depth + 1);
  return output;
}

function isCaptchaUrl(url: string): boolean {
  return /(?:^|[./_-])(captcha|recaptcha|hcaptcha|challenge)(?:[./?_-]|$)/i.test(url);
}

function isCaptchaText(text: string): boolean {
  return /captcha required|verify (that )?you('re| are) human|recaptcha|hcaptcha|g-recaptcha|challenge required|security challenge/i.test(text);
}

function isSaveFromApiUrl(url: string): boolean {
  try {
    const parsed = new URL(url, DEFAULT_PAGE_URL);
    const host = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    return (host === "worker.savefrom.net" && path.endsWith("/savefrom.php"))
      || (host.endsWith("savefrom.net") && path.endsWith("/savefrom.php"))
      || (host.endsWith("savefrom.net") && path === "/api/captcha");
  } catch (_) {
    return /(?:^|\/)(?:savefrom\.php|api\/captcha)(?:$|[/?])/i.test(url);
  }
}

function isRelevantRequest(request: any, sourceUrl: string): boolean {
  const url = String(request?.url ?? "");
  const lower = url.toLowerCase();
  let host = "";
  try { host = new URL(url, DEFAULT_PAGE_URL).hostname.toLowerCase(); } catch (_) {}
  const telemetry = /google-analytics|googletagmanager|doubleclick|facebook\.com\/tr/i.test(lower);
  return isSaveFromApiUrl(url)
    || host === "worker.savefrom.net"
    || host.endsWith("savefrom.net") && (request?.type === "XHR" || request?.type === "Fetch")
    || isCaptchaUrl(url)
    || String(request?.postData ?? "").includes(sourceUrl)
    || ((request?.type === "XHR" || request?.type === "Fetch") && !telemetry);
}

function summarizeSignature(events: any[]): Record<string, unknown> {
  const textEncoder = events.filter((event) => event.type === "builtin:TextEncoder.encode" || event.type === "builtin:TextEncoder.encodeInto");
  const digestCalls = events.filter((event) => event.type === "crypto:call" && event.method === "digest");
  const digestResults = events.filter((event) => event.type === "crypto:result" && event.method === "digest");
  const preimages = [...new Set(textEncoder
    .map((event) => event.input)
    .filter((value): value is string => typeof value === "string" && value.length > 0))]
    .slice(-100)
    .map((value) => ({ value, sha256: createHash("sha256").update(value, "utf8").digest("hex") }));
  return {
    digestCalls: digestCalls.slice(-100),
    digestResults: digestResults.slice(-100),
    textEncoderEvents: textEncoder.slice(-100),
    preimages,
    note: "Byte previews come from the generic crypto hook. This E2E observes the page and does not bypass CAPTCHA.",
  };
}

async function bestEffort<T>(work: () => Promise<T>, fallback: T): Promise<T> {
  try { return await work(); } catch (_) { return fallback; }
}

async function collectEvidence(client: McpStdioClient, sourceUrl: string, maxBodyChars: number): Promise<Record<string, unknown>> {
  const page = await client.tool("page_snapshot", { maxChars: 50_000 });
  const network = await client.tool("get_network", { limit: 1_000 });
  const requests = Array.isArray((network as any)?.requests) ? (network as any).requests : [];
  const relevant = requests.filter((request: any) => isRelevantRequest(request, sourceUrl)).slice(-150);
  const responseBodies: Array<Record<string, unknown>> = [];
  const observedUrls = collectHttpUrls(relevant);
  for (const request of relevant.slice(-40)) {
    const shouldRead = request?.type === "XHR"
      || request?.type === "Fetch"
      || isSaveFromApiUrl(String(request?.url ?? ""))
      || /captcha|worker\./i.test(String(request?.url ?? ""));
    if (!shouldRead || request?.status === undefined) continue;
    try {
      const body = await client.tool("get_network_body", { requestId: request.requestId, maxChars: maxBodyChars });
      responseBodies.push({ requestId: request.requestId, url: request.url, status: request.status, ...body as any });
      if (!(body as any)?.base64Encoded) collectHttpUrls((body as any)?.body, observedUrls);
    } catch (error) {
      responseBodies.push({ requestId: request.requestId, url: request.url, error: error instanceof Error ? error.message : String(error) });
    }
  }
  const hookEvents = await client.tool("get_hook_events", { limit: 1_000 });
  const consoleEvents = await client.tool("get_console", { limit: 300 });
  const timeline = await bestEffort(() => client.tool("timeline_recorder", { action: "read", limit: 1_000 }), {});
  const originTraces: Array<Record<string, unknown>> = [];
  for (const request of relevant.filter((item: any) => isSaveFromApiUrl(String(item?.url ?? ""))).slice(-3)) {
    originTraces.push(await bestEffort(
      () => client.tool("trace_request_origin", { requestId: request.requestId, includeSource: true }),
      { requestId: request.requestId, error: "trace unavailable" },
    ) as Record<string, unknown>);
  }
  const scripts = await bestEffort(() => client.tool("list_scripts", { limit: 300 }), []);
  const workerSearch = await bestEffort(() => client.tool("search_scripts", { query: "workerRequestBuilder", maxScripts: 200, maxMatches: 50 }), {});
  const endpointSearch = await bestEffort(() => client.tool("search_scripts", { query: "savefrom.php", maxScripts: 200, maxMatches: 50 }), {});
  const pageText = String((page as any)?.text ?? "");
  const captchaSignals: string[] = [];
  if (isCaptchaText(pageText)) captchaSignals.push("visible page text");
  for (const request of relevant) {
    if (isCaptchaUrl(String(request?.url ?? ""))) captchaSignals.push(`captcha URL: ${request.url}`);
    if ((request?.status === 403 || request?.status === 422) && isSaveFromApiUrl(String(request?.url ?? ""))) {
      captchaSignals.push(`HTTP ${request.status}: ${request.url}`);
    }
  }
  for (const body of responseBodies) {
    if (isCaptchaText(String(body.body ?? ""))) captchaSignals.push(`response body: ${body.url}`);
  }
  const uniqueCaptchaSignals = [...new Set(captchaSignals)];
  return {
    page,
    network: { relevantRequests: relevant, responseBodies, websocketFrames: (network as any)?.websocketFrames ?? [] },
    observedUrls: [...observedUrls].slice(0, 300),
    hookEvents,
    signature: summarizeSignature(Array.isArray(hookEvents) ? hookEvents : []),
    console: consoleEvents,
    timeline,
    scripts,
    searches: { workerRequestBuilder: workerSearch, savefromPhp: endpointSearch },
    originTraces,
    captcha: { detected: uniqueCaptchaSignals.length > 0, signals: uniqueCaptchaSignals, manualActionRequired: uniqueCaptchaSignals.length > 0 },
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const projectRoot = resolve(dirname(new URL(import.meta.url).pathname), "..");
  const pageUrl = stringArg(args, "page-url", process.env.SAVEFROM_PAGE_URL ?? DEFAULT_PAGE_URL);
  const sourceUrl = stringArg(args, "source-url", process.env.SAVEFROM_SOURCE_URL ?? DEFAULT_SOURCE_URL);
  const inputSelector = stringArg(args, "input-selector", "#sf_url");
  const submitSelector = stringArg(args, "submit-selector", "#sf_submit");
  const waitMs = numberArg(args, "wait-ms", 8_000, 500, 60_000);
  const maxBodyChars = numberArg(args, "max-body-chars", 50_000, 1_000, 200_000);
  const client = new McpStdioClient(projectRoot);
  const runId = `savefrom-e2e-${Date.now().toString(36)}`;
  let artifact: Record<string, unknown>;
  try {
    await client.request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "savefrom-e2e", version: "0.1.0" },
    });
    client.notify("notifications/initialized");
    const targets = await client.tool("browser_targets");
    const pages = Array.isArray(targets) ? targets.filter((target: any) => target.type === "page" || target.type === "webview") : [];
    const pageHost = new URL(pageUrl).hostname;
    const target = pages.find((candidate: any) => String(candidate.url ?? "").includes(pageHost)) ?? pages[0];
    if (!target) throw new Error("No Chrome page target. Start Chrome with --remote-debugging-port=9222 first.");
    await client.tool("browser_attach", { targetId: target.id });
    await client.tool("clear_capture_logs");
    await client.tool("install_hook", { hookId: `${runId}-fetch`, kind: "fetch", includeResponse: true });
    await client.tool("install_hook", { hookId: `${runId}-xhr`, kind: "xhr", includeResponse: true });
    await client.tool("hook_crypto_all", { hookId: `${runId}-crypto` });
    await client.tool("timeline_recorder", { action: "clear", limit: 100 });
    await client.tool("navigate", { url: pageUrl, waitMs: 1_500 });
    await client.tool("type_text", { selector: inputSelector, text: sourceUrl, clear: true });
    await client.tool("click_selector", { selector: submitSelector });

    const deadline = Date.now() + waitMs;
    let stoppedBecause = "timeout";
    while (Date.now() < deadline) {
      await sleep(Math.min(750, Math.max(100, deadline - Date.now())));
      const snapshot = await bestEffort(() => client.tool("page_snapshot", { maxChars: 20_000 }), {});
      const network = await bestEffort(() => client.tool("get_network", { limit: 300 }), {});
      const text = String((snapshot as any)?.text ?? "");
      const requests = Array.isArray((network as any)?.requests) ? (network as any).requests : [];
      const captcha = isCaptchaText(text) || requests.some((request: any) =>
        isCaptchaUrl(String(request?.url ?? ""))
        || ((request?.status === 403 || request?.status === 422) && /savefrom|worker\./i.test(String(request?.url ?? ""))));
      const completedApi = requests.some((request: any) =>
        request?.status !== undefined && request?.status >= 200 && request?.status < 300 && isSaveFromApiUrl(String(request?.url ?? "")) &&
        (request?.type === "XHR" || request?.type === "Fetch"));
      if (captcha) {
        stoppedBecause = "captcha_detected";
        break;
      }
      if (completedApi) {
        stoppedBecause = "savefrom_api_completed";
        break;
      }
    }
    const evidence = await collectEvidence(client, sourceUrl, maxBodyChars);
    artifact = {
      tool: "reverse-engineering-mcp",
      workflow: "savefrom-e2e",
      runId,
      pageUrl,
      sourceUrl,
      selectors: { input: inputSelector, submit: submitSelector },
      waitMs,
      stoppedBecause,
      capturedAt: new Date().toISOString(),
      ...evidence,
      safety: "Observation/reconstruction only. CAPTCHA and access-control challenges are reported, never bypassed.",
    };
    const outputPath = resolve(projectRoot, ".reverse-engineering", `${runId}.json`);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, JSON.stringify(artifact, null, 2));
    console.log(JSON.stringify({
      status: (artifact.captcha as any)?.detected ? "captcha_required" : "completed",
      artifact: outputPath,
      stoppedBecause,
      relevantRequests: (artifact.network as any)?.relevantRequests?.length ?? 0,
      digestCalls: (artifact.signature as any)?.digestCalls?.length ?? 0,
      observedUrls: (artifact.observedUrls as unknown[])?.length ?? 0,
    }, null, 2));
    if (artifact.captcha && (artifact.captcha as any).detected && args["fail-on-captcha"] === true) process.exitCode = 2;
  } finally {
    await bestEffort(() => client.tool("browser_detach"), {});
    await client.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

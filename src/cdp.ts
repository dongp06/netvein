import CDP from "chrome-remote-interface";
import { launchBrowser, type LaunchOptions, type LaunchResult } from "./launcher.js";
import { ToolError, toEnvelope, type Envelope } from "./errors.js";
import { activePatchIds, buildStealthScript, seedFromName, type StealthProfile } from "./stealth.js";
import { compressAxTree, diffSnapshots, formatSemanticView, type SemanticSnapshot } from "./pruner.js";
import {
  parseIdentityPayload,
  parseProxyServer,
  probeProxy,
  serializeIdentity,
  type IdentityPayload,
  type IdentityRecord,
} from "./identity.js";
import {
  beautifyJs,
  classifyAnticrawl,
  extractEndpointsAndSecrets,
  findCryptoCandidates,
  findTextMatches,
  generateJsrpcFiles,
  identifyCrypto,
  parseSourceMap,
  searchAst,
  textDiffSummary,
  type AstPattern,
} from "./analysis.js";
import type {
  AnticrawlMatch,
  BreakpointRecord,
  ConsoleRecord,
  CookieRecord,
  CryptoCandidate,
  CryptoMatch,
  DomBreakpointRecord,
  EventBreakpointRecord,
  HookEventRecord,
  HookRecord,
  InterceptRule,
  NetworkRecord,
  PauseState,
  ScriptRecord,
  StorageItem,
  TargetInfo,
  TimelineRecord,
  WebSocketFrameRecord,
  WebpackModuleInfo,
  XhrBreakpointRecord,
} from "./types.js";

const BINDING_NAME = "__reverse_engineering_mcp_emit";
const MAX_CONSOLE_EVENTS = 1_000;
const MAX_NETWORK_RECORDS = 1_000;
const MAX_SOCKET_EVENTS = 2_000;
const MAX_HOOK_EVENTS = 2_000;
const MAX_TIMELINE_EVENTS = 5_000;
const MAX_STORED_TEXT = 20_000;

export interface CdpOptions {
  host: string;
  port: number;
}

export interface TargetSelector {
  targetId?: string;
  url?: string;
  title?: string;
}

export interface NetworkQuery {
  urlContains?: string;
  type?: string;
  status?: number;
  limit?: number;
}

export interface NetworkWaitQuery {
  urlContains?: string;
  urlPathContains?: string;
  urlRegex?: string;
  type?: string;
  status?: number;
  requireResponse?: boolean;
  requireFinished?: boolean;
  timeoutMs?: number;
  pollMs?: number;
}

export interface HookOptions {
  hookId?: string;
  kind: HookRecord["kind"];
  includeResponse?: boolean;
  captureBuiltins?: boolean;
}

export interface TaintTrackerRecord {
  trackerId: string;
  label: string;
  expression: string;
  tokens: string[];
  scriptIdentifier?: string;
  installedAt: string;
}

interface ReplayOverrides {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

interface BundleScriptSnapshot {
  key: string;
  scriptId: string;
  url: string;
  source: string;
  capturedAt: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function truncate(value: string | undefined, max = MAX_STORED_TEXT): string | undefined {
  if (value === undefined) return undefined;
  return value.length > max ? `${value.slice(0, max)}… [truncated]` : value;
}

function timestampToIso(timestamp: unknown): string {
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) return nowIso();
  const milliseconds = timestamp < 10_000_000_000 ? timestamp * 1_000 : timestamp;
  return new Date(milliseconds).toISOString();
}

function redactHeaders(headers: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!headers) return undefined;
  const redacted = new Set([
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
  ]);
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key,
      redacted.has(key.toLowerCase()) ? "[redacted]" : value,
    ]),
  );
}

function jsonSafe(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value === "bigint") return `${value}n`;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(jsonSafe);
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    output[key] = jsonSafe(child);
  }
  return output;
}

function remoteObjectToValue(remoteObject: any): unknown {
  if (!remoteObject) return null;
  if (Object.prototype.hasOwnProperty.call(remoteObject, "value")) {
    return jsonSafe(remoteObject.value);
  }
  const result: Record<string, unknown> = {
    type: remoteObject.type,
  };
  if (remoteObject.subtype) result.subtype = remoteObject.subtype;
  if (remoteObject.description) result.description = remoteObject.description;
  if (remoteObject.unserializableValue) result.unserializableValue = remoteObject.unserializableValue;
  if (remoteObject.objectId) result.objectId = remoteObject.objectId;
  if (remoteObject.preview) {
    result.preview = {
      type: remoteObject.preview.type,
      description: remoteObject.preview.description,
      overflow: remoteObject.preview.overflow,
      properties: (remoteObject.preview.properties ?? []).slice(0, 50).map((property: any) => ({
        name: property.name,
        type: property.type,
        value: property.value,
        valuePreview: property.valuePreview?.description,
      })),
    };
  }
  return result;
}

function simplifyCallFrame(frame: any): Record<string, unknown> {
  return {
    callFrameId: frame.callFrameId,
    functionName: frame.functionName,
    functionLocation: frame.functionLocation,
    location: frame.location,
    url: frame.url,
    scopeChain: (frame.scopeChain ?? []).map((scope: any) => ({
      type: scope.type,
      name: scope.name,
      startLocation: scope.startLocation,
      endLocation: scope.endLocation,
      object: remoteObjectToValue(scope.object),
    })),
    this: remoteObjectToValue(frame.this),
  };
}

export function makeHookSource(hookId: string, kind: HookRecord["kind"], includeResponse: boolean, captureBuiltins = false): string {
  const encodedId = JSON.stringify(hookId);
  const encodedKind = JSON.stringify(kind);
  const responseFlag = includeResponse ? "true" : "false";
  const builtinsFlag = captureBuiltins ? "true" : "false";

  return `
(() => {
  const id = ${encodedId};
  const kind = ${encodedKind};
  const includeResponse = ${responseFlag};
  const captureBuiltins = ${builtinsFlag};
  const flag = "__reverse_engineering_mcp_hook_" + id;
  if (globalThis[flag]) return;
  const originalJSONStringify = JSON.stringify;
  let emitting = false;
  const emit = (event) => {
    if (emitting) return;
    emitting = true;
    try {
      if (typeof globalThis.${BINDING_NAME} === "function") {
        globalThis.${BINDING_NAME}(originalJSONStringify({ hookId: id, kind, ...event }));
      }
    } catch (_) {} finally { emitting = false; }
  };
  const describe = (value) => {
    try {
      if (value === undefined) return undefined;
      if (value === null) return null;
      if (typeof value === "string") return value.slice(0, 4000);
      if (typeof value === "number" || typeof value === "boolean") return value;
      if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        const bytes = value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        const sample = bytes.slice(0, 4096);
        let binary = "";
        for (let index = 0; index < sample.length; index += 0x8000) {
          binary += String.fromCharCode(...sample.subarray(index, index + 0x8000));
        }
        return {
          type: value instanceof ArrayBuffer ? "ArrayBuffer" : value.constructor.name,
          byteLength: bytes.byteLength,
          bytePreviewLength: sample.byteLength,
          bytePreviewHex: Array.from(sample, (byte) => byte.toString(16).padStart(2, "0")).join(""),
          bytePreviewBase64: btoa(binary),
          bytePreviewTruncated: sample.byteLength < bytes.byteLength,
        };
      }
      return JSON.parse(originalJSONStringify(value, (_, child) => typeof child === "bigint" ? String(child) : child));
    } catch (_) {
      try { return String(value).slice(0, 4000); } catch (_) { return "[unserializable]"; }
    }
  };
  const started = () => Date.now();
  const restore = { restore: () => {} };

  if (kind === "fetch" && typeof globalThis.fetch === "function") {
    const original = globalThis.fetch;
    restore.restore = () => { globalThis.fetch = original; delete globalThis[flag]; };
    globalThis.fetch = async function(input, init) {
      const startedAt = started();
      const url = typeof input === "string" ? input : (input && input.url) || String(input);
      const method = (init && init.method) || (input && input.method) || "GET";
      emit({ type: "fetch:request", url, method, body: describe(init && init.body) });
      try {
        const response = await original.apply(this, arguments);
        let responseBody;
        if (includeResponse) {
          try { responseBody = (await response.clone().text()).slice(0, 12000); } catch (_) {}
        }
        emit({ type: "fetch:response", url, method, status: response.status, ok: response.ok, durationMs: started() - startedAt, responseBody });
        return response;
      } catch (error) {
        emit({ type: "fetch:error", url, method, durationMs: started() - startedAt, error: String(error) });
        throw error;
      }
    };
  }

  if (kind === "xhr" && globalThis.XMLHttpRequest) {
    const proto = globalThis.XMLHttpRequest.prototype;
    const originalOpen = proto.open;
    const originalSend = proto.send;
    const metadata = new WeakMap();
    restore.restore = () => {
      proto.open = originalOpen;
      proto.send = originalSend;
      delete globalThis[flag];
    };
    proto.open = function(method, url) {
      metadata.set(this, { method: String(method), url: String(url), startedAt: 0 });
      return originalOpen.apply(this, arguments);
    };
    proto.send = function(body) {
      const meta = metadata.get(this) || { method: "GET", url: "", startedAt: 0 };
      meta.startedAt = started();
      metadata.set(this, meta);
      emit({ type: "xhr:request", url: meta.url, method: meta.method, body: describe(body) });
      this.addEventListener("loadend", () => {
        let responseBody;
        if (includeResponse) {
          try { responseBody = String(this.responseText).slice(0, 12000); } catch (_) {}
        }
        emit({ type: "xhr:response", url: meta.url, method: meta.method, status: this.status, durationMs: started() - meta.startedAt, responseBody });
      }, { once: true });
      return originalSend.apply(this, arguments);
    };
  }

  if (kind === "websocket" && typeof globalThis.WebSocket === "function") {
    const OriginalWebSocket = globalThis.WebSocket;
    const WrappedWebSocket = function(url, protocols) {
      const socket = protocols === undefined ? new OriginalWebSocket(url) : new OriginalWebSocket(url, protocols);
      emit({ type: "websocket:created", url: String(url) });
      socket.addEventListener("message", (event) => emit({ type: "websocket:received", url: String(url), data: describe(event.data) }));
      const originalSend = socket.send;
      socket.send = function(data) {
        emit({ type: "websocket:sent", url: String(url), data: describe(data) });
        return originalSend.call(this, data);
      };
      return socket;
    };
    WrappedWebSocket.prototype = OriginalWebSocket.prototype;
    try { Object.setPrototypeOf(WrappedWebSocket, OriginalWebSocket); } catch (_) {}
    restore.restore = () => { globalThis.WebSocket = OriginalWebSocket; delete globalThis[flag]; };
    globalThis.WebSocket = WrappedWebSocket;
  }

  if (kind === "crypto" && globalThis.crypto && globalThis.crypto.subtle) {
    const subtle = globalThis.crypto.subtle;
    const methods = ["digest", "encrypt", "decrypt", "sign", "verify", "deriveBits", "deriveKey", "importKey", "exportKey"];
    const originals = {};
    for (const method of methods) {
      if (typeof subtle[method] !== "function") continue;
      originals[method] = subtle[method];
      try {
        subtle[method] = async function() {
          emit({ type: "crypto:call", method, args: Array.from(arguments).map(describe) });
          const result = await originals[method].apply(this, arguments);
          emit({ type: "crypto:result", method, result: describe(result) });
          return result;
        };
      } catch (_) {}
    }
    restore.restore = () => {
      for (const method of Object.keys(originals)) {
        try { subtle[method] = originals[method]; } catch (_) {}
      }
      delete globalThis[flag];
    };
  }

  if (kind === "crypto" && captureBuiltins) {
    const originals = { atob: globalThis.atob, btoa: globalThis.btoa, jsonStringify: JSON.stringify };
    const originalRandom = Math.random;
    const originalDateNow = Date.now;
    const OriginalTextEncoder = globalThis.TextEncoder;
    try {
      if (typeof originals.atob === "function") {
        globalThis.atob = function(value) {
          const output = originals.atob.call(this, value);
          emit({ type: "builtin:atob", input: String(value).slice(0, 4000), output: String(output).slice(0, 4000), stack: new Error().stack });
          return output;
        };
      }
      if (typeof originals.btoa === "function") {
        globalThis.btoa = function(value) {
          const output = originals.btoa.call(this, value);
          emit({ type: "builtin:btoa", input: String(value).slice(0, 4000), output: String(output).slice(0, 4000), stack: new Error().stack });
          return output;
        };
      }
      JSON.stringify = function(value) {
        const output = originals.jsonStringify.apply(this, arguments);
        emit({ type: "builtin:JSON.stringify", input: describe(value), output: String(output).slice(0, 12000), stack: new Error().stack });
        return output;
      };
      Math.random = function() {
        const output = originalRandom.apply(this, arguments);
        emit({ type: "builtin:Math.random", output, stack: new Error().stack });
        return output;
      };
      Date.now = function() {
        const output = originalDateNow.apply(this, arguments);
        emit({ type: "builtin:Date.now", output, stack: new Error().stack });
        return output;
      };
      if (OriginalTextEncoder) {
        const WrappedTextEncoder = function() {
          const encoder = new OriginalTextEncoder();
          const originalEncode = encoder.encode.bind(encoder);
          const originalEncodeInto = encoder.encodeInto?.bind(encoder);
          encoder.encode = function(value) {
            const output = originalEncode(value);
            emit({ type: "builtin:TextEncoder.encode", input: String(value).slice(0, 4000), output: describe(output), stack: new Error().stack });
            return output;
          };
          if (originalEncodeInto) {
            encoder.encodeInto = function(value, destination) {
              const output = originalEncodeInto(value, destination);
              emit({ type: "builtin:TextEncoder.encodeInto", input: String(value).slice(0, 4000), output: describe(output), stack: new Error().stack });
              return output;
            };
          }
          return encoder;
        };
        WrappedTextEncoder.prototype = OriginalTextEncoder.prototype;
        globalThis.TextEncoder = WrappedTextEncoder;
      }
    } catch (_) {}
    const oldRestore = restore.restore;
    restore.restore = () => {
      oldRestore();
      try { globalThis.atob = originals.atob; } catch (_) {}
      try { globalThis.btoa = originals.btoa; } catch (_) {}
      try { JSON.stringify = originals.jsonStringify; } catch (_) {}
      try { Math.random = originalRandom; } catch (_) {}
      try { Date.now = originalDateNow; } catch (_) {}
      try { if (OriginalTextEncoder) globalThis.TextEncoder = OriginalTextEncoder; } catch (_) {}
    };
  }

  globalThis[flag] = restore;
})();
//# sourceURL=reverse-engineering-mcp-hook-${hookId}.js
`;
}

function deriveTaintTokens(value: unknown): string[] {
  const candidates: string[] = [];
  const visit = (item: unknown, depth = 0): void => {
    if (depth > 4 || candidates.length >= 40 || item === null || item === undefined) return;
    if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
      candidates.push(String(item));
      return;
    }
    if (Array.isArray(item)) {
      for (const child of item) visit(child, depth + 1);
      return;
    }
    if (typeof item === "object") {
      for (const child of Object.values(item as Record<string, unknown>)) visit(child, depth + 1);
      try { candidates.push(JSON.stringify(item)); } catch (_) {}
    }
  };
  visit(value);
  const expanded = [...candidates];
  for (const candidate of candidates) {
    if (candidate.length >= 4) {
      try { expanded.push(Buffer.from(candidate, "utf8").toString("base64")); } catch (_) {}
    }
  }
  return [...new Set(expanded.filter((candidate) => candidate.length >= 4))].slice(0, 80);
}

function firstMismatch(left: string, right: string): number | null {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return index;
  }
  return left.length === right.length ? null : length;
}

function parseJsonOrText(value: string): unknown {
  try { return JSON.parse(value); } catch (_) { return value.slice(0, 20_000); }
}

export function makeTaintSource(trackerId: string, label: string, tokens: string[]): string {
  return `
(() => {
  const trackerId = ${JSON.stringify(trackerId)};
  const label = ${JSON.stringify(label)};
  const tokens = ${JSON.stringify(tokens)};
  const flag = "__reverse_engineering_mcp_taint_" + trackerId;
  if (globalThis[flag]) return;
  const originalJSONStringify = JSON.stringify;
  let emitting = false;
  const emit = (stage, value, extra = {}) => {
    if (emitting) return;
    let serialized = "";
    try {
      if (typeof value === "string") serialized = value;
      else serialized = originalJSONStringify(value, (_, child) => typeof child === "bigint" ? String(child) : child);
    } catch (_) { try { serialized = String(value); } catch (_) {} }
    const matches = tokens.filter((token) => serialized.includes(token));
    if (!matches.length) return;
    emitting = true;
    try {
      globalThis.${BINDING_NAME}(originalJSONStringify({
        hookId: trackerId,
        kind: "taint",
        type: "taint:" + stage,
        label,
        matches,
        stack: new Error().stack,
        ...extra,
      }));
    } catch (_) {} finally { emitting = false; }
  };
  const restore = { restore: () => {} };
  const originalFetch = globalThis.fetch;
  if (typeof originalFetch === "function") {
    globalThis.fetch = async function(input, init) {
      const url = typeof input === "string" ? input : (input && input.url) || String(input);
      const method = (init && init.method) || (input && input.method) || "GET";
      emit("fetch:request", { url, method, body: init && init.body });
      const response = await originalFetch.apply(this, arguments);
      emit("fetch:response", { url, method, status: response.status });
      return response;
    };
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); globalThis.fetch = originalFetch; delete globalThis[flag]; };
  }
  if (typeof globalThis.btoa === "function") {
    const originalBtoa = globalThis.btoa;
    globalThis.btoa = function(value) { const output = originalBtoa.apply(this, arguments); emit("btoa", value, { output: String(output).slice(0, 12000) }); return output; };
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); globalThis.btoa = originalBtoa; delete globalThis[flag]; };
  }
  if (typeof globalThis.atob === "function") {
    const originalAtob = globalThis.atob;
    globalThis.atob = function(value) { const output = originalAtob.apply(this, arguments); emit("atob", value, { output: String(output).slice(0, 12000) }); return output; };
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); globalThis.atob = originalAtob; delete globalThis[flag]; };
  }
  if (typeof globalThis.TextEncoder === "function") {
    const OriginalTextEncoder = globalThis.TextEncoder;
    const WrappedTextEncoder = function() {
      const encoder = new OriginalTextEncoder();
      const originalEncode = encoder.encode.bind(encoder);
      encoder.encode = function(value) { const output = originalEncode(value); emit("TextEncoder.encode", value, { output: { byteLength: output.byteLength } }); return output; };
      return encoder;
    };
    WrappedTextEncoder.prototype = OriginalTextEncoder.prototype;
    globalThis.TextEncoder = WrappedTextEncoder;
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); globalThis.TextEncoder = OriginalTextEncoder; delete globalThis[flag]; };
  }
  const originalJSON = JSON.stringify;
  JSON.stringify = function(value) { const output = originalJSON.apply(this, arguments); emit("JSON.stringify", value, { output: String(output).slice(0, 12000) }); return output; };
  const jsonRestore = restore.restore;
  restore.restore = () => { jsonRestore(); JSON.stringify = originalJSON; delete globalThis[flag]; };
  if (globalThis.XMLHttpRequest) {
    const proto = globalThis.XMLHttpRequest.prototype;
    const originalOpen = proto.open;
    const originalSend = proto.send;
    const metadata = new WeakMap();
    proto.open = function(method, url) { metadata.set(this, { method: String(method), url: String(url) }); return originalOpen.apply(this, arguments); };
    proto.send = function(body) { const meta = metadata.get(this) || { method: "GET", url: "" }; emit("xhr:request", { ...meta, body }); return originalSend.apply(this, arguments); };
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); proto.open = originalOpen; proto.send = originalSend; delete globalThis[flag]; };
  }
  if (typeof globalThis.WebSocket === "function") {
    const OriginalWebSocket = globalThis.WebSocket;
    const WrappedWebSocket = function(url, protocols) {
      const socket = protocols === undefined ? new OriginalWebSocket(url) : new OriginalWebSocket(url, protocols);
      const originalSend = socket.send;
      socket.send = function(data) { emit("websocket:send", { url: String(url), data }); return originalSend.call(this, data); };
      return socket;
    };
    WrappedWebSocket.prototype = OriginalWebSocket.prototype;
    globalThis.WebSocket = WrappedWebSocket;
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); globalThis.WebSocket = OriginalWebSocket; delete globalThis[flag]; };
  }
  if (globalThis.crypto?.subtle) {
    const subtle = globalThis.crypto.subtle;
    const methods = ["digest", "encrypt", "decrypt", "sign", "verify", "deriveBits", "deriveKey", "importKey"];
    const originals = {};
    for (const method of methods) {
      if (typeof subtle[method] !== "function") continue;
      originals[method] = subtle[method];
      try { subtle[method] = function() { emit("crypto:" + method, Array.from(arguments)); return originals[method].apply(this, arguments); }; } catch (_) {}
    }
    const previousRestore = restore.restore;
    restore.restore = () => { previousRestore(); for (const method of Object.keys(originals)) { try { subtle[method] = originals[method]; } catch (_) {} } delete globalThis[flag]; };
  }
  globalThis[flag] = restore;
})();
//# sourceURL=reverse-engineering-mcp-taint-${trackerId}.js
`;
}

export class CdpSession {
  private readonly options: CdpOptions;
  private client: any | null = null;
  private target: TargetInfo | null = null;
  private connectedAt: string | null = null;
  private lastError: string | null = null;
  private consoleEvents: ConsoleRecord[] = [];
  private readonly scripts = new Map<string, ScriptRecord>();
  private readonly networkRecords = new Map<string, NetworkRecord>();
  private readonly rawRequestHeaders = new Map<string, Record<string, string>>();
  private networkOrder: string[] = [];
  private socketFrames: WebSocketFrameRecord[] = [];
  private hookEvents: HookEventRecord[] = [];
  private timeline: TimelineRecord[] = [];
  private timelineSequence = 0;
  private timelineEnabled = true;
  private hookEventSequence = 0;
  private consoleEventSequence = 0;
  private pauseState: PauseState | null = null;
  private readonly breakpoints = new Map<string, BreakpointRecord>();
  private readonly domBreakpoints = new Map<string, DomBreakpointRecord>();
  private readonly eventBreakpoints = new Set<string>();
  private readonly xhrBreakpoints = new Set<string>();
  private readonly interceptRules = new Map<string, InterceptRule>();
  private interceptionEnabled = false;
  private antiDebugBypassScriptId: string | null = null;
  private stealthScriptId: string | null = null;
  private stealthProfile: StealthProfile = "off";
  private stealthSeed = 0;
  private semanticSnapshot: SemanticSnapshot | null = null;
  private semanticVersionCounter = 0;
  private identities = new Map<string, IdentityRecord>();
  private readonly hooks = new Map<string, HookRecord>();
  private readonly taintTrackers = new Map<string, TaintTrackerRecord>();
  private readonly bundleSnapshots = new Map<string, Map<string, BundleScriptSnapshot>>();

  constructor(options: Partial<CdpOptions> = {}) {
    this.options = {
      host: options.host ?? process.env.CDP_HOST ?? "127.0.0.1",
      port: options.port ?? Number(process.env.CDP_PORT ?? 9222),
    };
  }

  get isConnected(): boolean {
    return this.client !== null;
  }

  async listTargets(autoLaunch = true): Promise<TargetInfo[]> {
    try {
      const targets = await CDP.List({ host: this.options.host, port: this.options.port });
      return (targets as TargetInfo[]).map((target) => ({
        id: target.id,
        type: target.type,
        title: target.title,
        url: target.url,
        description: target.description,
        webSocketDebuggerUrl: target.webSocketDebuggerUrl,
      }));
    } catch (err) {
      if (autoLaunch) {
        await launchBrowser({ host: this.options.host, port: this.options.port });
        return this.listTargets(false);
      }
      throw err;
    }
  }

  async launchBrowser(options: LaunchOptions = {}): Promise<LaunchResult> {
    return launchBrowser({
      host: this.options.host,
      port: this.options.port,
      ...options,
    });
  }

  async connect(selector: TargetSelector = {}): Promise<TargetInfo> {
    await this.disconnect();
    let targets: TargetInfo[];
    try {
      targets = await this.listTargets(true);
    } catch (err) {
      throw new Error(`Failed to list CDP targets or launch browser: ${String(err)}`);
    }

    let pages = targets.filter((target) => target.type === "page" || target.type === "webview");
    if (pages.length === 0) {
      try {
        await CDP.New({ host: this.options.host, port: this.options.port, url: selector.url || "about:blank" });
        targets = await this.listTargets(false);
        pages = targets.filter((target) => target.type === "page" || target.type === "webview");
      } catch (_) {}
    }

    const target = selector.targetId
      ? targets.find((candidate) => candidate.id === selector.targetId)
      : pages.find((candidate) => {
          if (selector.url && !candidate.url.includes(selector.url)) return false;
          if (selector.title && !candidate.title.includes(selector.title)) return false;
          return true;
        }) || pages[0];

    if (!target) {
      throw new Error(
        selector.targetId
          ? `CDP target not found: ${selector.targetId}`
          : "No matching page target found after launching browser.",
      );
    }

    this.client = await CDP({ host: this.options.host, port: this.options.port, target: target.id });
    this.target = target;
    this.connectedAt = nowIso();
    this.lastError = null;
    this.installEventHandlers(this.client);

    try {
      await this.client.Runtime.enable();
      await this.client.Log.enable();
      await this.client.Network.enable({ maxTotalBufferSize: 50 * 1024 * 1024, maxResourceBufferSize: 10 * 1024 * 1024 });
      await this.client.Page.enable();
      await this.client.Debugger.enable();
      await this.client.DOM.enable();
      await this.client.Runtime.addBinding({ name: BINDING_NAME });
    } catch (error) {
      await this.disconnect();
      throw error;
    }
    return target;
  }

  async disconnect(): Promise<void> {
    if (!this.client) {
      this.target = null;
      this.resetState();
      return;
    }
    const client = this.client;
    for (const hook of this.hooks.values()) {
      try {
        if (hook.scriptIdentifier) {
          await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: hook.scriptIdentifier });
        }
        await client.Runtime.evaluate({
          expression: `globalThis[${JSON.stringify(`__reverse_engineering_mcp_hook_${hook.hookId}`)}]?.restore?.()`,
          awaitPromise: false,
          returnByValue: true,
        });
      } catch (_) {
        // A target can disappear while its instrumentation is being cleaned up.
      }
    }
    for (const tracker of this.taintTrackers.values()) {
      try {
        if (tracker.scriptIdentifier) {
          await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: tracker.scriptIdentifier });
        }
        await client.Runtime.evaluate({
          expression: `globalThis[${JSON.stringify(`__reverse_engineering_mcp_taint_${tracker.trackerId}`)}]?.restore?.()`,
          awaitPromise: false,
          returnByValue: true,
        });
      } catch (_) {
        // A target can disappear while taint instrumentation is being cleaned up.
      }
    }
    for (const breakpoint of this.breakpoints.values()) {
      try {
        await client.Debugger.removeBreakpoint({ breakpointId: breakpoint.breakpointId });
      } catch (_) {
        // Breakpoints may already be gone with the target.
      }
    }
    for (const bp of this.domBreakpoints.values()) {
      try {
        await client.DOMDebugger.removeDOMBreakpoint({ nodeId: bp.nodeId, type: bp.type });
      } catch (_) {}
    }
    for (const ev of this.eventBreakpoints) {
      try {
        await client.DOMDebugger.removeEventListenerBreakpoint({ eventName: ev });
      } catch (_) {}
    }
    for (const xhr of this.xhrBreakpoints) {
      try {
        await client.DOMDebugger.removeXHRBreakpoint({ url: xhr });
      } catch (_) {}
    }
    if (this.interceptionEnabled) {
      try {
        await client.Fetch.disable();
      } catch (_) {}
      this.interceptionEnabled = false;
    }
    if (this.antiDebugBypassScriptId) {
      try {
        await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: this.antiDebugBypassScriptId });
      } catch (_) {}
      this.antiDebugBypassScriptId = null;
    }
    this.client = null;
    this.target = null;
    this.pauseState = null;
    try {
      await client.close();
    } catch (_) {
      // The browser may have closed the target already.
    }
    this.resetState();
  }

  status(): Record<string, unknown> {
    return {
      connected: this.isConnected,
      cdp: { host: this.options.host, port: this.options.port },
      target: this.target,
      connectedAt: this.connectedAt,
      lastError: this.lastError,
      counts: {
        scripts: this.scripts.size,
        console: this.consoleEvents.length,
        network: this.networkRecords.size,
        websocketFrames: this.socketFrames.length,
        hookEvents: this.hookEvents.length,
        timeline: this.timeline.length,
        breakpoints: this.breakpoints.size,
        domBreakpoints: this.domBreakpoints.size,
        eventBreakpoints: this.eventBreakpoints.size,
        xhrBreakpoints: this.xhrBreakpoints.size,
        interceptRules: this.interceptRules.size,
        hooks: this.hooks.size,
        taintTrackers: this.taintTrackers.size,
      },
      paused: this.pauseState !== null,
      timelineRecording: this.timelineEnabled,
      interceptionActive: this.interceptionEnabled,
      antiDebugActive: Boolean(this.antiDebugBypassScriptId),
    };
  }

  async getCurrentUrl(): Promise<string | undefined> {
    if (!this.client) return this.target?.url;
    const result = await this.client.Runtime.evaluate({ expression: "location.href", returnByValue: true });
    return result.result?.value ?? this.target?.url;
  }

  async navigate(url: string, waitMs = 500): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const result = await client.Page.navigate({ url });
    const boundedWait = Math.min(Math.max(waitMs, 0), 10_000);
    if (boundedWait > 0) await new Promise((resolve) => setTimeout(resolve, boundedWait));
    if (this.target) this.target.url = url;
    this.addTimeline("browser", "navigate", `navigate: ${url}`, { url, frameId: result.frameId, errorText: result.errorText });
    return { url, frameId: result.frameId, errorText: result.errorText };
  }

  async pageSnapshot(maxChars = 30_000): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const result = await client.Runtime.evaluate({
      expression: `(() => {
        const describe = (element) => ({
          tag: element.tagName?.toLowerCase(),
          text: (element.innerText || element.value || element.getAttribute("aria-label") || "").trim().slice(0, 300),
          id: element.id || undefined,
          name: element.getAttribute("name") || undefined,
          role: element.getAttribute("role") || undefined,
          type: element.getAttribute("type") || undefined,
          href: element.href || undefined,
          disabled: Boolean(element.disabled),
        });
        return {
          url: location.href,
          title: document.title,
          text: (document.body?.innerText || "").slice(0, ${Math.min(Math.max(maxChars, 1), 100_000)}),
          interactive: Array.from(document.querySelectorAll("a,button,input,textarea,select,[role=button],[contenteditable=true]"))
            .slice(0, 300).map(describe),
        };
      })()`,
      returnByValue: true,
    });
    return result.result?.value ?? { error: result.exceptionDetails?.text ?? "Snapshot failed" };
  }

  async waitForSelector(selector: string, timeoutMs = 10_000, pollMs = 100, visible = true): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const startedAt = Date.now();
    const timeout = Math.min(Math.max(timeoutMs, 0), 120_000);
    const interval = Math.min(Math.max(pollMs, 25), 2_000);
    let lastError: string | undefined;
    while (Date.now() - startedAt <= timeout) {
      try {
        const result = await client.Runtime.evaluate({
          expression: `(() => {
            try {
              const element = document.querySelector(${JSON.stringify(selector)});
              if (!element) return { found: false };
              const style = getComputedStyle(element);
              const isVisible = Boolean(element.getClientRects().length)
                && style.display !== "none"
                && style.visibility !== "hidden"
                && style.opacity !== "0";
              return {
                found: true,
                visible: isVisible,
                tag: element.tagName?.toLowerCase(),
                id: element.id || undefined,
                text: (element.innerText || element.value || "").trim().slice(0, 300),
              };
            } catch (error) {
              return { found: false, error: String(error) };
            }
          })()`,
          returnByValue: true,
        });
        const value = result.result?.value;
        if (value?.found && (!visible || value.visible)) {
          const output = { selector, ...value, waitedMs: Date.now() - startedAt };
          this.addTimeline("browser", "selector-found", `selector found: ${selector}`, output);
          return output;
        }
        lastError = value?.error;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }
      if (Date.now() - startedAt >= timeout) break;
      await sleep(Math.min(interval, Math.max(1, timeout - (Date.now() - startedAt))));
    }
    const output = {
      selector,
      found: false,
      timedOut: true,
      waitedMs: Date.now() - startedAt,
      error: lastError,
    };
    this.addTimeline("browser", "selector-timeout", `selector timeout: ${selector}`, output);
    return output;
  }

  async clickSelector(selector: string): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const expression = `(() => {
      const element = document.querySelector(${JSON.stringify(selector)});
      if (!element) return { found: false };
      element.scrollIntoView({ block: "center", inline: "center" });
      const rect = element.getBoundingClientRect();
      return { found: true, x: rect.left + rect.width / 2, y: rect.top + rect.height / 2, tag: element.tagName.toLowerCase() };
    })()`;
    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    const value = result.result?.value;
    if (!value?.found) throw new Error(`Element not found: ${selector}`);
    await client.Input.dispatchMouseEvent({ type: "mouseMoved", x: value.x, y: value.y });
    await client.Input.dispatchMouseEvent({ type: "mousePressed", x: value.x, y: value.y, button: "left", clickCount: 1 });
    await client.Input.dispatchMouseEvent({ type: "mouseReleased", x: value.x, y: value.y, button: "left", clickCount: 1 });
    this.addTimeline("browser", "click", `click: ${selector}`, value);
    return { clicked: selector, ...value };
  }

  async typeText(selector: string, text: string, clear = true): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    await this.clickSelector(selector);
    const expression = `(() => {
      const element = document.querySelector(${JSON.stringify(selector)});
      if (!element) return { found: false };
      element.focus();
      if (${clear ? "true" : "false"}) {
        if ("value" in element) {
          const prototype = Object.getPrototypeOf(element);
          const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");
          if (descriptor?.set) descriptor.set.call(element, "");
          else element.value = "";
        } else if (element.isContentEditable) {
          element.textContent = "";
        }
        element.dispatchEvent(new Event("input", { bubbles: true }));
      }
      return { found: true, tag: element.tagName.toLowerCase() };
    })()`;
    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    if (!result.result?.value?.found) throw new Error(`Element not found: ${selector}`);
    await client.Input.insertText({ text });
    this.addTimeline("browser", "type", `type into ${selector}: ${text.slice(0, 200)}`, { selector, length: text.length, cleared: clear });
    return { typed: text, selector, cleared: clear };
  }

  listScripts(urlContains?: string, limit = 200): ScriptRecord[] {
    return [...this.scripts.values()]
      .filter((script) => !urlContains || script.url.includes(urlContains))
      .slice(-Math.min(Math.max(limit, 1), 1_000));
  }

  async getScriptSource(scriptId: string, maxChars = 50_000, offset = 0): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const result = await client.Debugger.getScriptSource({ scriptId });
    const source = String(result.scriptSource ?? "");
    const safeOffset = Math.max(0, Math.min(offset, source.length));
    return {
      script: this.scripts.get(scriptId) ?? { scriptId },
      source: source.slice(safeOffset, safeOffset + Math.max(1, Math.min(maxChars, 200_000))),
      offset: safeOffset,
      totalLength: source.length,
      truncated: safeOffset + maxChars < source.length,
    };
  }

  async searchScripts(query: string, options: { caseSensitive?: boolean; maxScripts?: number; maxMatches?: number } = {}) {
    const scripts = this.listScripts(undefined, options.maxScripts ?? 100);
    const needle = options.caseSensitive ? query : query.toLowerCase();
    const matches: Array<Record<string, unknown>> = [];
    const skippedScripts: Array<Record<string, unknown>> = [];
    for (const script of scripts) {
      try {
        const result = await this.getScriptSource(script.scriptId, 2_000_000);
        const source = String(result.source ?? "");
        const haystack = options.caseSensitive ? source : source.toLowerCase();
        let start = 0;
        while (matches.length < (options.maxMatches ?? 100)) {
          const index = haystack.indexOf(needle, start);
          if (index < 0) break;
          const line = source.slice(0, index).split("\n").length;
          matches.push({
            scriptId: script.scriptId,
            url: script.url,
            line,
            column: index - source.lastIndexOf("\n", index - 1) - 1,
            snippet: source.slice(Math.max(0, index - 140), Math.min(source.length, index + query.length + 220)),
          });
          start = index + Math.max(needle.length, 1);
        }
      } catch (error) {
        skippedScripts.push({
          scriptId: script.scriptId,
          url: script.url,
          error: error instanceof Error ? error.message : String(error),
        });
      }
      if (matches.length >= (options.maxMatches ?? 100)) break;
    }
    return {
      query,
      matches,
      skippedScripts: skippedScripts.slice(0, 100),
      truncated: matches.length >= (options.maxMatches ?? 100),
    };
  }

  async smartBreakpoint(input: {
    pattern: string;
    regex?: boolean;
    urlContains?: string;
    condition?: string;
    maxMatches?: number;
  }): Promise<Record<string, unknown>> {
    const matches = await this.findSourceMatches(input.pattern, input.regex ?? false, input.urlContains, input.maxMatches ?? 20);
    const breakpoints: BreakpointRecord[] = [];
    const seen = new Set<string>();
    for (const match of matches) {
      const key = `${match.script.scriptId}:${match.text.line}:${match.text.column}`;
      if (seen.has(key)) continue;
      seen.add(key);
      breakpoints.push(await this.setBreakpoint({
        scriptId: match.script.scriptId,
        lineNumber: match.text.line,
        columnNumber: match.text.column,
        condition: input.condition,
      }));
    }
    return {
      pattern: input.pattern,
      regex: input.regex ?? false,
      matches: matches.map((match) => ({ script: match.script, ...match.text })),
      breakpoints,
      note: "Breakpoint locations are inferred from source text; Chrome may resolve a requested column to the nearest executable location.",
    };
  }

  async conditionalLogpointBatch(input: {
    pattern: string;
    logExpression: string;
    regex?: boolean;
    urlContains?: string;
    label?: string;
    maxMatches?: number;
  }): Promise<Record<string, unknown>> {
    const matches = await this.findSourceMatches(input.pattern, input.regex ?? false, input.urlContains, input.maxMatches ?? 20);
    const label = input.label ?? "revlog";
    const condition = `(() => { try { console.debug(${JSON.stringify(`[${label}]`)}, ${input.logExpression}); } catch (error) { console.debug(${JSON.stringify(`[${label}:error]`)}, String(error)); } return false; })()`;
    const breakpoints: BreakpointRecord[] = [];
    const seen = new Set<string>();
    for (const match of matches) {
      const key = `${match.script.scriptId}:${match.text.line}:${match.text.column}`;
      if (seen.has(key)) continue;
      seen.add(key);
      breakpoints.push(await this.setBreakpoint({
        scriptId: match.script.scriptId,
        lineNumber: match.text.line,
        columnNumber: match.text.column,
        condition,
      }));
    }
    return {
      pattern: input.pattern,
      logExpression: input.logExpression,
      matches: matches.map((match) => ({ script: match.script, ...match.text })),
      breakpoints,
      condition,
      note: "The generated condition logs and returns false, so execution should continue without pausing.",
    };
  }

  async astSearch(pattern: AstPattern, options: { urlContains?: string; maxScripts?: number; maxMatches?: number } = {}) {
    const scripts = this.listScripts(options.urlContains, options.maxScripts ?? 50);
    const matches: Array<Record<string, unknown>> = [];
    const parseErrors: Array<Record<string, unknown>> = [];
    const maxMatches = options.maxMatches ?? 100;
    for (const script of scripts) {
      if (matches.length >= maxMatches) break;
      try {
        const sourceResult = await this.getScriptSource(script.scriptId, 200_000);
        const result = searchAst(String(sourceResult.source ?? ""), pattern, maxMatches - matches.length);
        if (result.parseError) {
          parseErrors.push({ scriptId: script.scriptId, url: script.url, error: result.parseError });
          continue;
        }
        for (const match of result.matches) matches.push({ scriptId: script.scriptId, url: script.url, ...match });
      } catch (error) {
        parseErrors.push({ scriptId: script.scriptId, url: script.url, error: error instanceof Error ? error.message : String(error) });
      }
    }
    return { pattern, matches, parseErrors, truncated: matches.length >= maxMatches };
  }

  async captureBundleSnapshot(label: string, urlContains?: string, maxScripts = 200): Promise<Record<string, unknown>> {
    const scripts = this.listScripts(urlContains, maxScripts);
    const snapshot = new Map<string, BundleScriptSnapshot>();
    for (const script of scripts) {
      try {
        const sourceResult = await this.getScriptSource(script.scriptId, 200_000);
        const keyBase = script.url || `script:${script.scriptId}`;
        let key = keyBase;
        if (snapshot.has(key)) key = `${keyBase}#${script.scriptId}`;
        snapshot.set(key, {
          key,
          scriptId: script.scriptId,
          url: script.url,
          source: String(sourceResult.source ?? ""),
          capturedAt: nowIso(),
        });
      } catch (_) {
        // A script may disappear while a navigation is in progress.
      }
    }
    this.bundleSnapshots.set(label, snapshot);
    return {
      label,
      urlContains,
      scripts: snapshot.size,
      totalSourceChars: [...snapshot.values()].reduce((total, item) => total + item.source.length, 0),
      keys: [...snapshot.keys()],
    };
  }

  diffBundles(labelA: string, labelB: string, maxChanges = 100): Record<string, unknown> {
    const left = this.bundleSnapshots.get(labelA);
    const right = this.bundleSnapshots.get(labelB);
    if (!left) throw new Error(`Bundle snapshot not found: ${labelA}`);
    if (!right) throw new Error(`Bundle snapshot not found: ${labelB}`);
    const added: BundleScriptSnapshot[] = [];
    const removed: BundleScriptSnapshot[] = [];
    const changed: Array<Record<string, unknown>> = [];
    for (const [key, item] of right) {
      if (!left.has(key)) added.push(item);
      else if (left.get(key)?.source !== item.source) {
        changed.push({ key, url: item.url, scriptIdBefore: left.get(key)?.scriptId, scriptIdAfter: item.scriptId, diff: textDiffSummary(left.get(key)?.source ?? "", item.source) });
      }
    }
    for (const [key, item] of left) if (!right.has(key)) removed.push(item);
    return {
      labelA,
      labelB,
      counts: { before: left.size, after: right.size, added: added.length, removed: removed.length, changed: changed.length },
      added: added.slice(0, maxChanges).map(({ source: _source, ...item }) => item),
      removed: removed.slice(0, maxChanges).map(({ source: _source, ...item }) => item),
      changed: changed.slice(0, maxChanges),
      truncated: added.length > maxChanges || removed.length > maxChanges || changed.length > maxChanges,
    };
  }

  async generateOpenApi(options: { title?: string; urlContains?: string; includeExamples?: boolean; maxExamples?: number } = {}): Promise<Record<string, unknown>> {
    const paths: Record<string, any> = {};
    const origins = new Set<string>();
    const exampleBudget = options.maxExamples ?? 20;
    let examplesUsed = 0;
    for (const requestId of this.networkOrder) {
      const record = this.networkRecords.get(requestId);
      if (!record || (options.urlContains && !record.url.includes(options.urlContains))) continue;
      let parsed: URL;
      try { parsed = new URL(record.url); } catch (_) { continue; }
      origins.add(parsed.origin);
      const path = parsed.pathname || "/";
      const method = record.method.toLowerCase();
      const operation = paths[path]?.[method] ?? {
        operationId: `${method}_${path.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "") || "root"}`,
        parameters: [],
        responses: {},
        "x-reverse-engineering-requestIds": [],
      };
      const parameterNames = new Set((operation.parameters ?? []).map((parameter: any) => parameter.name));
      for (const [name, value] of parsed.searchParams.entries()) {
        if (parameterNames.has(name)) continue;
        parameterNames.add(name);
        operation.parameters.push({ name, in: "query", required: false, schema: { type: "string" }, example: value });
      }
      if (record.postData && method !== "get" && method !== "head") {
        const contentType = Object.entries(record.requestHeaders ?? {}).find(([key]) => key.toLowerCase() === "content-type")?.[1];
        const mediaType = typeof contentType === "string" ? contentType.split(";", 1)[0] : "application/octet-stream";
        operation.requestBody = operation.requestBody ?? { required: true, content: { [mediaType]: { example: parseJsonOrText(record.postData) } } };
      }
      const statusKey = String(record.status ?? "default");
      if (!operation.responses[statusKey]) {
        const response: Record<string, unknown> = { description: record.statusText || `Observed response ${statusKey}` };
        if (record.mimeType) response.content = { [record.mimeType]: {} };
        if (options.includeExamples && examplesUsed < exampleBudget && record.status !== undefined) {
          try {
            const body = await this.getNetworkBody(record.requestId, 20_000);
            const mediaType = record.mimeType || "text/plain";
            const responseContent = (response.content ?? {}) as Record<string, unknown>;
            responseContent[mediaType] = { example: mediaType.includes("json") ? parseJsonOrText(String(body.body)) : String(body.body) };
            response.content = responseContent;
            examplesUsed += 1;
          } catch (_) {}
        }
        operation.responses[statusKey] = response;
      }
      operation["x-reverse-engineering-requestIds"].push(record.requestId);
      paths[path] ??= {};
      paths[path][method] = operation;
    }
    return {
      openapi: "3.0.3",
      info: { title: options.title ?? "Observed web API", version: "0.1.0", description: "Generated from captured browser traffic by reverse-engineering-mcp." },
      servers: [...origins].map((url) => ({ url })),
      paths,
      "x-reverse-engineering": { observedRequests: this.networkRecords.size, examplesIncluded: examplesUsed },
    };
  }

  async evaluate(expression: string, options: { awaitPromise?: boolean; returnByValue?: boolean; expand?: boolean } = {}) {
    const client = this.requireClient();
    const result = await client.Runtime.evaluate({
      expression,
      awaitPromise: options.awaitPromise ?? true,
      returnByValue: options.returnByValue ?? false,
      userGesture: true,
      includeCommandLineAPI: true,
      replMode: true,
      objectGroup: "reverse-engineering-mcp",
    });
    return this.formatEvaluationResult(result, options.expand ?? false);
  }

  async evaluateOnCallFrame(callFrameId: string, expression: string, expand = false) {
    const client = this.requireClient();
    const result = await client.Debugger.evaluateOnCallFrame({
      callFrameId,
      expression,
      awaitPromise: true,
      returnByValue: false,
      throwOnSideEffect: false,
    });
    return this.formatEvaluationResult(result, expand);
  }

  getConsole(limit = 100, type?: string): ConsoleRecord[] {
    return this.consoleEvents
      .filter((event) => !type || event.type === type)
      .slice(-Math.min(Math.max(limit, 1), MAX_CONSOLE_EVENTS));
  }

  getNetwork(query: NetworkQuery = {}) {
    const limit = Math.min(Math.max(query.limit ?? 100, 1), MAX_NETWORK_RECORDS);
    const requests = this.networkOrder
      .map((requestId) => this.networkRecords.get(requestId))
      .filter((record): record is NetworkRecord => Boolean(record))
      .filter((record) => !query.urlContains || record.url.includes(query.urlContains))
      .filter((record) => !query.type || record.type === query.type)
      .filter((record) => query.status === undefined || record.status === query.status)
      .slice(-limit);
    return { requests, websocketFrames: this.socketFrames.slice(-limit) };
  }

  async waitForNetwork(query: NetworkWaitQuery = {}): Promise<Record<string, unknown>> {
    const startedAt = Date.now();
    const timeout = Math.min(Math.max(query.timeoutMs ?? 10_000, 0), 120_000);
    const interval = Math.min(Math.max(query.pollMs ?? 100, 25), 2_000);
    let expression: RegExp | undefined;
    if (query.urlRegex) {
      try {
        expression = new RegExp(query.urlRegex);
      } catch (error) {
        throw new Error(`Invalid network URL regex: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    const matches = (): NetworkRecord[] => this.getNetwork({ limit: MAX_NETWORK_RECORDS }).requests.filter((record) => {
      if (query.urlContains && !record.url.includes(query.urlContains)) return false;
      if (query.urlPathContains) {
        let pathname: string;
        try { pathname = new URL(record.url).pathname; } catch (_) { pathname = record.url; }
        if (!pathname.includes(query.urlPathContains)) return false;
      }
      if (expression) {
        expression.lastIndex = 0;
        if (!expression.test(record.url)) return false;
      }
      if (query.type && record.type !== query.type) return false;
      if (query.status !== undefined && record.status !== query.status) return false;
      if (query.requireResponse && record.status === undefined) return false;
      if (query.requireFinished && record.finishedAt === undefined) return false;
      return true;
    });
    while (Date.now() - startedAt <= timeout) {
      const records = matches();
      const record = records.at(-1);
      if (record) {
        const output = { matched: true, request: record, query, waitedMs: Date.now() - startedAt };
        this.addTimeline("network", "wait-matched", `network matched: ${record.method} ${record.url}`.slice(0, 500), output);
        return output;
      }
      if (Date.now() - startedAt >= timeout) break;
      await sleep(Math.min(interval, Math.max(1, timeout - (Date.now() - startedAt))));
    }
    const output = { matched: false, waitedMs: Date.now() - startedAt, query };
    this.addTimeline("network", "wait-timeout", "network wait timed out", output);
    return output;
  }

  async getNetworkBody(requestId: string, maxChars = 100_000) {
    const client = this.requireClient();
    const body = await client.Network.getResponseBody({ requestId });
    const content = String(body.body ?? "");
    return {
      requestId,
      base64Encoded: Boolean(body.base64Encoded),
      body: content.slice(0, Math.min(Math.max(maxChars, 1), 500_000)),
      totalLength: content.length,
      truncated: content.length > maxChars,
    };
  }

  async traceRequestOrigin(requestId: string, includeSource = true): Promise<Record<string, unknown>> {
    const record = this.networkRecords.get(requestId);
    if (!record) throw new Error(`Network request not found: ${requestId}`);
    const initiator = record.initiator as any;
    const callFrames = initiator?.stack?.callFrames ?? initiator?.stackTrace?.callFrames ?? [];
    const frames: Array<Record<string, unknown>> = [];
    for (const frame of callFrames.slice(0, 100)) {
      const mapped: Record<string, unknown> = {
        functionName: frame.functionName,
        url: frame.url,
        scriptId: frame.scriptId,
        lineNumber: frame.lineNumber,
        columnNumber: frame.columnNumber,
      };
      if (includeSource && frame.scriptId) {
        try {
          const source = await this.getScriptSource(String(frame.scriptId), 200_000);
          const text = String(source.source ?? "");
          const lines = text.split("\n");
          const line = Math.max(0, Number(frame.lineNumber ?? 0));
          mapped.sourceContext = lines.slice(Math.max(0, line - 2), Math.min(lines.length, line + 3)).map((content, index) => ({
            line: Math.max(0, line - 2) + index,
            content,
          }));
        } catch (_) {
          // Source can disappear after a navigation or a worker restart.
        }
      }
      frames.push(mapped);
    }
    const isInstrumentationFrame = (frame: Record<string, unknown>): boolean =>
      /reverse-engineering-mcp-(?:hook|taint)-/i.test(String(frame.url ?? ""));
    const applicationFrames = frames.filter((frame) => !isInstrumentationFrame(frame));
    return {
      request: record,
      initiatorType: initiator?.type,
      initiatorUrl: initiator?.url,
      stack: frames,
      origin: applicationFrames[0] ?? frames[0] ?? null,
      leafOrigin: applicationFrames.at(-1) ?? frames.at(-1) ?? null,
      instrumentationFrames: frames.length - applicationFrames.length,
      note: frames.length
        ? "Origin uses the first non-MCP frame; leafOrigin is the deepest application frame in Chrome's initiator stack."
        : "Chrome did not provide a JavaScript initiator stack for this request.",
    };
  }

  async replayAndVerify(requestId: string, overrides: ReplayOverrides = {}, maxBodyChars = 500_000): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const record = this.networkRecords.get(requestId);
    if (!record) throw new Error(`Network request not found: ${requestId}`);
    const originalHeaders = this.rawRequestHeaders.get(requestId) ?? {};
    const forbiddenTransportHeaders = new Set(["connection", "content-length", "host", "origin", "referer", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "user-agent"]);
    const sensitiveCapturedHeaders = new Set(["authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token"]);
    const headers = Object.fromEntries([
      ...Object.entries(originalHeaders).filter(([key]) => !forbiddenTransportHeaders.has(key.toLowerCase()) && !sensitiveCapturedHeaders.has(key.toLowerCase())),
      ...Object.entries(overrides.headers ?? {}).filter(([key]) => !forbiddenTransportHeaders.has(key.toLowerCase())),
    ].map(([key, value]) => [key, String(value)]));
    const url = overrides.url ?? record.url;
    const method = (overrides.method ?? record.method).toUpperCase();
    const requestBody = overrides.body ?? record.postData;
    const bodyLimit = Math.min(Math.max(maxBodyChars, 1), 500_000);
    const expression = `(async () => {
      const url = ${JSON.stringify(url)};
      const method = ${JSON.stringify(method)};
      const headers = ${JSON.stringify(headers)};
      const init = { method, headers, credentials: "include", redirect: "manual" };
      if (method !== "GET" && method !== "HEAD" && ${JSON.stringify(requestBody !== undefined)}) init.body = ${JSON.stringify(requestBody)};
      const response = await fetch(url, init);
      const bytes = new Uint8Array(await response.arrayBuffer());
      const parts = [];
      for (let offset = 0; offset < bytes.length; offset += 0x8000) parts.push(String.fromCharCode(...bytes.subarray(offset, offset + 0x8000)));
      return { status: response.status, statusText: response.statusText, headers: Object.fromEntries(response.headers.entries()), bodyBase64: btoa(parts.join("")), bodyBytes: bytes.length };
    })()`;
    const result = await client.Runtime.evaluate({ expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "Replay failed in page context");
    }
    const replay = result.result?.value ?? {};
    let originalBody: any = null;
    try {
      originalBody = await client.Network.getResponseBody({ requestId });
    } catch (_) {
      // Cached, opaque and navigational responses may not expose a body.
    }
    const originalBase64 = originalBody
      ? originalBody.base64Encoded
        ? String(originalBody.body ?? "")
        : Buffer.from(String(originalBody.body ?? ""), "utf8").toString("base64")
      : undefined;
    const replayBase64 = typeof replay.bodyBase64 === "string" ? replay.bodyBase64 : undefined;
    const mismatchIndex = originalBase64 !== undefined && replayBase64 !== undefined
      ? firstMismatch(originalBase64, replayBase64)
      : undefined;
    return {
      requestId,
      request: { url, method, headers, body: requestBody === undefined ? undefined : truncate(requestBody, 12_000) },
      original: { status: record.status, bodyAvailable: originalBase64 !== undefined, bodyBytes: originalBase64 ? Math.floor(originalBase64.length * 0.75) : undefined },
      replay: { status: replay.status, statusText: replay.statusText, bodyBytes: replay.bodyBytes, bodyPreviewBase64: replayBase64?.slice(0, bodyLimit) },
      comparison: {
        statusEqual: record.status === undefined ? undefined : record.status === replay.status,
        bodyEqual: originalBase64 === undefined || replayBase64 === undefined ? undefined : originalBase64 === replayBase64,
        firstBodyMismatchIndex: mismatchIndex,
        contentTypeOriginal: record.mimeType,
        contentTypeReplay: replay.headers?.["content-type"],
      },
      note: "Replay runs in the attached browser context with credentials included; browser CORS and server-side nonce checks still apply.",
    };
  }

  async environmentDiff(includeCanvas = false, extraExpressions: Record<string, string> = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const canvasExpression = includeCanvas
      ? `(() => { try { const canvas = document.createElement("canvas"); canvas.width = 240; canvas.height = 80; const context = canvas.getContext("2d"); context.font = "16px Arial"; context.fillText("reverse-engineering-mcp", 3, 30); const value = canvas.toDataURL(); let hash = 2166136261; for (let i = 0; i < value.length; i++) { hash ^= value.charCodeAt(i); hash = Math.imul(hash, 16777619); } return (hash >>> 0).toString(16); } catch (_) { return null; } })()`
      : "null";
    const expression = `(async () => ({
      navigator: {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages,
        vendor: navigator.vendor,
        webdriver: navigator.webdriver,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        maxTouchPoints: navigator.maxTouchPoints,
        cookieEnabled: navigator.cookieEnabled,
        userAgentData: navigator.userAgentData ? { brands: navigator.userAgentData.brands, platform: navigator.userAgentData.platform, mobile: navigator.userAgentData.mobile } : null
      },
      screen: { width: screen.width, height: screen.height, availWidth: screen.availWidth, availHeight: screen.availHeight, colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth },
      window: { innerWidth, innerHeight, outerWidth, outerHeight, devicePixelRatio },
      locale: { language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, locale: Intl.DateTimeFormat().resolvedOptions().locale },
      features: { fetch: typeof fetch === "function", cryptoSubtle: Boolean(globalThis.crypto?.subtle), webAssembly: typeof WebAssembly !== "undefined", sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined", offscreenCanvas: typeof OffscreenCanvas !== "undefined", webGL: Boolean(document.createElement("canvas").getContext("webgl")) },
      canvasHash: ${canvasExpression}
    }))()`;
    const browserResult = await client.Runtime.evaluate({ expression, awaitPromise: true, returnByValue: true });
    if (browserResult.exceptionDetails) throw new Error(browserResult.exceptionDetails.text ?? "Could not read browser environment");
    const browser = browserResult.result?.value ?? {};
    const extras: Record<string, unknown> = {};
    for (const [name, extraExpression] of Object.entries(extraExpressions).slice(0, 30)) {
      const extraResult = await client.Runtime.evaluate({ expression: extraExpression, awaitPromise: true, returnByValue: true });
      extras[name] = extraResult.exceptionDetails ? `[error: ${extraResult.exceptionDetails.text ?? "evaluation failed"}]` : extraResult.result?.value;
    }
    const node = {
      runtime: process.version,
      platform: process.platform,
      arch: process.arch,
      locale: { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, locale: Intl.DateTimeFormat().resolvedOptions().locale },
      features: { fetch: typeof globalThis.fetch === "function", cryptoSubtle: Boolean(globalThis.crypto?.subtle), webAssembly: typeof WebAssembly !== "undefined", sharedArrayBuffer: typeof SharedArrayBuffer !== "undefined" },
      globals: { window: false, document: false, navigator: false, atob: typeof globalThis.atob === "function", btoa: typeof globalThis.btoa === "function" },
    };
    const browserWithExtras = { ...browser, extras };
    const flatten = (value: unknown, prefix = "", output: Record<string, unknown> = {}): Record<string, unknown> => {
      if (value === null || typeof value !== "object") { output[prefix] = value; return output; }
      if (Array.isArray(value)) { value.forEach((child, index) => flatten(child, `${prefix}[${index}]`, output)); return output; }
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) flatten(child, prefix ? `${prefix}.${key}` : key, output);
      return output;
    };
    const browserFlat = flatten(browserWithExtras);
    const nodeFlat = flatten(node);
    const differences = Object.keys(browserFlat).filter((key) => key in nodeFlat && JSON.stringify(browserFlat[key]) !== JSON.stringify(nodeFlat[key])).slice(0, 300).map((key) => ({ path: key, browser: browserFlat[key], node: nodeFlat[key] }));
    return {
      browser: browserWithExtras,
      node,
      differences,
      browserOnly: Object.keys(browserFlat).filter((key) => !(key in nodeFlat)).slice(0, 100),
      nodeOnly: Object.keys(nodeFlat).filter((key) => !(key in browserFlat)).slice(0, 100),
    };
  }

  async startTaintTracking(expression: string, label: string, trackerId?: string): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const sourceResult = await client.Runtime.evaluate({ expression, awaitPromise: true, returnByValue: true });
    if (sourceResult.exceptionDetails) throw new Error(sourceResult.exceptionDetails.text ?? "Taint source evaluation failed");
    const value = sourceResult.result?.value;
    const tokens = deriveTaintTokens(value);
    if (!tokens.length) throw new Error("The source produced no trackable string/number tokens (minimum length is 4).");
    const id = trackerId?.trim() || `taint-${Date.now().toString(36)}`;
    if (this.taintTrackers.has(id)) throw new Error(`Taint tracker already exists: ${id}`);
    const source = makeTaintSource(id, label, tokens);
    const registration = await client.Page.addScriptToEvaluateOnNewDocument({ source });
    await client.Runtime.evaluate({ expression: source, awaitPromise: false, returnByValue: true });
    const tracker: TaintTrackerRecord = { trackerId: id, label, expression, tokens, scriptIdentifier: registration.identifier, installedAt: nowIso() };
    this.taintTrackers.set(id, tracker);
    return { ...tracker, sourceValue: remoteObjectToValue(sourceResult.result), mode: "dynamic-sink-tracing", limitation: "Tracks exact and base64 token appearances at instrumented sinks; arbitrary cryptographic transforms require crypto hook output inspection." };
  }

  async stopTaintTracking(trackerId: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    const tracker = this.taintTrackers.get(trackerId);
    if (!tracker) throw new Error(`Taint tracker not found: ${trackerId}`);
    if (tracker.scriptIdentifier) await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: tracker.scriptIdentifier });
    await client.Runtime.evaluate({ expression: `globalThis[${JSON.stringify(`__reverse_engineering_mcp_taint_${trackerId}`)}]?.restore?.()`, awaitPromise: false, returnByValue: true });
    this.taintTrackers.delete(trackerId);
    return { removed: trackerId };
  }

  listTaintTrackers(): TaintTrackerRecord[] {
    return [...this.taintTrackers.values()];
  }

  getTimeline(limit = 200, categories?: string[]): TimelineRecord[] {
    return this.timeline
      .filter((event) => !categories?.length || categories.includes(event.category))
      .slice(-Math.min(Math.max(limit, 1), MAX_TIMELINE_EVENTS));
  }

  timelineRecorder(action: "start" | "stop" | "read" | "clear", limit = 200, categories?: string[]): Record<string, unknown> {
    if (action === "start") this.timelineEnabled = true;
    if (action === "stop") this.timelineEnabled = false;
    if (action === "clear") this.timeline = [];
    return { action, recording: this.timelineEnabled, events: action === "read" || action === "clear" ? this.getTimeline(limit, categories) : undefined };
  }

  async setBreakpoint(input: {
    lineNumber: number;
    columnNumber?: number;
    url?: string;
    urlRegex?: string;
    scriptId?: string;
    condition?: string;
  }): Promise<BreakpointRecord> {
    const client = this.requireClient();
    const columnNumber = input.columnNumber ?? 0;
    let result: any;
    if (input.scriptId) {
      result = await client.Debugger.setBreakpoint({
        location: { scriptId: input.scriptId, lineNumber: input.lineNumber, columnNumber },
        condition: input.condition,
      });
    } else {
      if (!input.url && !input.urlRegex) throw new Error("Provide url, urlRegex, or scriptId for a breakpoint.");
      result = await client.Debugger.setBreakpointByUrl({
        url: input.url,
        urlRegex: input.urlRegex,
        lineNumber: input.lineNumber,
        columnNumber,
        condition: input.condition,
      });
    }
    const record: BreakpointRecord = {
      breakpointId: result.breakpointId,
      url: input.url,
      urlRegex: input.urlRegex,
      scriptId: input.scriptId,
      lineNumber: input.lineNumber,
      columnNumber,
      condition: input.condition,
      locations: result.locations ?? [],
      createdAt: nowIso(),
    };
    this.breakpoints.set(record.breakpointId, record);
    return record;
  }

  async removeBreakpoint(breakpointId: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    await client.Debugger.removeBreakpoint({ breakpointId });
    this.breakpoints.delete(breakpointId);
    return { removed: breakpointId };
  }

  listBreakpoints(): BreakpointRecord[] {
    return [...this.breakpoints.values()];
  }

  getDebuggerStatus(): Record<string, unknown> {
    return {
      paused: this.pauseState !== null,
      pause: this.pauseState,
      breakpoints: this.listBreakpoints(),
    };
  }

  async resume(): Promise<{ action: string }> {
    await this.requireClient().Debugger.resume();
    return { action: "resume" };
  }

  async step(action: "over" | "into" | "out"): Promise<{ action: string }> {
    const debuggerDomain = this.requireClient().Debugger;
    if (action === "over") await debuggerDomain.stepOver();
    if (action === "into") await debuggerDomain.stepInto();
    if (action === "out") await debuggerDomain.stepOut();
    return { action: `step_${action}` };
  }

  async setPauseOnExceptions(state: "none" | "uncaught" | "all") {
    await this.requireClient().Debugger.setPauseOnExceptions({ state });
    return { state };
  }

  async installHook(options: HookOptions): Promise<HookRecord> {
    const client = this.requireClient();
    const hookId = options.hookId?.trim() || `${options.kind}-${Date.now().toString(36)}`;
    if (this.hooks.has(hookId)) throw new Error(`Hook already exists: ${hookId}`);
    const includeResponse = options.includeResponse ?? false;
    const captureBuiltins = options.captureBuiltins ?? false;
    const source = makeHookSource(hookId, options.kind, includeResponse, captureBuiltins);
    const registration = await client.Page.addScriptToEvaluateOnNewDocument({ source });
    await client.Runtime.evaluate({ expression: source, awaitPromise: false, returnByValue: true });
    const record: HookRecord = {
      hookId,
      kind: options.kind,
      includeResponse,
      captureBuiltins,
      installedAt: nowIso(),
      scriptIdentifier: registration.identifier,
    };
    this.hooks.set(hookId, record);
    return record;
  }

  async removeHook(hookId: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    const hook = this.hooks.get(hookId);
    if (!hook) throw new Error(`Hook not found: ${hookId}`);
    if (hook.scriptIdentifier) {
      await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: hook.scriptIdentifier });
    }
    const expression = `globalThis[${JSON.stringify(`__reverse_engineering_mcp_hook_${hookId}`)}]?.restore?.()`;
    await client.Runtime.evaluate({ expression, awaitPromise: false, returnByValue: true });
    this.hooks.delete(hookId);
    return { removed: hookId };
  }

  listHooks(): HookRecord[] {
    return [...this.hooks.values()];
  }

  getHookEvents(options: { hookId?: string; limit?: number } = {}): HookEventRecord[] {
    return this.hookEvents
      .filter((event) => !options.hookId || event.hookId === options.hookId)
      .slice(-Math.min(Math.max(options.limit ?? 100, 1), MAX_HOOK_EVENTS));
  }

  getTaintEvents(trackerId?: string, limit = 200): HookEventRecord[] {
    return this.hookEvents
      .filter((event) => event.kind === "taint")
      .filter((event) => !trackerId || event.hookId === trackerId)
      .slice(-Math.min(Math.max(limit, 1), MAX_HOOK_EVENTS));
  }

  async clearLogs(): Promise<{ cleared: true }> {
    this.consoleEvents = [];
    this.networkRecords.clear();
    this.rawRequestHeaders.clear();
    this.networkOrder = [];
    this.socketFrames = [];
    this.hookEvents = [];
    this.timeline = [];
    return { cleared: true };
  }

  // ==========================================
  // BROWSER AUTOMATION & INTERACTION
  // ==========================================

  async screenshot(options: {
    selector?: string;
    fullPage?: boolean;
    format?: "png" | "jpeg";
    quality?: number;
  } = {}): Promise<{ dataBase64: string; mimeType: string; width?: number; height?: number }> {
    const client = this.requireClient();
    const format = options.format ?? "png";
    const quality = format === "jpeg" ? (options.quality ?? 80) : undefined;

    if (options.fullPage) {
      const metrics = await client.Page.getLayoutMetrics();
      const width = Math.ceil(metrics.contentSize ? metrics.contentSize.width : metrics.layoutViewport.clientWidth);
      const height = Math.ceil(metrics.contentSize ? metrics.contentSize.height : metrics.layoutViewport.clientHeight);
      const result = await client.Page.captureScreenshot({
        format,
        quality,
        clip: { x: 0, y: 0, width, height, scale: 1 },
        captureBeyondViewport: true,
      });
      return { dataBase64: result.data, mimeType: `image/${format}`, width, height };
    }

    if (options.selector) {
      const evalResult = await client.Runtime.evaluate({
        expression: `(() => {
          const el = document.querySelector(${JSON.stringify(options.selector)});
          if (!el) return null;
          el.scrollIntoView({ block: 'center', inline: 'center' });
          const rect = el.getBoundingClientRect();
          return { x: rect.left, y: rect.top, width: rect.width, height: rect.height };
        })()`,
        returnByValue: true,
      });
      const rect = evalResult.result?.value;
      if (!rect || rect.width <= 0 || rect.height <= 0) {
        throw new Error(`Element not found or not visible for selector: ${options.selector}`);
      }
      const result = await client.Page.captureScreenshot({
        format,
        quality,
        clip: {
          x: Math.max(0, rect.x),
          y: Math.max(0, rect.y),
          width: Math.max(1, rect.width),
          height: Math.max(1, rect.height),
          scale: 1,
        },
        captureBeyondViewport: true,
      });
      return {
        dataBase64: result.data,
        mimeType: `image/${format}`,
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      };
    }

    const result = await client.Page.captureScreenshot({ format, quality });
    return { dataBase64: result.data, mimeType: `image/${format}` };
  }

  async pressKey(
    key: string,
    modifiers?: Array<"Alt" | "Control" | "Meta" | "Shift">,
  ): Promise<{ pressed: string; modifiers: string[] }> {
    const client = this.requireClient();
    let modifierBitmask = 0;
    if (modifiers?.includes("Alt")) modifierBitmask |= 1;
    if (modifiers?.includes("Control")) modifierBitmask |= 2;
    if (modifiers?.includes("Meta")) modifierBitmask |= 4;
    if (modifiers?.includes("Shift")) modifierBitmask |= 8;

    const keyMap: Record<string, { code: string; keyCode: number; text?: string }> = {
      Enter: { code: "Enter", keyCode: 13, text: "\r" },
      Tab: { code: "Tab", keyCode: 9, text: "\t" },
      Escape: { code: "Escape", keyCode: 27 },
      Backspace: { code: "Backspace", keyCode: 8 },
      Delete: { code: "Delete", keyCode: 46 },
      Space: { code: "Space", keyCode: 32, text: " " },
      ArrowDown: { code: "ArrowDown", keyCode: 40 },
      ArrowUp: { code: "ArrowUp", keyCode: 38 },
      ArrowLeft: { code: "ArrowLeft", keyCode: 37 },
      ArrowRight: { code: "ArrowRight", keyCode: 39 },
      PageDown: { code: "PageDown", keyCode: 34 },
      PageUp: { code: "PageUp", keyCode: 33 },
      Home: { code: "Home", keyCode: 36 },
      End: { code: "End", keyCode: 35 },
      F12: { code: "F12", keyCode: 123 },
    };

    const keyInfo = keyMap[key];
    if (keyInfo) {
      await client.Input.dispatchKeyEvent({
        type: "rawKeyDown",
        key,
        code: keyInfo.code,
        windowsVirtualKeyCode: keyInfo.keyCode,
        modifiers: modifierBitmask,
        text: keyInfo.text,
        unmodifiedText: keyInfo.text,
      });
      if (keyInfo.text) {
        await client.Input.dispatchKeyEvent({
          type: "char",
          key,
          code: keyInfo.code,
          windowsVirtualKeyCode: keyInfo.keyCode,
          modifiers: modifierBitmask,
          text: keyInfo.text,
          unmodifiedText: keyInfo.text,
        });
      }
      await client.Input.dispatchKeyEvent({
        type: "keyUp",
        key,
        code: keyInfo.code,
        windowsVirtualKeyCode: keyInfo.keyCode,
        modifiers: modifierBitmask,
      });
    } else {
      for (const char of key) {
        await client.Input.dispatchKeyEvent({
          type: "keyDown",
          text: char,
          unmodifiedText: char,
          modifiers: modifierBitmask,
        });
        await client.Input.dispatchKeyEvent({
          type: "keyUp",
          modifiers: modifierBitmask,
        });
      }
    }

    this.addTimeline("browser", "press_key", `Key pressed: ${key} (${(modifiers ?? []).join("+")})`, {
      key,
      modifiers,
    });
    return { pressed: key, modifiers: modifiers ?? [] };
  }

  async hoverSelector(selector: string): Promise<{ hovered: string; x: number; y: number }> {
    const client = this.requireClient();
    const evalResult = await client.Runtime.evaluate({
      expression: `(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return null;
        el.scrollIntoView({ block: 'center', inline: 'center' });
        const rect = el.getBoundingClientRect();
        return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
      })()`,
      returnByValue: true,
    });
    const coords = evalResult.result?.value;
    if (!coords) throw new Error(`Element not found for selector: ${selector}`);

    await client.Input.dispatchMouseEvent({
      type: "mouseMoved",
      x: coords.x,
      y: coords.y,
    });

    this.addTimeline("browser", "hover", `Hovered on ${selector} at (${Math.round(coords.x)}, ${Math.round(coords.y)})`);
    return { hovered: selector, x: Math.round(coords.x), y: Math.round(coords.y) };
  }

  async scrollPage(options: { x?: number; y?: number; selector?: string } = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    if (options.selector) {
      const evalResult = await client.Runtime.evaluate({
        expression: `(() => {
          const el = document.querySelector(${JSON.stringify(options.selector)});
          if (!el) return false;
          el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' });
          return true;
        })()`,
        returnByValue: true,
      });
      if (!evalResult.result?.value) throw new Error(`Element not found for selector: ${options.selector}`);
      return { scrolled: true, selector: options.selector };
    }

    const evalResult = await client.Runtime.evaluate({
      expression: `(() => {
        window.scrollBy({ left: ${options.x ?? 0}, top: ${options.y ?? 0}, behavior: 'instant' });
        return { scrollX: window.scrollX, scrollY: window.scrollY };
      })()`,
      returnByValue: true,
    });
    return { scrolled: true, currentScroll: evalResult.result?.value };
  }

  async selectOption(selector: string, value: string): Promise<{ selected: string; value: string }> {
    const client = this.requireClient();
    const evalResult = await client.Runtime.evaluate({
      expression: `(() => {
        const select = document.querySelector(${JSON.stringify(selector)});
        if (!select || select.tagName !== 'SELECT') return false;
        let found = false;
        for (const opt of select.options) {
          if (opt.value === ${JSON.stringify(value)} || opt.text === ${JSON.stringify(value)}) {
            select.value = opt.value;
            found = true;
            break;
          }
        }
        if (!found) select.value = ${JSON.stringify(value)};
        select.dispatchEvent(new Event('input', { bubbles: true }));
        select.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      })()`,
      returnByValue: true,
    });
    if (!evalResult.result?.value) throw new Error(`Could not select option in ${selector} with value: ${value}`);
    return { selected: selector, value };
  }

  async reloadPage(ignoreCache = true, scriptToEvaluateOnLoad?: string): Promise<{ reloaded: boolean; ignoreCache: boolean }> {
    const client = this.requireClient();
    await client.Page.reload({ ignoreCache, scriptToEvaluateOnLoad });
    this.addTimeline("browser", "reload", `Page reloaded (ignoreCache: ${ignoreCache})`);
    return { reloaded: true, ignoreCache };
  }

  async setViewport(options: { width: number; height: number; deviceScaleFactor?: number; mobile?: boolean }): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    await client.Emulation.setDeviceMetricsOverride({
      width: options.width,
      height: options.height,
      deviceScaleFactor: options.deviceScaleFactor ?? 1,
      mobile: options.mobile ?? false,
    });
    return { width: options.width, height: options.height, mobile: options.mobile ?? false };
  }

  async setUserAgent(options: { userAgent: string; acceptLanguage?: string; platform?: string }): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    await client.Network.setUserAgentOverride({
      userAgent: options.userAgent,
      acceptLanguage: options.acceptLanguage,
      platform: options.platform,
    });
    return { userAgent: options.userAgent, acceptLanguage: options.acceptLanguage, platform: options.platform };
  }

  async getCookies(urls?: string[]): Promise<CookieRecord[]> {
    const client = this.requireClient();
    const result = await client.Network.getCookies({
      urls: urls ?? (this.target?.url ? [this.target.url] : undefined),
    });
    return (result.cookies ?? []).map((c: any) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      expires: c.expires,
      size: c.size,
      httpOnly: c.httpOnly,
      secure: c.secure,
      session: c.session,
      sameSite: c.sameSite,
    }));
  }

  async setCookie(cookie: {
    name: string;
    value: string;
    domain?: string;
    path?: string;
    secure?: boolean;
    httpOnly?: boolean;
    sameSite?: string;
    expires?: number;
  }): Promise<{ success: boolean; name: string }> {
    const client = this.requireClient();
    const url = cookie.domain ? undefined : await this.getCurrentUrl();
    await client.Network.setCookie({
      name: cookie.name,
      value: cookie.value,
      url,
      domain: cookie.domain,
      path: cookie.path ?? "/",
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
      expires: cookie.expires,
    });
    return { success: true, name: cookie.name };
  }

  async deleteCookies(name: string, url?: string, domain?: string): Promise<{ deleted: string }> {
    const client = this.requireClient();
    const cookieUrl = url ?? (domain ? undefined : await this.getCurrentUrl());
    await client.Network.deleteCookies({ name, url: cookieUrl, domain });
    return { deleted: name };
  }

  async getStorage(type: "local" | "session" | "both" = "both"): Promise<Record<string, Record<string, string>>> {
    const client = this.requireClient();
    const result = await client.Runtime.evaluate({
      expression: `(() => {
        const dump = (s) => {
          const res = {};
          if (!s) return res;
          for (let i = 0; i < s.length; i++) {
            const k = s.key(i);
            if (k) res[k] = s.getItem(k);
          }
          return res;
        };
        return {
          localStorage: dump(window.localStorage),
          sessionStorage: dump(window.sessionStorage),
        };
      })()`,
      returnByValue: true,
    });
    const val = result.result?.value ?? {};
    if (type === "local") return { localStorage: val.localStorage ?? {} };
    if (type === "session") return { sessionStorage: val.sessionStorage ?? {} };
    return val;
  }

  async setStorage(type: "local" | "session", key: string, value: string): Promise<{ type: string; key: string; value: string }> {
    const client = this.requireClient();
    const storageName = type === "local" ? "localStorage" : "sessionStorage";
    await client.Runtime.evaluate({
      expression: `window.${storageName}.setItem(${JSON.stringify(key)}, ${JSON.stringify(value)})`,
      returnByValue: true,
    });
    return { type, key, value };
  }

  async clearStorage(type: "local" | "session" | "cookies" | "all" = "all"): Promise<{ cleared: string }> {
    const client = this.requireClient();
    if (type === "cookies" || type === "all") {
      await client.Network.clearBrowserCookies();
    }
    if (type === "local" || type === "all") {
      await client.Runtime.evaluate({ expression: "window.localStorage?.clear()", returnByValue: true });
    }
    if (type === "session" || type === "all") {
      await client.Runtime.evaluate({ expression: "window.sessionStorage?.clear()", returnByValue: true });
    }
    if (type === "all") {
      const currentUrl = await this.getCurrentUrl();
      if (currentUrl) {
        try {
          const origin = new URL(currentUrl).origin;
          await client.Storage.clearDataForOrigin({ origin, storageTypes: "all" });
        } catch (_) {}
      }
    }
    return { cleared: type };
  }

  // ==========================================
  // BREAKPOINTS & DEBUGGER EXTENSIONS
  // ==========================================

  async setDomBreakpoint(
    selector: string,
    type: "subtree-modified" | "attribute-modified" | "node-removed",
  ): Promise<DomBreakpointRecord> {
    const client = this.requireClient();
    const doc = await client.DOM.getDocument({ depth: -1 });
    const { nodeId } = await client.DOM.querySelector({ nodeId: doc.root.nodeId, selector });
    if (!nodeId || nodeId === 0) {
      throw new Error(`Element not found for selector: ${selector}`);
    }
    await client.DOMDebugger.setDOMBreakpoint({ nodeId, type });
    const breakpointId = `dom-${nodeId}-${type}`;
    const record: DomBreakpointRecord = {
      breakpointId,
      nodeId,
      selector,
      type,
      createdAt: nowIso(),
    };
    this.domBreakpoints.set(breakpointId, record);
    this.addTimeline("debugger", "dom_breakpoint_set", `DOM breakpoint set on ${selector} (${type})`, record);
    return record;
  }

  async removeDomBreakpoint(breakpointId: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    const record = this.domBreakpoints.get(breakpointId);
    if (!record) throw new Error(`DOM breakpoint not found: ${breakpointId}`);
    await client.DOMDebugger.removeDOMBreakpoint({ nodeId: record.nodeId, type: record.type });
    this.domBreakpoints.delete(breakpointId);
    return { removed: breakpointId };
  }

  async setEventBreakpoint(eventName: string, targetName?: string): Promise<EventBreakpointRecord> {
    const client = this.requireClient();
    await client.DOMDebugger.setEventListenerBreakpoint({ eventName, targetName });
    this.eventBreakpoints.add(eventName);
    this.addTimeline("debugger", "event_breakpoint_set", `Event breakpoint set on ${eventName}`);
    return { eventName, targetName, createdAt: nowIso() };
  }

  async removeEventBreakpoint(eventName: string, targetName?: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    await client.DOMDebugger.removeEventListenerBreakpoint({ eventName, targetName });
    this.eventBreakpoints.delete(eventName);
    return { removed: eventName };
  }

  async setXhrBreakpoint(url: string): Promise<XhrBreakpointRecord> {
    const client = this.requireClient();
    await client.DOMDebugger.setXHRBreakpoint({ url });
    this.xhrBreakpoints.add(url);
    this.addTimeline("debugger", "xhr_breakpoint_set", `XHR breakpoint set on URL pattern: ${url}`);
    return { url, createdAt: nowIso() };
  }

  async removeXhrBreakpoint(url: string): Promise<{ removed: string }> {
    const client = this.requireClient();
    await client.DOMDebugger.removeXHRBreakpoint({ url });
    this.xhrBreakpoints.delete(url);
    return { removed: url };
  }

  listAllBreakpoints(): Record<string, unknown> {
    return {
      javascript: this.listBreakpoints(),
      dom: [...this.domBreakpoints.values()],
      eventListeners: [...this.eventBreakpoints],
      xhr: [...this.xhrBreakpoints],
    };
  }

  async getCallFrameScope(callFrameId: string): Promise<Record<string, unknown>> {
    if (!this.pauseState) throw new Error("Debugger is not paused");
    const frame = (this.pauseState.callFrames as any[]).find((f) => f.callFrameId === callFrameId);
    if (!frame) throw new Error(`Call frame not found: ${callFrameId}`);

    const scopes: Array<Record<string, unknown>> = [];
    for (const scope of frame.scopeChain ?? []) {
      let variables: unknown[] = [];
      if (scope.object?.objectId) {
        try {
          variables = await this.getObjectProperties(scope.object.objectId);
        } catch (_) {}
      }
      scopes.push({
        type: scope.type,
        name: scope.name,
        variables,
      });
    }

    return {
      callFrameId,
      functionName: frame.functionName,
      url: frame.url,
      location: frame.location,
      scopes,
    };
  }

  async setVariableValue(input: {
    callFrameId: string;
    scopeNumber: number;
    variableName: string;
    value: unknown;
  }): Promise<{ updated: boolean }> {
    const client = this.requireClient();
    await client.Debugger.setVariableValue({
      callFrameId: input.callFrameId,
      scopeNumber: input.scopeNumber,
      variableName: input.variableName,
      newValue: { value: input.value },
    });
    return { updated: true };
  }

  async restartFrame(callFrameId: string): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const result = await client.Debugger.restartFrame({ callFrameId });
    return { callFrames: (result.callFrames ?? []).map(simplifyCallFrame) };
  }

  // ==========================================
  // NETWORK SEARCH, WEBSOCKET & TRAFFIC TAMPERING
  // ==========================================

  async searchNetwork(options: {
    query: string;
    isRegex?: boolean;
    caseSensitive?: boolean;
    limit?: number;
  }): Promise<Array<Record<string, unknown>>> {
    const limit = options.limit ?? 50;
    const isRegex = options.isRegex ?? false;
    const caseSensitive = options.caseSensitive ?? false;

    let matcher: (text: string) => boolean;
    if (isRegex) {
      const regex = new RegExp(options.query, caseSensitive ? "" : "i");
      matcher = (text: string) => regex.test(text);
    } else {
      const query = caseSensitive ? options.query : options.query.toLowerCase();
      matcher = (text: string) => {
        const target = caseSensitive ? text : text.toLowerCase();
        return target.includes(query);
      };
    }

    const matches: Array<Record<string, unknown>> = [];
    for (const record of this.networkRecords.values()) {
      if (matches.length >= limit) break;
      const matchedFields: string[] = [];

      if (matcher(record.url)) matchedFields.push("url");
      if (record.postData && matcher(record.postData)) matchedFields.push("postData");
      if (record.requestHeaders && matcher(JSON.stringify(record.requestHeaders))) matchedFields.push("requestHeaders");
      if (record.responseHeaders && matcher(JSON.stringify(record.responseHeaders))) matchedFields.push("responseHeaders");

      if (matchedFields.length > 0) {
        matches.push({
          requestId: record.requestId,
          method: record.method,
          url: record.url,
          status: record.status,
          type: record.type,
          matchedFields,
          snippet: record.postData ? record.postData.slice(0, 300) : undefined,
        });
      }
    }

    return matches;
  }

  getWebSocketMessages(options: {
    requestId?: string;
    urlContains?: string;
    direction?: "sent" | "received" | "both";
    query?: string;
    limit?: number;
  } = {}): WebSocketFrameRecord[] {
    const direction = options.direction ?? "both";
    const limit = options.limit ?? 100;

    return this.socketFrames
      .filter((frame) => {
        if (options.requestId && frame.requestId !== options.requestId) return false;
        if (direction !== "both" && frame.direction !== direction) return false;
        if (options.query && !frame.payloadData.toLowerCase().includes(options.query.toLowerCase())) return false;
        return true;
      })
      .slice(-limit);
  }

  async setRequestInterception(rule: {
    urlPattern: string;
    action: "block" | "mock" | "modify" | "inspect";
    resourceType?: string;
    mockStatus?: number;
    mockHeaders?: Record<string, string>;
    mockBody?: string;
    modifyHeaders?: Record<string, string>;
    modifyPostData?: string;
    newUrl?: string;
    newMethod?: string;
  }): Promise<InterceptRule> {
    const client = this.requireClient();
    if (!this.interceptionEnabled) {
      await client.Fetch.enable({ patterns: [{ urlPattern: "*" }] });
      this.interceptionEnabled = true;
    }

    const id = `rule-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    const record: InterceptRule = {
      id,
      urlPattern: rule.urlPattern,
      resourceType: rule.resourceType,
      action: rule.action,
      mockStatus: rule.mockStatus,
      mockHeaders: rule.mockHeaders,
      mockBody: rule.mockBody,
      modifyHeaders: rule.modifyHeaders,
      modifyPostData: rule.modifyPostData,
      newUrl: rule.newUrl,
      newMethod: rule.newMethod,
      hitCount: 0,
      createdAt: nowIso(),
    };

    this.interceptRules.set(id, record);
    this.addTimeline("interception", "rule_added", `Interception rule added for ${rule.urlPattern} (${rule.action})`, record);
    return record;
  }

  listInterceptions(): InterceptRule[] {
    return [...this.interceptRules.values()];
  }

  async clearInterceptions(): Promise<{ cleared: number }> {
    const count = this.interceptRules.size;
    if (this.client && this.interceptionEnabled) {
      try {
        await this.client.Fetch.disable();
      } catch (_) {}
      this.interceptionEnabled = false;
    }
    this.interceptRules.clear();
    return { cleared: count };
  }

  exportHar(): string {
    const entries = [...this.networkRecords.values()].map((record) => {
      const rawHeaders = this.rawRequestHeaders.get(record.requestId) ?? {};
      return {
        startedDateTime: record.startedAt,
        time: 50,
        request: {
          method: record.method,
          url: record.url,
          httpVersion: "HTTP/1.1",
          headers: Object.entries(rawHeaders).map(([name, value]) => ({ name, value })),
          queryString: [],
          cookies: [],
          headersSize: -1,
          bodySize: record.postData ? record.postData.length : 0,
          postData: record.postData
            ? {
                mimeType: String(rawHeaders["content-type"] || "application/octet-stream"),
                text: record.postData,
              }
            : undefined,
        },
        response: {
          status: record.status ?? 0,
          statusText: record.statusText ?? "",
          httpVersion: "HTTP/1.1",
          headers: Object.entries(record.responseHeaders ?? {}).map(([name, value]) => ({
            name,
            value: String(value),
          })),
          cookies: [],
          content: {
            size: record.encodedDataLength ?? 0,
            mimeType: record.mimeType ?? "text/plain",
          },
          redirectURL: "",
          headersSize: -1,
          bodySize: record.encodedDataLength ?? -1,
        },
        cache: {},
        timings: { send: 0, wait: 50, receive: 0 },
      };
    });

    const har = {
      log: {
        version: "1.2",
        creator: { name: "reverse-engineering-mcp", version: "0.2.0" },
        pages: [],
        entries,
      },
    };

    return JSON.stringify(har, null, 2);
  }

  // ==========================================
  // WEB REVERSE ENGINEERING & DEEP INSPECTION
  // ==========================================

  async antiDebugBypass(options: {
    disableDebugger?: boolean;
    disableConsoleClear?: boolean;
    disableTimingChecks?: boolean;
  } = {}): Promise<{ active: boolean; scriptId: string }> {
    const client = this.requireClient();
    const disableDebugger = options.disableDebugger ?? true;
    const disableConsoleClear = options.disableConsoleClear ?? true;
    const disableTimingChecks = options.disableTimingChecks ?? true;

    const script = `
(() => {
  if (window.__reverse_engineering_mcp_anti_debug_active) return;
  window.__reverse_engineering_mcp_anti_debug_active = true;

  ${disableDebugger ? `
  const OriginalFunction = window.Function;
  const FunctionProxy = function(...args) {
    if (args.length > 0) {
      const bodyIndex = args.length - 1;
      if (typeof args[bodyIndex] === "string" && args[bodyIndex].includes("debugger")) {
        args[bodyIndex] = args[bodyIndex].replace(/debugger\\s*;?/g, "/* debugger stripped */");
      }
    }
    return OriginalFunction.apply(this, args);
  };
  FunctionProxy.prototype = OriginalFunction.prototype;
  window.Function = FunctionProxy;

  const originalEval = window.eval;
  window.eval = function(code) {
    if (typeof code === "string" && code.includes("debugger")) {
      code = code.replace(/debugger\\s*;?/g, "/* debugger stripped */");
    }
    return originalEval.call(this, code);
  };

  const originalSetInterval = window.setInterval;
  window.setInterval = function(fn, delay, ...args) {
    if (typeof fn === "string" && fn.includes("debugger")) {
      return -1;
    }
    if (typeof fn === "function") {
      const fnStr = fn.toString();
      if (fnStr.includes("debugger") || (fnStr.includes("constructor") && fnStr.includes("call"))) {
        return -1;
      }
    }
    return originalSetInterval.call(this, fn, delay, ...args);
  };
  ` : ""}

  ${disableConsoleClear ? `
  if (window.console) {
    window.console.clear = function() { /* console.clear neutralized */ };
  }
  ` : ""}

  ${disableTimingChecks ? `
  try {
    Object.defineProperty(window, "outerWidth", { get: () => window.innerWidth });
    Object.defineProperty(window, "outerHeight", { get: () => window.innerHeight });
  } catch (_) {}
  ` : ""}
})();
    `;

    if (this.antiDebugBypassScriptId) {
      try {
        await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: this.antiDebugBypassScriptId });
      } catch (_) {}
    }

    const res = await client.Page.addScriptToEvaluateOnNewDocument({ source: script });
    this.antiDebugBypassScriptId = res.identifier;
    await client.Runtime.evaluate({ expression: script, awaitPromise: false, returnByValue: true });

    this.addTimeline("debugger", "anti_debug_bypass", "Anti-debugging bypass enabled on target");
    return { active: true, scriptId: res.identifier };
  }

  /**
   * Install a stealth patch profile on the attached target. Patches are registered
   * for all future documents in this target, and applied to the current document
   * immediately so the page does not need a reload.
   */
  async applyStealth(profile: StealthProfile, seed?: number): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const resolvedSeed = seed ?? (this.target?.id ? seedFromName(this.target.id) : 0);

    if (this.stealthScriptId) {
      try {
        await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: this.stealthScriptId });
      } catch (_) {
        // The document may already have been torn down; a stale registration is harmless.
      }
      this.stealthScriptId = null;
    }

    const script = buildStealthScript(profile, resolvedSeed);
    if (script.length === 0) {
      this.stealthProfile = "off";
      this.stealthSeed = resolvedSeed;
      return { profile: "off", patchIds: [], applied: false };
    }

    try {
      const registration = await client.Page.addScriptToEvaluateOnNewDocument({ source: script });
      this.stealthScriptId = registration.identifier;
      await client.Runtime.evaluate({ expression: script, returnByValue: true });
    } catch (error) {
      throw new ToolError(
        "ERR_STEALTH_PATCH_FAILED",
        error instanceof Error ? error.message : String(error),
        "Confirm a tab is attached with browser_attach, then retry stealth_enable.",
      );
    }

    this.stealthProfile = profile;
    this.stealthSeed = resolvedSeed;
    this.addTimeline("browser", "stealth", `stealth: ${profile}`, { profile, seed: resolvedSeed });

    return { profile, patchIds: activePatchIds(profile), seed: resolvedSeed, applied: true };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async applyStealthEnvelope(profile: StealthProfile, seed?: number): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.applyStealth(profile, seed) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /** Report the active stealth profile without performing any CDP I/O. */
  stealthStatus(): { profile: StealthProfile; patchIds: string[]; seed: number; scriptRegistered: boolean } {
    return {
      profile: this.stealthProfile,
      patchIds: activePatchIds(this.stealthProfile),
      seed: this.stealthSeed,
      scriptRegistered: this.stealthScriptId !== null,
    };
  }

  /**
   * Run a detection suite in the page and report what still leaks, per check.
   * Each check returns the observed value so patch rot is visible rather than silent.
   */
  async stealthProbe(maxChars = MAX_STORED_TEXT): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    void maxChars;
    const expression = `(() => {
      const checks = [];
      const push = (id, passed, observed) => checks.push({ id, passed, observed });
      try { push("webdriver", navigator.webdriver === undefined, String(navigator.webdriver)); }
      catch (e) { push("webdriver", false, "threw: " + e.message); }
      try { push("plugins", navigator.plugins && navigator.plugins.length > 0, String(navigator.plugins && navigator.plugins.length)); }
      catch (e) { push("plugins", false, "threw: " + e.message); }
      try {
        const canvas = document.createElement("canvas");
        canvas.width = 64; canvas.height = 32;
        const ctx = canvas.getContext("2d");
        const noise = ctx.getImageData(0, 0, 64, 32).data;
        push("canvas", noise.length === 64 * 32 * 4, "length=" + noise.length);
      } catch (e) { push("canvas", false, "threw: " + e.message); }
      try {
        const gl = document.createElement("canvas").getContext("webgl");
        push("webgl", Boolean(gl), gl ? String(gl.getParameter(37445)) : "no webgl context");
      } catch (e) { push("webgl", false, "threw: " + e.message); }
      const failed = checks.filter((c) => !c.passed).map((c) => c.id);
      return { profile: ${JSON.stringify(this.stealthProfile)}, checks, failed };
    })()`;
    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    const value = (result.result?.value ?? { profile: this.stealthProfile, checks: [], failed: [] }) as {
      profile: StealthProfile;
      checks: Array<{ id: string; passed: boolean; observed: string }>;
      failed: string[];
    };
    return {
      profile: value.profile,
      failed: value.failed,
      checks: value.checks.map((check) => ({
        id: check.id,
        passed: check.passed,
        observed: truncate(check.observed, 200) ?? "",
      })),
    };
  }

  /**
   * Read the accessibility tree, compress it, and assign short integer ids.
   * The id map is invalidated by navigation and by DOM.documentUpdated, which
   * the event handlers already observe.
   */
  async semanticView(options: {
    interactiveOnly?: boolean;
    maxNodes?: number;
    maxChars?: number;
  } = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();

    let nodes: unknown;
    try {
      await client.Accessibility.enable();
      const result = await client.Accessibility.getFullAXTree({});
      nodes = result?.nodes;
    } catch (error) {
      throw new ToolError(
        "ERR_AX_TREE_UNAVAILABLE",
        error instanceof Error ? error.message : String(error),
        "The accessibility tree is unavailable on about:blank, PDF viewers and crashed renderers. Navigate to a real page first.",
      );
    }

    if (!Array.isArray(nodes) || nodes.length === 0) {
      throw new ToolError(
        "ERR_AX_TREE_UNAVAILABLE",
        "The accessibility tree returned no nodes.",
        "Navigate to a real page and retry semantic_view.",
      );
    }

    this.semanticVersionCounter += 1;
    const snapshot = compressAxTree(nodes as never, {
      version: this.semanticVersionCounter,
      interactiveOnly: options.interactiveOnly ?? false,
      maxNodes: options.maxNodes ?? 300,
    });
    this.semanticSnapshot = snapshot;

    const maxChars = Math.min(Math.max(options.maxChars ?? MAX_STORED_TEXT, 1000), MAX_STORED_TEXT);
    const text = truncate(formatSemanticView(snapshot), maxChars) ?? "";

    this.addTimeline("browser", "semantic_view", `semantic_view v${snapshot.version}`, {
      version: snapshot.version,
      nodes: snapshot.nodes.length,
      truncated: snapshot.truncated,
    });

    return { version: snapshot.version, nodeCount: snapshot.nodes.length, truncated: snapshot.truncated, view: text };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async semanticViewEnvelope(options: {
    interactiveOnly?: boolean;
    maxNodes?: number;
    maxChars?: number;
  } = {}): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.semanticView(options) };
    } catch (error) {
      // AX-unavailable is always raised as a ToolError, so the only non-ToolError
      // reaching here is requireClient(), which means no session.
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /** Expose the most recent snapshot so callers can validate id versions. */
  currentSemanticSnapshot(): SemanticSnapshot | null {
    return this.semanticSnapshot;
  }

  /**
   * Act on a node by its short integer id. The id is validated against the
   * version that produced it so an id from a previous page can never be applied
   * to a node that happens to reuse the same backendDOMNodeId.
   */
  async interactSemantic(
    id: number,
    action: "click" | "type" | "hover" | "select" | "focus",
    value?: string,
    versionAtCall?: number,
  ): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const snapshot = this.semanticSnapshot;
    if (!snapshot) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        "No semantic snapshot exists for this page.",
        "Run semantic_view first and use the ids it returns.",
      );
    }
    if (versionAtCall !== undefined && versionAtCall !== snapshot.version) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} belongs to snapshot version ${versionAtCall}, current version is ${snapshot.version}.`,
        "Re-run semantic_view and use the ids from the new snapshot.",
      );
    }

    const backendNodeId = snapshot.idMap.get(id);
    if (backendNodeId === undefined) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} is not addressable in snapshot version ${snapshot.version}.`,
        "Re-run semantic_view; non-interactive nodes have no backendDOMNodeId.",
      );
    }

    const resolved = await client.DOM.resolveNode({ backendNodeId });
    const objectId = resolved?.object?.objectId;
    if (!objectId) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} could not be resolved; the element was likely detached.`,
        "Re-run semantic_view and retry with a fresh id.",
      );
    }

    const geometry = await client.Runtime.callFunctionOn({
      objectId,
      functionDeclaration: `function () {
        this.scrollIntoView({ block: "center", inline: "center" });
        const rect = this.getBoundingClientRect();
        return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2, tag: this.tagName.toLowerCase() };
      }`,
      returnByValue: true,
    });
    const point = geometry?.result?.value ?? { x: 0, y: 0, tag: "unknown" };

    if (action === "click") {
      await client.Input.dispatchMouseEvent({ type: "mouseMoved", x: point.x, y: point.y });
      await client.Input.dispatchMouseEvent({ type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1 });
      await client.Input.dispatchMouseEvent({ type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1 });
    } else if (action === "hover") {
      await client.Input.dispatchMouseEvent({ type: "mouseMoved", x: point.x, y: point.y });
    } else if (action === "focus") {
      await client.DOM.focus({ backendNodeId });
    } else if (action === "type") {
      await client.DOM.focus({ backendNodeId });
      await client.Input.insertText({ text: value ?? "" });
    } else if (action === "select") {
      await client.Runtime.callFunctionOn({
        objectId,
        functionDeclaration: `function (target) {
          this.value = target;
          this.dispatchEvent(new Event("input", { bubbles: true }));
          this.dispatchEvent(new Event("change", { bubbles: true }));
          return this.value;
        }`,
        arguments: [{ value: value ?? "" }],
        returnByValue: true,
      });
    }

    this.addTimeline("browser", "interact_semantic", `${action} on [${id}]`, { id, action, version: snapshot.version });
    return { id, action, version: snapshot.version, tag: point.tag, value };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async interactSemanticEnvelope(
    id: number,
    action: "click" | "type" | "hover" | "select" | "focus",
    value?: string,
    versionAtCall?: number,
  ): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.interactSemantic(id, action, value, versionAtCall) };
    } catch (error) {
      // Every stale-id case is raised as a ToolError with its own code, so the
      // only non-ToolError reaching here is requireClient(): no session.
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /**
   * Compare the current accessibility tree against the previous snapshot and
   * return only added, removed and changed nodes, so an agent loop does not
   * re-read the whole tree after every action.
   */
  async semanticDiff(maxChanges = 100): Promise<Record<string, unknown>> {
    const previous = this.semanticSnapshot;
    if (!previous) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        "No previous semantic snapshot to diff against.",
        "Run semantic_view twice, with an action in between, then call semantic_diff.",
      );
    }
    await this.semanticView({});
    const current = this.semanticSnapshot!;
    const diff = diffSnapshots(previous, current, maxChanges);
    return {
      fromVersion: previous.version,
      toVersion: current.version,
      added: diff.added,
      removed: diff.removed,
      changed: diff.changed,
    };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async semanticDiffEnvelope(maxChanges = 100): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.semanticDiff(maxChanges) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /**
   * Create an isolated browser context, optionally bound to a proxy. The proxy is
   * verified with a TCP probe before the context is created, so a bad proxy fails
   * at creation rather than mid-navigation.
   */
  async createIdentity(options: { name: string; proxy?: string; seed?: number }): Promise<IdentityRecord> {
    // Validate and probe the proxy before touching the session. A bad proxy must
    // fail as ERR_PROXY_UNREACHABLE whether or not a tab is attached, and no
    // identity is registered on failure.
    let proxyServer: string | undefined;
    if (options.proxy) {
      try {
        proxyServer = parseProxyServer(options.proxy);
      } catch (error) {
        throw new ToolError(
          "ERR_PROXY_UNREACHABLE",
          error instanceof Error ? error.message : String(error),
          "Pass a proxy as host:port.",
        );
      }
      try {
        await probeProxy(proxyServer);
      } catch (error) {
        throw new ToolError(
          "ERR_PROXY_UNREACHABLE",
          error instanceof Error ? error.message : String(error),
          "Confirm the proxy is running and reachable from this host.",
        );
      }
    }

    const client = this.requireClient();

    if (this.identities.has(options.name)) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `An identity named "${options.name}" already exists.`,
        "Choose another name or call identity_use to switch to it.",
      );
    }

    const created = await client.Target.createBrowserContext(
      proxyServer ? { proxyServer, proxyBypassList: ["127.0.0.1", "localhost"] } : {},
    );

    const record: IdentityRecord = {
      name: options.name,
      browserContextId: created?.browserContextId ?? null,
      proxy: proxyServer,
      seed: options.seed ?? seedFromName(options.name),
      createdAt: new Date().toISOString(),
      usable: true,
    };
    this.identities.set(options.name, record);
    this.addTimeline("browser", "identity_create", `identity: ${options.name}`, { proxy: proxyServer });
    return record;
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async createIdentityEnvelope(options: {
    name: string;
    proxy?: string;
    seed?: number;
  }): Promise<Envelope<IdentityRecord>> {
    try {
      return { success: true, data: await this.createIdentity(options) };
    } catch (error) {
      return toEnvelope(error, "ERR_PROXY_UNREACHABLE");
    }
  }

  /** Mark an identity active and apply its seed to the stealth layer. */
  async useIdentity(name: string): Promise<Record<string, unknown>> {
    const record = this.identities.get(name);
    if (!record) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `No identity named "${name}".`,
        "Call identity_list, then identity_create, then identity_use.",
      );
    }
    if (!record.usable) {
      throw new ToolError("ERR_NO_IDENTITY", `Identity "${name}" is quarantined.`, "Create a fresh identity.");
    }
    await this.applyStealth(this.stealthProfile === "off" ? "basic" : this.stealthProfile, record.seed);
    return { name: record.name, proxy: record.proxy, seed: record.seed, browserContextId: record.browserContextId };
  }

  listIdentities(): IdentityRecord[] {
    return [...this.identities.values()];
  }

  /** Serialize cookies and web storage for an identity into a portable document. */
  async exportIdentity(name: string): Promise<IdentityPayload> {
    const record = this.identities.get(name);
    if (!record) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `No identity named "${name}".`,
        "Use identity_list to see available identities.",
      );
    }
    const cookies = await this.getCookies();
    const storage = await this.getStorage("both");
    return serializeIdentity(record.name, record.proxy, cookies, storage.localStorage ?? {}, storage.sessionStorage ?? {});
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async exportIdentityEnvelope(name: string): Promise<Envelope<IdentityPayload>> {
    try {
      return { success: true, data: await this.exportIdentity(name) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_IDENTITY");
    }
  }

  /**
   * Restore an exported identity. The payload is validated in full before any
   * cookie or storage write happens, so a malformed payload applies nothing.
   */
  async importIdentity(json: string, name?: string): Promise<Record<string, unknown>> {
    const payload = parseIdentityPayload(json);
    const targetName = name ?? payload.name;

    await this.clearStorage("all");

    let cookiesApplied = 0;
    for (const cookie of payload.cookies) {
      try {
        await this.setCookie(cookie);
        cookiesApplied += 1;
      } catch (_) {
        // A cookie whose domain no longer resolves is skipped rather than aborting the restore.
      }
    }

    for (const [key, value] of Object.entries(payload.localStorage)) {
      await this.setStorage("local", key, value);
    }
    for (const [key, value] of Object.entries(payload.sessionStorage)) {
      await this.setStorage("session", key, value);
    }

    const existing = this.identities.get(targetName);
    const record: IdentityRecord = existing ?? {
      name: targetName,
      browserContextId: null,
      proxy: payload.proxy,
      seed: seedFromName(targetName),
      createdAt: new Date().toISOString(),
      usable: true,
    };
    this.identities.set(targetName, record);

    this.addTimeline("browser", "identity_import", `identity import: ${targetName}`, {
      cookies: cookiesApplied,
      localStorage: Object.keys(payload.localStorage).length,
      sessionStorage: Object.keys(payload.sessionStorage).length,
    });

    return { name: targetName, cookiesApplied, localStorageApplied: Object.keys(payload.localStorage).length };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async importIdentityEnvelope(json: string, name?: string): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.importIdentity(json, name) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_IDENTITY");
    }
  }

  async extractEndpoints(options: {
    scriptId?: string;
    includeNetworkHistory?: boolean;
    includeDom?: boolean;
  } = {}): Promise<Record<string, unknown>> {
    const includeNetwork = options.includeNetworkHistory ?? true;
    const includeDom = options.includeDom ?? true;

    const allEndpoints = new Set<string>();
    const allUrls = new Set<string>();
    const allWebsockets = new Set<string>();
    const allSecrets: Array<{ type: string; value: string; source: string }> = [];
    const allParams = new Set<string>();
    const hiddenInputs: Array<{ name?: string; value?: string; id?: string }> = [];

    const scriptsToScan = options.scriptId
      ? [this.scripts.get(options.scriptId)].filter(Boolean) as ScriptRecord[]
      : [...this.scripts.values()];

    for (const script of scriptsToScan.slice(0, 100)) {
      try {
        const src = await this.getScriptSource(script.scriptId, 300_000);
        if (src.source) {
          const insights = extractEndpointsAndSecrets(String(src.source));
          insights.endpoints.forEach((ep) => allEndpoints.add(ep));
          insights.urls.forEach((u) => allUrls.add(u));
          insights.websockets.forEach((w) => allWebsockets.add(w));
          insights.parameters.forEach((p) => allParams.add(p));
          insights.secrets.forEach((s) => allSecrets.push({ ...s, source: script.url || script.scriptId }));
        }
      } catch (_) {}
    }

    if (includeNetwork) {
      for (const record of this.networkRecords.values()) {
        allUrls.add(record.url);
        try {
          const parsed = new URL(record.url);
          allEndpoints.add(parsed.pathname);
          parsed.searchParams.forEach((_, key) => allParams.add(key));
        } catch (_) {}
        if (record.postData) {
          const insights = extractEndpointsAndSecrets(record.postData);
          insights.secrets.forEach((s) => allSecrets.push({ ...s, source: `request:${record.url}` }));
        }
      }
    }

    if (includeDom && this.client) {
      try {
        const domResult = await this.client.Runtime.evaluate({
          expression: `(() => {
            const links = Array.from(document.querySelectorAll("a[href], link[href]")).map(el => el.getAttribute("href")).filter(Boolean);
            const forms = Array.from(document.querySelectorAll("form")).map(el => ({ action: el.getAttribute("action"), method: el.method }));
            const hidden = Array.from(document.querySelectorAll("input[type=hidden]")).map(el => ({ name: el.name, id: el.id, value: el.value }));
            const scripts = Array.from(document.querySelectorAll("script[src]")).map(el => el.getAttribute("src")).filter(Boolean);
            return { links, forms, hidden, scripts };
          })()`,
          returnByValue: true,
        });
        const domData = domResult.result?.value;
        if (domData) {
          (domData.links || []).forEach((link: string) => {
            if (link.startsWith("http")) allUrls.add(link);
            else if (link.startsWith("/")) allEndpoints.add(link);
          });
          (domData.scripts || []).forEach((src: string) => {
            if (src.startsWith("http")) allUrls.add(src);
            else if (src.startsWith("/")) allEndpoints.add(src);
          });
          (domData.forms || []).forEach((form: any) => {
            if (form.action?.startsWith("/")) allEndpoints.add(form.action);
            else if (form.action?.startsWith("http")) allUrls.add(form.action);
          });
          (domData.hidden || []).forEach((h: any) => hiddenInputs.push(h));
        }
      } catch (_) {}
    }

    return {
      summary: {
        totalEndpoints: allEndpoints.size,
        totalUrls: allUrls.size,
        totalWebsockets: allWebsockets.size,
        totalSecrets: allSecrets.length,
        totalParameters: allParams.size,
        totalHiddenInputs: hiddenInputs.length,
      },
      apiEndpoints: [...allEndpoints].sort(),
      externalUrls: [...allUrls].sort().slice(0, 300),
      websockets: [...allWebsockets].sort(),
      potentialSecrets: allSecrets.slice(0, 50),
      parameters: [...allParams].sort(),
      hiddenInputs,
    };
  }

  async extractSourceMap(options: { scriptId?: string; urlContains?: string } = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const candidates: ScriptRecord[] = [];
    for (const script of this.scripts.values()) {
      if (options.scriptId && script.scriptId !== options.scriptId) continue;
      if (options.urlContains && !script.url.includes(options.urlContains)) continue;
      if (script.sourceMapURL) candidates.push(script);
    }

    if (candidates.length === 0) {
      return {
        found: 0,
        message: "No scripts found with sourceMapURL matching criteria.",
        scriptsWithSourceMapCount: [...this.scripts.values()].filter((s) => Boolean(s.sourceMapURL)).length,
      };
    }

    const results: Array<Record<string, unknown>> = [];
    for (const candidate of candidates.slice(0, 5)) {
      let rawMap: string | undefined;
      const sourceMapURL = candidate.sourceMapURL!;

      if (sourceMapURL.startsWith("data:application/json;base64,")) {
        rawMap = Buffer.from(sourceMapURL.slice(29), "base64").toString("utf8");
      } else if (sourceMapURL.startsWith("data:application/json;charset=utf-8;base64,")) {
        rawMap = Buffer.from(sourceMapURL.slice(44), "base64").toString("utf8");
      } else {
        try {
          const resolvedUrl = new URL(sourceMapURL, candidate.url).href;
          const evalFetch = await client.Runtime.evaluate({
            expression: `fetch(${JSON.stringify(resolvedUrl)}).then(r => r.text())`,
            awaitPromise: true,
            returnByValue: true,
          });
          rawMap = evalFetch.result?.value;
        } catch (_) {}
      }

      if (rawMap) {
        try {
          const parsed = parseSourceMap(rawMap);
          results.push({
            scriptId: candidate.scriptId,
            scriptUrl: candidate.url,
            sourceMapURL,
            version: parsed.version,
            file: parsed.file,
            sourceFilesCount: parsed.sources.length,
            sourceFiles: parsed.sources.map((s) => s.path),
            sourcesWithContentCount: parsed.sources.filter((s) => Boolean(s.content)).length,
            sampleSource: parsed.sources.find((s) => Boolean(s.content))
              ? {
                  path: parsed.sources.find((s) => Boolean(s.content))!.path,
                  contentPreview: parsed.sources.find((s) => Boolean(s.content))!.content!.slice(0, 2000),
                }
              : undefined,
          });
        } catch (err) {
          results.push({
            scriptId: candidate.scriptId,
            scriptUrl: candidate.url,
            sourceMapURL,
            parseError: String(err),
          });
        }
      } else {
        results.push({
          scriptId: candidate.scriptId,
          scriptUrl: candidate.url,
          sourceMapURL,
          fetchError: "Could not fetch source map content",
        });
      }
    }

    return {
      found: results.length,
      results,
    };
  }

  async beautifyScript(scriptId: string, maxChars = 50_000, offset = 0): Promise<Record<string, unknown>> {
    const script = await this.getScriptSource(scriptId, 200_000);
    const rawSource = String(script.source ?? "");
    const formatted = beautifyJs(rawSource);
    const lines = formatted.split("\n");
    const slicedLines = lines.slice(offset, offset + 500);
    const numberedSnippet = slicedLines
      .map((line, index) => `${String(offset + index + 1).padStart(5, " ")}: ${line}`)
      .join("\n")
      .slice(0, maxChars);

    return {
      scriptId,
      totalLines: lines.length,
      offset,
      returnedLines: slicedLines.length,
      formattedSource: numberedSnippet,
    };
  }

  async inspectElement(selector: string): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const expression = `(() => {
      const el = document.querySelector(${JSON.stringify(selector)});
      if (!el) return null;
      const attrs = {};
      for (const attr of el.attributes) {
        attrs[attr.name] = attr.value;
      }
      const computed = window.getComputedStyle(el);
      const box = el.getBoundingClientRect();
      return {
        tagName: el.tagName.toLowerCase(),
        id: el.id,
        className: el.className,
        attributes: attrs,
        box: { x: box.left, y: box.top, width: box.width, height: box.height },
        visible: box.width > 0 && box.height > 0 && computed.visibility !== "hidden" && computed.display !== "none",
        childElementCount: el.childElementCount,
        innerText: el.innerText ? el.innerText.slice(0, 1000) : "",
        outerHtmlSnippet: el.outerHTML ? el.outerHTML.slice(0, 2000) : ""
      };
    })()`;

    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    const elementData = result.result?.value;
    if (!elementData) {
      throw new Error(`Element not found for selector: ${selector}`);
    }

    let listeners: unknown[] = [];
    try {
      const objResult = await client.Runtime.evaluate({
        expression: `document.querySelector(${JSON.stringify(selector)})`,
        returnByValue: false,
      });
      if (objResult.result?.objectId) {
        const listenersResult = await client.DOMDebugger.getEventListeners({
          objectId: objResult.result.objectId,
          depth: 1,
        });
        listeners = (listenersResult.listeners ?? []).map((l: any) => ({
          type: l.type,
          useCapture: l.useCapture,
          passive: l.passive,
          once: l.once,
          scriptId: l.scriptId,
          lineNumber: l.lineNumber,
          columnNumber: l.columnNumber,
          handlerDescription: l.handler?.description,
        }));
      }
    } catch (_) {}

    return {
      ...elementData,
      eventListeners: listeners,
    };
  }

  async overrideFunction(
    target: string,
    behavior: "log" | "mock" | "passthrough",
    mockReturnValue?: unknown,
  ): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const targetJson = JSON.stringify(target);
    const behaviorJson = JSON.stringify(behavior);
    const mockReturnJson = JSON.stringify(mockReturnValue);

    const expression = `
(() => {
  const path = ${targetJson}.split(".");
  let current = window;
  for (let i = 0; i < path.length - 1; i++) {
    current = current[path[i]];
    if (!current) throw new Error("Path segment not found: " + path[i]);
  }
  const funcName = path[path.length - 1];
  const original = current[funcName];
  if (typeof original !== "function") throw new Error("Target is not a function: " + ${targetJson});

  const behavior = ${behaviorJson};
  const mockValue = ${mockReturnJson};

  current[funcName] = function(...args) {
    const stack = new Error().stack;
    const callData = {
      target: ${targetJson},
      arguments: args.map(a => {
        try { return JSON.parse(JSON.stringify(a)); } catch (_) { return String(a); }
      }),
      stack
    };

    if (typeof window.${BINDING_NAME} === "function") {
      try {
        window.${BINDING_NAME}(JSON.stringify({
          hookId: "override",
          kind: "override",
          type: "function:call",
          ...callData
        }));
      } catch (_) {}
    }

    if (behavior === "mock") return mockValue;
    const result = original.apply(this, args);

    if (typeof window.${BINDING_NAME} === "function") {
      try {
        window.${BINDING_NAME}(JSON.stringify({
          hookId: "override",
          kind: "override",
          type: "function:return",
          target: ${targetJson},
          result: (function() {
            try { return JSON.parse(JSON.stringify(result)); } catch (_) { return String(result); }
          })()
        }));
      } catch (_) {}
    }
    return result;
  };

  return { target: ${targetJson}, behavior, installed: true };
})()
    `;

    const result = await client.Runtime.evaluate({ expression, awaitPromise: true, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || "Failed to override function");
    }
    return result.result?.value ?? { installed: true };
  }

  searchConsole(query: string, level?: string, isRegex = false): ConsoleRecord[] {
    let matcher: (text: string) => boolean;
    if (isRegex) {
      const regex = new RegExp(query, "i");
      matcher = (text: string) => regex.test(text);
    } else {
      const q = query.toLowerCase();
      matcher = (text: string) => text.toLowerCase().includes(q);
    }

    return this.consoleEvents.filter((record) => {
      if (level && record.type !== level && !record.type.startsWith(level)) return false;
      const text = record.args.map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a ?? ""))).join(" ");
      return matcher(text);
    });
  }

  async detectCrypto(options: {
    scriptId?: string;
    urlContains?: string;
    scanGlobalMemory?: boolean;
  } = {}): Promise<Record<string, unknown>> {
    const scanGlobal = options.scanGlobalMemory ?? true;
    const matchesByScript: Array<{
      scriptId: string;
      url: string;
      matches: CryptoMatch[];
    }> = [];

    const scriptsToScan = options.scriptId
      ? [this.scripts.get(options.scriptId)].filter(Boolean) as ScriptRecord[]
      : this.listScripts(options.urlContains, 100);

    let totalMatches = 0;
    for (const script of scriptsToScan) {
      try {
        const src = await this.getScriptSource(script.scriptId, 300_000);
        if (src.source) {
          const found = identifyCrypto(String(src.source));
          if (found.length > 0) {
            totalMatches += found.length;
            matchesByScript.push({
              scriptId: script.scriptId,
              url: script.url,
              matches: found,
            });
          }
        }
      } catch (_) {}
    }

    let globalMemoryFindings: Record<string, unknown> | undefined;
    if (scanGlobal && this.client) {
      try {
        const evalRes = await this.client.Runtime.evaluate({
          expression: `(() => {
            const findings = {};
            findings.hasCryptoJS = typeof window.CryptoJS !== "undefined";
            findings.hasJSEncrypt = typeof window.JSEncrypt !== "undefined";
            findings.hasForge = typeof window.forge !== "undefined";
            findings.hasSmCrypto = typeof window.smCrypto !== "undefined" || typeof window.sm2 !== "undefined" || typeof window.sm3 !== "undefined" || typeof window.sm4 !== "undefined";
            findings.hasWebCrypto = typeof window.crypto?.subtle !== "undefined";
            findings.hasWebAssembly = typeof window.WebAssembly !== "undefined";
            
            const suspectedGlobals = [];
            const keys = Object.getOwnPropertyNames(window);
            const suspiciousPatterns = [/aes/i, /des/i, /rsa/i, /md5/i, /sha/i, /sm[234]/i, /encrypt/i, /decrypt/i, /sign/i, /token/i, /auth/i, /hash/i];
            for (const key of keys.slice(0, 500)) {
              if (suspiciousPatterns.some(p => p.test(key))) {
                const val = window[key];
                suspectedGlobals.push({
                  name: key,
                  type: typeof val,
                  preview: typeof val === "function" ? val.toString().slice(0, 100) : (typeof val === "object" && val !== null ? Object.keys(val).slice(0, 10) : String(val).slice(0, 50))
                });
              }
            }
            findings.suspectedGlobals = suspectedGlobals;
            return findings;
          })()`,
          returnByValue: true,
        });
        globalMemoryFindings = evalRes.result?.value;
      } catch (_) {}
    }

    return {
      summary: {
        totalScriptsScanned: scriptsToScan.length,
        scriptsWithCrypto: matchesByScript.length,
        totalIndicatorsFound: totalMatches,
      },
      matchesByScript,
      globalMemoryFindings,
    };
  }

  async findCryptoCandidates(options: {
    scriptId?: string;
    targetParams?: string[];
  } = {}): Promise<Record<string, unknown>> {
    const targetParams = options.targetParams && options.targetParams.length > 0
      ? options.targetParams
      : ["password", "pwd", "sign", "token", "signature", "key", "encrypt", "hash", "timestamp", "nonce", "auth"];

    const candidatesByScript: Array<{
      scriptId: string;
      url: string;
      candidates: CryptoCandidate[];
    }> = [];

    const scriptsToScan = options.scriptId
      ? [this.scripts.get(options.scriptId)].filter(Boolean) as ScriptRecord[]
      : [...this.scripts.values()].filter(s => s.url && !s.url.includes("chrome-extension://")).slice(0, 30);

    let totalCandidates = 0;
    for (const script of scriptsToScan) {
      try {
        const src = await this.getScriptSource(script.scriptId, 300_000);
        if (src.source) {
          const candidates = findCryptoCandidates(String(src.source), targetParams);
          if (candidates.length > 0) {
            totalCandidates += candidates.length;
            candidatesByScript.push({
              scriptId: script.scriptId,
              url: script.url,
              candidates,
            });
          }
        }
      } catch (_) {}
    }

    return {
      summary: {
        totalScriptsScanned: scriptsToScan.length,
        scriptsWithCandidates: candidatesByScript.length,
        totalCandidates,
        targetParameters: targetParams,
      },
      candidatesByScript,
    };
  }

  async classifyAnticrawl(options: { scriptId?: string } = {}): Promise<Record<string, unknown>> {
    const networkUrls = [...this.networkRecords.values()].map((r) => r.url);
    const staticMatches: AnticrawlMatch[] = [];

    const scriptsToScan = options.scriptId
      ? [this.scripts.get(options.scriptId)].filter(Boolean) as ScriptRecord[]
      : [...this.scripts.values()].slice(0, 50);

    for (const script of scriptsToScan) {
      try {
        const src = await this.getScriptSource(script.scriptId, 200_000);
        if (src.source) {
          const matches = classifyAnticrawl(String(src.source), networkUrls);
          for (const m of matches) {
            if (!staticMatches.some(existing => existing.vendor === m.vendor && existing.type === m.type)) {
              staticMatches.push(m);
            }
          }
        }
      } catch (_) {}
    }

    let runtimeChecks: Record<string, unknown> = {};
    if (this.client) {
      try {
        const evalRes = await this.client.Runtime.evaluate({
          expression: `(() => {
            const checks = {};
            checks.webdriver = Boolean(navigator.webdriver);
            checks.phantom = Boolean(window._phantom || window.callPhantom);
            checks.nightmare = Boolean(window.__nightmare);
            checks.selenium = Boolean(window.document.__selenium_unwrapped || window.document.__webdriver_evaluate || window.document.__driver_evaluate);
            checks.turnstile = Boolean(window.turnstile);
            checks.recaptcha = Boolean(window.grecaptcha);
            checks.geetest = Boolean(window.initGeetest || window.Geetest);
            checks.dingxiang = Boolean(window._dx || window.DX);
            checks.aliCaptcha = Boolean(window.AWSC || window.baxiaCommon);
            checks.tencentCaptcha = Boolean(window.TencentCaptcha);
            checks.fingerprintJs = Boolean(window.Fingerprint2 || window.fpjs);
            checks.cloudflareChallenge = Boolean(window._cf_chl_opt || document.querySelector("#challenge-running, #cf-please-wait"));
            checks.debuggerProtection = false;
            
            try {
              checks.btoaIsNative = Function.prototype.toString.call(window.btoa).includes("[native code]");
            } catch (e) {
              checks.btoaIsNative = false;
            }
            return checks;
          })()`,
          returnByValue: true,
        });
        runtimeChecks = evalRes.result?.value ?? {};
      } catch (_) {}
    }

    const combinedMatches: AnticrawlMatch[] = [...staticMatches];
    if (runtimeChecks.turnstile) {
      combinedMatches.push({ vendor: "Cloudflare Turnstile", type: "captcha", confidence: "high", evidence: "window.turnstile present in runtime" });
    }
    if (runtimeChecks.recaptcha) {
      combinedMatches.push({ vendor: "Google reCAPTCHA", type: "captcha", confidence: "high", evidence: "window.grecaptcha present in runtime" });
    }
    if (runtimeChecks.geetest) {
      combinedMatches.push({ vendor: "GeeTest", type: "captcha", confidence: "high", evidence: "window.initGeetest present in runtime" });
    }
    if (runtimeChecks.dingxiang) {
      combinedMatches.push({ vendor: "DingXiang (顶象)", type: "captcha", confidence: "high", evidence: "window._dx present in runtime" });
    }
    if (runtimeChecks.aliCaptcha) {
      combinedMatches.push({ vendor: "Alibaba / Baxia", type: "bot_defense", confidence: "high", evidence: "window.AWSC / baxia present in runtime" });
    }
    if (runtimeChecks.tencentCaptcha) {
      combinedMatches.push({ vendor: "Tencent Waterproof Wall", type: "captcha", confidence: "high", evidence: "window.TencentCaptcha present in runtime" });
    }
    if (runtimeChecks.cloudflareChallenge) {
      combinedMatches.push({ vendor: "Cloudflare Challenge", type: "bot_defense", confidence: "high", evidence: "Cloudflare Challenge DOM / _cf_chl_opt active" });
    }

    return {
      totalVendorsDetected: combinedMatches.length,
      detections: combinedMatches,
      runtimeEnvironment: runtimeChecks,
      suggestedBypass: combinedMatches.map(m => {
        if (m.type === "anti_debug") return "Use anti_debug_bypass tool to neutralize Function/eval/debugger traps.";
        if (m.type === "captcha") return "Solve captcha through browser interaction or use JSRPC to forward signed tokens.";
        if (m.type === "jsvmp") return "Locate opcode dispatcher loop or hook entry/exit functions using override_function or set_breakpoint.";
        return "Inspect network cookies and headers using get_cookies and get_network_request.";
      }),
    };
  }

  async unpackWebpack(options: {
    exportModuleId?: string | number;
    maxModules?: number;
  } = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const maxModules = options.maxModules ?? 200;
    const targetModuleId = options.exportModuleId !== undefined ? JSON.stringify(options.exportModuleId) : "null";

    const expression = `
(() => {
  const result = {
    webpackGlobals: [],
    hasRequireHook: false,
    totalModulesCount: 0,
    modules: [],
    exportedModule: null,
  };

  for (const key of Object.getOwnPropertyNames(window)) {
    if ((key.startsWith("webpackChunk") || key === "webpackJsonp") && Array.isArray(window[key])) {
      result.webpackGlobals.push(key);
    }
  }

  if (!window.__mcp_webpack_require__) {
    for (const key of result.webpackGlobals) {
      try {
        const arr = window[key];
        const probeChunkId = "__mcp_rev_probe_" + Math.floor(Math.random() * 100000);
        arr.push([
          [probeChunkId],
          {},
          (r) => {
            window.__mcp_webpack_require__ = r;
          }
        ]);
        if (window.__mcp_webpack_require__) break;
      } catch (_) {}
    }
  }

  const req = window.__mcp_webpack_require__;
  if (req) {
    result.hasRequireHook = true;
    const modulesObj = req.m;
    if (modulesObj) {
      const keys = Array.isArray(modulesObj) ? modulesObj.map((_, idx) => idx) : Object.keys(modulesObj);
      result.totalModulesCount = keys.length;
      
      const sampledKeys = keys.slice(0, ${maxModules});
      result.modules = sampledKeys.map((id) => {
        const fn = modulesObj[id];
        return {
          id,
          type: typeof fn,
          preview: typeof fn === "function" ? fn.toString().slice(0, 150) : typeof fn,
        };
      });
    }

    const targetId = ${targetModuleId};
    if (targetId !== null) {
      try {
        const exported = req(targetId);
        result.exportedModule = {
          id: targetId,
          type: typeof exported,
          exportsKeys: exported && typeof exported === "object" ? Object.keys(exported).slice(0, 100) : [],
          stringPreview: String(exported).slice(0, 500),
        };
      } catch (err) {
        result.exportedModule = {
          id: targetId,
          error: "Failed to require module: " + String(err),
        };
      }
    }
  }

  return result;
})()
    `;

    const evalRes = await client.Runtime.evaluate({
      expression,
      returnByValue: true,
      awaitPromise: true,
    });

    if (evalRes.exceptionDetails) {
      throw new Error(evalRes.exceptionDetails.exception?.description || evalRes.exceptionDetails.text || "Failed to inspect webpack runtime");
    }

    return evalRes.result?.value ?? {};
  }

  generateJsrpc(options: {
    actionName: string;
    targetExpression: string;
    port?: number;
  }): Record<string, unknown> {
    const files = generateJsrpcFiles({
      actionName: options.actionName,
      targetExpression: options.targetExpression,
      port: options.port,
    });

    return {
      actionName: options.actionName,
      targetExpression: options.targetExpression,
      port: options.port ?? 12080,
      files,
      quickUsage: [
        "1. Inject inPageStub into the target webpage via browser_evaluate.",
        "2. Save flaskProxy into a .py script and run `python proxy.py`.",
        "3. Configure Burp Suite AutoDecoder or script to send HTTP requests to http://127.0.0.1:" + (options.port ?? 12080) + "/go?action=" + options.actionName,
      ],
    };
  }

  private resetState(): void {
    this.consoleEvents = [];
    this.scripts.clear();
    this.networkRecords.clear();
    this.rawRequestHeaders.clear();
    this.networkOrder = [];
    this.socketFrames = [];
    this.hookEvents = [];
    this.timeline = [];
    this.timelineEnabled = true;
    this.pauseState = null;
    this.breakpoints.clear();
    this.domBreakpoints.clear();
    this.eventBreakpoints.clear();
    this.xhrBreakpoints.clear();
    this.interceptRules.clear();
    this.interceptionEnabled = false;
    this.antiDebugBypassScriptId = null;
    this.hooks.clear();
    this.taintTrackers.clear();
  }

  private requireClient(): any {
    if (!this.client) throw new Error("Not connected to a Chrome target. Call browser_attach first.");
    return this.client;
  }

  private async findSourceMatches(pattern: string, regex: boolean, urlContains: string | undefined, maxMatches: number): Promise<Array<{ script: ScriptRecord; text: ReturnType<typeof findTextMatches>[number] }>> {
    const matches: Array<{ script: ScriptRecord; text: ReturnType<typeof findTextMatches>[number] }> = [];
    for (const script of this.listScripts(urlContains, 200)) {
      if (matches.length >= maxMatches) break;
      try {
        const sourceResult = await this.getScriptSource(script.scriptId, 200_000);
        const sourceMatches = findTextMatches(String(sourceResult.source ?? ""), pattern, regex, maxMatches - matches.length);
        for (const text of sourceMatches) matches.push({ script, text });
      } catch (_) {
        // A script can disappear while navigation is replacing the document.
      }
    }
    return matches;
  }

  private async formatEvaluationResult(result: any, expand: boolean): Promise<Record<string, unknown>> {
    const formatted: Record<string, unknown> = {
      result: remoteObjectToValue(result.result),
    };
    if (result.exceptionDetails) {
      formatted.exception = {
        text: result.exceptionDetails.text,
        description: result.exceptionDetails.exception?.description,
        lineNumber: result.exceptionDetails.lineNumber,
        columnNumber: result.exceptionDetails.columnNumber,
        stackTrace: result.exceptionDetails.stackTrace,
      };
    }
    if (expand && result.result?.objectId) {
      const properties = await this.getObjectProperties(result.result.objectId);
      formatted.properties = properties;
    }
    return formatted;
  }

  private async getObjectProperties(objectId: string): Promise<unknown[]> {
    const client = this.requireClient();
    const result = await client.Runtime.getProperties({ objectId, ownProperties: true, generatePreview: true });
    return (result.result ?? []).slice(0, 100).map((property: any) => ({
      name: property.name,
      enumerable: property.enumerable,
      writable: property.writable,
      value: remoteObjectToValue(property.value),
      get: remoteObjectToValue(property.get),
      set: remoteObjectToValue(property.set),
    }));
  }

  private installEventHandlers(client: any): void {
    client.on("disconnect", () => {
      this.client = null;
      this.pauseState = null;
    });

    client.DOM.on("documentUpdated", () => {
      // The document was replaced, so every node id from the previous snapshot is stale.
      this.semanticSnapshot = null;
    });

    client.Runtime.on("consoleAPICalled", (params: any) => {
      const event: ConsoleRecord = {
        id: ++this.consoleEventSequence,
        timestamp: timestampToIso(params.timestamp),
        type: params.type,
        args: (params.args ?? []).map(remoteObjectToValue),
        executionContextId: params.executionContextId,
        stack: params.stackTrace,
      };
      this.pushLimited(this.consoleEvents, event, MAX_CONSOLE_EVENTS);
      this.addTimeline("console", params.type, `${params.type}: ${event.args.map((value) => String(value ?? "")).join(" ").slice(0, 300)}`, event);
    });

    client.Runtime.on("exceptionThrown", (params: any) => {
      const event: ConsoleRecord = {
        id: ++this.consoleEventSequence,
        timestamp: timestampToIso(params.timestamp),
        type: "exception",
        args: [remoteObjectToValue(params.exceptionDetails?.exception), params.exceptionDetails?.text],
        stack: params.exceptionDetails?.stackTrace,
      };
      this.pushLimited(this.consoleEvents, event, MAX_CONSOLE_EVENTS);
      this.addTimeline("console", "exception", `exception: ${String(params.exceptionDetails?.text ?? "").slice(0, 300)}`, event);
    });

    client.Log.on("entryAdded", (params: any) => {
      const event: ConsoleRecord = {
        id: ++this.consoleEventSequence,
        timestamp: timestampToIso(params.entry?.timestamp),
        type: `log:${params.entry?.level ?? "info"}`,
        args: [params.entry?.text, params.entry?.url, params.entry?.source],
      };
      this.pushLimited(this.consoleEvents, event, MAX_CONSOLE_EVENTS);
      this.addTimeline("console", event.type, `log: ${String(params.entry?.text ?? "").slice(0, 300)}`, event);
    });

    client.Runtime.on("bindingCalled", (params: any) => {
      if (params.name !== BINDING_NAME) return;
      try {
        const event = JSON.parse(params.payload) as Record<string, unknown>;
        const hookEvent: HookEventRecord = {
          id: ++this.hookEventSequence,
          hookId: String(event.hookId ?? "unknown"),
          timestamp: nowIso(),
          type: String(event.type ?? "hook:event"),
          ...event,
        };
        this.pushLimited(this.hookEvents, hookEvent, MAX_HOOK_EVENTS);
        this.addTimeline("hook", hookEvent.type, `${hookEvent.hookId}: ${hookEvent.type}`, hookEvent);
      } catch (error) {
        this.lastError = `Invalid hook event: ${String(error)}`;
      }
    });

    client.Debugger.on("scriptParsed", (params: any) => {
      this.scripts.set(String(params.scriptId), {
        scriptId: String(params.scriptId),
        url: params.url ?? "",
        startLine: params.startLine ?? 0,
        startColumn: params.startColumn ?? 0,
        endLine: params.endLine ?? 0,
        endColumn: params.endColumn ?? 0,
        executionContextId: params.executionContextId,
        hash: params.hash,
        isModule: params.isModule,
        sourceMapURL: params.sourceMapURL,
        length: params.length,
      });
    });

    client.Debugger.on("paused", (params: any) => {
      this.pauseState = {
        reason: params.reason,
        hitBreakpoints: params.hitBreakpoints ?? [],
        callFrames: (params.callFrames ?? []).map(simplifyCallFrame),
        asyncStackTrace: params.asyncStackTrace,
        timestamp: nowIso(),
      };
      this.addTimeline("debugger", "paused", `paused: ${params.reason ?? "unknown"}`, this.pauseState);
    });

    client.Debugger.on("resumed", () => {
      this.pauseState = null;
      this.addTimeline("debugger", "resumed", "debugger resumed");
    });

    client.Network.on("requestWillBeSent", (params: any) => {
      const request = params.request ?? {};
      const record: NetworkRecord = {
        requestId: String(params.requestId),
        loaderId: params.loaderId,
        documentURL: params.documentURL,
        type: params.type,
        url: request.url ?? "",
        method: request.method ?? "GET",
        requestHeaders: redactHeaders(request.headers),
        postData: truncate(request.postData, 12_000),
        startedAt: timestampToIso(params.timestamp),
        initiator: params.initiator,
      };
      this.networkRecords.set(record.requestId, record);
      this.rawRequestHeaders.set(record.requestId, Object.fromEntries(Object.entries(request.headers ?? {}).map(([key, value]) => [key, String(value)])));
      this.networkOrder.push(record.requestId);
      this.trimNetworkRecords();
      this.addTimeline("network", "request", `${record.method} ${record.url}`.slice(0, 500), record);
    });

    client.Network.on("responseReceived", (params: any) => {
      const record = this.networkRecords.get(String(params.requestId));
      if (!record) return;
      const response = params.response ?? {};
      record.status = response.status;
      record.statusText = response.statusText;
      record.mimeType = response.mimeType;
      record.responseHeaders = redactHeaders(response.headers);
      record.fromCache = response.fromDiskCache || response.fromPrefetchCache || response.fromServiceWorker;
      this.addTimeline("network", "response", `${record.status ?? "?"} ${record.url}`.slice(0, 500), { requestId: record.requestId, status: record.status, mimeType: record.mimeType, url: record.url });
    });

    client.Network.on("loadingFinished", (params: any) => {
      const record = this.networkRecords.get(String(params.requestId));
      if (!record) return;
      record.encodedDataLength = params.encodedDataLength;
      record.finishedAt = nowIso();
    });

    client.Network.on("loadingFailed", (params: any) => {
      const record = this.networkRecords.get(String(params.requestId));
      if (!record) return;
      record.errorText = params.errorText;
      record.finishedAt = nowIso();
      this.addTimeline("network", "failed", `${record.url}: ${record.errorText}`.slice(0, 500), record);
    });

    client.Network.on("webSocketFrameSent", (params: any) => {
      const frame: WebSocketFrameRecord = {
        requestId: String(params.requestId),
        direction: "sent",
        timestamp: timestampToIso(params.timestamp),
        opcode: params.response?.opcode,
        mask: params.response?.mask,
        payloadData: truncate(params.response?.payloadData, 20_000) ?? "",
      };
      this.pushLimited(this.socketFrames, frame, MAX_SOCKET_EVENTS);
      this.addTimeline("websocket", "sent", `ws → ${frame.payloadData.slice(0, 300)}`, frame);
    });

    client.Network.on("webSocketFrameReceived", (params: any) => {
      const frame: WebSocketFrameRecord = {
        requestId: String(params.requestId),
        direction: "received",
        timestamp: timestampToIso(params.timestamp),
        opcode: params.response?.opcode,
        mask: params.response?.mask,
        payloadData: truncate(params.response?.payloadData, 20_000) ?? "",
      };
      this.pushLimited(this.socketFrames, frame, MAX_SOCKET_EVENTS);
      this.addTimeline("websocket", "received", `ws ← ${frame.payloadData.slice(0, 300)}`, frame);
    });

    client.Fetch.on("requestPaused", async (params: any) => {
      const { requestId, request } = params;
      const url = request?.url || "";

      let matchedRule: InterceptRule | undefined;
      for (const rule of this.interceptRules.values()) {
        if (this.matchWildcard(rule.urlPattern, url)) {
          matchedRule = rule;
          break;
        }
      }

      if (!matchedRule) {
        try {
          await client.Fetch.continueRequest({ requestId });
        } catch (_) {}
        return;
      }

      matchedRule.hitCount++;
      this.addTimeline("interception", matchedRule.action, `Intercepted ${request.method} ${url} -> ${matchedRule.action}`, {
        url,
        action: matchedRule.action,
        ruleId: matchedRule.id,
      });

      try {
        if (matchedRule.action === "block") {
          await client.Fetch.failRequest({ requestId, errorReason: "BlockedByClient" });
          return;
        }

        if (matchedRule.action === "mock") {
          const responseCode = matchedRule.mockStatus ?? 200;
          const headers = Object.entries(matchedRule.mockHeaders ?? { "content-type": "application/json" }).map(([name, value]) => ({
            name,
            value: String(value),
          }));
          const bodyBase64 = Buffer.from(matchedRule.mockBody ?? "{}").toString("base64");
          await client.Fetch.fulfillRequest({
            requestId,
            responseCode,
            responseHeaders: headers,
            body: bodyBase64,
          });
          return;
        }

        if (matchedRule.action === "modify") {
          const continueParams: any = { requestId };
          if (matchedRule.newUrl) continueParams.url = matchedRule.newUrl;
          if (matchedRule.newMethod) continueParams.method = matchedRule.newMethod;
          if (matchedRule.modifyHeaders) {
            continueParams.headers = Object.entries(matchedRule.modifyHeaders).map(([name, value]) => ({ name, value: String(value) }));
          }
          if (matchedRule.modifyPostData) {
            continueParams.postData = Buffer.from(matchedRule.modifyPostData).toString("base64");
          }
          await client.Fetch.continueRequest(continueParams);
          return;
        }

        await client.Fetch.continueRequest({ requestId });
      } catch (_) {
        try {
          await client.Fetch.continueRequest({ requestId });
        } catch (_) {}
      }
    });
  }

  private matchWildcard(pattern: string, text: string): boolean {
    if (pattern === "*" || !pattern) return true;
    const regexPattern = "^" + pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".") + "$";
    try {
      return new RegExp(regexPattern, "i").test(text);
    } catch (_) {
      return text.includes(pattern);
    }
  }

  private trimNetworkRecords(): void {
    while (this.networkOrder.length > MAX_NETWORK_RECORDS) {
      const oldest = this.networkOrder.shift();
      if (oldest) {
        this.networkRecords.delete(oldest);
        this.rawRequestHeaders.delete(oldest);
      }
    }
  }

  private pushLimited<T>(array: T[], value: T, max: number): void {
    array.push(value);
    if (array.length > max) array.splice(0, array.length - max);
  }

  private addTimeline(category: TimelineRecord["category"], type: string, summary: string, data?: unknown): void {
    if (!this.timelineEnabled) return;
    const event: TimelineRecord = {
      sequence: ++this.timelineSequence,
      timestamp: nowIso(),
      category,
      type,
      summary: summary.slice(0, 1_000),
      data: data === undefined ? undefined : jsonSafe(data),
    };
    this.pushLimited(this.timeline, event, MAX_TIMELINE_EVENTS);
  }
}

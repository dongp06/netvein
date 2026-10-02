import CDP from "chrome-remote-interface";
import { findTextMatches, searchAst, textDiffSummary, type AstPattern } from "./analysis.js";
import type {
  BreakpointRecord,
  ConsoleRecord,
  HookEventRecord,
  HookRecord,
  NetworkRecord,
  PauseState,
  ScriptRecord,
  TargetInfo,
  TimelineRecord,
  WebSocketFrameRecord,
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

  async listTargets(): Promise<TargetInfo[]> {
    const targets = await CDP.List({ host: this.options.host, port: this.options.port });
    return (targets as TargetInfo[]).map((target) => ({
      id: target.id,
      type: target.type,
      title: target.title,
      url: target.url,
      description: target.description,
      webSocketDebuggerUrl: target.webSocketDebuggerUrl,
    }));
  }

  async connect(selector: TargetSelector = {}): Promise<TargetInfo> {
    await this.disconnect();
    const targets = await this.listTargets();
    const pages = targets.filter((target) => target.type === "page" || target.type === "webview");
    const target = selector.targetId
      ? targets.find((candidate) => candidate.id === selector.targetId)
      : pages.find((candidate) => {
          if (selector.url && !candidate.url.includes(selector.url)) return false;
          if (selector.title && !candidate.title.includes(selector.title)) return false;
          return true;
        });

    if (!target) {
      throw new Error(
        selector.targetId
          ? `CDP target not found: ${selector.targetId}`
          : "No matching page target found. Start Chrome with --remote-debugging-port=9222 and open a page first.",
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
        hooks: this.hooks.size,
        taintTrackers: this.taintTrackers.size,
      },
      paused: this.pauseState !== null,
      timelineRecording: this.timelineEnabled,
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
    for (const script of scripts) {
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
      if (matches.length >= (options.maxMatches ?? 100)) break;
    }
    return { query, matches, truncated: matches.length >= (options.maxMatches ?? 100) };
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
    return {
      request: record,
      initiatorType: initiator?.type,
      initiatorUrl: initiator?.url,
      stack: frames,
      origin: frames[0] ?? null,
      note: frames.length ? "Origin inferred from Network.requestWillBeSent initiator stack." : "Chrome did not provide a JavaScript initiator stack for this request.",
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

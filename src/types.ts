export interface TargetInfo {
  id: string;
  type: string;
  title: string;
  url: string;
  description?: string;
  webSocketDebuggerUrl?: string;
}

export interface ScriptRecord {
  scriptId: string;
  url: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  executionContextId?: number;
  hash?: string;
  isModule?: boolean;
  sourceMapURL?: string;
  length?: number;
}

export interface ConsoleRecord {
  id: number;
  timestamp: string;
  type: string;
  args: unknown[];
  executionContextId?: number;
  stack?: unknown;
}

export interface NetworkRecord {
  requestId: string;
  loaderId?: string;
  documentURL?: string;
  type?: string;
  url: string;
  method: string;
  requestHeaders?: Record<string, unknown>;
  postData?: string;
  startedAt: string;
  status?: number;
  statusText?: string;
  mimeType?: string;
  responseHeaders?: Record<string, unknown>;
  encodedDataLength?: number;
  finishedAt?: string;
  errorText?: string;
  fromCache?: boolean;
  initiator?: unknown;
}

export interface WebSocketFrameRecord {
  requestId: string;
  direction: "sent" | "received";
  timestamp: string;
  opcode?: number;
  mask?: boolean;
  payloadData: string;
}

export interface PauseState {
  reason: string;
  hitBreakpoints: string[];
  callFrames: unknown[];
  asyncStackTrace?: unknown;
  timestamp: string;
}

export interface BreakpointRecord {
  breakpointId: string;
  url?: string;
  urlRegex?: string;
  scriptId?: string;
  lineNumber: number;
  columnNumber: number;
  condition?: string;
  locations: unknown[];
  createdAt: string;
}

export interface HookRecord {
  hookId: string;
  kind: "fetch" | "xhr" | "websocket" | "crypto";
  includeResponse: boolean;
  captureBuiltins?: boolean;
  installedAt: string;
  scriptIdentifier?: string;
}

export interface HookEventRecord {
  id: number;
  hookId: string;
  timestamp: string;
  type: string;
  [key: string]: unknown;
}

export interface TimelineRecord {
  sequence: number;
  timestamp: string;
  category: "console" | "network" | "websocket" | "debugger" | "hook" | "browser";
  type: string;
  summary: string;
  data?: unknown;
}

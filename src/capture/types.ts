export interface CaptureSessionConfig {
  id: string;
  name: string;
  dir: string;
  flowsFile: string;
  bodiesDir: string;
  startTime: string;
  endTime?: string;
  focus?: string[];
  dropTelemetry?: boolean;
  keepSecrets?: boolean;
  storeBodies?: boolean;
  status: "active" | "stopped";
  flowCount: number;
}

export interface ProxiedExecOptions {
  command: string;
  args?: string[];
  cwd?: string;
  timeoutMs?: number;
  maxChars?: number;
  env?: Record<string, string>;
  focus?: string[];
  inheritStdio?: boolean;
}

export interface ProxiedExecResult {
  command: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  flowsBefore: number;
  flowsAfter: number;
  flowsCaptured: number;
}

export interface StreamEvent {
  index: number;
  event?: string;
  id?: string;
  data: unknown;
  raw?: string;
}

export interface InspectBodyResult {
  path?: string;
  sizeBytes: number;
  decompressed: boolean;
  encoding?: string;
  contentType?: string;
  format: "json" | "text" | "hex" | "base64";
  content: string;
}

export interface SearchMatch {
  sessionId?: string;
  flowId: string;
  method: string;
  url: string;
  status: number | null;
  matchIn: "url" | "header" | "request_body" | "response_body";
  snippet: string;
}

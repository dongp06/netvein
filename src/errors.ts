export const ERROR_CODES = {
  ERR_STALE_NODE_ID: "The node id belongs to an outdated accessibility snapshot.",
  ERR_NO_SESSION: "No Chrome target is attached to the session.",
  ERR_NO_IDENTITY: "The requested identity does not exist.",
  ERR_PROXY_UNREACHABLE: "The identity's proxy could not be reached.",
  ERR_STEALTH_PATCH_FAILED: "A stealth patch failed to install.",
  ERR_AX_TREE_UNAVAILABLE: "The accessibility tree is unavailable on this page.",
  ERR_CAPTCHA_PROVIDER_DISABLED: "No captcha provider is registered.",
  ERR_MITM_UNAVAILABLE: "mitmdump was not found on PATH.",
  ERR_MITM_PORT_BUSY: "The requested proxy port is already in use.",
  ERR_MITM_NOT_RUNNING: "The traffic daemon is not running.",
  ERR_MITM_LOST: "The traffic daemon died mid-operation.",
  ERR_MITM_FLOW_NOT_FOUND: "No flow matches that id in the daemon store.",
  ERR_MITM_BAD_PATTERN: "The breakpoint pattern is not a valid regex.",
  ERR_PROJECT_EXISTS: "A .netvein workspace already exists at that path.",
  ERR_CAPTURE_NO_SESSION: "No active capture session.",
  ERR_BODY_NOT_FOUND: "The requested body was not found.",
  ERR_INVALID_PARAM: "Invalid parameter provided to capture tool.",
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

/**
 * Suggestions attached to a fallback envelope, where the throwing site did not
 * supply one. The spec requires every envelope to carry a suggestion, because
 * the suggestion is what lets the model correct itself on the next turn.
 */
export const DEFAULT_SUGGESTIONS: Record<ErrorCode, string> = {
  ERR_STALE_NODE_ID: "Re-run semantic_view and use the ids from the new snapshot.",
  ERR_NO_SESSION: "Call browser_attach to attach a tab, then retry.",
  ERR_NO_IDENTITY: "Call identity_list to see available identities, or identity_create first.",
  ERR_PROXY_UNREACHABLE: "Confirm the proxy is reachable from this host.",
  ERR_STEALTH_PATCH_FAILED: "Confirm a tab is attached with browser_attach, then retry stealth_enable.",
  ERR_AX_TREE_UNAVAILABLE: "Navigate to a real page first; the tree is unavailable on about:blank and PDF viewers.",
  ERR_CAPTCHA_PROVIDER_DISABLED: "Call captcha_provider_hook with a provider and key, or rely on captcha_detect alone.",
  ERR_MITM_UNAVAILABLE: "Install mitmproxy first: pipx install mitmproxy.",
  ERR_MITM_PORT_BUSY: "Pass a different port to traffic_start.",
  ERR_MITM_NOT_RUNNING: "Call traffic_start before using traffic tools.",
  ERR_MITM_LOST: "Call traffic_start again; flow history was lost with the daemon.",
  ERR_MITM_FLOW_NOT_FOUND: "List flows with traffic_flows and use a current id.",
  ERR_MITM_BAD_PATTERN: "Use a valid JS regex, for example .*api/login.*",
  ERR_PROJECT_EXISTS: "Pass force to skip existing files, or point dir at a different path.",
  ERR_CAPTURE_NO_SESSION: "Call capture_session_start to begin a new capture session.",
  ERR_BODY_NOT_FOUND: "Check available flows with traffic_flows or inspect the session bodies directory.",
  ERR_INVALID_PARAM: "Verify the parameters passed to the tool.",
};

export interface OkEnvelope<T> {
  success: true;
  data: T;
}

export interface ErrEnvelope {
  success: false;
  error_code: ErrorCode;
  message: string;
  suggestion?: string;
}

export type Envelope<T> = OkEnvelope<T> | ErrEnvelope;

export function ok<T>(data: T): OkEnvelope<T> {
  return { success: true, data };
}

export function err(code: ErrorCode, message: string, suggestion?: string): ErrEnvelope {
  if (suggestion === undefined) {
    return { success: false, error_code: code, message };
  }
  return { success: false, error_code: code, message, suggestion };
}

export class ToolError extends Error {
  readonly code: ErrorCode;
  readonly suggestion?: string;

  constructor(code: ErrorCode, message: string, suggestion?: string) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.suggestion = suggestion;
  }

  toEnvelope(): ErrEnvelope {
    return err(this.code, this.message, this.suggestion);
  }
}

export function toEnvelope(error: unknown, fallbackCode: ErrorCode): ErrEnvelope {
  if (error instanceof ToolError) return error.toEnvelope();
  const message = error instanceof Error ? error.message : String(error);
  return err(fallbackCode, message, DEFAULT_SUGGESTIONS[fallbackCode]);
}

/** For throwers that carry their own registry code (e.g. MitmError) but are not ToolError. */
export function envelopeFromThrow(error: unknown, fallback: ErrorCode): ErrEnvelope {
  const raw = error as { code?: ErrorCode; suggestion?: string };
  const code = raw?.code && raw.code in DEFAULT_SUGGESTIONS ? raw.code : fallback;
  const message = error instanceof Error ? error.message : String(error);
  return err(code, message, raw?.suggestion ?? DEFAULT_SUGGESTIONS[code]);
}

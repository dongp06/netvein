import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CdpSession } from "./cdp.js";

type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2) ?? "null";
}

function success(value: unknown): ToolResult {
  return { content: [{ type: "text", text: stringify(value) }] };
}

function failure(error: unknown): ToolResult {
  const message = error instanceof Error ? error.message : String(error);
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify({ error: message }, null, 2) }],
  };
}

function safeTool<TArgs>(handler: (args: TArgs) => Promise<unknown>) {
  return async (args: TArgs): Promise<ToolResult> => {
    try {
      return success(await handler(args));
    } catch (error) {
      return failure(error);
    }
  };
}

export function createServer(session: CdpSession): McpServer {
  const server = new McpServer({
    name: "reverse-engineering-mcp",
    version: "0.1.0",
  });

  server.registerTool(
    "browser_targets",
    {
      title: "List Chrome targets",
      description: "List inspectable Chrome tabs/targets exposed by the local CDP endpoint.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listTargets()),
  );

  server.registerTool(
    "browser_attach",
    {
      title: "Attach to a browser target",
      description: "Attach the single MCP-owned CDP session to a Chrome page. Use targetId or a URL/title substring.",
      inputSchema: {
        targetId: z.string().optional().describe("Exact CDP target id from browser_targets."),
        url: z.string().optional().describe("Substring that must occur in the target URL."),
        title: z.string().optional().describe("Substring that must occur in the target title."),
      },
    },
    safeTool(async (args: { targetId?: string; url?: string; title?: string }) => session.connect(args)),
  );

  server.registerTool(
    "browser_detach",
    {
      title: "Detach from Chrome",
      description: "Close the MCP-owned CDP connection without closing Chrome.",
    },
    safeTool(async () => {
      await session.disconnect();
      return { detached: true };
    }),
  );

  server.registerTool(
    "browser_status",
    {
      title: "Browser session status",
      description: "Return current target, capture counters, breakpoint count and pause state.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => ({ ...session.status(), currentUrl: await session.getCurrentUrl() })),
  );

  server.registerTool(
    "navigate",
    {
      title: "Navigate the page",
      description: "Navigate the selected Chrome page to a URL and wait briefly for the document to start loading.",
      inputSchema: {
        url: z.string().url(),
        waitMs: z.number().int().min(0).max(10000).default(500),
      },
    },
    safeTool(async (args: { url: string; waitMs: number }) => session.navigate(args.url, args.waitMs)),
  );

  server.registerTool(
    "page_snapshot",
    {
      title: "Snapshot the page",
      description: "Return page title, visible text and a bounded list of interactive elements.",
      inputSchema: {
        maxChars: z.number().int().min(1).max(100000).default(30000),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { maxChars: number }) => session.pageSnapshot(args.maxChars)),
  );

  server.registerTool(
    "click_selector",
    {
      title: "Click a page element",
      description: "Scroll an element into view and dispatch a real mouse click at its center using the CDP Input domain.",
      inputSchema: { selector: z.string().min(1) },
    },
    safeTool(async (args: { selector: string }) => session.clickSelector(args.selector)),
  );

  server.registerTool(
    "type_text",
    {
      title: "Type into a page element",
      description: "Focus a form control and insert text through the CDP Input domain.",
      inputSchema: {
        selector: z.string().min(1),
        text: z.string(),
        clear: z.boolean().default(true),
      },
    },
    safeTool(async (args: { selector: string; text: string; clear: boolean }) => session.typeText(args.selector, args.text, args.clear)),
  );

  server.registerTool(
    "list_scripts",
    {
      title: "List loaded scripts",
      description: "List scripts observed through Debugger.scriptParsed, including source map metadata.",
      inputSchema: {
        urlContains: z.string().optional(),
        limit: z.number().int().min(1).max(1000).default(200),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { urlContains?: string; limit: number }) => session.listScripts(args.urlContains, args.limit)),
  );

  server.registerTool(
    "get_script_source",
    {
      title: "Read script source",
      description: "Read a bounded slice of a loaded script by its CDP scriptId.",
      inputSchema: {
        scriptId: z.string(),
        offset: z.number().int().min(0).default(0),
        maxChars: z.number().int().min(1).max(200000).default(50000),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId: string; offset: number; maxChars: number }) => session.getScriptSource(args.scriptId, args.maxChars, args.offset)),
  );

  server.registerTool(
    "search_scripts",
    {
      title: "Search loaded scripts",
      description: "Search source text across loaded scripts and return bounded snippets with line numbers.",
      inputSchema: {
        query: z.string().min(1),
        caseSensitive: z.boolean().default(false),
        maxScripts: z.number().int().min(1).max(200).default(100),
        maxMatches: z.number().int().min(1).max(500).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { query: string; caseSensitive: boolean; maxScripts: number; maxMatches: number }) =>
      session.searchScripts(args.query, args),
    ),
  );

  server.registerTool(
    "smart_breakpoint",
    {
      title: "Set smart source breakpoints",
      description: "Find literal or regex matches across loaded scripts and set executable breakpoints at their source locations.",
      inputSchema: {
        pattern: z.string().min(1),
        regex: z.boolean().default(false),
        urlContains: z.string().optional(),
        condition: z.string().optional(),
        maxMatches: z.number().int().min(1).max(100).default(20),
      },
    },
    safeTool(async (args: { pattern: string; regex: boolean; urlContains?: string; condition?: string; maxMatches: number }) =>
      session.smartBreakpoint(args),
    ),
  );

  server.registerTool(
    "conditional_logpoint_batch",
    {
      title: "Install batch logpoints",
      description: "Find source matches and install non-pausing conditional breakpoints that log an expression and return false.",
      inputSchema: {
        pattern: z.string().min(1),
        logExpression: z.string().min(1),
        regex: z.boolean().default(false),
        urlContains: z.string().optional(),
        label: z.string().optional(),
        maxMatches: z.number().int().min(1).max(100).default(20),
      },
    },
    safeTool(async (args: { pattern: string; logExpression: string; regex: boolean; urlContains?: string; label?: string; maxMatches: number }) =>
      session.conditionalLogpointBatch(args),
    ),
  );

  server.registerTool(
    "ast_search",
    {
      title: "Search JavaScript AST",
      description: "Parse loaded scripts and search structural patterns such as calls, operators, literals or functions containing calls/XOR.",
      inputSchema: {
        pattern: z.object({
          nodeType: z.string().optional().describe("ESTree node type, or Function for any function node."),
          callee: z.string().optional().describe("Identifier or member property called by a CallExpression."),
          operator: z.string().optional(),
          literal: z.string().optional(),
          containsCalls: z.array(z.string()).optional(),
          containsOperators: z.array(z.string()).optional(),
        }),
        urlContains: z.string().optional(),
        maxScripts: z.number().int().min(1).max(200).default(50),
        maxMatches: z.number().int().min(1).max(500).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: {
      pattern: { nodeType?: string; callee?: string; operator?: string; literal?: string; containsCalls?: string[]; containsOperators?: string[] };
      urlContains?: string;
      maxScripts: number;
      maxMatches: number;
    }) => session.astSearch(args.pattern, args)),
  );

  server.registerTool(
    "capture_bundle_snapshot",
    {
      title: "Capture a bundle snapshot",
      description: "Save the currently loaded script sources under a label for later diff_bundles comparison.",
      inputSchema: {
        label: z.string().min(1),
        urlContains: z.string().optional(),
        maxScripts: z.number().int().min(1).max(500).default(200),
      },
    },
    safeTool(async (args: { label: string; urlContains?: string; maxScripts: number }) =>
      session.captureBundleSnapshot(args.label, args.urlContains, args.maxScripts),
    ),
  );

  server.registerTool(
    "diff_bundles",
    {
      title: "Diff bundle snapshots",
      description: "Compare two labeled script snapshots and report added, removed and changed bundles with bounded text diffs.",
      inputSchema: {
        labelA: z.string().min(1),
        labelB: z.string().min(1),
        maxChanges: z.number().int().min(1).max(500).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { labelA: string; labelB: string; maxChanges: number }) =>
      session.diffBundles(args.labelA, args.labelB, args.maxChanges),
    ),
  );

  server.registerTool(
    "openapi_generator",
    {
      title: "Generate an OpenAPI draft",
      description: "Generate an OpenAPI 3.0 draft from captured browser requests, query parameters and observed responses.",
      inputSchema: {
        title: z.string().optional(),
        urlContains: z.string().optional(),
        includeExamples: z.boolean().default(false),
        maxExamples: z.number().int().min(0).max(100).default(20),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { title?: string; urlContains?: string; includeExamples: boolean; maxExamples: number }) =>
      session.generateOpenApi(args),
    ),
  );

  server.registerTool(
    "evaluate",
    {
      title: "Evaluate JavaScript",
      description: "Evaluate JavaScript in the selected page's main runtime. Use expand for own properties of an object result.",
      inputSchema: {
        expression: z.string().min(1),
        awaitPromise: z.boolean().default(true),
        returnByValue: z.boolean().default(false),
        expand: z.boolean().default(false),
      },
    },
    safeTool(async (args: { expression: string; awaitPromise: boolean; returnByValue: boolean; expand: boolean }) =>
      session.evaluate(args.expression, args),
    ),
  );

  server.registerTool(
    "evaluate_on_call_frame",
    {
      title: "Evaluate in a paused call frame",
      description: "Evaluate an expression against local variables in a paused debugger call frame.",
      inputSchema: {
        callFrameId: z.string(),
        expression: z.string().min(1),
        expand: z.boolean().default(false),
      },
    },
    safeTool(async (args: { callFrameId: string; expression: string; expand: boolean }) =>
      session.evaluateOnCallFrame(args.callFrameId, args.expression, args.expand),
    ),
  );

  server.registerTool(
    "get_console",
    {
      title: "Read console events",
      description: "Read recent console API calls, exceptions and Log domain entries captured from the page.",
      inputSchema: {
        limit: z.number().int().min(1).max(1000).default(100),
        type: z.string().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { limit: number; type?: string }) => session.getConsole(args.limit, args.type)),
  );

  server.registerTool(
    "get_network",
    {
      title: "Read network events",
      description: "Read captured HTTP requests/responses and recent WebSocket frames. Sensitive headers are redacted.",
      inputSchema: {
        urlContains: z.string().optional(),
        type: z.string().optional(),
        status: z.number().int().optional(),
        limit: z.number().int().min(1).max(1000).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { urlContains?: string; type?: string; status?: number; limit: number }) => session.getNetwork(args)),
  );

  server.registerTool(
    "get_network_body",
    {
      title: "Read a response body",
      description: "Fetch a response body from Chrome's Network domain by requestId, with a size limit.",
      inputSchema: {
        requestId: z.string(),
        maxChars: z.number().int().min(1).max(500000).default(100000),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { requestId: string; maxChars: number }) => session.getNetworkBody(args.requestId, args.maxChars)),
  );

  server.registerTool(
    "trace_request_origin",
    {
      title: "Trace request origin",
      description: "Trace a captured request back through Chrome's JavaScript initiator stack and attach source context.",
      inputSchema: {
        requestId: z.string(),
        includeSource: z.boolean().default(true),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { requestId: string; includeSource: boolean }) => session.traceRequestOrigin(args.requestId, args.includeSource)),
  );

  server.registerTool(
    "replay_and_verify",
    {
      title: "Replay and verify a request",
      description: "Replay a captured request inside the attached page and compare status and response bytes with the original.",
      inputSchema: {
        requestId: z.string(),
        url: z.string().url().optional(),
        method: z.string().optional(),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        maxBodyChars: z.number().int().min(1).max(500000).default(500000),
      },
    },
    safeTool(async (args: { requestId: string; url?: string; method?: string; headers?: Record<string, string>; body?: string; maxBodyChars: number }) =>
      session.replayAndVerify(args.requestId, args, args.maxBodyChars),
    ),
  );

  server.registerTool(
    "env_diff",
    {
      title: "Compare browser and Node environments",
      description: "Collect browser fingerprint/runtime features and compare them with the Node environment used for reconstruction.",
      inputSchema: {
        includeCanvas: z.boolean().default(false),
        extraExpressions: z.record(z.string()).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { includeCanvas: boolean; extraExpressions?: Record<string, string> }) =>
      session.environmentDiff(args.includeCanvas, args.extraExpressions ?? {}),
    ),
  );

  server.registerTool(
    "taint_track",
    {
      title: "Start dynamic taint tracking",
      description: "Evaluate a source expression, derive exact/base64 tokens and trace them at JSON, encoding, crypto and request sinks.",
      inputSchema: {
        expression: z.string().min(1),
        label: z.string().min(1),
        trackerId: z.string().optional(),
      },
    },
    safeTool(async (args: { expression: string; label: string; trackerId?: string }) =>
      session.startTaintTracking(args.expression, args.label, args.trackerId),
    ),
  );

  server.registerTool(
    "taint_events",
    {
      title: "Read taint events",
      description: "Read sink events emitted by dynamic taint trackers.",
      inputSchema: {
        trackerId: z.string().optional(),
        limit: z.number().int().min(1).max(2000).default(200),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { trackerId?: string; limit: number }) => session.getTaintEvents(args.trackerId, args.limit)),
  );

  server.registerTool(
    "taint_stop",
    {
      title: "Stop taint tracking",
      description: "Remove a dynamic taint tracker from the current page and future navigations.",
      inputSchema: { trackerId: z.string() },
    },
    safeTool(async (args: { trackerId: string }) => session.stopTaintTracking(args.trackerId)),
  );

  server.registerTool(
    "taint_list",
    {
      title: "List taint trackers",
      description: "List active dynamic taint trackers.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listTaintTrackers()),
  );

  server.registerTool(
    "hook_crypto_all",
    {
      title: "Hook browser crypto and entropy APIs",
      description: "Capture Web Crypto, atob/btoa, TextEncoder, JSON.stringify, Math.random and Date.now with stack traces.",
      inputSchema: { hookId: z.string().optional() },
    },
    safeTool(async (args: { hookId?: string }) => session.installHook({ hookId: args.hookId, kind: "crypto", captureBuiltins: true })),
  );

  server.registerTool(
    "timeline_recorder",
    {
      title: "Control unified timeline",
      description: "Start/stop/clear/read the unified browser, debugger, console, network, WebSocket and hook timeline.",
      inputSchema: {
        action: z.enum(["start", "stop", "read", "clear"]),
        limit: z.number().int().min(1).max(5000).default(200),
        categories: z.array(z.string()).optional(),
      },
    },
    safeTool(async (args: { action: "start" | "stop" | "read" | "clear"; limit: number; categories?: string[] }) =>
      session.timelineRecorder(args.action, args.limit, args.categories),
    ),
  );

  server.registerTool(
    "set_breakpoint",
    {
      title: "Set a JavaScript breakpoint",
      description: "Set a breakpoint by scriptId or URL/URL regex. lineNumber and columnNumber are zero-based.",
      inputSchema: {
        scriptId: z.string().optional(),
        url: z.string().optional(),
        urlRegex: z.string().optional(),
        lineNumber: z.number().int().min(0),
        columnNumber: z.number().int().min(0).default(0),
        condition: z.string().optional(),
      },
    },
    safeTool(async (args: {
      scriptId?: string;
      url?: string;
      urlRegex?: string;
      lineNumber: number;
      columnNumber: number;
      condition?: string;
    }) => session.setBreakpoint(args)),
  );

  server.registerTool(
    "remove_breakpoint",
    {
      title: "Remove a breakpoint",
      description: "Remove a breakpoint by the breakpointId returned by set_breakpoint.",
      inputSchema: { breakpointId: z.string() },
    },
    safeTool(async (args: { breakpointId: string }) => session.removeBreakpoint(args.breakpointId)),
  );

  server.registerTool(
    "list_breakpoints",
    {
      title: "List breakpoints",
      description: "List breakpoints created by this MCP session.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listBreakpoints()),
  );

  server.registerTool(
    "get_debugger_status",
    {
      title: "Get debugger status",
      description: "Return pause reason, hit breakpoint ids, call frames and scope previews.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.getDebuggerStatus()),
  );

  server.registerTool(
    "resume_execution",
    {
      title: "Resume JavaScript",
      description: "Resume a paused target.",
    },
    safeTool(async () => session.resume()),
  );

  server.registerTool(
    "step_execution",
    {
      title: "Step JavaScript",
      description: "Step over, into or out of the current paused call frame.",
      inputSchema: { action: z.enum(["over", "into", "out"]) },
    },
    safeTool(async (args: { action: "over" | "into" | "out" }) => session.step(args.action)),
  );

  server.registerTool(
    "set_pause_on_exceptions",
    {
      title: "Configure exception pauses",
      description: "Pause on no exceptions, uncaught exceptions, or all exceptions.",
      inputSchema: { state: z.enum(["none", "uncaught", "all"]) },
    },
    safeTool(async (args: { state: "none" | "uncaught" | "all" }) => session.setPauseOnExceptions(args.state)),
  );

  server.registerTool(
    "install_hook",
    {
      title: "Install a runtime hook",
      description: "Instrument fetch, XHR, WebSocket or Web Crypto in the current page and future navigations.",
      inputSchema: {
        hookId: z.string().optional(),
        kind: z.enum(["fetch", "xhr", "websocket", "crypto"]),
        includeResponse: z.boolean().default(false),
      },
    },
    safeTool(async (args: { hookId?: string; kind: "fetch" | "xhr" | "websocket" | "crypto"; includeResponse: boolean }) =>
      session.installHook(args),
    ),
  );

  server.registerTool(
    "remove_hook",
    {
      title: "Remove a runtime hook",
      description: "Remove a hook from the current page and from future navigations.",
      inputSchema: { hookId: z.string() },
    },
    safeTool(async (args: { hookId: string }) => session.removeHook(args.hookId)),
  );

  server.registerTool(
    "list_hooks",
    {
      title: "List runtime hooks",
      description: "List hooks installed by this MCP session.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listHooks()),
  );

  server.registerTool(
    "get_hook_events",
    {
      title: "Read hook events",
      description: "Read events emitted by installed runtime hooks.",
      inputSchema: {
        hookId: z.string().optional(),
        limit: z.number().int().min(1).max(2000).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { hookId?: string; limit: number }) => session.getHookEvents(args)),
  );

  server.registerTool(
    "clear_capture_logs",
    {
      title: "Clear captured logs",
      description: "Clear in-memory console, network, WebSocket and hook event buffers for this session.",
    },
    safeTool(async () => session.clearLogs()),
  );

  return server;
}

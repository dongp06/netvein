import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { CdpSession } from "./cdp.js";
import { ok, type Envelope } from "./errors.js";
import { SERVER_INSTRUCTIONS } from "./instructions.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";
import { checkForUpdate, defaultUpdateDeps, isUpdateCheckEnabled } from "./updater.js";
import { VERSION } from "./version.js";

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

/**
 * Handlers for the tools added after the structured-error change return an
 * Envelope directly, so the client always sees `success`/`error_code`/
 * `message`/`suggestion` instead of a bare `{error}` string. MCP-level
 * `isError` is still set for transport-visible failures (spec §5.4).
 */
function envelopeTool<TArgs>(handler: (args: TArgs) => Promise<Envelope<unknown>>) {
  return async (args: TArgs): Promise<ToolResult> => {
    const result = await handler(args);
    return {
      ...(result.success ? {} : { isError: true }),
      content: [{ type: "text", text: stringify(result) }],
    };
  };
}

export function createServer(session: CdpSession): McpServer {
  const server = new McpServer(
    {
      name: "reverse-engineering-mcp",
      version: VERSION,
    },
    {
      instructions: SERVER_INSTRUCTIONS,
      capabilities: {
        resources: {},
        prompts: {},
        logging: {},
      },
    },
  );

  registerResources(server, session);
  registerPrompts(server);

  server.registerTool(
    "browser_launch",
    {
      title: "Launch browser with CDP remote debugging",
      description:
        "Automatically find and launch Chrome, Edge, or Brave with remote debugging flags enabled (--remote-debugging-port=9222), or confirm if already running.",
      inputSchema: {
        targetUrl: z.string().optional().describe("Initial URL to open upon browser launch."),
        headless: z.boolean().default(false).describe("Whether to launch browser in headless mode."),
        userDataDir: z.string().optional().describe("Custom user data profile directory."),
        executablePath: z.string().optional().describe("Explicit path to the Chrome/Edge/Brave browser binary."),
      },
    },
    safeTool(
      async (args: {
        targetUrl?: string;
        headless?: boolean;
        userDataDir?: string;
        executablePath?: string;
      }) => session.launchBrowser(args),
    ),
  );

  server.registerTool(
    "browser_targets",
    {
      title: "List Chrome targets",
      description: "List inspectable Chrome tabs/targets exposed by the local CDP endpoint. Automatically launches browser if not running.",
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
    "stealth_enable",
    {
      title: "Enable a stealth patch profile",
      description:
        "Install anti-detection patches on the attached target. Patches apply to the current document immediately and to every future document in this target. Profile 'basic' covers identity leaks; 'strict' adds canvas, WebGL and audio fingerprint noise plus Function.prototype.toString integrity.",
      inputSchema: {
        profile: z.enum(["off", "basic", "strict"]).default("basic").describe("Patch level. 'off' removes all patches."),
        seed: z
          .number()
          .int()
          .min(0)
          .max(4294967295)
          .optional()
          .describe("Deterministic fingerprint seed. Omit to derive one from the attached target id."),
      },
    },
    envelopeTool(async (args: { profile?: "off" | "basic" | "strict"; seed?: number }) =>
      session.applyStealthEnvelope(args.profile ?? "basic", args.seed),
    ),
  );

  server.registerTool(
    "stealth_status",
    {
      title: "Report the active stealth profile",
      description: "Return the active stealth profile, the patch ids it activates, and whether a patch script is registered.",
      annotations: { readOnlyHint: true },
    },
    envelopeTool(async () => session.stealthStatusEnvelope()),
  );

  server.registerTool(
    "stealth_probe",
    {
      title: "Probe the page for stealth leaks",
      description:
        "Run a detection suite in the attached page and report, per check, what still leaks and the observed value. Use this to detect when a stealth patch has gone stale.",
      inputSchema: {
        maxChars: z.number().int().min(1000).max(20000).default(20000).describe("Maximum characters returned."),
      },
    },
    envelopeTool(async (args: { maxChars?: number }) => session.stealthProbeEnvelope(args.maxChars ?? 20_000)),
  );

  server.registerTool(
    "semantic_view",
    {
      title: "Pruned semantic view of the page",
      description:
        "Return a compressed accessibility tree with short integer ids instead of raw HTML. Costs roughly 1-2k tokens where a raw DOM dump costs orders of magnitude more. Ids are valid until the page navigates or the DOM changes; a stale id returns ERR_STALE_NODE_ID.",
      inputSchema: {
        interactiveOnly: z.boolean().default(false).describe("Keep only actionable roles (button, link, textbox, checkbox, ...)."),
        maxNodes: z.number().int().min(1).max(2000).default(300).describe("Maximum nodes returned."),
        maxChars: z.number().int().min(1000).max(20000).default(20000).describe("Maximum characters in the rendered view."),
      },
    },
    envelopeTool(async (args: { interactiveOnly?: boolean; maxNodes?: number; maxChars?: number }) =>
      session.semanticViewEnvelope(args),
    ),
  );

  server.registerTool(
    "interact_semantic",
    {
      title: "Act on a node by semantic id",
      description:
        "Click, type into, hover, focus or select a node using the short integer id from semantic_view. Do not construct CSS selectors or XPath. Pass snapshotVersion from semantic_view to have a stale id rejected instead of applied to the wrong element.",
      inputSchema: {
        id: z.number().int().min(1).describe("Integer id from the most recent semantic_view."),
        action: z.enum(["click", "type", "hover", "select", "focus"]).describe("Interaction to perform."),
        value: z.string().optional().describe("Text for 'type', or option value for 'select'."),
        snapshotVersion: z
          .number()
          .int()
          .min(1)
          .describe("Version returned by semantic_view. Required, so a stale id can never be applied to the wrong element."),
      },
    },
    safeTool(
      async (args: {
        id: number;
        action: "click" | "type" | "hover" | "select" | "focus";
        value?: string;
        snapshotVersion?: number;
      }) => session.interactSemanticEnvelope(args.id, args.action, args.value, args.snapshotVersion),
    ),
  );

  server.registerTool(
    "semantic_diff",
    {
      title: "Diff the semantic view since the last snapshot",
      description:
        "Re-read the accessibility tree and return only the nodes added, removed or changed since the previous snapshot. Use this instead of calling semantic_view again after every action.",
      inputSchema: {
        maxChanges: z.number().int().min(1).max(500).default(100).describe("Maximum entries per change category."),
      },
    },
    envelopeTool(async (args: { maxChanges?: number }) => session.semanticDiffEnvelope(args.maxChanges ?? 100)),
  );

  server.registerTool(
    "identity_create",
    {
      title: "Create an isolated browser identity",
      description:
        "Create a browser context for an identity, optionally bound to a proxy, and record it. The proxy is TCP-probed before the context is created, and the scheme is preserved so a SOCKS proxy is not registered as HTTP. Note: the session does not switch into the context — identity_use only applies the identity's fingerprint seed and returns, so tools keep driving the tab selected by browser_attach.",
      inputSchema: {
        name: z.string().min(1).describe("Unique identity name."),
        proxy: z.string().optional().describe("Proxy in host:port or scheme://host:port form."),
        seed: z.number().int().min(0).max(4294967295).optional().describe("Fingerprint seed. Defaults to a hash of the name."),
      },
    },
    envelopeTool(async (args: { name: string; proxy?: string; seed?: number }) => session.createIdentityEnvelope(args)),
  );

  server.registerTool(
    "identity_use",
    {
      title: "Activate an identity",
      description:
        "Apply an identity's fingerprint seed to the stealth layer. This does not switch the session into the identity's browser context; the attached tab is unchanged.",
      inputSchema: {
        name: z.string().min(1).describe("Identity name from identity_list."),
      },
    },
    envelopeTool(async (args: { name: string }) => session.useIdentityEnvelope(args.name)),
  );

  server.registerTool(
    "identity_list",
    {
      title: "List identities",
      description: "List created identities with their proxy binding, seed and usability.",
      annotations: { readOnlyHint: true },
    },
    envelopeTool(async () => session.listIdentitiesEnvelope()),
  );

  server.registerTool(
    "identity_export",
    {
      title: "Export an identity",
      description:
        "Serialize an identity's cookies, localStorage and sessionStorage into one portable JSON document that identity_import can restore elsewhere.",
      inputSchema: {
        name: z.string().min(1).describe("Identity name from identity_list."),
      },
    },
    envelopeTool(async (args: { name: string }) => session.exportIdentityEnvelope(args.name)),
  );

  server.registerTool(
    "identity_import",
    {
      title: "Import an identity",
      description:
        "Restore cookies and web storage from an exported identity payload. The payload is validated in full before anything is written, so a malformed payload applies nothing.",
      inputSchema: {
        json: z.string().min(2).describe("The JSON document produced by identity_export."),
        name: z.string().optional().describe("Override the identity name carried in the payload."),
      },
    },
    envelopeTool(async (args: { json: string; name?: string }) => session.importIdentityEnvelope(args.json, args.name)),
  );

  server.registerTool(
    "captcha_detect",
    {
      title: "Detect a captcha or bot challenge",
      description:
        "Inspect the current page for Cloudflare Turnstile, hCaptcha, reCAPTCHA or GeeTest, and report the vendor, evidence and challenge frames. This reports only; it does not solve. Use the result to decide whether to rotate identity or pause for a human.",
      annotations: { readOnlyHint: true },
    },
    envelopeTool(async () => session.captchaDetectEnvelope()),
  );

  server.registerTool(
    "captcha_provider_hook",
    {
      title: "Register an external captcha provider",
      description:
        "Register an external solving endpoint. Off by default; no solving occurs until this is called with a provider and key. captcha_detect works without it.",
      inputSchema: {
        provider: z.string().min(1).describe("Provider identifier, for example '2captcha' or 'capsolver'."),
        apiKey: z.string().min(1).describe("Provider API key."),
      },
    },
    envelopeTool(async (args: { provider: string; apiKey: string }) =>
      session.captchaProviderHookEnvelope(args.provider, args.apiKey),
    ),
  );

  server.registerTool(
    "check_for_update",
    {
      title: "Check for a newer release",
      description:
        "Compare this build's version against the tags on the project's git remote and report whether a newer release exists. Read-only by design: it never downloads, replaces files, or executes remote content, so an update is always an explicit operator decision.",
      inputSchema: {
        force: z.boolean().default(false).describe("Bypass the check interval and query the remote now."),
      },
      annotations: { readOnlyHint: true },
    },
    envelopeTool(async (args: { force?: boolean }) => {
      if (!isUpdateCheckEnabled()) {
        return ok({
          status: "disabled",
          localVersion: VERSION,
          detail: "Update checking is disabled by REVERSE_MCP_UPDATE_CHECK.",
        });
      }
      return ok(await checkForUpdate(defaultUpdateDeps({ force: args.force ?? false })));
    }),
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
    "wait_for_selector",
    {
      title: "Wait for a page selector",
      description: "Poll the attached page until a CSS selector exists and is visible (or until the bounded timeout expires).",
      inputSchema: {
        selector: z.string().min(1),
        timeoutMs: z.number().int().min(0).max(120000).default(10000),
        pollMs: z.number().int().min(25).max(2000).default(100),
        visible: z.boolean().default(true),
      },
    },
    safeTool(async (args: { selector: string; timeoutMs: number; pollMs: number; visible: boolean }) =>
      session.waitForSelector(args.selector, args.timeoutMs, args.pollMs, args.visible),
    ),
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
    "wait_for_network",
    {
      title: "Wait for a network request",
      description: "Poll captured network records until a URL/type/status filter matches or the bounded timeout expires.",
      inputSchema: {
        urlContains: z.string().optional(),
        urlPathContains: z.string().optional().describe("Substring matched against URL pathname, excluding query parameters."),
        urlRegex: z.string().optional(),
        type: z.string().optional(),
        status: z.number().int().optional(),
        requireResponse: z.boolean().default(false),
        requireFinished: z.boolean().default(false),
        timeoutMs: z.number().int().min(0).max(120000).default(10000),
        pollMs: z.number().int().min(25).max(2000).default(100),
      },
    },
    safeTool(async (args: { urlContains?: string; urlPathContains?: string; urlRegex?: string; type?: string; status?: number; requireResponse: boolean; requireFinished: boolean; timeoutMs: number; pollMs: number }) =>
      session.waitForNetwork(args),
    ),
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

  // --- BROWSER AUTOMATION & INTERACTION TOOLS ---

  server.registerTool(
    "screenshot",
    {
      title: "Take a screenshot",
      description: "Capture a screenshot of the viewport, full page, or a specific selector element as base64 image.",
      inputSchema: {
        selector: z.string().optional().describe("CSS selector of an element to screenshot."),
        fullPage: z.boolean().default(false).describe("Capture the entire scrollable page."),
        format: z.enum(["png", "jpeg"]).default("png"),
        quality: z.number().int().min(0).max(100).optional().describe("Quality for jpeg format (0-100)."),
      },
    },
    safeTool(async (args: { selector?: string; fullPage: boolean; format: "png" | "jpeg"; quality?: number }) =>
      session.screenshot(args),
    ),
  );

  server.registerTool(
    "press_key",
    {
      title: "Press a keyboard key",
      description: "Send keyboard events (Enter, Escape, Tab, Backspace, Arrow keys, or shortcuts with Alt/Control/Shift).",
      inputSchema: {
        key: z.string().min(1).describe("Key name like Enter, Tab, Escape, Backspace, ArrowDown, or character text."),
        modifiers: z.array(z.enum(["Alt", "Control", "Meta", "Shift"])).optional().describe("Modifier keys to hold."),
      },
    },
    safeTool(async (args: { key: string; modifiers?: Array<"Alt" | "Control" | "Meta" | "Shift"> }) =>
      session.pressKey(args.key, args.modifiers),
    ),
  );

  server.registerTool(
    "hover_selector",
    {
      title: "Hover mouse over selector",
      description: "Scroll an element into view and trigger hover/mouseMoved events over its center coordinates.",
      inputSchema: { selector: z.string().min(1) },
    },
    safeTool(async (args: { selector: string }) => session.hoverSelector(args.selector)),
  );

  server.registerTool(
    "scroll_page",
    {
      title: "Scroll page or element",
      description: "Scroll the viewport by x/y pixels or scroll a specific selector element into view.",
      inputSchema: {
        x: z.number().int().default(0),
        y: z.number().int().default(0),
        selector: z.string().optional().describe("CSS selector of element to scroll into view."),
      },
    },
    safeTool(async (args: { x: number; y: number; selector?: string }) => session.scrollPage(args)),
  );

  server.registerTool(
    "select_option",
    {
      title: "Select dropdown option",
      description: "Select an option in a <select> element by value or text and trigger change/input events.",
      inputSchema: {
        selector: z.string().min(1).describe("CSS selector of the <select> element."),
        value: z.string().min(1).describe("Option value or text to select."),
      },
    },
    safeTool(async (args: { selector: string; value: string }) => session.selectOption(args.selector, args.value)),
  );

  server.registerTool(
    "reload_page",
    {
      title: "Reload page",
      description: "Reload the current page with optional cache bypass and script to evaluate on load.",
      inputSchema: {
        ignoreCache: z.boolean().default(true),
        scriptToEvaluateOnLoad: z.string().optional(),
      },
    },
    safeTool(async (args: { ignoreCache: boolean; scriptToEvaluateOnLoad?: string }) =>
      session.reloadPage(args.ignoreCache, args.scriptToEvaluateOnLoad),
    ),
  );

  server.registerTool(
    "set_viewport",
    {
      title: "Set viewport metrics",
      description: "Emulate device screen dimensions, mobile emulation, and device scale factor.",
      inputSchema: {
        width: z.number().int().min(100).max(7680),
        height: z.number().int().min(100).max(4320),
        deviceScaleFactor: z.number().min(0.5).max(4).default(1),
        mobile: z.boolean().default(false),
      },
    },
    safeTool(async (args: { width: number; height: number; deviceScaleFactor: number; mobile: boolean }) =>
      session.setViewport(args),
    ),
  );

  server.registerTool(
    "set_user_agent",
    {
      title: "Override User-Agent",
      description: "Set custom User-Agent, Accept-Language, and Platform headers for browser requests.",
      inputSchema: {
        userAgent: z.string().min(1),
        acceptLanguage: z.string().optional(),
        platform: z.string().optional(),
      },
    },
    safeTool(async (args: { userAgent: string; acceptLanguage?: string; platform?: string }) =>
      session.setUserAgent(args),
    ),
  );

  server.registerTool(
    "get_cookies",
    {
      title: "Get browser cookies",
      description: "Retrieve cookies for the current page or specified URLs, including name, value, domain, path, and security flags.",
      inputSchema: {
        urls: z.array(z.string()).optional(),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { urls?: string[] }) => session.getCookies(args.urls)),
  );

  server.registerTool(
    "set_cookie",
    {
      title: "Set browser cookie",
      description: "Add or overwrite a browser cookie with custom security attributes and expiration.",
      inputSchema: {
        name: z.string().min(1),
        value: z.string(),
        domain: z.string().optional(),
        path: z.string().default("/"),
        secure: z.boolean().optional(),
        httpOnly: z.boolean().optional(),
        sameSite: z.enum(["Strict", "Lax", "None"]).optional(),
        expires: z.number().optional(),
      },
    },
    safeTool(async (args: {
      name: string;
      value: string;
      domain?: string;
      path: string;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: "Strict" | "Lax" | "None";
      expires?: number;
    }) => session.setCookie(args)),
  );

  server.registerTool(
    "delete_cookies",
    {
      title: "Delete browser cookies",
      description: "Delete a cookie by name, URL, or domain.",
      inputSchema: {
        name: z.string().min(1),
        url: z.string().optional(),
        domain: z.string().optional(),
      },
    },
    safeTool(async (args: { name: string; url?: string; domain?: string }) =>
      session.deleteCookies(args.name, args.url, args.domain),
    ),
  );

  server.registerTool(
    "get_storage",
    {
      title: "Get web storage",
      description: "Read all key-value entries from localStorage and/or sessionStorage for the current origin.",
      inputSchema: {
        type: z.enum(["local", "session", "both"]).default("both"),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { type: "local" | "session" | "both" }) => session.getStorage(args.type)),
  );

  server.registerTool(
    "set_storage",
    {
      title: "Set web storage item",
      description: "Set a key-value item in localStorage or sessionStorage for the current origin.",
      inputSchema: {
        type: z.enum(["local", "session"]).default("local"),
        key: z.string().min(1),
        value: z.string(),
      },
    },
    safeTool(async (args: { type: "local" | "session"; key: string; value: string }) =>
      session.setStorage(args.type, args.key, args.value),
    ),
  );

  server.registerTool(
    "clear_storage",
    {
      title: "Clear web storage or cookies",
      description: "Clear localStorage, sessionStorage, cookies, or all storage data for the current origin.",
      inputSchema: {
        type: z.enum(["local", "session", "cookies", "all"]).default("all"),
      },
    },
    safeTool(async (args: { type: "local" | "session" | "cookies" | "all" }) => session.clearStorage(args.type)),
  );

  // --- BREAKPOINTS & DEBUGGER EXTENSIONS ---

  server.registerTool(
    "set_dom_breakpoint",
    {
      title: "Set DOM breakpoint",
      description: "Pause JavaScript execution when a DOM element's subtree is modified, attributes change, or the node is removed.",
      inputSchema: {
        selector: z.string().min(1).describe("CSS selector of target element."),
        type: z.enum(["subtree-modified", "attribute-modified", "node-removed"]).default("subtree-modified"),
      },
    },
    safeTool(async (args: { selector: string; type: "subtree-modified" | "attribute-modified" | "node-removed" }) =>
      session.setDomBreakpoint(args.selector, args.type),
    ),
  );

  server.registerTool(
    "remove_dom_breakpoint",
    {
      title: "Remove DOM breakpoint",
      description: "Remove an active DOM breakpoint by its breakpointId.",
      inputSchema: { breakpointId: z.string().min(1) },
    },
    safeTool(async (args: { breakpointId: string }) => session.removeDomBreakpoint(args.breakpointId)),
  );

  server.registerTool(
    "set_event_breakpoint",
    {
      title: "Set event listener breakpoint",
      description: "Pause JavaScript at the start of event listeners (e.g. click, submit, keydown, setTimeout, setInterval, WebSocket).",
      inputSchema: {
        eventName: z.string().min(1).describe("Event name, e.g. click, submit, keydown, setTimeout, setInterval, etc."),
        targetName: z.string().optional(),
      },
    },
    safeTool(async (args: { eventName: string; targetName?: string }) =>
      session.setEventBreakpoint(args.eventName, args.targetName),
    ),
  );

  server.registerTool(
    "remove_event_breakpoint",
    {
      title: "Remove event listener breakpoint",
      description: "Remove an event listener breakpoint.",
      inputSchema: {
        eventName: z.string().min(1),
        targetName: z.string().optional(),
      },
    },
    safeTool(async (args: { eventName: string; targetName?: string }) =>
      session.removeEventBreakpoint(args.eventName, args.targetName),
    ),
  );

  server.registerTool(
    "set_xhr_breakpoint",
    {
      title: "Set XHR/fetch breakpoint",
      description: "Pause JavaScript immediately before an XMLHttpRequest or fetch() call containing the specified URL pattern is dispatched.",
      inputSchema: {
        url: z.string().min(1).describe("URL substring or pattern to match."),
      },
    },
    safeTool(async (args: { url: string }) => session.setXhrBreakpoint(args.url)),
  );

  server.registerTool(
    "remove_xhr_breakpoint",
    {
      title: "Remove XHR/fetch breakpoint",
      description: "Remove an active XHR/fetch breakpoint.",
      inputSchema: { url: z.string().min(1) },
    },
    safeTool(async (args: { url: string }) => session.removeXhrBreakpoint(args.url)),
  );

  server.registerTool(
    "list_all_breakpoints",
    {
      title: "List all active breakpoints",
      description: "Return all active JavaScript, DOM, event listener, and XHR breakpoints.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listAllBreakpoints()),
  );

  server.registerTool(
    "get_call_frame_scope",
    {
      title: "Get call frame scope variables",
      description: "Inspect local, closure, script, and global variables for a paused debugger call frame with expanded properties.",
      inputSchema: {
        callFrameId: z.string().min(1),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { callFrameId: string }) => session.getCallFrameScope(args.callFrameId)),
  );

  server.registerTool(
    "set_variable_value",
    {
      title: "Modify variable in call frame",
      description: "Mutate the value of a local or closure variable inside a paused debugger call frame.",
      inputSchema: {
        callFrameId: z.string().min(1),
        scopeNumber: z.number().int().min(0).describe("Zero-based index of scope in scopeChain (0 is usually local)."),
        variableName: z.string().min(1),
        value: z.unknown().describe("New value for variable (string, number, boolean, object)."),
      },
    },
    safeTool(async (args: { callFrameId: string; scopeNumber: number; variableName: string; value: unknown }) =>
      session.setVariableValue(args),
    ),
  );

  server.registerTool(
    "restart_frame",
    {
      title: "Restart call frame execution",
      description: "Restart execution of the current function call frame from its beginning without reloading the page.",
      inputSchema: { callFrameId: z.string().min(1) },
    },
    safeTool(async (args: { callFrameId: string }) => session.restartFrame(args.callFrameId)),
  );

  // --- NETWORK SEARCH, WEBSOCKET & TRAFFIC TAMPERING ---

  server.registerTool(
    "search_network",
    {
      title: "Search network requests and bodies",
      description: "Search across URLs, request headers, POST bodies, and response headers for sensitive tokens, endpoints, or parameters.",
      inputSchema: {
        query: z.string().min(1),
        isRegex: z.boolean().default(false),
        caseSensitive: z.boolean().default(false),
        limit: z.number().int().min(1).max(500).default(50),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { query: string; isRegex: boolean; caseSensitive: boolean; limit: number }) =>
      session.searchNetwork(args),
    ),
  );

  server.registerTool(
    "get_websocket_messages",
    {
      title: "Get WebSocket messages",
      description: "Filter and read captured WebSocket messages (sent/received) with payloads and timestamps.",
      inputSchema: {
        requestId: z.string().optional(),
        urlContains: z.string().optional(),
        direction: z.enum(["sent", "received", "both"]).default("both"),
        query: z.string().optional().describe("Filter payload by substring."),
        limit: z.number().int().min(1).max(1000).default(100),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: {
      requestId?: string;
      urlContains?: string;
      direction: "sent" | "received" | "both";
      query?: string;
      limit: number;
    }) => session.getWebSocketMessages(args)),
  );

  server.registerTool(
    "set_request_interception",
    {
      title: "Intercept, mock, or modify network requests",
      description: "Intercept HTTP requests matching a URL pattern to block, mock with custom response, or tamper with headers/POST body before sending.",
      inputSchema: {
        urlPattern: z.string().min(1).describe("URL wildcard pattern (e.g. *api/v1/auth*, *.png, https://target.com/*)."),
        action: z.enum(["block", "mock", "modify", "inspect"]).default("inspect"),
        resourceType: z.string().optional(),
        mockStatus: z.number().int().optional().describe("Status code for mock action (e.g. 200, 403)."),
        mockHeaders: z.record(z.string()).optional().describe("Response headers for mock action."),
        mockBody: z.string().optional().describe("Response body string for mock action."),
        modifyHeaders: z.record(z.string()).optional().describe("Request headers to override for modify action."),
        modifyPostData: z.string().optional().describe("Modified POST body for modify action."),
        newUrl: z.string().optional().describe("Redirect request to new URL for modify action."),
        newMethod: z.string().optional().describe("Change HTTP method for modify action."),
      },
    },
    safeTool(async (args: {
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
    }) => session.setRequestInterception(args)),
  );

  server.registerTool(
    "list_interceptions",
    {
      title: "List active interception rules",
      description: "List all active request interception, blocking, and mocking rules with hit counts.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listInterceptions()),
  );

  server.registerTool(
    "clear_interceptions",
    {
      title: "Clear all request interception rules",
      description: "Remove all active interception rules and disable Fetch domain interception.",
    },
    safeTool(async () => session.clearInterceptions()),
  );

  server.registerTool(
    "export_har",
    {
      title: "Export network traffic as HAR",
      description: "Export all captured requests, responses, headers, cookies, and timings in standard HTTP Archive (HAR 1.2) format for Burp/Charles/Caido.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.exportHar()),
  );

  // --- REVERSE ENGINEERING & DEEP INSPECTION ---

  server.registerTool(
    "anti_debug_bypass",
    {
      title: "Bypass anti-debugging protections",
      description: "Neutralize anti-debugging protections: strip debugger statements from Function/eval/setInterval/setTimeout, prevent console.clear, and mask window sizing checks.",
      inputSchema: {
        disableDebugger: z.boolean().default(true),
        disableConsoleClear: z.boolean().default(true),
        disableTimingChecks: z.boolean().default(true),
      },
    },
    safeTool(async (args: { disableDebugger: boolean; disableConsoleClear: boolean; disableTimingChecks: boolean }) =>
      session.antiDebugBypass(args),
    ),
  );

  server.registerTool(
    "extract_endpoints",
    {
      title: "Extract API endpoints and secrets",
      description: "Scan loaded scripts, DOM elements (links, forms, hidden inputs), and network traffic to extract REST endpoints, full URLs, WebSockets, API keys, and JWT tokens.",
      inputSchema: {
        scriptId: z.string().optional().describe("Scan a specific scriptId only, or omit to scan all loaded scripts."),
        includeNetworkHistory: z.boolean().default(true),
        includeDom: z.boolean().default(true),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId?: string; includeNetworkHistory: boolean; includeDom: boolean }) =>
      session.extractEndpoints(args),
    ),
  );

  server.registerTool(
    "extract_sourcemap",
    {
      title: "Extract original source map files",
      description: "Check loaded scripts for source maps (sourceMappingURL or base64 data URIs), download and parse them to extract original unminified TypeScript/React source files.",
      inputSchema: {
        scriptId: z.string().optional(),
        urlContains: z.string().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId?: string; urlContains?: string }) => session.extractSourceMap(args)),
  );

  server.registerTool(
    "beautify_script",
    {
      title: "Beautify minified JavaScript",
      description: "Format minified JavaScript code with indentation and line numbers for easier source reading and breakpoint placement.",
      inputSchema: {
        scriptId: z.string().min(1),
        maxChars: z.number().int().min(1000).max(200000).default(50000),
        offset: z.number().int().min(0).default(0).describe("Starting line offset."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId: string; maxChars: number; offset: number }) =>
      session.beautifyScript(args.scriptId, args.maxChars, args.offset),
    ),
  );

  server.registerTool(
    "inspect_element",
    {
      title: "Inspect DOM element and event listeners",
      description: "Inspect element tag, attributes, computed styles, child count, HTML snippet, and attached JavaScript event listeners (click, change, submit, etc.).",
      inputSchema: {
        selector: z.string().min(1).describe("CSS selector of element to inspect."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { selector: string }) => session.inspectElement(args.selector)),
  );

  server.registerTool(
    "override_function",
    {
      title: "Hook or monkey-patch a function",
      description: "Intercept a global or nested object function (e.g. CryptoJS.AES.encrypt, window.signRequest) to log arguments/return values or mock return value.",
      inputSchema: {
        target: z.string().min(1).describe("Object property path, e.g. CryptoJS.AES.encrypt or window.signRequest."),
        behavior: z.enum(["log", "mock", "passthrough"]).default("log"),
        mockReturnValue: z.unknown().optional().describe("Return value to use when behavior is 'mock'."),
      },
    },
    safeTool(async (args: { target: string; behavior: "log" | "mock" | "passthrough"; mockReturnValue?: unknown }) =>
      session.overrideFunction(args.target, args.behavior, args.mockReturnValue),
    ),
  );

  server.registerTool(
    "search_console",
    {
      title: "Search console messages",
      description: "Search captured console logs, errors, and exceptions by text or regex query.",
      inputSchema: {
        query: z.string().min(1),
        level: z.string().optional().describe("Filter by log level (log, info, warn, error, exception)."),
        isRegex: z.boolean().default(false),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { query: string; level?: string; isRegex: boolean }) =>
      session.searchConsole(args.query, args.level, args.isRegex),
    ),
  );

  server.registerTool(
    "detect_crypto",
    {
      title: "Detect crypto algorithms and libraries",
      description: "Scan loaded scripts and page runtime memory for cryptographic signatures (AES S-Boxes, DES, RSA PEM, MD5/SHA constants, SM2/SM3/SM4, CryptoJS, JSEncrypt, Forge, WebCrypto).",
      inputSchema: {
        scriptId: z.string().optional().describe("Scan a specific scriptId only, or omit to scan all loaded scripts."),
        urlContains: z.string().optional().describe("Filter scripts whose URL contains this substring."),
        scanGlobalMemory: z.boolean().default(true).describe("Whether to scan window/runtime memory for active crypto objects."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId?: string; urlContains?: string; scanGlobalMemory: boolean }) =>
      session.detectCrypto(args),
    ),
  );

  server.registerTool(
    "find_crypto_candidates",
    {
      title: "Rank encryption function candidates via AST",
      description: "Perform AST analysis on JavaScript to locate and score candidate encryption/signing functions based on parameter names (password, sign, token, etc.), bitwise density, and hex formatting.",
      inputSchema: {
        scriptId: z.string().optional().describe("Specific scriptId to scan, or omit to scan all application scripts."),
        targetParams: z.array(z.string()).optional().describe("Parameter names to search for (default: password, pwd, sign, token, signature, key, etc.)."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId?: string; targetParams?: string[] }) =>
      session.findCryptoCandidates(args),
    ),
  );

  server.registerTool(
    "classify_anticrawl",
    {
      title: "Classify bot defense and anti-debug protections",
      description: "Inspect page source, network traffic, and runtime global variables to identify anti-crawling vendors (Cloudflare, Akamai, DataDome, GeeTest, reCAPTCHA, DingXiang), JSVMP, and anti-debug traps.",
      inputSchema: {
        scriptId: z.string().optional().describe("Scan a specific scriptId, or omit to scan all loaded scripts and active page environment."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { scriptId?: string }) => session.classifyAnticrawl(args)),
  );

  server.registerTool(
    "unpack_webpack",
    {
      title: "Inspect and unpack Webpack runtime modules",
      description: "Discover Webpack/Vite chunk runtimes on the page (webpackChunk*, webpackJsonp), intercept __webpack_require__, list modules, and optionally require/dump a specific module.",
      inputSchema: {
        exportModuleId: z.union([z.string(), z.number()]).optional().describe("Require and inspect exports of a specific module ID."),
        maxModules: z.number().int().min(1).max(2000).default(200).describe("Maximum module IDs to return."),
      },
    },
    safeTool(async (args: { exportModuleId?: string | number; maxModules: number }) =>
      session.unpackWebpack(args),
    ),
  );

  server.registerTool(
    "generate_jsrpc",
    {
      title: "Generate JSRPC browser-to-proxy bridge",
      description: "Generate in-page hook stub, Python Flask HTTP proxy, and Burp Suite AutoDecoder configuration for exposing browser encryption functions directly to external tools.",
      inputSchema: {
        actionName: z.string().min(1).describe("Action name identifier, e.g. 'encrypt_password' or 'sign'."),
        targetExpression: z.string().min(1).describe("JavaScript expression callable in page, e.g. 'window.sign' or '__mcp_webpack_require__(42).encrypt'."),
        port: z.number().int().min(1024).max(65535).default(12080).describe("Local port for the Flask proxy bridge."),
      },
      annotations: { readOnlyHint: true },
    },
    safeTool(async (args: { actionName: string; targetExpression: string; port: number }) =>
      session.generateJsrpc(args),
    ),
  );

  return server;
}


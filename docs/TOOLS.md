# Tool Catalog & Reference Guide

`netvein-mcp` exposes **112 tools** through the Model Context Protocol. All tools return standardized JSON-compatible responses and respect bounded buffer limits.

---

## 1. Browser Lifecycle & Automation

| Tool | Parameters | Description |
|---|---|---|
| `browser_launch` | `targetUrl?`, `headless?`, `userDataDir?`, `executablePath?` | Automatically find and launch Chrome/Edge/Brave with remote debugging enabled (`--remote-debugging-port=9222`), or verify if already running. |
| `browser_targets` | None | List inspectable Chrome tabs/targets on the local CDP port. **Auto-launches browser if not running.** |
| `browser_attach` | `targetId?`, `url?`, `title?` | Attach the session to a specific tab by ID or substring. **Auto-launches browser and spawns page if none exist.** |
| `browser_detach` | None | Detach the CDP session without closing the browser. |
| `browser_status` | None | View current target, counters, pause state, and active URL. |
| `navigate` | `url`, `waitMs?` | Navigate the attached page to a URL and wait for load. |
| `page_snapshot` | `maxChars?` | Extract page title, visible text, and interactive elements. |
| `screenshot` | `type?`, `selector?` | Take a viewport, full-page, or element screenshot (base64 PNG). |
| `wait_for_selector`| `selector`, `timeoutMs?`| Poll until a CSS selector exists and is visible. |
| `click_selector` | `selector` | Dispatch a real mouse click at an element's center via Input domain. |
| `type_text` | `selector`, `text`, `clear?` | Focus an element and type text via Input domain. |
| `press_key` | `key` | Dispatch a keyboard key press (`Enter`, `Tab`, `Escape`, `ArrowDown`). |
| `hover_selector` | `selector` | Dispatch mouse move to hover over an element. |
| `scroll_page` | `deltaX?`, `deltaY?` | Dispatch mouse wheel scroll event. |
| `select_option` | `selector`, `value` | Select an option in a `<select>` dropdown. |
| `reload_page` | `ignoreCache?` | Reload the current page. |
| `set_viewport` | `width`, `height`, `mobile?` | Emulate screen dimensions and device scale factor. |
| `set_user_agent` | `userAgent` | Override the browser's User-Agent string. |
| `evaluate` | `expression`, `awaitPromise?` | Evaluate arbitrary JavaScript in the page execution context. |

---

## 2. Storage & Cookie Inspection

| Tool | Parameters | Description |
|---|---|---|
| `get_cookies` | `urls?` | Retrieve all cookies for the current page or specified URLs. |
| `set_cookie` | `name`, `value`, `domain`, `path?`, `secure?` | Inject or update a cookie in the browser profile. |
| `delete_cookies` | `name`, `domain?` | Delete specific cookies by name. |
| `get_storage` | `type` (`local` / `session`) | Read all key-value entries from localStorage or sessionStorage. |
| `set_storage` | `type`, `key`, `value` | Set an item in localStorage or sessionStorage. |
| `clear_storage` | `type` | Clear all entries from localStorage or sessionStorage. |

---

## 3. Cryptography & Reverse Engineering Suite

| Tool | Parameters | Description |
|---|---|---|
| `detect_crypto` | `scriptId?`, `urlContains?`, `scanGlobalMemory?` | Scan scripts and memory for cryptographic signatures (AES, SM4, MD5, SHA, RSA, CryptoJS, JSEncrypt, Forge, WebCrypto). |
| `find_crypto_candidates` | `scriptId?`, `targetParams?` | AST analysis to score and rank candidate encryption/signing functions based on parameter names and bitwise operations. |
| `classify_anticrawl` | `scriptId?` | Detect bot defense vendors (Cloudflare, Akamai, DataDome, GeeTest, reCAPTCHA, DingXiang), JSVMP, and anti-debug loops. |
| `unpack_webpack` | `exportModuleId?`, `maxModules?` | Discover Webpack/Vite runtimes, intercept `__webpack_require__`, list modules, and dump specific module exports. |
| `generate_jsrpc` | `actionName`, `targetExpression`, `port?` | Generate browser hook stub, Python Flask HTTP proxy, and Burp Suite AutoDecoder configuration. |

---

## 4. Source Intelligence & Anti-Debug

| Tool | Parameters | Description |
|---|---|---|
| `list_scripts` | `urlContains?`, `limit?` | List all parsed JavaScript files with URLs, hashes, and source map links. |
| `get_script_source`| `scriptId`, `maxChars?` | Fetch bounded source code of a loaded script. |
| `search_scripts` | `pattern`, `regex?`, `urlContains?` | Search across all loaded scripts for strings or regex patterns. |
| `ast_search` | `pattern`, `urlContains?` | Search scripts by AST node structure (e.g. CallExpression, BinaryExpression). |
| `beautify_script` | `scriptId`, `maxChars?`, `offset?` | Format minified JavaScript with indentation and clean line wrapping. |
| `extract_sourcemap`| `scriptId?`, `urlContains?` | Recover original unminified TypeScript/React files from source maps. |
| `extract_endpoints`| `scriptId?`, `includeNetwork?`, `includeDom?` | Extract REST API endpoints, full URLs, WebSockets, hidden form inputs, and JWT tokens. |
| `anti_debug_bypass`| None | Neutralize `debugger` traps in Function/eval/timers, disable console.clear, and mask DevTools dimensions. |
| `inspect_element` | `selector` | Inspect DOM element tags, styles, and attached JS event listeners (`click`, `change`, `submit`). |
| `override_function`| `target`, `behavior`, `mockReturnValue?` | Monkey-patch an in-page function to log arguments or return mock values. |

---

## 5. Debugger & Breakpoints

| Tool | Parameters | Description |
|---|---|---|
| `set_breakpoint` | `scriptId?`, `urlRegex?`, `lineNumber`, `condition?` | Set a standard JavaScript line breakpoint with optional condition. |
| `remove_breakpoint`| `breakpointId` | Remove a JavaScript line breakpoint. |
| `list_breakpoints` | None | List active JS line breakpoints. |
| `set_dom_breakpoint`| `selector`, `type` | Set a DOM modification breakpoint (`subtree-modified`, `attribute-modified`, `node-removed`). |
| `remove_dom_breakpoint`| `selector`, `type` | Remove a DOM breakpoint. |
| `set_event_breakpoint`| `eventName` | Break on DOM events (`click`, `submit`, `keydown`, `timer`, `WebSocket`). |
| `remove_event_breakpoint`| `eventName` | Remove an event listener breakpoint. |
| `set_xhr_breakpoint`| `url` | Break on XHR or fetch requests matching URL pattern. |
| `remove_xhr_breakpoint`| `url` | Remove an XHR breakpoint. |
| `list_all_breakpoints`| None | Summary table of all active JS, DOM, Event, and XHR breakpoints. |
| `get_debugger_status`| None | Check if the debugger is paused, hit breakpoint ID, and call frames. |
| `get_call_frame_scope`| `callFrameId` | Inspect all local, closure, and global variables in a paused call frame. |
| `set_variable_value`| `callFrameId`, `scopeNumber`, `variableName`, `newValue` | Mutate a variable's value live on the paused call stack. |
| `restart_frame` | `callFrameId` | Re-execute the selected call frame from its beginning. |
| `evaluate_on_call_frame`| `callFrameId`, `expression` | Evaluate an expression in the exact scope of a paused call frame. |
| `step_execution` | `action` (`into` / `over` / `out`) | Step through execution while paused. |
| `resume_execution`| None | Resume JavaScript execution. |
| `set_pause_on_exceptions`| `state` (`none` / `uncaught` / `all`) | Break automatically when an exception is thrown. |
| `smart_breakpoint`| `nameOrPattern` | Automatically find function declaration in scripts and place a breakpoint. |
| `conditional_logpoint_batch`| `entries` | Install non-breaking logpoints that emit to console without pausing execution. |

---

## 6. Network & Request Interception

| Tool | Parameters | Description |
|---|---|---|
| `get_network` | `urlContains?`, `status?`, `limit?` | Query captured HTTP requests and responses. |
| `get_network_body`| `requestId`, `maxChars?` | Fetch response body (JSON, text, or base64 binary). |
| `wait_for_network`| `urlContains?`, `timeoutMs?` | Block until a specific network request completes. |
| `search_network` | `query`, `isRegex?` | Search across all captured request URLs, headers, and post data. |
| `get_websocket_messages`| `requestId?`, `limit?` | Inspect incoming and outgoing WebSocket frames. |
| `set_request_interception`| `urlPattern`, `action` (`block`/`mock`/`modify`), ... | Dynamically intercept requests to block, mock responses, or tamper with headers/body. |
| `list_interceptions`| None | List active request interception rules. |
| `clear_interceptions`| None | Clear all request interception rules. |
| `export_har` | None | Export captured traffic as a valid HAR 1.2 archive for Burp or Caido. |
| `trace_request_origin`| `requestId` | Trace the JavaScript call stack and initiator that triggered a request. |
| `replay_and_verify`| `requestId`, `overrides?` | Replay a request from inside the browser context and compare responses. |
| `openapi_generator`| `urlContains?` | Generate an OpenAPI 3.0 draft specification from observed network traffic. |

---

## 7. Instrumentation, Hooks & Taint Tracking

| Tool | Parameters | Description |
|---|---|---|
| `install_hook` | `kind`, `includeResponse?` | Install runtime hooks (`fetch`, `xhr`, `websocket`, `btoa`, `crypto`). |
| `remove_hook` | `hookId` | Remove an installed runtime hook. |
| `list_hooks` | None | List all active runtime hooks. |
| `get_hook_events`| `hookId?`, `limit?` | Retrieve captured hook events and argument values. |
| `hook_crypto_all`| None | Pre-configured hook to capture all Web Crypto API calls and preimages. |
| `taint_track` | `expression`, `tokens` | Inject runtime tracking on sensitive variables or data sinks. |
| `taint_events` | `trackerId?` | View events where tainted data was accessed or transferred. |
| `taint_stop` | `trackerId` | Stop a taint tracking probe. |
| `taint_list` | None | List active taint trackers. |
| `timeline_recorder`| `action` (`read` / `clear` / `pause` / `resume`) | Inspect the chronological timeline of events across all domains. |
| `get_console` | `limit?`, `type?` | View captured console logs, warnings, and errors. |
| `search_console`| `query`, `level?`, `isRegex?` | Search console logs by text or regex. |
| `clear_capture_logs`| None | Clear network, console, timeline, and hook event buffers. |

---

## 8. Versioning & Diffs

| Tool | Parameters | Description |
|---|---|---|
| `capture_bundle_snapshot`| `key` | Snapshot all current script URLs, hashes, and sizes for drift detection. |
| `diff_bundles` | `baselineKey`, `currentKey` | Compare two bundle snapshots to identify updated or injected scripts. |
| `env_diff` | None | Compare browser environment globals against a standard Node.js environment to spot anti-crawl tampering. |

---

## 9. Stealth & Fingerprint Control

| Tool | Parameters | Description |
|---|---|---|
| `stealth_enable` | `profile` (`off`/`basic`/`strict`), `seed?` | Install anti-detection patches on the attached target. `basic` covers identity leaks; `strict` adds canvas, WebGL and audio noise plus `Function.prototype.toString` integrity. |
| `stealth_status` | None | Report the active profile, its patch ids, and whether a patch script is registered. |
| `stealth_probe` | `maxChars?` | Run a detection suite in the page and report, per check, what still leaks and the observed value. |

---

## 10. Semantic Tree & Pruning

| Tool | Parameters | Description |
|---|---|---|
| `semantic_view` | `interactiveOnly?`, `maxNodes?`, `maxChars?` | Compressed accessibility tree with short integer ids, replacing raw DOM dumps. |
| `interact_semantic` | `id`, `action`, `value?`, `snapshotVersion?` | Click, type, hover, focus or select by semantic id. A mismatched `snapshotVersion` is rejected rather than applied. |
| `semantic_diff` | `maxChanges?` | Re-read the tree and return only nodes added, removed or changed since the previous snapshot. |

---

## 11. Identity & Captcha

| Tool | Parameters | Description |
|---|---|---|
| `identity_create` | `name`, `proxy?`, `seed?` | Create and record a browser context for an identity, optionally proxy-bound. The proxy is TCP-probed first and its scheme is preserved. The session does **not** switch into the context. |
| `identity_use` | `name` | Apply an identity's fingerprint seed to the stealth layer. Does not change the attached tab. |
| `identity_list` | None | List identities with proxy, seed and usability. |
| `identity_export` | `name` | Serialize cookies and web storage into one portable JSON document. |
| `identity_import` | `json`, `name?` | Restore an exported identity. Validated in full before anything is written. |
| `captcha_detect` | None | Detect Turnstile, hCaptcha, reCAPTCHA or GeeTest and report the evidence. Reports only. |
| `captcha_provider_hook` | `provider`, `apiKey` | Register an external solving endpoint. Off by default. |

---

## 12. Traffic Wire Layer

A netvein-owned loopback `mitmdump` daemon (pipx install mitmproxy) captures at the wire:
all tabs, survives CDP detach, out-of-page replay. `traffic_start` first; browsers launched
by netvein afterwards route through the proxy automatically.

| Tool | Parameters | Description |
|---|---|---|
| `traffic_start` | `port?`, `caDir?`, `allowHosts?`, `attachBrowser?` | Spawn the owned mitmdump daemon with the netvein control addon. Private confdir CA; loopback only. |
| `traffic_stop` | None | Gracefully stop the daemon. Flow history is lost unless exported first. |
| `traffic_status` | None | Daemon state (`stopped`/`running`/`dead`), proxy endpoint, held ids, last stats. |
| `traffic_flows` | `host?`, `pathContains?`, `method?`, `status?`, `since?`, `heldOnly?`, `limit?`, `full?` | Filter the flow ring; compact one-line view by default, `full=true` for raw summaries. |
| `traffic_flow` | `id`, `part?`, `maxChars?` | Curated headers + beautified body for one flow; `request`/`response`/`both`/`ws`. |
| `traffic_curl` | `id` | Ready-to-run, shell-quoted curl reconstructed from a captured flow. |
| `traffic_breakpoint_set` | `pattern`, `maxHoldMs?` | Hold flows matching a URL regex in flight; auto-passes at `maxHoldMs`. Returns the breakpoint table. |
| `traffic_breakpoint_release` | `flowId`, `action?`, `patch?` | Release a held flow: `pass`, `modify` (url/method/headers/body), or `drop`. |
| `traffic_replay` | `id`, `overrides?`, `compare?` | Resend a captured request through the daemon's proxy (no page context), so the replay itself appears in `traffic_flows`; optional path-level diff vs the original. |
| `traffic_export` | `format?`, `path?` | Write flow history as HAR 1.2 or JSONL; returns path + count. |

---

## 13. Maintenance

| Tool | Parameters | Description |
|---|---|---|
| `check_for_update` | `force?` | Compare this build against the project's git remote and report whether a newer release exists. Compares release tags **and** the tracked branch head, because the repository may carry no tags. Read-only: never downloads, replaces files, or executes remote content. |

Disabled with `NETVEIN_UPDATE_CHECK=0`; the interval is `NETVEIN_UPDATE_INTERVAL_HOURS` (default 24). A non-blocking check also runs at start-up and reports through MCP logging.

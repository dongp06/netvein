# Technical Architecture & Design

`netvein-mcp` is designed as a high-performance, single-session Chrome DevTools Protocol (CDP) bridge tailored specifically for AI-driven web reverse engineering.

```text
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                             │
│        (Antigravity, Codex, Claude Code, Cursor)            │
└──────────────────────────────┬──────────────────────────────┘
                               │ JSON-RPC (stdio transport)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 netvein-mcp                      │
│                                                             │
│   ┌─────────────────────┐       ┌──────────────────────┐    │
│   │   McpServer Core    │       │    Server Prompts    │    │
│   │   (Tools & Schemas) │       │   (Triage & Sign)    │    │
│   └──────────┬──────────┘       └──────────────────────┘    │
│              │                                              │
│              ▼                                              │
│   ┌────────────────────────────────────────────────────┐    │
│   │                     CdpSession                     │    │
│   │  (Maintains single persistent tab session state)   │    │
│   └──────┬────────────┬─────────────┬────────────┬─────┘    │
│          │            │             │            │          │
│          ▼            ▼             ▼            ▼          │
│     Runtime &    Debugger &      Fetch &     DOM, Storage   │
│     Console       Hooks       Interception    & Cookies     │
└──────────┼────────────┼─────────────┼────────────┼──────────┘
           │            │             │            │
           ▼            ▼             ▼            ▼
┌─────────────────────────────────────────────────────────────┐
│              Chromium Browser (CDP on 127.0.0.1:9222)       │
│  Page Target  │  V8 Engine  │  Network Stack  │  DOM Tree   │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Design Principles

### Single Coherent Session
Most web reverse engineering workflows require shared context: setting a breakpoint on an event listener, clicking a button, intercepting the request, and inspecting the paused call frame. Unlike stateless headless browser wrappers, `netvein-mcp` connects to a single persistent tab, preserving state across all 87 tools.

### Bounded Memory & Token Safety
Browser sessions generate massive amounts of data (tens of thousands of network frames, script files, and console logs). To prevent blowing up the LLM's context window:
- Strings and post data are truncated to predefined safe boundaries (`MAX_STORED_TEXT = 20,000`).
- Sensitive transport headers (`Authorization`, `Cookie`, `X-API-Key`) are redacted in tool outputs.
- Captured arrays (network records, console events, timeline items) use FIFO sliding windows with strict capacity limits.

---

## 2. Core Subsystems

### A. Dynamic Request Interception (`CDP Fetch Domain`)
While `Network.enable` can only monitor traffic passively, `netvein-mcp` utilizes `Fetch.enable` and `Fetch.requestPaused` to allow dynamic request tampering:
- **`block`**: Fails the request with `BlockedByClient`.
- **`mock`**: Returns a custom synthetic status code, response headers, and base64 response body without touching the network.
- **`modify`**: Dynamically overrides outgoing URL, HTTP method, headers, or POST payload on the fly.

### B. Multi-Tier Breakpoint Subsystem
Reverse engineers cannot always find the exact function name in minified code. The server supports four orthogonal breakpoint strategies:
1. **Source Breakpoints**: Set by script ID / URL regex and line number.
2. **DOM Modification Breakpoints**: Triggered on `subtree-modified`, `attribute-modified`, or `node-removed`.
3. **Event Listener Breakpoints**: Triggered on DOM events (`click`, `submit`, `keydown`, `timer`, `WebSocket`).
4. **XHR / Fetch Breakpoints**: Triggered whenever `fetch` or `XMLHttpRequest.send()` targets a matching URL pattern.

### C. Static & AST Candidate Scoring Engine
Built on top of Acorn parser (`acorn` & `acorn-walk`):
- Tolerant AST parsing (automatic fallback between ES module and script modes).
- Mathematical heuristic scoring based on parameter names (`password`, `sign`, `token`, `nonce`), bitwise operator density (`^`, `>>>`, `<<`), and `.toString(16)` conversions.

### D. Cryptographic Fingerprint Database
Identifies standard and proprietary cryptographic implementations directly in JavaScript source code without running it:
- **AES**: Standard Rijndael S-Box (`0x63, 0x7c...`).
- **SM4**: National Secret SM4 S-Box (`0xd6, 0x90, 0xe9, 0xfe...`).
- **MD5**: Initial initialization vector constants (`0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`).
- **SHA-1 / SHA-256 / SHA-512**: State initialization constants and round tables.
- **RSA**: PKCS#1 and PKCS#8 PEM public and private key delimiters.
- **Libraries**: CryptoJS, JSEncrypt, Forge, WebCrypto Subtle, WebAssembly modules.

### E. JSRPC Automation Pipeline
For complex, heavily obfuscated or VM-protected (JSVMP) targets, manual de-obfuscation is inefficient. The JSRPC pipeline automatically generates:
1. **In-Page Stub**: Registers the target function into `window.__JSRPC_ACTIONS__`.
2. **Flask HTTP Bridge**: Exposes a local HTTP POST/GET endpoint (`http://127.0.0.1:12080/go`) that allows external programs to invoke the browser function remotely.
3. **Burp Suite AutoDecoder Config**: Provides step-by-step instructions for transparent automated decryption/re-encryption in Burp Repeater.

---

### F. Stealth, Semantic Pruning & Identity Isolation

Three additions sit on top of the existing CDP session without changing it.

**Stealth layer.** Patch payloads are generated by pure functions in `src/stealth.ts`
and injected through `Page.addScriptToEvaluateOnNewDocument`, the same mechanism
already used for runtime hooks. All fingerprint noise is derived from a per-identity
seed, because inconsistent spoofing is itself a detection signal. `stealth_probe`
runs a detection suite in-page so patch rot is visible rather than silent.

**Semantic pruner.** `src/pruner.ts` compresses `Accessibility.getFullAXTree` output
into an integer-addressed flat tree, discarding ignored, generic and presentational
nodes. Ids are valid only for the snapshot version that produced them; navigation and
`DOM.documentUpdated` invalidate the map. A stale id is rejected with
`ERR_STALE_NODE_ID` rather than applied to a node that reuses the same
`backendDOMNodeId`.

**Identity records.** Each identity owns a `Target.createBrowserContext`, created with a
proxy when one is supplied, so any page later opened in that context inherits the proxy
for every socket it opens. The context is created and recorded; **the session does not
switch into it** — `identity_use` applies the identity's fingerprint seed to the stealth
layer and returns, and all tools continue to drive the tab selected by `browser_attach`.
Switching the active target into an identity's context is not implemented. Cookies and
web storage serialize into one portable document for replay elsewhere.

**Error envelope.** New tools return `{success, error_code, message, suggestion}` so
the model can correct itself on the next turn instead of the reasoning chain breaking.
The 88 pre-existing tools keep their original error shape.

### G. Update Checking

`src/updater.ts` compares the local build against the git remote and reports the
difference. It is **read-only by construction**: the module has no code path that
downloads, writes to the repository, or executes remote content, so an update is always
an explicit operator decision. `check_for_update` exposes it on demand and a
non-blocking check runs at start-up.

Two signals are reported, because neither is sufficient alone. Release tags give a
version comparison but a repository may carry none — this one did not — so the tracked
branch head is compared against local HEAD as well. Without a fetch the two heads
cannot be ordered, so the result reports `branchDiffers` rather than claiming which
side is ahead.

The start-up report goes through MCP logging, never stdout: on a stdio transport stdout
is the JSON-RPC channel and a stray line would corrupt the protocol.

---

### H. Traffic Wire Layer

The CDP network capture is tab-scoped and surgical; the traffic layer adds the wire.
`src/mitm/manager.ts` spawns and owns a `mitmdump` bound to loopback, loading
`python/netvein_addon.py`, a thin control servant that speaks JSON-lines over a private
127.0.0.1 control socket (port discovered through a portfile in the confdir). Everything
the model sees is shaped in Node (`src/mitm/store.ts`); the daemon only captures, holds,
replays and exports, because the flow objects live there.

That split buys what CDP cannot: capture across all tabs and non-browser clients, a
history that survives detach, out-of-page replay with overrides, in-flight holds
(`traffic_breakpoint_set`) that auto-pass after `maxHoldMs` rather than wedging the
client, and HAR/JSONL export for Burp/Charles. Browsers launched by netvein pick up
`--proxy-server` plus an `--ignore-certificate-errors-spki-list` pin automatically; an
already-attached browser is reported as a note, never silently rerouted.

**Trust model.** The daemon is loopback-only and netvein-owned: the CA lives in a
private confdir, is never installed into any system trust store, and the spki pin is
scoped to the browsers netvein itself launches. Replay deliberately disables TLS
verification — RE targets routinely present certificates a loopback CA cannot verify.

Failure states are distinct: `stopped` (never started or cleanly stopped), `running`,
and `dead` (the child died; queued commands reject and flow history is lost). A stopped
daemon answers `traffic_status` as data, not as an error.

---

## 3. Error Handling & Resilience
- **Rejection Guards**: Captures `unhandledRejection` events from remote WebSocket disconnects without crashing the server process.
- **Auto-Recovery**: If a tab closes or navigates away unexpectedly, the session resets internal buffers and cleanly reports target detachment.
- **Standardized MCP Tool Results**: All handlers wrap errors in standard MCP JSON error structures (`isError: true`) with actionable diagnostics.

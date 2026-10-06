<div align="center">

<img src="assets/brand/netvein-logo.svg" width="620" alt="NetVein" />

Already installed? Run `netvein install` to wire up new agents.

Follow [@dongp06](https://github.com/dongp06) on GitHub for updates.

### Supercharge Claude Code, Cursor, Codex, OpenCode, Hermes Agent, Gemini, and Antigravity with Autonomous Web Reverse Engineering & Wire-Level Dynamic Instrumentation

**100% Local · Single-Session CDP · Autonomous Capture Kit · Wire-Level Traffic Daemon · 123 Specialized Tools**

[![npm version](https://img.shields.io/npm/v/netvein-mcp.svg)](https://www.npmjs.com/package/netvein-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-brightgreen.svg)](https://nodejs.org/)
[![Tests](https://img.shields.io/badge/Tests-203%2F203%20Passing-brightgreen)](test/index.test.ts)

[![Windows](https://img.shields.io/badge/Windows-supported-blue.svg)](#supported-platforms)
[![macOS](https://img.shields.io/badge/macOS-supported-blue.svg)](#supported-platforms)
[![Linux](https://img.shields.io/badge/Linux-supported-blue.svg)](#supported-platforms)

[![Claude Code](https://img.shields.io/badge/Claude_Code-supported-blueviolet.svg)](#supported-agents)
[![Cursor](https://img.shields.io/badge/Cursor-supported-blueviolet.svg)](#supported-agents)
[![Codex](https://img.shields.io/badge/Codex-supported-blueviolet.svg)](#supported-agents)
[![OpenCode](https://img.shields.io/badge/OpenCode-supported-blueviolet.svg)](#supported-agents)
[![Hermes Agent](https://img.shields.io/badge/Hermes_Agent-supported-blueviolet.svg)](#supported-agents)
[![Gemini](https://img.shields.io/badge/Gemini-supported-blueviolet.svg)](#supported-agents)
[![Antigravity](https://img.shields.io/badge/Antigravity-supported-blueviolet.svg)](#supported-agents)

</div>

## Contents

- [Get Started](#get-started)
- [Why NetVein?](#why-netvein)
- [Key Features](#key-features)
- [Autonomous Capture Kit Workflow](#autonomous-capture-kit-workflow)
- [CLI Reference](#cli-reference)
- [MCP Tool Catalog (123 Tools)](#mcp-tool-catalog-123-tools)
- [Project Workspace (`.netvein/`)](#project-workspace-netvein)
- [Supported AI Assistants & Configuration](#supported-ai-assistants--configuration)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [Supported Platforms](#supported-platforms)
- [Supported Agents](#supported-agents)
- [License](#license)

---

## Get Started

### 1. Install the CLI

**No Node.js required** — one command grabs the right build for your OS:

```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/dongp06/netvein-mcp/main/install.sh | sh

# Windows (PowerShell)
irm https://raw.githubusercontent.com/dongp06/netvein-mcp/main/install.ps1 | iex
```

<details>
<summary><b>Already have Node? Use npm instead (works on any version)</b></summary>

```bash
npm i -g netvein-mcp
```

<sub>The installer puts `netvein` and `netvein-mcp` on your PATH — open a new terminal before the next step so the command resolves cleanly.</sub>

</details>

### 2. Wire up your agent(s)

In a **new terminal**, run the installer to connect NetVein to the agents you use:

```bash
netvein install
```

<sub>Detects and auto-configures Claude Code, Cursor, Codex CLI, OpenCode, Hermes Agent, Gemini CLI, and Antigravity IDE — wiring the NetVein MCP server into each. **This is the step that connects NetVein to your agent;** installing the CLI in step 1 does not do it on its own. NetVein boots Chrome, Edge, or Brave automatically on port `9222` upon your first tool call. (Shortcut: `npx netvein-mcp install` downloads and runs this in one go.)</sub>

### 3. Initialize each project (Optional)

```bash
cd your-project
netvein init
```

<sub>Like CodeGraph's `.codegraph/`, `netvein init` creates a local `.netvein/` directory (`config.json`, `captures/`, `notes/`). When active, finished network flows are automatically persisted to disk and project-level configs cascade seamlessly into your sessions.</sub>

### Uninstall

Changed your mind? One command removes NetVein from every agent it configured **and** the CLI itself:

```bash
netvein uninstall
```

Pass `--keep-cli` to remove only the agent configurations and keep the CLI installed.

---

## Why NetVein?

Traditional AI browser integrations (Puppeteer, Playwright, standard CDP scrapers) are designed for end-to-end web testing or scraping rendered text. When an agent is tasked with **reverse engineering a web application, analyzing obfuscated request signatures, neutralizing bot defenses, or capturing wire-level network streams**, traditional tools fail:

1. **Context Window Blowout**: Dumping raw `outerHTML` burns 50,000+ tokens per step with useless DOM noise.
2. **Blind to Network Signatures**: Standard tools cannot hook `window.crypto.subtle`, score candidate hashing functions via AST analysis, or hold in-flight requests for payload mutation.
3. **Bot Defense Traps**: Cloudflare Turnstile, Akamai, DataDome, and anti-debug `debugger;` loops freeze or disconnect generic automation agents.
4. **Subprocess Isolation**: External CLI scripts, Node.js fetch commands, and background tools bypass browser-only interceptors.

**NetVein solves this by placing a full-spectrum reverse engineering suite into your agent's hands:**

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AI Agent / MCP Client                           │
│        (Claude Code, Cursor, Codex, Antigravity, Gemini, OpenCode)     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ JSON-RPC (stdio transport)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                              NetVein MCP                               │
│                                                                        │
│  ├── 123 Specialized RE & CDP Tools (capture kit, AST, hooks)          │
│  ├── Autonomous Capture Kit (sessions, process shims, stream decoders) │
│  ├── Auto-Browser Launcher (Chrome, Edge, Brave auto-detection)        │
│  ├── Acorn AST Engine (bitwise density scoring, crypto fingerprinting) │
│  ├── In-Process Wire-Level mitmdump Daemon (in-flight breakpoint hold) │
│  └── .netvein Workspace (auto-capture flows, config cascade)           │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ WebSocket (port 9222)          │ HTTP Proxy (port 8080)
                    ▼                                ▼
┌───────────────────────────────────┐    ┌───────────────────────────────┐
│          Chromium Engine          │    │      Target Web Network       │
│  Runtime · Debugger · DOM · Fetch │    │  APIs · WebSockets · Proxies  │
└───────────────────────────────────┘    └───────────────────────────────┘
```

### NetVein vs. Generic Browser Tools

| Feature | Generic Browser MCPs | Playwright / Puppeteer | NetVein MCP |
|---|:---:|:---:|:---:|
| **DOM Inspection** | Raw outerHTML (~50k tokens) | Raw HTML strings | **Integer-addressed semantic accessibility tree (~1-2k tokens)** |
| **Autonomous Capture Kit** | ❌ None | ❌ Manual scripts | **Autonomous sessions, node proxy shims, SSE/EventStream decoders, hex view** |
| **Crypto Fingerprinting** | ❌ None | ❌ None | **Static AST + S-Box detection (AES, SM4, RSA, MD5, SHA)** |
| **Signature Function Search** | ❌ None | ❌ None | **AST candidate scoring by bitwise density (`^`, `>>>`, `<<`)** |
| **SubtleCrypto Capture** | ❌ None | ❌ Manual scripts | **One-call `hook_crypto_all` (extracts keys & plaintext preimages)** |
| **Wire-Level Traffic Capture** | Tab-bound only | Process-bound only | **Loopback daemon (all tabs, survives detach, WebSocket frames)** |
| **In-Flight Request Hold** | Basic URL block | Basic abort/continue | **Full regex hold with in-flight header/body mutation or drop** |
| **Anti-Debug Bypass** | ❌ Freezes | ❌ Freezes | **Auto defuse `debugger;` loops, console tampering, timing traps** |
| **Obfuscated JS Deobfuscation** | ❌ Manual | ❌ Manual | **Automated JSRPC (Python Flask bridge + Burp AutoDecoder stubs)** |
| **Project Workspace** | ❌ None | ❌ None | **`.netvein/` auto-capture history, JSONL persistence, config cascade** |

---

## Key Features

| Capability | Description |
|---|---|
| 📡 **Autonomous Capture Kit** | AI agents autonomously start, stop, filter, inspect, and search structured traffic sessions (`session.json`, `flows.jsonl`, `bodies/`). Zero manual scripts required. |
| 🚀 **Zero-Config Auto Browser Launch** | Automatically locates Chrome, Microsoft Edge, or Brave on Windows, macOS, or Linux, and boots it with `--remote-debugging-port=9222` upon tool invocation. |
| 👁️ **Semantic Tree Pruner** | Replaces multi-megabyte HTML dumps with a compact, integer-addressed accessibility view (`semantic_view`). Inspect and interact (`interact_semantic`) with surgical token efficiency. |
| 🛑 **Multi-Tier Breakpoints** | Pause execution on **XHR/Fetch URLs**, **DOM mutations** (subtree/attribute/removal), **DOM events** (click, submit, keydown), or **AST function matches**. Evaluate and mutate variables live on call frames. |
| 🔐 **Cryptographic Fingerprinting** | Instant static identification of **AES S-Boxes**, **SM4 S-Boxes**, **MD5/SHA constants**, **RSA PEMs**, **RC4**, and libraries (**CryptoJS, JSEncrypt, Forge, WebCrypto, WebAssembly**). |
| 🧠 **AST Function Candidate Scoring** | Scans scripts to rank encryption and request signing candidates based on parameter naming patterns (`sign`, `token`, `hash`) and bitwise operator frequency. |
| 🧵 **Wire-Level Traffic Daemon** | Built-in loopback `mitmdump` proxy: capture all browser tabs and external tools, hold in-flight requests (`traffic_breakpoint_set`), tamper with headers/body, replay outside the page, and export to **HAR 1.2 / JSONL**. |
| 🛡️ **Anti-Debug & Bot Evasion** | Built-in neutralizing of `debugger` traps and console hijacking. Classifies **Cloudflare (Turnstile/Challenge)**, **Akamai Bot Manager**, **DataDome**, **GeeTest**, **reCAPTCHA**, and **JSVMP opcode loops**. |
| 🔌 **Automated JSRPC Bridge** | When encryption logic is heavily obfuscated or VM-protected (JSVMP), generate in-page hook stubs, a local Python Flask HTTP RPC bridge, and Burp Suite AutoDecoder configurations in one call. |
| 🗂️ **Project Workspace (`.netvein/`)** | Per-project directory: `netvein init` lays down `config.json` defaults, auto-captures every finished traffic flow to `captures/`, and routes exports cleanly. Found by upward discovery. |
| 📜 **Source Recovery & Endpoint Audit** | Automatically downloads and parses source maps to recover original unminified TypeScript/React sources. Extracts all REST routes, URL parameters, hidden form fields, and API tokens. |
| 🔒 **100% Local & Private** | Operates entirely on your local machine without sending code, telemetry, or API tokens to any remote service. |

---

## Autonomous Capture Kit Workflow

NetVein includes an autonomous capture harness modeled after production reverse-engineering kits (`capture-kit`), elevated so that AI agents drive the complete capture lifecycle directly via MCP tools without writing manual PowerShell or Bash scripts.

### 1. Structure of a Capture Session

When an agent calls `capture_session_start(name: "checkout")`, NetVein creates a structured capture directory:

```
.netvein/
└── captures/
    └── checkout-2026-10-06_16-00-00/
        ├── session.json         # Session metadata, timing, focus rules, total flow count
        ├── flows.jsonl          # Stream of completed HTTP/WS flows (JSONL format)
        └── bodies/              # Binary raw bodies, deduplicated by SHA-256
            ├── flow-01-req-a1b2c3d4e5f6.bin
            └── flow-01-res-f6e5d4c3b2a1.bin
```

### 2. Autonomous Execution Lifecycle

```
Agent: capture_session_start(name, focus)
   │
   ├─► Agent: capture_exec(command) or CDP Navigate
   │      │
   │      └─► Subprocess traffic routed through NetVein + Node.js Shim
   │
   ├─► Bodies dumped to bodies/ & flows logged to flows.jsonl
   │
   ├─► Agent: capture_search(query)
   │
   ├─► Agent: capture_inspect_body(flowId / filePath) [auto-decompress gzip/br/deflate]
   │
   ├─► Agent: capture_decode_stream(SSE / AWS EventStream)
   │
   └─► Agent: capture_session_stop()
```

1. **Start Named Capture**:
   The agent calls `capture_session_start` with target domains in `focus`. Noisy analytics (Sentry, Segment, Datadog) are silently dropped, keeping token budgets focused on relevant APIs.
2. **Execute Proxied Subprocesses**:
   The agent calls `capture_exec` to spawn CLI programs (Node.js, Python, curl). NetVein injects `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, and the `node-proxy.mjs` shim (which intercepts Node.js `undici` and `globalThis.fetch`), capturing all network operations.
3. **Inspect Bodies & Decode Streams**:
   - `capture_inspect_body`: Inspects request/response payloads with automatic decompression (gzip, brotli, deflate) and presentation in JSON, text, hex dump, or base64.
   - `capture_decode_stream`: Decodes streaming responses (Server-Sent Events / SSE and AWS EventStream) into clean, structured event arrays for AI model inspection.
   - `capture_search`: Runs multi-session searches across URLs, headers, and payload bodies.
4. **Finalize Session**:
   The agent calls `capture_session_stop` to close out the session and write final statistics to `session.json`.

---

## CLI Reference

NetVein includes a unified CLI that supports both standalone project workflows and running as an MCP server:

```bash
netvein [command] [options]
```

### Commands

| Command | Description |
|---|---|
| `netvein serve [--mcp]` | Start NetVein as an MCP server over stdio for AI assistants |
| `netvein init [path] [--force]` | Initialize a `.netvein` project workspace in the target directory |
| `netvein status [path]` | Inspect current workspace configuration and newest capture artifacts |
| `netvein install [options]` | Automatically register NetVein MCP into detected AI assistants |
| `netvein uninstall [options]` | Remove NetVein MCP configuration from AI assistants |

### Options & Environment Variables

| Flag / Option | Description |
|---|---|
| `--project <dir>` | Explicit `.netvein` workspace directory (overrides upward discovery) |
| `--host <string>` | CDP host (default: `127.0.0.1` or `CDP_HOST` env) |
| `--port <number>` | CDP port (default: `9222` or `CDP_PORT` env) |
| `--target <agents>` | Target assistants for install/uninstall (`claude,cursor,antigravity,codex,all`) |
| `--force` | Force initialization or overwrite existing assistant configurations |
| `-v, --version` | Display version number |
| `-h, --help` | Display command help |

---

## MCP Tool Catalog (123 Tools)

Tools are organized by reverse engineering domain. Each tool provides rich argument schemas and structured error envelopes.

### 🕹️ Browser Lifecycle & Hardware Emulation (18 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `browser_launch` | Launch Chrome/Edge/Brave with CDP debugging enabled | `targetUrl`, `headless`, `userDataDir` |
| `browser_targets` | List inspectable browser tabs and targets | *None* |
| `browser_attach` | Attach CDP session to a specific tab target | `targetId` |
| `browser_detach` | Detach CDP session from the currently attached target | *None* |
| `browser_status` | Report current CDP connection and target status | *None* |
| `navigate` | Navigate attached tab to a URL and wait for load | `url`, `waitUntil` |
| `page_snapshot` | Capture complete HTML and title of the page | *None* |
| `screenshot` | Capture full-page or element screenshot (PNG/JPEG) | `selector`, `fullPage`, `format` |
| `wait_for_selector` | Wait for a DOM selector to appear or match state | `selector`, `timeout` |
| `click_selector` | Dispatch genuine hardware mouse click on an element | `selector`, `button`, `clickCount` |
| `type_text` | Dispatch real keyboard typing into an element | `selector`, `text`, `delay` |
| `press_key` | Dispatch specific keyboard key / combination | `key`, `modifiers` |
| `hover_selector` | Move mouse cursor over specified DOM element | `selector` |
| `scroll_page` | Scroll viewport by coordinate delta or to bottom | `deltaX`, `deltaY`, `toBottom` |
| `select_option` | Select option within `<select>` element | `selector`, `value` |
| `reload_page` | Reload current page with optional cache bypass | `ignoreCache` |
| `set_viewport` | Resize browser viewport dimensions and DPR | `width`, `height`, `deviceScaleFactor` |
| `set_user_agent` | Override browser User-Agent and platform string | `userAgent`, `platform` |

### 👁️ Semantic UI & Accessibility Tree (3 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `semantic_view` | Extract integer-addressed compact accessibility tree (~1-2k tokens) | *None* |
| `interact_semantic` | Interact with elements using semantic integer IDs (click, type, focus) | `nodeId`, `action`, `text` |
| `semantic_diff` | Compute structural visual diff between two page states | `snapshotA`, `snapshotB` |

### 📡 Autonomous Capture Kit (9 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `capture_session_start` | Start structured session (`session.json`, `flows.jsonl`, `bodies/`); configures focus domain filters, telemetry dropping, secrets policy | `name`, `focus`, `dropTelemetry`, `keepSecrets`, `storeBodies`, `port` |
| `capture_session_stop` | Finalize active capture session, persisting end timestamps and total flow counts | *None* |
| `capture_session_status` | Inspect active capture session metadata, live flow counts, body store paths, and proxy health | *None* |
| `capture_session_list` | List historical capture sessions saved in `.netvein/captures/`, sorted newest-first | *None* |
| `capture_exec` | Spawn external process (Node, Python, CLI tools) with `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, and Node.js fetch/undici shim preconfigured | `command`, `args`, `cwd`, `env`, `timeoutMs` |
| `capture_env` | Generate environment variable dictionary (`HTTP_PROXY`, `SSL_CERT_FILE`, `NODE_OPTIONS`) and CA cert path for external tools | `focus` |
| `capture_inspect_body` | Inspect request or response body by file path or flowId with auto-decompression (gzip, zlib, brotli) and formatting (json, text, hex, base64) | `filePath`, `flowId`, `part`, `format`, `maxChars` |
| `capture_decode_stream` | Decode streaming responses (Server-Sent Events / SSE or AWS EventStream binary chunks) into structured event lists | `type`, `filePath`, `flowId`, `content`, `maxEvents` |
| `capture_search` | Search captured requests, responses, headers, and bodies across all sessions with regex or substring matching | `query`, `isRegex`, `sessionId`, `limit` |

### 🧵 Wire-Level Traffic Daemon (10 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `traffic_start` | Boot loopback mitmdump daemon; auto-routes browser through it | `port`, `allowHosts`, `capture` |
| `traffic_stop` | Stop traffic daemon and release bound proxy ports | *None* |
| `traffic_status` | Report traffic daemon state, uptime, and captured count | *None* |
| `traffic_flows` | Filter and list captured network flows across all tabs | `host`, `pathContains`, `method`, `status` |
| `traffic_flow` | Inspect curated headers and beautified body for a single flow | `id`, `part`, `maxChars` |
| `traffic_curl` | Reconstruct ready-to-run curl command for a captured flow | `id` |
| `traffic_breakpoint_set` | Hold matching outgoing requests in flight by URL regex | `pattern`, `maxHoldMs` |
| `traffic_breakpoint_release`| Release held request: pass unchanged, modify headers/body, or drop | `flowId`, `action`, `patch` |
| `traffic_replay` | Resend flow outside browser with optional overrides and diff | `id`, `overrides`, `compare` |
| `traffic_export` | Export captured flow history as HAR 1.2 or JSONL | `format`, `path` |

### 🔬 Cryptography & Signature Analysis (5 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `detect_crypto` | Scan scripts for AES, DES, SM4, RSA, MD5/SHA, CryptoJS constants | `scriptId`, `urlPattern` |
| `find_crypto_candidates` | Rank candidate encryption/signing functions by AST scoring | `minScore`, `limit` |
| `hook_crypto_all` | Intercept `window.crypto.subtle` to capture keys & preimages | *None* |
| `unpack_webpack` | Inventory internal Webpack modules and export utilities | `chunkName` |
| `generate_jsrpc` | Generate browser hook stub + Python Flask bridge + Burp configs | `functionPath`, `port` |

### 🛑 Multi-Tier Breakpoints & Debugger (20 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `set_xhr_breakpoint` | Pause execution when request URL matches pattern | `urlPattern` |
| `remove_xhr_breakpoint` | Remove active XHR/Fetch URL breakpoint | `urlPattern` |
| `set_event_breakpoint` | Pause execution on DOM event listener triggers | `eventName` |
| `remove_event_breakpoint` | Remove active DOM event breakpoint | `eventName` |
| `set_dom_breakpoint` | Pause execution on DOM subtree/attribute mutation | `nodeId`, `type` |
| `remove_dom_breakpoint` | Remove active DOM mutation breakpoint | `nodeId`, `type` |
| `smart_breakpoint` | Set breakpoint based on function name or AST pattern | `target`, `condition` |
| `conditional_logpoint_batch`| Set multiple non-breaking logpoints across scripts | `logpoints` |
| `set_breakpoint` | Set standard line breakpoint in a script | `scriptId`, `lineNumber`, `condition` |
| `remove_breakpoint` | Remove breakpoint by ID | `breakpointId` |
| `list_breakpoints` | List all active breakpoints | *None* |
| `list_all_breakpoints` | Comprehensive inventory of XHR, DOM, Event, and Line breakpoints | *None* |
| `get_debugger_status` | Report debugger state (running, paused, call frames) | *None* |
| `get_call_frame_scope` | Inspect local/closure scope variables on paused call frame | `callFrameId` |
| `evaluate_on_call_frame` | Evaluate JS expression within paused call frame scope | `callFrameId`, `expression` |
| `set_variable_value` | Mutate variable value live on paused call frame | `callFrameId`, `scopeNumber`, `variableName`, `newValue` |
| `restart_frame` | Restart execution from top of specified call frame | `callFrameId` |
| `step_execution` | Step over, into, or out of current call frame | `action` (`over`, `into`, `out`) |
| `resume_execution` | Resume script execution until next breakpoint | *None* |
| `set_pause_on_exceptions`| Configure debugger exception break mode | `state` (`none`, `uncaught`, `all`) |

### 📜 Script & Source Intelligence (10 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `list_scripts` | List all parsed JS scripts and WebAssembly modules | *None* |
| `get_script_source` | Retrieve raw script content by script ID | `scriptId` |
| `search_scripts` | Regex/text search across all loaded scripts | `query`, `caseSensitive` |
| `ast_search` | Query script AST structure using selector patterns | `scriptId`, `selector` |
| `beautify_script` | Format and de-minify script for readable inspection | `scriptId`, `source` |
| `extract_sourcemap` | Fetch and extract original unminified source tree | `scriptId`, `url` |
| `extract_endpoints` | Audit script for REST endpoints, secrets, and routes | `scriptId`, `urlPattern` |
| `anti_debug_bypass` | Neutralize infinite `debugger;` loops and detection | *None* |
| `inspect_element` | Inspect DOM node details and computed properties | `selector`, `backendNodeId` |
| `override_function` | Hot-patch / override in-page JavaScript function | `functionPath`, `code` |

### 🌐 CDP Network & Request Interception (12 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `get_network` | Retrieve summarized network requests captured by CDP | `limit`, `filter` |
| `get_network_body` | Retrieve request or response body for network request | `requestId` |
| `wait_for_network` | Wait for network idle state or specific request to settle | `urlPattern`, `timeout` |
| `search_network` | Search across headers, URLs, and bodies of requests | `query` |
| `get_websocket_messages`| Retrieve incoming and outgoing WebSocket frames | `requestId`, `limit` |
| `set_request_interception`| Intercept outgoing requests to mock, modify, or block | `patterns` |
| `list_interceptions` | List active CDP request interception rules | *None* |
| `clear_interceptions` | Remove all active CDP request interceptions | *None* |
| `export_har` | Export current CDP session network log to HAR | *None* |
| `trace_request_origin` | Trace JavaScript call stack that initiated network request | `requestId` |
| `replay_and_verify` | Resend request inside page context and assert response | `requestId`, `overrides` |
| `openapi_generator` | Generate OpenAPI 3.0 specification from captured requests | `filterHost` |

### 🛡️ Stealth & Anti-Crawl Evasion (5 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `stealth_enable` | Apply seeded fingerprint spoofing profile (`basic`, `advanced`, `full`) | `profile`, `seed` |
| `stealth_status` | Report active stealth profile and patch registrations | *None* |
| `stealth_probe` | Run leak detection suite to verify stealth integrity | `maxChars` |
| `classify_anticrawl` | Identify bot defense systems (Cloudflare, Akamai, DataDome, GeeTest) | *None* |
| `captcha_detect` | Detect active CAPTCHA challenges to enable routing around them | *None* |

### 👤 Identity & Browser Isolation (5 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `identity_create` | Create isolated browser profile with dedicated proxy binding | `name`, `proxyServer` |
| `identity_use` | Switch active session to use specific identity | `name` |
| `identity_list` | List configured browser identities and proxy bindings | *None* |
| `identity_export` | Export identity state (cookies, storage, seed) to JSON | `name` |
| `identity_import` | Import serialized identity into session | `payload` |

### ⚡ Runtime Instrumentation & Taint Tracking (13 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `install_hook` | Install custom JS hook into window or object properties | `target`, `wrapperCode` |
| `remove_hook` | Uninstall active runtime hook | `hookId` |
| `list_hooks` | List all active runtime instrumentation hooks | *None* |
| `get_hook_events` | Fetch events captured by installed runtime hooks | `hookId`, `limit` |
| `taint_track` | Track flow of sensitive data through JavaScript variables | `sourceExpression` |
| `taint_events` | Fetch recorded taint propagation events | `limit` |
| `taint_stop` | Stop active taint tracking session | *None* |
| `taint_list` | List active taint tracking targets | *None* |
| `timeline_recorder` | Start or stop chronological event timeline recording | `action` (`start`, `stop`) |
| `get_console` | Fetch recorded console logs, warnings, and errors | `limit`, `level` |
| `search_console` | Search console logs using text query | `query` |
| `clear_capture_logs` | Clear in-memory capture logs and console buffers | *None* |
| `evaluate` | Evaluate arbitrary JavaScript expression in page context | `expression`, `awaitPromise` |

### 📊 Bundle Versioning, Project Workspace & Maintenance (13 Tools)

| Tool | Intent & Description | Key Arguments |
|---|---|---|
| `capture_bundle_snapshot`| Snapshot loaded bundle hashes for drift detection | `name` |
| `diff_bundles` | Diff current bundle state against saved snapshot | `baselineName` |
| `env_diff` | Detect environment differences between identity contexts | `identityA`, `identityB` |
| `netvein_project` | Inspect `.netvein` workspace status, config, and captures | *None* |
| `netvein_init` | Initialize `.netvein` workspace with auto-capture | `dir`, `force` |
| `check_for_update` | Check for newer releases and updates | `force` |
| `captcha_provider_hook`| Configure external CAPTCHA solver provider | `provider`, `apiKey` |
| `get_cookies` | Retrieve all browser cookies with domain/path filters | `urls` |
| `set_cookie` | Add or update browser cookie | `name`, `value`, `domain`, `path`, `secure` |
| `delete_cookies` | Delete specific cookies by name and URL | `name`, `url` |
| `get_storage` | Retrieve `localStorage` or `sessionStorage` entries | `securityOrigin`, `storageType` |
| `set_storage` | Set entry in `localStorage` or `sessionStorage` | `securityOrigin`, `storageType`, `key`, `value` |
| `clear_storage` | Clear all entries from storage or Cache API | `securityOrigin`, `storageTypes` |

---

## Project Workspace (`.netvein/`)

NetVein adopts the **CodeGraph workspace paradigm**. When working within a project, NetVein walks upward from the current working directory to discover a `.netvein/` folder.

### What the Workspace Enables

1. **Automatic Flow Capture**: When the traffic daemon is running, every finished HTTP exchange and WebSocket frame sequence is automatically appended to `.netvein/captures/flows-<utc>.jsonl`. Your network data survives browser crashes, daemon stops, and restarts.
2. **Configuration Cascade**: Workspace `config.json` overrides built-in defaults cleanly:
   ```json
   {
     "cdp": {
       "host": "127.0.0.1",
       "port": 9222
     },
     "traffic": {
       "port": 8080,
       "capture": true,
       "attachBrowser": true
     }
   }
   ```
3. **Dedicated Artifacts**: Manual HAR and JSONL exports default to `.netvein/captures/`, keeping project root clean.

---

## Supported AI Assistants & Configuration

While `netvein install` sets up your environment automatically, you can also manually register the MCP server:

### Claude Code (`~/.claude.json`)

```json
{
  "mcpServers": {
    "netvein": {
      "command": "netvein",
      "args": ["serve", "--mcp"]
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "netvein": {
      "command": "netvein",
      "args": ["serve", "--mcp"]
    }
  }
}
```

### Antigravity / Gemini CLI (`~/.gemini/config/mcp_config.json`)

```json
{
  "mcpServers": {
    "netvein": {
      "command": "netvein",
      "args": ["serve", "--mcp"],
      "env": {
        "CDP_HOST": "127.0.0.1",
        "CDP_PORT": "9222"
      }
    }
  }
}
```

### Codex CLI (`~/.codex/config.toml`)

```toml
[mcp_servers.netvein]
command = "netvein"
args = ["serve", "--mcp"]
startup_timeout_sec = 60
[mcp_servers.netvein.env]
CDP_HOST = "127.0.0.1"
CDP_PORT = "9222"
```

---

## Testing & Quality Assurance

NetVein includes an extensive test suite verifying protocol bridges, AST engines, and cryptographic heuristics:

```bash
# Run unit & integration tests
npm test

# Type-check TypeScript codebase
npm run check

# Build production bundle
npm run build
```

---

## Supported Platforms

- **Windows**: x64 & ARM64 (Windows 10, 11, Server)
- **macOS**: Apple Silicon (M1/M2/M3/M4) & Intel
- **Linux**: x64 & ARM64 (Ubuntu, Debian, Fedora, Arch, Alpine)

## Supported Agents

- [Claude Code](https://claude.ai/code)
- [Cursor](https://cursor.com/)
- [Codex CLI](https://github.com/openai/codex)
- [OpenCode](https://opencode.ai/)
- [Hermes Agent](https://hermes-agent.ai/)
- [Gemini CLI](https://ai.google.dev/)
- [Antigravity IDE](https://deepmind.google/technologies/antigravity/)

---

## License

This project is licensed under the [MIT License](LICENSE).

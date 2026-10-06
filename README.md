# Netvein-MCP ⚡

> **The reverse engineer's browser MCP. Break request signatures, take apart bot defenses, and dissect systems you do not own — from a single, token-bounded CDP session.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio%201.31-6E56CF)](https://modelcontextprotocol.io/)
[![CDP](https://img.shields.io/badge/Chrome-CDP-4285F4?logo=googlechrome&logoColor=white)](https://chromedevtools.github.io/devtools-protocol/)
[![Tests](https://img.shields.io/badge/Tests-137%2F137%20Passing-brightgreen)](test/index.test.ts)
[![Tools](https://img.shields.io/badge/Tools-102%20Available-orange)](#tool-catalog)

---

## Overview

Most AI browser integrations can only click buttons or scrape rendered DOM text. When dealing with modern single-page applications, minified bundles, obfuscated request signatures, bot defenses, or VM-protected JavaScript (JSVMP), traditional tools fail.

**Netvein** connects an AI agent directly to a real Chromium browser via a privileged, single-session Chrome DevTools Protocol (CDP) connection. It brings browser automation, source intelligence, multi-tier breakpoints, dynamic request tampering, cryptographic signature detection, AST candidate scoring, and JSRPC generation into **one unified, cohesive context**.

**🚀 Zero-Configuration Auto-Launch**: If Chromium (Chrome, Microsoft Edge, Brave) is not currently running on CDP port 9222, the server **automatically finds the installed browser executable and boots it in the background** with remote debugging enabled—no manual terminal commands required!

Beyond CDP instrumentation, the server ships a stealth layer (three patch profiles
with deterministic per-identity seeds), a semantic tree pruner that replaces raw DOM
dumps with an integer-addressed accessibility view, isolated browser identities with
per-context proxy binding, and captcha detection. Captcha solving is out of scope —
`captcha_detect` reports a challenge so an agent can route around it.

```text
┌─────────────────────────────────────────────────────────────┐
│                 AI Agent / MCP Client                       │
│        (Antigravity, Codex, Claude Code, Cursor)            │
└──────────────────────────────┬──────────────────────────────┘
                               │ JSON-RPC (stdio transport)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                         netvein-mcp                         │
│                                                             │
│  ├── 102 Tools across 12 specialized domains                │
│  ├── Auto-Browser Launcher (Chrome, Edge, Brave discovery)  │
│  ├── 3 Live State MCP Resources (status, logs, timeline)    │
│  ├── 2 Guided MCP Prompts (triage-target, crack-signing)    │
│  ├── Bounded Token Context (strict truncation & redaction)  │
│  └── Acorn AST Engine & Cryptographic Signature Database    │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket (localhost:9222)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Chromium Engine                           │
│     Runtime  │  Debugger  │  Fetch Intercept  │  DOM Tree   │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Capabilities

| Capability | Description |
|---|---|
| 🚀 **Auto Browser Detection & Launch** | Automatically locates Chrome, Edge, or Brave on Windows, macOS, or Linux, and boots it with `--remote-debugging-port=9222` seamlessly on the first tool invocation. |
| 🕹️ **Full Browser Automation** | Real hardware-level input dispatch (mouse clicks, typing, keyboard shortcuts, hover, scrolling, dropdown selection, viewport emulation, User-Agent masking, full-page/element screenshots). |
| 🛑 **Multi-Tier Breakpoints** | Don't know the function name? Break on **XHR/fetch URLs**, **DOM mutations** (subtree/attribute/removal), **DOM events** (click, submit, keydown, WebSocket), or line numbers. Inspect and modify variables live on the call stack. |
| 🔐 **Crypto Fingerprinting** | Instant static identification of **AES S-Boxes**, **SM4 S-Boxes**, **MD5/SHA constants**, **RSA PEMs**, **RC4**, and libraries (**CryptoJS, JSEncrypt, Forge, WebCrypto Subtle, WebAssembly**). |
| 🧠 **AST Function Candidate Scoring** | Automatically parses JS AST to rank candidate encryption and signature functions based on parameter names (`password`, `sign`, `token`) and bitwise operator density (`^`, `>>>`, `<<`). |
| 🛡️ **Bot Defense & Anti-Debug Bypass** | Automatic detection of **Cloudflare (Turnstile/Challenge)**, **Akamai Bot Manager**, **DataDome**, **GeeTest**, **reCAPTCHA**, **DingXiang**, and **JSVMP opcode dispatcher loops**. Built-in one-click neutralizing of `debugger` traps and console tampering. |
| 📦 **Webpack Runtime Extraction** | Auto-discovers `webpackChunk*` and `webpackJsonp` arrays, hooks `__webpack_require__`, inventories all internal modules, and exports/dumps internal utilities dynamically. |
| 🌐 **Dynamic Request Interception** | Powered by CDP `Fetch.requestPaused`: intercept outgoing requests to **block**, **mock synthetic responses** (status, headers, body), or **tamper with headers/POST payloads** live. |
| 🔌 **JSRPC Automation Pipeline** | Generate in-page hook stubs, local Python Flask HTTP bridges, and **Burp Suite AutoDecoder** configs to automate encryption/decryption without tedious manual decompilation. |
| 📜 **Source Recovery & Endpoint Audit** | Automatically download and parse source maps to recover original unminified TypeScript/React source files. Extract all REST endpoints, query parameters, hidden form values, and API keys. |

---

## Quick Start (1 Minute)

### 1. Installation

#### Automated (Recommended)
- **Windows (PowerShell):**
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\install.ps1
  ```
- **Linux / macOS (Bash):**
  ```bash
  chmod +x install.sh
  ./install.sh
  ```

#### Manual Build
```bash
npm install
npm test       # Runs the 137 automated unit & smoke tests
npm run build  # Compiles to dist/index.js
```

### 2. Browser Startup (Fully Automatic)
You **do not need to start Chrome manually**. Whenever you call `browser_targets`, `browser_attach`, or `browser_launch`, the MCP server will:
1. Probe `http://127.0.0.1:9222/json/version`.
2. If unreachable, discover Chrome, Microsoft Edge, or Brave in standard system directories.
3. Spawn an isolated background browser instance with `--remote-debugging-port=9222` and a dedicated temporary profile.
4. Wait for the CDP port to respond and return immediately.

*(Optional)* If you prefer launching your browser manually:
```powershell
# Windows (Chrome)
& "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222 --user-data-dir="$env:TEMP\chrome-cdp"
```

### 3. Register with your MCP Client

#### For Antigravity / Gemini (`~/.gemini/config/mcp_config.json`):
```json
{
  "mcpServers": {
    "netvein-mcp": {
      "command": "node",
      "args": ["D:\\MCP\\netvein-mcp\\dist\\index.js"],
      "env": {
        "CDP_HOST": "127.0.0.1",
        "CDP_PORT": "9222"
      }
    }
  }
}
```

#### For Codex CLI (`~/.codex/config.toml`):
```toml
[mcp_servers.netvein-mcp]
command = "node"
args = ["D:\\MCP\\netvein-mcp\\dist\\index.js"]
startup_timeout_sec = 60
[mcp_servers.netvein-mcp.env]
CDP_HOST = "127.0.0.1"
CDP_PORT = "9222"
```

---

## MCP Resources & Prompts

### Live Resources
MCP clients can read session state via URI without invoking tools:
- `netvein://session/status`: Current target, connection state, paused callframes, and active breakpoint counts.
- `netvein://session/console`: Real-time stream of captured console logs, warnings, and unhandled exceptions.
- `netvein://session/timeline`: Chronological timeline of network events, debugger triggers, and runtime hooks.

### Interactive Prompts
- `triage-target`: Automated initial reconnaissance runbook (navigates, checks bot defenses, inventories endpoints, inspects source maps).
- `crack-api-signing`: Step-by-step guided workflow to isolate, trace, and replicate client-side signature generation.

---

## Tool Catalog (102 Tools)

### 🕹️ Browser Lifecycle & Emulation
`browser_targets` · `browser_attach` · `browser_detach` · `browser_status` · `navigate` · `page_snapshot` · `screenshot` · `wait_for_selector` · `click_selector` · `type_text` · `press_key` · `hover_selector` · `scroll_page` · `select_option` · `reload_page` · `set_viewport` · `set_user_agent` · `evaluate`

### 🍪 Storage & Cookies
`get_cookies` · `set_cookie` · `delete_cookies` · `get_storage` · `set_storage` · `clear_storage`

### 🔬 Cryptography & Algorithm Reverse Engineering
`detect_crypto` · `find_crypto_candidates` · `classify_anticrawl` · `unpack_webpack` · `generate_jsrpc`

### 🔍 Source Intelligence & Anti-Debug
`list_scripts` · `get_script_source` · `search_scripts` · `ast_search` · `beautify_script` · `extract_sourcemap` · `extract_endpoints` · `anti_debug_bypass` · `inspect_element` · `override_function`

### 🛑 Debugger & Multi-Tier Breakpoints
`set_breakpoint` · `remove_breakpoint` · `list_breakpoints` · `set_dom_breakpoint` · `remove_dom_breakpoint` · `set_event_breakpoint` · `remove_event_breakpoint` · `set_xhr_breakpoint` · `remove_xhr_breakpoint` · `list_all_breakpoints` · `get_debugger_status` · `get_call_frame_scope` · `set_variable_value` · `restart_frame` · `evaluate_on_call_frame` · `step_execution` · `resume_execution` · `set_pause_on_exceptions` · `smart_breakpoint` · `conditional_logpoint_batch`

### 🌐 Network & Interception
`get_network` · `get_network_body` · `wait_for_network` · `search_network` · `get_websocket_messages` · `set_request_interception` · `list_interceptions` · `clear_interceptions` · `export_har` · `trace_request_origin` · `replay_and_verify` · `openapi_generator`

### ⚡ Instrumentation, Hooks & Taint Tracking
`install_hook` · `remove_hook` · `list_hooks` · `get_hook_events` · `hook_crypto_all` · `taint_track` · `taint_events` · `taint_stop` · `taint_list` · `timeline_recorder` · `get_console` · `search_console` · `clear_capture_logs`

### 📊 Bundle Versioning & Environment Diffs
`capture_bundle_snapshot` · `diff_bundles` · `env_diff`

---

## Detailed Documentation

- 📖 [**Installation Guide**](docs/INSTALLATION.md): Complete setup for Windows, Linux, macOS, Claude, Codex, Cursor.
- 🏗️ [**Architecture & Design**](docs/ARCHITECTURE.md): CDP protocol bridge, AST candidate scoring, memory management.
- 📚 [**Tool Catalog Reference**](docs/TOOLS.md): Detailed parameter lists, return shapes, and examples for all 102 tools.
- 🎯 [**Reverse Engineering Playbooks**](docs/WORKFLOWS.md): Step-by-step tutorials for cracking signatures, bypassing anti-debug, and Webpack dumping.

---

## Testing & Verification

The suite includes comprehensive automated tests covering all core analysis algorithms:

```bash
# Run unit & smoke tests (Node.js test runner)
npm test

# Typecheck without emitting
npm run check

# Production build
npm run build
```

---

## License

This project is licensed under the [MIT License](LICENSE).

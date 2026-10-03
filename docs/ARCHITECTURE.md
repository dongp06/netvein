# Technical Architecture & Design

`reverse-engineering-mcp` is designed as a high-performance, single-session Chrome DevTools Protocol (CDP) bridge tailored specifically for AI-driven web reverse engineering.

```text
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                             │
│        (Antigravity, Codex, Claude Code, Cursor)            │
└──────────────────────────────┬──────────────────────────────┘
                               │ JSON-RPC (stdio transport)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 reverse-engineering-mcp                      │
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
Most web reverse engineering workflows require shared context: setting a breakpoint on an event listener, clicking a button, intercepting the request, and inspecting the paused call frame. Unlike stateless headless browser wrappers, `reverse-engineering-mcp` connects to a single persistent tab, preserving state across all 87 tools.

### Bounded Memory & Token Safety
Browser sessions generate massive amounts of data (tens of thousands of network frames, script files, and console logs). To prevent blowing up the LLM's context window:
- Strings and post data are truncated to predefined safe boundaries (`MAX_STORED_TEXT = 20,000`).
- Sensitive transport headers (`Authorization`, `Cookie`, `X-API-Key`) are redacted in tool outputs.
- Captured arrays (network records, console events, timeline items) use FIFO sliding windows with strict capacity limits.

---

## 2. Core Subsystems

### A. Dynamic Request Interception (`CDP Fetch Domain`)
While `Network.enable` can only monitor traffic passively, `reverse-engineering-mcp` utilizes `Fetch.enable` and `Fetch.requestPaused` to allow dynamic request tampering:
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

## 3. Error Handling & Resilience
- **Rejection Guards**: Captures `unhandledRejection` events from remote WebSocket disconnects without crashing the server process.
- **Auto-Recovery**: If a tab closes or navigates away unexpectedly, the session resets internal buffers and cleanly reports target detachment.
- **Standardized MCP Tool Results**: All handlers wrap errors in standard MCP JSON error structures (`isError: true`) with actionable diagnostics.

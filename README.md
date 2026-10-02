# Reverse Engineering MCP

> A local-first MCP server that lets an AI inspect and debug a real Chromium tab through Chrome DevTools Protocol.

![TypeScript](https://img.shields.io/badge/TypeScript-ESM-3178C6?logo=typescript&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF)
![CDP](https://img.shields.io/badge/Chrome-CDP-4285F4?logo=googlechrome&logoColor=white)
![Status](https://img.shields.io/badge/status-experimental-orange)

Reverse Engineering MCP gives an AI one coherent browser session for source inspection, runtime instrumentation, debugger control, network capture and dynamic analysis. It is designed for authorized research, debugging and interoperability work on pages you are allowed to inspect.

## Why this exists

Most browser automation tools can click and type, while most debugger integrations can inspect JavaScript but know nothing about the request that triggered it. This server joins those views:

```text
MCP client
    │ stdio / JSON-RPC
    ▼
Reverse Engineering MCP
    │ one attached CDP session
    ├── Runtime + Console
    ├── Debugger + source maps
    ├── Network + WebSocket
    ├── hooks: fetch / XHR / crypto
    └── timeline + evidence buffers
    ▼
Chromium tab on 127.0.0.1:9222
```

The core stays site-agnostic. Site-specific experiments belong in external workflows; the included SaveFrom flow is an MCP client, not hard-coded behavior in the server.

## Capabilities

| Area | What the AI can do |
| --- | --- |
| Browser | Attach to a tab, navigate, inspect visible text, click and type through CDP input events |
| JavaScript | Inventory scripts, read bounded source, text search and ESTree AST search |
| Debugger | Set/remove conditional breakpoints, inspect call frames, evaluate locals and step execution |
| Network | Capture requests, responses, initiators, bodies, WebSocket frames and generate an OpenAPI draft |
| Hooks | Observe fetch, XHR, WebSocket and Web Crypto calls; capture bounded response bodies |
| Tracing | Trace request origin (with MCP-wrapper filtering), dynamic sink-oriented taint tracking and browser-vs-Node environment differences |
| Reconstruction | Replay a captured request in the attached browser context and compare status/body bytes |
| Evidence | Unified timeline, console buffer, bundle snapshots and bundle diffs |

Sensitive transport headers such as `Cookie`, `Authorization` and API keys are redacted in MCP output. Buffers are bounded so a noisy page does not consume the entire model context.

## Requirements

- Node.js 20 or newer
- Chromium/Chrome started with a localhost CDP endpoint
- An MCP-compatible client

Install and build:

```bash
npm install
npm run check
npm run build
```

Start a dedicated browser profile:

```bash
google-chrome \
  --remote-debugging-address=127.0.0.1 \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/reverse-engineering-chrome
```

Keep the CDP endpoint bound to localhost. Do not expose port `9222` to a network you do not control.

## MCP client configuration

Register the built server as a stdio MCP server:

```json
{
  "mcpServers": {
    "reverse-engineering": {
      "command": "node",
      "args": ["/absolute/path/to/reverse-engineering-mcp/dist/index.js"],
      "env": {
        "CDP_HOST": "127.0.0.1",
        "CDP_PORT": "9222"
      }
    }
  }
}
```

The normal first calls are:

```text
browser_targets → browser_attach → browser_status
```

After attaching, all debugger, hook and network tools operate on that same tab.

## Tool map

### Browser and runtime

`browser_targets` · `browser_attach` · `browser_detach` · `browser_status` · `navigate` · `page_snapshot` · `wait_for_selector` · `wait_for_network` · `click_selector` · `type_text` · `evaluate`

### Source intelligence

`list_scripts` · `get_script_source` · `search_scripts` · `ast_search` · `smart_breakpoint` · `conditional_logpoint_batch`

### Debugger

`set_breakpoint` · `remove_breakpoint` · `list_breakpoints` · `get_debugger_status` · `evaluate_on_call_frame` · `step_execution` · `resume_execution` · `set_pause_on_exceptions`

### Network and reconstruction

`get_network` · `get_network_body` · `trace_request_origin` · `replay_and_verify` · `openapi_generator`

`wait_for_network` can match the raw URL (`urlContains`/`urlRegex`) or only the pathname (`urlPathContains`), and can require a response or completed loading (`requireResponse`/`requireFinished`).

### Instrumentation and evidence

`install_hook` · `remove_hook` · `list_hooks` · `get_hook_events` · `hook_crypto_all` · `taint_track` · `taint_events` · `taint_stop` · `taint_list` · `timeline_recorder` · `get_console` · `clear_capture_logs`

### Version and environment analysis

`capture_bundle_snapshot` · `diff_bundles` · `env_diff`

## Example investigation loop

1. Attach to the target page and clear old capture buffers.
2. Capture a bundle snapshot before the action.
3. Install only the hooks needed for the hypothesis.
4. Perform the action through the browser tools.
5. Correlate `get_network`, `trace_request_origin`, `get_hook_events` and `timeline_recorder`.
6. Set a narrow breakpoint or logpoint when a source location is known.
7. Capture a second snapshot and use `diff_bundles` after a site update.

For request signing, `hook_crypto_all` records Web Crypto calls plus bounded byte previews for `ArrayBuffer`/typed-array inputs and outputs. The companion E2E workflow also computes SHA-256 values for observed `TextEncoder` preimages.

## SaveFrom E2E through MCP

`src/e2e-savefrom.ts` is deliberately outside the core server. It acts as a small MCP client over stdio and calls the generic tools exactly as an agent would: browser attach, navigation, input, hooks, network, console, timeline and script analysis.

Start Chrome first, then run:

```bash
npm run e2e:savefrom -- \
  --source-url 'https://vt.tiktok.com/ZSb5aNRof/' \
  --page-url 'https://en1.savefrom.net/19wr/'
```

The run writes a bounded JSON artifact under `.reverse-engineering/` containing:

- the observed request/response chain;
- request initiator traces and loaded script inventory;
- hook and console events;
- crypto digest calls, byte previews and candidate preimages;
- candidate URLs found in DOM/network evidence;
- explicit CAPTCHA status.

CAPTCHA or another access challenge is surfaced as `captcha_required` and handed back to the operator for manual interaction. The workflow does not automate or bypass the challenge. Use `--fail-on-captcha` when running it in CI.

## Data and security notes

- This server attaches to a local browser through CDP; it is not a remote browser service.
- Treat captured bodies, console events and script sources as sensitive project data.
- Header redaction reduces accidental disclosure but does not make page content safe to publish.
- `replay_and_verify` runs inside the attached page and remains subject to CORS, cookies, nonce checks and server-side validation.
- `taint_track` is dynamic sink tracing based on observed token appearances; it is not a complete static taint engine.
- Use the tools only on applications and traffic you are authorized to analyze.

## Development

```bash
npm run check          # TypeScript without emitting files
npm run build          # Compile dist/
npm run start          # Start the built MCP server
npm run dev            # Run the MCP server through tsx
npm run e2e:savefrom  # Build and run the MCP-based SaveFrom workflow
npm audit --omit=dev
```

The project intentionally keeps the CDP session in one `CdpSession` instance. This prevents multiple MCP tools from racing separate browser connections or profiles.

## Project layout

```text
src/
├── analysis.ts       AST/text search and bundle diff helpers
├── cdp.ts            CDP session, domains, hooks and evidence buffers
├── e2e-savefrom.ts   external MCP-client E2E workflow
├── server.ts         MCP tool registration
├── types.ts          bounded evidence and CDP record types
└── index.ts          stdio MCP entry point
```

## Roadmap

- source-map-aware smart breakpoints for minified bundles;
- optional proxy/Reqable evidence adapter;
- deobfuscation adapters that preserve original evidence;
- WASM export inspection adapters for IDA/Ghidra;
- persistent, redacted investigation notebooks.

## Status

Experimental and intended for local, authorized research workflows. APIs may change while the tool surface settles.

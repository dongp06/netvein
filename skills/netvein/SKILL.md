---
name: netvein
description: >-
  Autonomous web reverse engineering, wire-level traffic interception, and browser instrumentation.
  Activate when analyzing obfuscated web APIs, decrypting payload signatures, tampering with in-flight HTTP/WebSocket requests, bypassing bot anti-crawl defenses (Cloudflare, Akamai, Turnstile), or capturing wire traffic.
---

# NetVein — Web Reverse Engineering & Wire Daemon Skill

NetVein gives AI coding agents a dedicated Chrome DevTools Protocol (CDP) session and a wire-level loopback MITM proxy daemon for deep dynamic analysis and reverse engineering.

---

## Mental Model & Architecture

1. **Persistent Single-Session**: NetVein maintains an open Chrome instance on port `9222`. Never spawn external Playwright or Puppeteer processes; NetVein tools run within this persistent session.
2. **Wire-Level Interception**: Built-in traffic daemon on port `8080` captures raw HTTP/HTTPS and WebSocket frames on the network stack. Subprocesses, background scripts, and `curl` route through transparently.
3. **Workspace State (`.netvein/`)**: When initialized (`netvein_init`), streaming JSONL captures (`capture/flows-<utc>.jsonl`) survive process restarts and browser crashes.

---

## Core Playbooks & Workflows

### 1. Wire-Level Traffic Interception & API Reconstruction

When you need to discover endpoints, inspect request payloads, or generate API specs:

```
Step 1: Check daemon state
  -> call traffic_status()
     Ensure state is "running". If stopped, start traffic or run an initial CDP navigation.

Step 2: Filter flows ring buffer
  -> call traffic_flows({ host: "api.target.com", method: "POST", limit: 20 })
     Returns compact flow summaries (id, method, path, status, latency).

Step 3: Deep inspect flow details
  -> call traffic_flow({ id: "<flow_id>", part: "both", maxChars: 4000 })
     Renders curated headers and pretty-printed JSON request/response bodies.

Step 4: Generate cURL command
  -> call traffic_curl({ id: "<flow_id>" })
     Returns a shell-escaped, ready-to-run cURL command.

Step 5: Generate OpenAPI specification
  -> call openapi_generator({ filterHost: "api.target.com" })
     Auto-constructs an OpenAPI 3.0 schema from observed network traffic.
```

---

### 2. In-Flight Breakpoint & Payload Tampering

When you need to pause an outgoing request, tamper with signatures or parameters before dispatch:

```
Step 1: Arm in-flight breakpoint
  -> call traffic_breakpoint_set({ pattern: "/api/v2/secure/.*", maxHoldMs: 15000 })
     Holds matching requests on the wire before they reach the remote server.

Step 2: Inspect held flow
  -> call traffic_flows({ heldOnly: true })
  -> call traffic_flow({ id: "<flow_id>", part: "request" })

Step 3: Mutate and release flow
  -> call traffic_breakpoint_release({
       flowId: "<flow_id>",
       action: "modify",
       patch: {
         headers: { "X-Client-Signature": "custom_hash_value" },
         body: JSON.stringify({ mutated: true })
       }
     })
     Flow is patched on the wire and forwarded to target server.

Step 4: Replay & verify
  -> call traffic_replay({ id: "<flow_id>", compare: true })
     Resends the request and produces a dot-path schema diff against the original response.
```

---

### 3. Cryptographic Signature & Hash Reverse Engineering

When analyzing obfuscated request signing routines (HMAC, SHA256, AES, custom hashing):

```
Step 1: Heuristic AST Crypto Discovery
  -> call detect_crypto({ algorithm: "HMAC-SHA256" })
     Scans loaded scripts using Acorn AST traversal for crypto constants and algorithms.

Step 2: Score Candidate Signing Functions
  -> call find_crypto_candidates({ minEntropy: 4.5 })
     Ranks functions by bitwise operations, math operations, and array transforms.

Step 3: Runtime SubtleCrypto Hooking
  -> call hook_crypto_all()
     Hooks window.crypto.subtle (sign, digest, encrypt, importKey).
     Logs key material, input plaintext, and signature outputs in real time.

Step 4: Origin Call-Stack Tracing
  -> call trace_request_origin({ requestId: "<req_id>" })
     Returns the exact JavaScript call frame and source line that initiated the network call.

Step 5: Live Execution / JSRPC
  -> call generate_jsrpc({ functionPath: "window.encryptPayload" })
     Extracts or wraps browser functions for standalone programmatic calling.
```

---

### 4. Stealth & Anti-Bot Defense Evasion

When targeting sites protected by Cloudflare Turnstile, Akamai, DataDome, or anti-debug traps:

```
Step 1: Classify Anti-Crawl Defenses
  -> call classify_anticrawl()
  -> call captcha_detect()
     Identifies active bot defense challenges and vendors.

Step 2: Activate Seeded Fingerprint Spoofing
  -> call stealth_enable({ profile: "full", seed: "custom_session_seed" })
     Spoofs WebGL, Canvas, AudioContext, navigator.plugins, and hardwareConcurrency.

Step 3: Defeat Anti-Debug Traps
  -> call anti_debug_bypass()
     Hot-patches timer-based and endless Function constructor `debugger;` loops.

Step 4: Verify Stealth Integrity
  -> call stealth_probe()
     Runs comprehensive leak detection suite to verify zero fingerprint leakage.
```

---

### 5. Token-Efficient Semantic Navigation

Avoid dumping full outerHTML, which burns 50,000+ context tokens. Use semantic snapshots:

```
Step 1: Navigate to target URL
  -> call navigate({ url: "https://example.com", waitUntil: "networkidle" })

Step 2: Pruned Semantic Accessibility Snapshot
  -> call page_snapshot({ maxTokens: 800 })
     Returns an ultra-compact accessibility tree with interactive element IDs (< 400 tokens).

Step 3: Targeted Interaction
  -> call click_selector({ selector: "#submit-btn" })
  -> call type_text({ selector: "input[name='search']", text: "query" })
```

---

### 6. Workspace & Capture Persistence

Maintain persistent history in `.netvein/`:

```
Step 1: Initialize workspace
  -> call netvein_init({ dir: "." })
     Creates .netvein/ (config.json, captures/, notes/).

Step 2: Export traffic artifacts
  -> call traffic_export({ format: "har", path: ".netvein/captures/analysis.har" })
  -> call traffic_export({ format: "jsonl" })
```

---

## Anti-Patterns to Avoid

- **DO NOT** execute `npx playwright` or `puppeteer` via shell commands. Use NetVein's persistent session tools (`navigate`, `page_snapshot`, `evaluate`).
- **DO NOT** call `get_network` with huge unbounded limits. Filter by host, method, or use `traffic_flows`.
- **DO NOT** read raw DOM strings when analyzing dynamic APIs. Intercept network flows directly on the wire with `traffic_flow` or `traffic_breakpoint_set`.

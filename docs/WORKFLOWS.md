# Reverse Engineering Playbooks & Workflows

This document outlines proven, step-by-step procedures for common reverse engineering scenarios using `netvein-mcp`.

---

## Playbook 1: Initial Target Reconnaissance

**Goal:** Quickly inventory endpoints, check for bot protections, and find unminified code.

1. **Attach to Browser Tab:**
   ```json
   // 1. List targets
   browser_targets()
   
   // 2. Attach to target page
   browser_attach({ "url": "example.com" })
   ```

2. **Run Bot Protection & Anti-Debug Classification:**
   ```json
   classify_anticrawl()
   ```
   *If anti-debugging traps are detected, immediately run:*
   ```json
   anti_debug_bypass()
   ```

3. **Check for Original Source Maps:**
   ```json
   extract_sourcemap()
   ```
   *If source maps exist, this tool recovers original unminified TypeScript/React source code directly without needing reverse engineering.*

4. **Extract REST Endpoints & Secrets:**
   ```json
   extract_endpoints({ "includeNetworkHistory": true, "includeDom": true })
   ```
   *Yields all discovered API routes, hidden form values, JWT tokens, and WebSocket feeds.*

---

## Playbook 2: Cracking Client-Side Request Signing

**Goal:** Replicate or hook an obfuscated signature header (`X-Sign`, `_signature`, `token`).

1. **Locate the Target Request:**
   Trigger the action in the browser, then inspect captured traffic:
   ```json
   search_network({ "query": "api/v1/data" })
   ```
   Note the initiator call stack from `trace_request_origin({ "requestId": "..." })`.

2. **Score Candidate Functions via AST:**
   Scan loaded scripts for candidate encryption/signing functions:
   ```json
   find_crypto_candidates({
     "targetParams": ["sign", "signature", "token", "password", "nonce"]
   })
   ```

3. **Detect Cryptographic Algorithms:**
   Check if standard algorithms (MD5, SHA-256, AES, SM3, SM4) are used:
   ```json
   detect_crypto()
   ```

4. **Intercept with XHR Breakpoint:**
   Break execution right before the request leaves the browser:
   ```json
   set_xhr_breakpoint({ "url": "/api/v1/data" })
   ```
   When the debugger pauses:
   - Call `get_call_frame_scope` to see unminified parameters and signing keys.
   - Call `evaluate_on_call_frame` to test running the signing function with custom inputs.

---

## Playbook 3: Webpack Module Unpacking

**Goal:** Extract internal encryption utilities from a Webpack/Vite bundle.

1. **Inspect Webpack Chunks:**
   ```json
   unpack_webpack({ "maxModules": 100 })
   ```
   This probes `window.webpackChunk*` or `window.webpackJsonp` and intercepts `__webpack_require__`.

2. **Dump Specific Module Exports:**
   Find the module ID containing crypto helpers from the module list and export it:
   ```json
   unpack_webpack({ "exportModuleId": 42 })
   ```
   Returns the module's exported functions (e.g. `encrypt`, `decrypt`, `sign`).

---

## Playbook 4: JSRPC Automation with Burp Suite

**Goal:** When algorithms are protected by JSVMP or heavy control-flow flattening, bypass manual decompilation by calling the in-browser function remotely.

1. **Generate JSRPC Bridge Files:**
   ```json
   generate_jsrpc({
     "actionName": "sign_payload",
     "targetExpression": "window.signData",
     "port": 12080
   })
   ```
   This returns:
   - `inPageStub`: Browser hook script.
   - `flaskProxy`: Python HTTP proxy server.
   - `burpDoc`: AutoDecoder integration configuration.

2. **Inject In-Page Stub:**
   ```json
   evaluate({
     "expression": "<paste inPageStub code here>"
   })
   ```

3. **Launch Flask Proxy:**
   Save `flaskProxy` to `proxy.py` and run:
   ```bash
   python proxy.py
   ```

4. **Burp Suite AutoDecoder Integration:**
   In Burp Suite Repeater, configure AutoDecoder to route outgoing request bodies through `http://127.0.0.1:12080/go?action=sign_payload`. Burp will now automatically encrypt/sign payloads on the fly!

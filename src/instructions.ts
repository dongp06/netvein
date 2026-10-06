/**
 * High-level server instructions emitted during MCP initialize handshake.
 * Guides AI agents on optimal workflows, tool sequencing, and anti-patterns for web reverse engineering.
 */
export const SERVER_INSTRUCTIONS = `# Netvein — Autonomous Web Reverse Engineering & Wire-Level Dynamic Instrumentation Suite

Netvein provides a direct, privileged Chrome DevTools Protocol (CDP) session coupled with an
in-process wire-level mitmproxy traffic daemon for full-spectrum web reverse engineering,
cryptographic signature dissection, bot defense evasion, and AST intelligence.

## Tool Selection by Intent

- **Inspect page state without token bloat** → \`semantic_view\` (PRIMARY for UI inspection: returns a clean integer-addressed accessibility view instead of megabyte-scale raw HTML dumps)
- **Interact with UI elements** → \`interact_semantic\` (click/type/focus via integer element ids) or hardware-level \`click_selector\` / \`type_text\` / \`press_key\`
- **Project workspace & auto-capture** → \`netvein_project\` (check status) or \`netvein_init\` (initialize \`.netvein/\` workspace; auto-captures traffic to disk)
- **Autonomous Capture Sessions (Capture Kit)** → \`capture_session_start\` (structured \`session.json\`, \`flows.jsonl\`, \`bodies/\`), \`capture_session_stop\`, \`capture_session_status\`, \`capture_session_list\`
- **Proxied Process Execution** → \`capture_exec\` (runs external node/python/cli commands with HTTP_PROXY and Node.js fetch shims injected), \`capture_env\`
- **Deep Body Inspection & Stream Decoding** → \`capture_inspect_body\` (auto-decompresses gzip/br/deflate, outputs json/text/hex/base64), \`capture_decode_stream\` (decodes SSE and AWS EventStream chunks into typed events), \`capture_search\` (cross-session search)
- **Full wire-level traffic interception (all tabs & external tools)** → \`traffic_start\`, \`traffic_flows\`, \`traffic_flow\`, \`traffic_curl\`
- **Hold & tamper with requests in flight** → \`traffic_breakpoint_set\` (regex hold) → \`traffic_breakpoint_release\` (pass, modify URL/headers/body, or drop)
- **Replay captured requests outside the browser** → \`traffic_replay\` (resend via daemon proxy with path-level diff comparison)
- **Export network history for Burp Suite / Charles** → \`traffic_export\` (HAR 1.2 or JSONL) or \`export_har\`
- **Identify encryption & hashing algorithms** → \`detect_crypto\` (locates AES, SM4, RSA, MD5/SHA, CryptoJS constants)
- **Find request signing & encryption functions** → \`find_crypto_candidates\` (AST parameter scoring + bitwise operator density)
- **Steal WebCrypto keys & preimages live** → \`hook_crypto_all\` (hooks window.crypto.subtle in real-time)
- **Neutralize debugger traps & anti-crawling** → \`anti_debug_bypass\` (defuses infinite debugger loops), \`classify_anticrawl\` (identifies Cloudflare, Akamai, DataDome, GeeTest, JSVMP), \`stealth_enable\` (applies seeded fingerprint evasion)
- **Targeted execution pausing** → \`set_xhr_breakpoint\` (by API URL pattern), \`set_event_breakpoint\` (click/submit), \`smart_breakpoint\` (function/AST), \`set_dom_breakpoint\`
- **Inspect execution context when paused** → \`get_call_frame_scope\`, \`evaluate_on_call_frame\`, \`set_variable_value\`, \`step_execution\`, \`resume_execution\`
- **Expose obfuscated functions via RPC bridge** → \`generate_jsrpc\` (generates browser injection stub + Python Flask bridge + Burp AutoDecoder)
- **Unpack bundled source code** → \`extract_sourcemap\` (recovers original TS/React sources) or \`unpack_webpack\` (enumerates internal webpack modules)

## Common Workflow Chains

1. **Reconnaissance & Surface Mapping**:
   \`browser_targets\` → \`browser_attach\` → \`classify_anticrawl\` → \`extract_endpoints\` → \`extract_sourcemap\`
   Surface all REST APIs, secret keys, source maps, and bot protection barriers immediately.

2. **Cracking Request Signatures / Tokens**:
   \`find_crypto_candidates\` + \`detect_crypto\` → \`set_xhr_breakpoint\` on API endpoint → trigger action with \`interact_semantic\` → inspect call frame with \`get_call_frame_scope\` → extract keys via \`hook_crypto_all\` or bridge via \`generate_jsrpc\`.

3. **Autonomous Capture Kit (Process / API Recording & Stream Analysis)**:
   \`capture_session_start(name: "checkout", focus: ["api.target.com"])\` → run actions via CDP or execute external CLI with \`capture_exec\` → locate flows via \`capture_search\` → inspect decompressed bodies via \`capture_inspect_body\` → parse SSE/EventStream responses via \`capture_decode_stream\` → \`capture_session_stop\`.

4. **Wire-Level Traffic Capture & Replay**:
   \`netvein_init\` (ensure \`.netvein/\` workspace exists) → \`traffic_start\` → navigate/interact → \`traffic_flows\` → \`traffic_curl\` or \`traffic_replay\` to verify out-of-browser reproducibility.

5. **In-Flight Tampering & Parameter Fuzzing**:
   \`traffic_breakpoint_set\` (e.g. \`/api/checkout\`) → trigger flow → \`traffic_breakpoint_release\` with \`patch\` (modify headers/body) → inspect response.

## Anti-Patterns

- **Do NOT dump raw HTML with \`evaluate("document.documentElement.outerHTML")\`**: Call \`semantic_view\` instead to save thousands of tokens.
- **Do NOT guess encryption algorithms or keys blindly**: Run \`detect_crypto\` and \`find_crypto_candidates\` first.
- **Do NOT set broad breakpoints in frequent loops**: Use \`conditional_logpoint_batch\` or \`set_xhr_breakpoint\` to avoid freezing the CDP session.
- **Always invoke \`anti_debug_bypass\` before stepping** if the target utilizes anti-debugging protection.
- **If \`.netvein/\` workspace is missing**: Offer to run \`netvein_init\` so that traffic flows are automatically saved and persistent configuration is active.
`;

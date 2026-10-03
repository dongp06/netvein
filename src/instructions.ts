/**
 * High-level server instructions emitted during MCP initialize handshake.
 * Guides AI agents on optimal workflows, tool sequencing, and anti-patterns for web reverse engineering.
 */
export const SERVER_INSTRUCTIONS = `# Reverse Engineering MCP — Autonomous Browser & Web RE Suite

This MCP server provides a direct, privileged Chrome DevTools Protocol (CDP) session for interactive web reverse engineering, dynamic runtime instrumentation, crypto analysis, and bot protection bypassing.

## Core Methodology & Playbook

1. **Reconnaissance & Initial Discovery**:
   - Call \`browser_targets\` and \`browser_attach\` to bind to the active Chrome tab.
   - Use \`extract_endpoints\` to discover REST routes, hidden form parameters, websockets, and API tokens.
   - Run \`classify_anticrawl\` to check if the target uses Cloudflare, Akamai, DataDome, GeeTest, or JSVMP.
   - If anti-debugging loops are detected, call \`anti_debug_bypass\` immediately before setting breakpoints.

2. **Source Analysis & Algorithm Identification**:
   - Check if source maps exist via \`extract_sourcemap\` to recover unminified TypeScript/React source.
   - Run \`detect_crypto\` to identify cryptographic algorithms (AES S-Boxes, DES, RSA, SM2/SM3/SM4, MD5/SHA constants, CryptoJS, JSEncrypt).
   - Use \`find_crypto_candidates\` to rank encryption/signing functions by AST parameter scoring and bitwise density.
   - Inspect Webpack runtime modules via \`unpack_webpack\` to locate internal module exports and utilities.

3. **Runtime Instrumentation & Debugging**:
   - Set targeted breakpoints:
     - \`set_xhr_breakpoint\` when you know the endpoint URL pattern.
     - \`set_event_breakpoint\` for UI click/submit events.
     - \`set_dom_breakpoint\` to track DOM mutation.
     - \`smart_breakpoint\` for function names or AST patterns.
   - When paused, inspect scopes with \`get_call_frame_scope\`, evaluate expressions via \`evaluate_on_call_frame\`, or mutate variables live with \`set_variable_value\`.
   - Use \`hook_crypto_all\` to automatically capture all \`window.crypto.subtle\` encryption keys and plaintext preimages.

4. **Network Tampering & Interception**:
   - Use \`set_request_interception\` to mock API responses, bypass client-side checks, or modify outgoing headers and POST payloads.
   - Inspect real-time frames using \`get_websocket_messages\`.
   - Export full traffic dumps via \`export_har\` for external analysis in Burp Suite, Caido, or Charles.

5. **JSRPC Bridging**:
   - When encryption logic is heavily obfuscated or VM-protected (JSVMP), do not spend days de-obfuscating; instead call \`generate_jsrpc\` to expose the in-page function directly to external tools via a Python Flask HTTP bridge and Burp Suite AutoDecoder.

## Anti-Patterns to Avoid

- **Do NOT guess encryption keys or algorithms**: Always verify with \`detect_crypto\` or \`hook_crypto_all\`.
- **Do NOT set broad breakpoints in noisy loops**: Prefer \`conditional_logpoint_batch\` or \`set_xhr_breakpoint\` to prevent debugger lockup.
- **Always run \`anti_debug_bypass\` first** if a site pauses immediately or detects DevTools.
`;

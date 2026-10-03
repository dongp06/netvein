import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

/**
 * Register guided MCP prompts for common reverse engineering scenarios.
 */
export function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    "triage-target",
    {
      title: "Triage Web Target",
      description: "Standard reconnaissance runbook: attach to page, discover endpoints, check anticrawl, inspect scripts.",
      argsSchema: {
        url: z.string().optional().describe("Target URL to navigate to (or leave empty if already open)."),
      },
    },
    async (args) => {
      const targetNav = args.url ? `1. Use navigate to load "${args.url}".` : "1. Use browser_status to verify the active tab.";
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Please perform a structured reverse-engineering triage on this target:
${targetNav}
2. Call classify_anticrawl to detect any bot defense (Cloudflare, Akamai, DataDome, GeeTest, or JSVMP). If anti-debugger loops exist, call anti_debug_bypass immediately.
3. Call extract_endpoints to inventory all REST APIs, parameters, tokens, and forms.
4. Call extract_sourcemap to check if original unminified source code is recoverable.
5. Provide an evidence-backed summary of findings with recommended next steps.`,
            },
          },
        ],
      };
    },
  );

  server.registerPrompt(
    "crack-api-signing",
    {
      title: "Analyze & Replicate API Signature",
      description: "Runbook to locate, trace, and extract client-side request signing / encryption parameters.",
      argsSchema: {
        apiPattern: z.string().describe("URL pattern or endpoint name of the signed request, e.g. /api/v1/auth or sign."),
      },
    },
    async (args) => {
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `We need to reverse-engineer and replicate the client-side signing/encryption algorithm for endpoint: "${args.apiPattern}".
1. Set an XHR breakpoint using set_xhr_breakpoint with url: "${args.apiPattern}".
2. Trigger the action or inspect captured requests using get_network and search_network.
3. Call find_crypto_candidates with targetParams: ["sign", "signature", "token", "password", "nonce"] to pinpoint the hashing/encryption function in the scripts.
4. Call detect_crypto to confirm if it uses standard MD5, SHA-256, AES, SM3/SM4, or custom JSVMP.
5. If obfuscated, call generate_jsrpc to create a browser bridge stub and Python Flask proxy so we can invoke the signing function remotely without tedious manual decompilation.`,
            },
          },
        ],
      };
    },
  );
}

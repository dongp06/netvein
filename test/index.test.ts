import assert from "node:assert/strict";
import test from "node:test";
import {
  beautifyJs,
  classifyAnticrawl,
  extractEndpointsAndSecrets,
  findCryptoCandidates,
  generateJsrpcFiles,
  identifyCrypto,
} from "../src/analysis.js";
import { CdpSession } from "../src/cdp.js";
import { findBrowserExecutable } from "../src/launcher.js";
import { createServer } from "../src/server.js";

test("Server & Tool Registration", async (t) => {
  await t.test("Initializes server with all tools, resources, and prompts", () => {
    const session = new CdpSession();
    const server = createServer(session);

    // Verify tools registered
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.ok(tools.length >= 87, `Expected >= 87 tools, got ${tools.length}`);

    // Verify critical tools are present
    const critical = [
      "browser_launch",
      "browser_targets",
      "browser_attach",
      "detect_crypto",
      "find_crypto_candidates",
      "classify_anticrawl",
      "unpack_webpack",
      "generate_jsrpc",
      "anti_debug_bypass",
      "set_request_interception",
      "export_har",
      "set_dom_breakpoint",
      "set_xhr_breakpoint",
      "set_event_breakpoint",
    ];
    for (const name of critical) {
      assert.ok(tools.includes(name), `Missing critical tool: ${name}`);
    }

    // Verify resources registered by URI
    const resources = Object.keys((server as any)._registeredResources || {});
    assert.ok(resources.includes("reverse://session/status"), "Missing session-status resource");
    assert.ok(resources.includes("reverse://session/console"), "Missing console-logs resource");
    assert.ok(resources.includes("reverse://session/timeline"), "Missing timeline-events resource");

    // Verify prompts registered
    const prompts = Object.keys((server as any)._registeredPrompts || {});
    assert.ok(prompts.includes("triage-target"), "Missing triage-target prompt");
    assert.ok(prompts.includes("crack-api-signing"), "Missing crack-api-signing prompt");
  });
});

test("Crypto Algorithm Identification", async (t) => {
  await t.test("Identifies AES S-Box constants", () => {
    const code = `
      const SBOX = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76];
      function encryptBlock(state) { return state ^ SBOX[0]; }
    `;
    const matches = identifyCrypto(code);
    assert.ok(matches.some((m) => m.algorithm === "AES" && m.confidence === "high"));
  });

  await t.test("Identifies MD5 initial constants", () => {
    const code = `
      var a = 0x67452301;
      var b = 0xefcdab89;
      var c = 0x98badcfe;
      var d = 0x10325476;
    `;
    const matches = identifyCrypto(code);
    assert.ok(matches.some((m) => m.algorithm === "MD5"));
  });

  await t.test("Identifies SHA-256 state constants", () => {
    const code = `
      const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5];
      const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
    `;
    const matches = identifyCrypto(code);
    assert.ok(matches.some((m) => m.algorithm === "SHA-256"));
  });

  await t.test("Identifies SM4 S-Box", () => {
    const code = `
      const sm4_sbox = [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7];
    `;
    const matches = identifyCrypto(code);
    assert.ok(matches.some((m) => m.algorithm === "SM4"));
  });
});

test("AST Encryption Function Candidate Scoring", async (t) => {
  await t.test("Scores functions containing target parameters and bitwise math higher", () => {
    const code = `
      function signRequest(password, token, timestamp) {
        let hash = 0;
        for (let i = 0; i < password.length; i++) {
          hash = ((hash << 5) - hash) ^ password.charCodeAt(i);
          hash = hash >>> 0;
        }
        return hash.toString(16);
      }

      function renderButton(label) {
        return "<button>" + label + "</button>";
      }
    `;

    const candidates = findCryptoCandidates(code, ["password", "token"]);
    assert.ok(candidates.length > 0);
    assert.equal(candidates[0].functionName, "signRequest");
    assert.ok(candidates[0].score > 10);
    assert.ok(candidates[0].matchedParameters.includes("password"));
    assert.ok(candidates[0].matchedParameters.includes("token"));
  });
});

test("Anti-Crawl Classification", async (t) => {
  await t.test("Detects Cloudflare Turnstile & Challenge", () => {
    const code = `
      window._cf_chl_opt = { cType: "non-interactive" };
      const script = document.createElement("script");
      script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js";
    `;
    const detections = classifyAnticrawl(code);
    assert.ok(detections.some((d) => d.vendor.includes("Cloudflare")));
  });

  await t.test("Detects JSVMP Opcode dispatcher loop", () => {
    const code = `
      while(true) {
        switch(opcode) {
          case 0x1: a = b + c; break;
          case 0x2: return a;
        }
      }
    `;
    const detections = classifyAnticrawl(code);
    assert.ok(detections.some((d) => d.type === "jsvmp"));
  });

  await t.test("Detects anti-debugging traps", () => {
    const code = `
      setInterval(function() {
        (function() { return false; }['constructor']('debugger')['call']());
      }, 50);
    `;
    const detections = classifyAnticrawl(code);
    assert.ok(detections.some((d) => d.type === "anti_debug"));
  });
});

test("JSRPC Automation Generator", async (t) => {
  await t.test("Generates valid in-page stub, Flask server, and Burp guide", () => {
    const result = generateJsrpcFiles({
      actionName: "encrypt_token",
      targetExpression: "window.encryptData",
      port: 13370,
    });

    assert.ok(result.inPageStub.includes("window.__JSRPC_ACTIONS__"));
    assert.ok(result.inPageStub.includes("encrypt_token"));
    assert.ok(result.flaskProxy.includes("13370"));
    assert.ok(result.flaskProxy.includes("from flask import Flask"));
    assert.ok(result.burpDoc.includes("AutoDecoder"));
  });
});

test("Endpoint & Secret Extraction", async (t) => {
  await t.test("Extracts REST APIs, websockets, and JWT tokens", () => {
    const code = `
      const API_LOGIN = "/api/v2/user/login";
      const WS_FEED = "wss://stream.example.com/live";
      const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6-dummy";
    `;
    const result = extractEndpointsAndSecrets(code);
    assert.ok(result.endpoints.includes("/api/v2/user/login"));
    assert.ok(result.websockets.includes("wss://stream.example.com/live"));
    assert.ok(result.secrets.some((s) => s.type.toLowerCase().includes("jwt")));
  });
});

test("JavaScript Beautifier", async (t) => {
  await t.test("Formats minified one-line code with indentation", () => {
    const minified = "function foo(a,b){if(a>0){return a+b;}else{return b;}}";
    const beautified = beautifyJs(minified);
    assert.ok(beautified.includes("\n"));
    assert.ok(beautified.includes("return a+b;"));
  });
});

test("Browser Launcher Discovery", async (t) => {
  await t.test("Discovers installed browser executable on current OS or returns null gracefully", () => {
    const binary = findBrowserExecutable();
    // On Windows development machines with Edge or Chrome, it will locate the executable
    if (binary) {
      assert.equal(typeof binary, "string");
      assert.ok(binary.length > 0);
    } else {
      assert.equal(binary, null);
    }
  });
});


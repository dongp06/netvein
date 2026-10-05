import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
import { DEFAULT_SUGGESTIONS, ERROR_CODES, ToolError, err, ok, toEnvelope } from "../src/errors.js";
import { parseIdentityPayload, parseProxyServer, serializeIdentity, toCdpProxyServer } from "../src/identity.js";
import { findBrowserExecutable } from "../src/launcher.js";
import { compressAxTree, diffSnapshots, formatSemanticView } from "../src/pruner.js";
import { createServer } from "../src/server.js";
import { activePatchIds, buildStealthScript, createSeededPrng, seedFromName } from "../src/stealth.js";

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

test("Structured Error Envelope", async (t) => {
  await t.test("ok() wraps data with success true", () => {
    const result = ok({ nodes: 3 });
    assert.equal(result.success, true);
    assert.deepEqual(result.data, { nodes: 3 });
  });

  await t.test("err() omits suggestion when not supplied", () => {
    const result = err("ERR_NO_SESSION", "no tab");
    assert.equal(result.success, false);
    assert.equal(result.error_code, "ERR_NO_SESSION");
    assert.equal(result.message, "no tab");
    assert.equal("suggestion" in result, false);
  });

  await t.test("err() includes suggestion when supplied", () => {
    const result = err("ERR_STALE_NODE_ID", "stale", "re-run semantic_view");
    assert.equal(result.suggestion, "re-run semantic_view");
  });

  await t.test("ToolError round-trips into an envelope", () => {
    const error = new ToolError("ERR_STALE_NODE_ID", "id 15 is from version 2", "re-run semantic_view");
    const envelope = error.toEnvelope();
    assert.equal(envelope.error_code, "ERR_STALE_NODE_ID");
    assert.equal(envelope.suggestion, "re-run semantic_view");
  });

  await t.test("toEnvelope maps a thrown non-ToolError to the fallback code", () => {
    const envelope = toEnvelope(new Error("boom"), "ERR_AX_TREE_UNAVAILABLE");
    assert.equal(envelope.error_code, "ERR_AX_TREE_UNAVAILABLE");
    assert.equal(envelope.message, "boom");
  });

  await t.test("toEnvelope attaches the default suggestion on the fallback path", () => {
    const envelope = toEnvelope(new Error("no tab"), "ERR_NO_SESSION");
    assert.equal(envelope.suggestion, DEFAULT_SUGGESTIONS.ERR_NO_SESSION);
  });

  await t.test("every error code has a default suggestion", () => {
    for (const code of Object.keys(ERROR_CODES) as Array<keyof typeof ERROR_CODES>) {
      assert.ok(DEFAULT_SUGGESTIONS[code]?.length > 0, `Missing default suggestion for ${code}`);
    }
  });

  await t.test("toEnvelope preserves a thrown ToolError's own code", () => {
    const envelope = toEnvelope(new ToolError("ERR_PROXY_UNREACHABLE", "proxy down"), "ERR_NO_SESSION");
    assert.equal(envelope.error_code, "ERR_PROXY_UNREACHABLE");
  });

  await t.test("every registry entry has a non-empty description", () => {
    for (const [code, description] of Object.entries(ERROR_CODES)) {
      assert.ok(description.length > 0, `Empty description for ${code}`);
      assert.ok(code.startsWith("ERR_"), `Code ${code} missing ERR_ prefix`);
    }
  });
});

test("Stealth Patch Generator", async (t) => {
  await t.test("off profile activates no patches", () => {
    assert.deepEqual(activePatchIds("off"), []);
  });

  await t.test("basic profile activates exactly the four identity patches", () => {
    assert.deepEqual(activePatchIds("basic").sort(), [
      "iframe-content-window",
      "navigator-surface",
      "navigator-webdriver",
      "runtime-leak",
    ]);
  });

  await t.test("strict profile activates every patch", () => {
    const strict = activePatchIds("strict");
    assert.ok(strict.length > activePatchIds("basic").length);
    for (const id of activePatchIds("basic")) {
      assert.ok(strict.includes(id), `strict missing basic patch ${id}`);
    }
    assert.ok(strict.includes("canvas-noise"));
    assert.ok(strict.includes("webgl-vendor"));
    assert.ok(strict.includes("audio-noise"));
    assert.ok(strict.includes("to-string-integrity"));
  });

  await t.test("buildStealthScript is deterministic for the same profile and seed", () => {
    assert.equal(buildStealthScript("strict", 483920), buildStealthScript("strict", 483920));
  });

  await t.test("buildStealthScript differs across seeds", () => {
    assert.notEqual(buildStealthScript("strict", 1), buildStealthScript("strict", 2));
  });

  await t.test("off profile produces an empty script", () => {
    assert.equal(buildStealthScript("off", 99), "");
  });

  await t.test("strict script mentions the patched surfaces", () => {
    const script = buildStealthScript("strict", 1234);
    assert.ok(script.includes("webdriver"));
    assert.ok(script.includes("getImageData"));
    assert.ok(script.includes("37445"));
    assert.ok(script.includes("getFloatFrequencyData"));
  });

  await t.test("the seed literal appears in the generated script", () => {
    assert.ok(buildStealthScript("basic", 777).includes("777"));
  });

  await t.test("seeded prng is deterministic and bounded", () => {
    const a = createSeededPrng(42);
    const b = createSeededPrng(42);
    for (let i = 0; i < 50; i++) {
      const value = a();
      assert.equal(value, b());
      assert.ok(value >= 0 && value < 1, `value out of range: ${value}`);
    }
  });

  await t.test("seedFromName is stable and collision-free for distinct names", () => {
    assert.equal(seedFromName("identity-a"), seedFromName("identity-a"));
    assert.notEqual(seedFromName("identity-a"), seedFromName("identity-b"));
  });
});

test("Stealth Tool Registration & Session Guards", async (t) => {
  await t.test("registers the three stealth tools", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    for (const name of ["stealth_enable", "stealth_status", "stealth_probe"]) {
      assert.ok(tools.includes(name), `Missing tool: ${name}`);
    }
  });

  await t.test("stealth_enable without an attached tab returns ERR_NO_SESSION", async () => {
    const session = new CdpSession();
    const result = await session.applyStealthEnvelope("strict");
    assert.equal(result.success, false);
    if (!result.success) {
      assert.equal(result.error_code, "ERR_NO_SESSION");
      assert.ok(result.suggestion);
    }
  });

  await t.test("stealthStatus reports the active profile and patch ids without a tab", () => {
    const session = new CdpSession();
    const status = session.stealthStatus();
    assert.equal(status.profile, "off");
    assert.deepEqual(status.patchIds, []);
  });
});

const loginAxTree = JSON.parse(
  readFileSync(new URL("./fixtures/ax-tree-login.json", import.meta.url), "utf8"),
).nodes;

test("Semantic Pruner", async (t) => {
  await t.test("drops ignored and generic nodes", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1 });
    assert.equal(snapshot.nodes.some((n) => n.role === "generic"), false);
    assert.equal(snapshot.nodes.some((n) => n.role === "none"), false);
  });

  await t.test("keeps the accessible role and name, dropping an empty value", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1 });
    const email = snapshot.nodes.find((n) => n.name === "Email");
    assert.ok(email);
    assert.equal(email!.role, "textbox");
    // An empty value carries no information, so it is omitted rather than
    // rendered as value="". The diff test below covers a non-empty value.
    assert.equal(email!.value, undefined);
  });

  await t.test("assigns sequential integer ids starting at 1", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1 });
    assert.deepEqual(
      snapshot.nodes.map((n) => n.id),
      [1, 2, 3, 4],
    );
  });

  await t.test("idMap maps each integer id to its backendDOMNodeId", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1 });
    // id 1 is the RootWebArea, which carries no backendDOMNodeId, so the first
    // addressable id is 2 (Email → 11). RootWebArea is still rendered.
    assert.equal(snapshot.idMap.get(1), undefined);
    assert.equal(snapshot.idMap.get(2), 11);
    assert.equal(snapshot.idMap.get(3), 12);
    assert.equal(snapshot.idMap.get(4), 13);
  });

  await t.test("interactiveOnly keeps only actionable roles", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1, interactiveOnly: true });
    assert.deepEqual(
      snapshot.nodes.map((n) => n.role),
      ["textbox", "textbox", "button"],
    );
  });

  await t.test("maxNodes truncates and reports truncation", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1, maxNodes: 2 });
    assert.equal(snapshot.nodes.length, 2);
    assert.equal(snapshot.truncated, true);
  });

  await t.test("formatSemanticView renders one labelled line per node", () => {
    const snapshot = compressAxTree(loginAxTree, { version: 1 });
    const text = formatSemanticView(snapshot);
    assert.ok(text.includes("#1"));
    assert.ok(text.includes('"Login"'));
    assert.ok(text.includes('[4] button'));
    assert.ok(text.includes('"Sign in"'));
  });

  await t.test("diffSnapshots reports a rename as one addition and one removal", () => {
    const before = compressAxTree(loginAxTree, { version: 1 });
    const afterTree = JSON.parse(JSON.stringify(loginAxTree));
    afterTree[4].name.value = "Sign out";
    const after = compressAxTree(afterTree, { version: 2 });
    const diff = diffSnapshots(before, after, 100);
    // Nodes are keyed by role + name, so a rename is a removal of the old key
    // and an addition of the new one, not a change of a single node.
    assert.equal(diff.added.some((n) => n.name === "Sign out"), true);
    assert.equal(diff.removed.some((n) => n.name === "Sign in"), true);
    assert.equal(diff.changed.length, 0);
  });

  await t.test("diffSnapshots reports a changed value for a stable key", () => {
    const before = compressAxTree(loginAxTree, { version: 1 });
    const afterTree = JSON.parse(JSON.stringify(loginAxTree));
    afterTree[2].value.value = "user@example.com";
    const after = compressAxTree(afterTree, { version: 2 });
    const diff = diffSnapshots(before, after, 100);
    assert.equal(diff.changed.length, 1);
    assert.equal(diff.changed[0].name, "Email");
    assert.equal(diff.changed[0].value, "user@example.com");
  });

  await t.test("diffSnapshots reports a removed visible node", () => {
    const before = compressAxTree(loginAxTree, { version: 1 });
    const trimmed = JSON.parse(JSON.stringify(loginAxTree));
    // Drop the button node (index 4) and its reference from the generic parent.
    trimmed[1].childIds = ["3", "4", "6"];
    trimmed.splice(4, 1);
    const after = compressAxTree(trimmed, { version: 2 });
    const diff = diffSnapshots(before, after, 100);
    assert.equal(diff.removed.length, 1);
    assert.equal(diff.removed[0].name, "Sign in");
  });
});

test("Semantic View Tool", async (t) => {
  await t.test("registers semantic_view", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.ok(tools.includes("semantic_view"));
  });

  await t.test("semantic_view without an attached tab returns ERR_NO_SESSION", async () => {
    const session = new CdpSession();
    const result = await session.semanticViewEnvelope({});
    assert.equal(result.success, false);
    if (!result.success) assert.equal(result.error_code, "ERR_NO_SESSION");
  });

  await t.test("currentSemanticSnapshot is null before the first call", () => {
    assert.equal(new CdpSession().currentSemanticSnapshot(), null);
  });
});

test("Semantic Interaction Tools", async (t) => {
  await t.test("registers interact_semantic and semantic_diff", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.ok(tools.includes("interact_semantic"));
    assert.ok(tools.includes("semantic_diff"));
  });

  await t.test("interact_semantic with no snapshot fails as stale rather than crashing", async () => {
    const session = new CdpSession();
    const result = await session.interactSemanticEnvelope(3, "click");
    assert.equal(result.success, false);
    if (!result.success) {
      assert.ok(
        result.error_code === "ERR_STALE_NODE_ID" || result.error_code === "ERR_NO_SESSION",
        `unexpected code ${result.error_code}`,
      );
      assert.ok(result.suggestion);
    }
  });

  await t.test("semantic_diff without a snapshot returns an envelope error", async () => {
    const session = new CdpSession();
    const result = await session.semanticDiffEnvelope(100);
    assert.equal(result.success, false);
  });
});

test("Identity Module", async (t) => {
  await t.test("parseProxyServer accepts host:port", () => {
    assert.equal(parseProxyServer("127.0.0.1:8080"), "127.0.0.1:8080");
  });

  await t.test("parseProxyServer accepts scheme://host:port and strips the scheme", () => {
    assert.equal(parseProxyServer("http://127.0.0.1:8080"), "127.0.0.1:8080");
    assert.equal(parseProxyServer("socks5://10.0.0.1:1080"), "10.0.0.1:1080");
  });

  await t.test("parseProxyServer rejects a string without a port", () => {
    assert.throws(() => parseProxyServer("127.0.0.1"), /host:port/);
  });

  await t.test("parseProxyServer rejects an out-of-range port", () => {
    assert.throws(() => parseProxyServer("127.0.0.1:99999"), /host:port/);
  });

  await t.test("registers the three identity tools", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    for (const name of ["identity_create", "identity_use", "identity_list"]) {
      assert.ok(tools.includes(name), `Missing tool: ${name}`);
    }
  });

  await t.test("identity_create with an unreachable proxy reports ERR_PROXY_UNREACHABLE and registers nothing", async () => {
    const session = new CdpSession();
    const result = await session.createIdentityEnvelope({
      name: "probe-fail",
      proxy: "127.0.0.1:1",
    });
    assert.equal(result.success, false);
    if (!result.success) assert.equal(result.error_code, "ERR_PROXY_UNREACHABLE");
    assert.equal(session.listIdentities().length, 0);
  });
});

test("Identity Serialization", async (t) => {
  const sampleCookies = [
    {
      name: "sid",
      value: "abc",
      domain: ".example.com",
      path: "/",
      expires: 0,
      size: 3,
      httpOnly: true,
      secure: true,
      session: true,
    },
  ];

  await t.test("serializeIdentity produces a parseable payload", () => {
    const payload = serializeIdentity("alpha", "host:3128", sampleCookies, { theme: "dark" }, { tab: "1" });
    const json = JSON.stringify(payload);
    const parsed = parseIdentityPayload(json);
    assert.equal(parsed.name, "alpha");
    assert.equal(parsed.proxy, "host:3128");
    assert.equal(parsed.cookies.length, 1);
    assert.equal(parsed.localStorage.theme, "dark");
    assert.equal(parsed.sessionStorage.tab, "1");
  });

  await t.test("parseIdentityPayload rejects invalid JSON", () => {
    assert.throws(() => parseIdentityPayload("{not json"), /not valid JSON/);
  });

  await t.test("parseIdentityPayload rejects a payload missing cookies", () => {
    assert.throws(() => parseIdentityPayload('{"name":"x"}'), /cookies/);
  });

  await t.test("parseIdentityPayload rejects a payload missing name", () => {
    assert.throws(() => parseIdentityPayload('{"cookies":[]}'), /name/);
  });

  await t.test("registers the two identity transfer tools", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    for (const name of ["identity_export", "identity_import"]) {
      assert.ok(tools.includes(name), `Missing tool: ${name}`);
    }
  });

  await t.test("identity_import with a malformed payload returns an envelope error and applies nothing", async () => {
    const session = new CdpSession();
    const result = await session.importIdentityEnvelope("{not json");
    assert.equal(result.success, false);
    if (!result.success) assert.ok(result.message.length > 0);
  });
});

test("Captcha Tools", async (t) => {
  await t.test("registers captcha_detect and captcha_provider_hook", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    for (const name of ["captcha_detect", "captcha_provider_hook"]) {
      assert.ok(tools.includes(name), `Missing tool: ${name}`);
    }
  });

  await t.test("captcha_provider_hook is inert until called", () => {
    const session = new CdpSession();
    assert.deepEqual(session.captchaProviderStatus(), { registered: false });
  });

  await t.test("captcha_detect without an attached tab returns ERR_NO_SESSION", async () => {
    const session = new CdpSession();
    const result = await session.captchaDetectEnvelope();
    assert.equal(result.success, false);
    if (!result.success) assert.equal(result.error_code, "ERR_NO_SESSION");
  });
});

test("Tool Surface Contract", async (t) => {
  await t.test("server exposes exactly 101 tools", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.equal(tools.length, 101, `Expected 101 tools, got ${tools.length}`);
  });

  await t.test("every new tool is registered", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    const expected = [
      "stealth_enable",
      "stealth_status",
      "stealth_probe",
      "semantic_view",
      "interact_semantic",
      "semantic_diff",
      "identity_create",
      "identity_use",
      "identity_list",
      "identity_export",
      "identity_import",
      "captcha_detect",
      "captcha_provider_hook",
    ];
    for (const name of expected) {
      assert.ok(tools.includes(name), `Missing new tool: ${name}`);
    }
  });
});

test("New tools return the structured error envelope at the MCP boundary", async (t) => {
  // Drives the handler the MCP client actually calls, not the session method,
  // so a green session-level test cannot hide an unwired envelope.
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
    const server = createServer(new CdpSession());
    const entry = (server as any)._registeredTools[name];
    const result = await entry.handler(args, {} as never);
    return JSON.parse(result.content[0].text) as Record<string, unknown>;
  };

  await t.test("stealth_enable with no session returns the envelope, not a bare error string", async () => {
    const payload = await call("stealth_enable", { profile: "basic" });
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_NO_SESSION");
    assert.equal(typeof payload.suggestion, "string");
  });

  await t.test("semantic_view with no session returns the envelope", async () => {
    const payload = await call("semantic_view", {});
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_NO_SESSION");
  });

  await t.test("interact_semantic with no session returns the envelope", async () => {
    const payload = await call("interact_semantic", { id: 1, action: "click", snapshotVersion: 1 });
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_NO_SESSION");
  });

  await t.test("identity_create with no session returns the envelope", async () => {
    const payload = await call("identity_create", { name: "boundary" });
    assert.equal(payload.success, false);
    assert.ok(typeof payload.error_code === "string");
  });

  await t.test("identity_import with a malformed payload returns the envelope and applies nothing", async () => {
    const payload = await call("identity_import", { json: "{not json" });
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_NO_IDENTITY");
    assert.equal(typeof payload.suggestion, "string");
  });

  await t.test("captcha_detect with no session returns the envelope", async () => {
    const payload = await call("captcha_detect", {});
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_NO_SESSION");
  });

  await t.test("captcha_provider_hook with an empty key returns ERR_CAPTCHA_PROVIDER_DISABLED", async () => {
    const payload = await call("captcha_provider_hook", { provider: "", apiKey: "" });
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_CAPTCHA_PROVIDER_DISABLED");
  });

  await t.test("a successful call still returns success true", async () => {
    const payload = await call("stealth_status", {});
    assert.equal(payload.success, true);
  });
});

test("Final review fixes", async (t) => {
  await t.test("I4: toCdpProxyServer preserves the scheme so a SOCKS proxy is not sent to Chrome as HTTP", () => {
    assert.equal(toCdpProxyServer("socks5://10.0.0.1:1080"), "socks5://10.0.0.1:1080");
    assert.equal(toCdpProxyServer("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
    assert.equal(toCdpProxyServer("127.0.0.1:8080"), "127.0.0.1:8080");
  });

  await t.test("I4: toCdpProxyServer still rejects a malformed proxy", () => {
    assert.throws(() => toCdpProxyServer("127.0.0.1"), /host:port/);
    assert.throws(() => toCdpProxyServer("127.0.0.1:99999"), /host:port/);
  });

  const strictScript = buildStealthScript("strict", 4242);

  await t.test("I5: canvas coverage includes toDataURL and toBlob, not only getImageData", () => {
    assert.ok(strictScript.includes("toDataURL"), "canvas toDataURL not patched");
    assert.ok(strictScript.includes("toBlob"), "canvas toBlob not patched");
    assert.ok(strictScript.includes("getImageData"), "canvas getImageData not patched");
  });

  await t.test("I5: audio coverage includes getByteFrequencyData", () => {
    assert.ok(strictScript.includes("getByteFrequencyData"));
  });

  await t.test("I5: WebGL2 is patched, not only WebGL1", () => {
    assert.ok(strictScript.includes("WebGL2RenderingContext"));
  });

  await t.test("I5: navigator surface includes mimeTypes and platform", () => {
    assert.ok(strictScript.includes("mimeTypes"), "navigator.mimeTypes not patched");
    assert.ok(strictScript.includes("platform"), "navigator.platform not patched");
  });

  await t.test("I6: patches register their replacements for toString integrity", () => {
    assert.ok(
      strictScript.includes("__markPatched"),
      "patched prototype methods are not registered, so getImageData.toString() reveals the patch",
    );
  });

  await t.test("I6: the markPatched helper exists even in the basic profile", () => {
    assert.ok(buildStealthScript("basic", 4242).includes("__markPatched"));
  });

  await t.test("I2: interact_semantic requires snapshotVersion so the stale-id guard is not opt-in", () => {
    const server = createServer(new CdpSession());
    const registered = (server as any)._registeredTools["interact_semantic"].inputSchema;
    // The SDK wraps the raw ZodRawShape in a Zod object; fields live on .shape.
    const fields = registered.shape ?? registered;
    assert.equal(fields.snapshotVersion.safeParse(undefined).success, false);
    assert.equal(fields.snapshotVersion.safeParse(3).success, true);
  });
});


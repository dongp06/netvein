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
import { checkForUpdate, classifyUpdate, compareVersions, isCheckDue, parseVersion } from "../src/updater.js";
import { beautifyBody, buildCurl, diffReplay, filterFlows, formatFlowList, stripHeaders, type FlowDetail, type FlowSummary } from "../src/mitm/store.js";
import { buildProxyArgs, MitmError } from "../src/mitm/manager.js";
import { shapeFlowDetail } from "../src/mitm/store.js";
import { envelopeFromThrow } from "../src/errors.js";

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
    assert.ok(resources.includes("netvein://session/status"), "Missing session-status resource");
    assert.ok(resources.includes("netvein://session/console"), "Missing console-logs resource");
    assert.ok(resources.includes("netvein://session/timeline"), "Missing timeline-events resource");

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

  await t.test("traffic error codes are registered with suggestions", () => {
    for (const code of [
      "ERR_MITM_UNAVAILABLE",
      "ERR_MITM_PORT_BUSY",
      "ERR_MITM_NOT_RUNNING",
      "ERR_MITM_LOST",
      "ERR_MITM_FLOW_NOT_FOUND",
      "ERR_MITM_BAD_PATTERN",
    ] as const) {
      assert.ok(code in ERROR_CODES, `missing code ${code}`);
      assert.ok(code in DEFAULT_SUGGESTIONS, `missing suggestion ${code}`);
    }
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
  await t.test("server exposes exactly 123 tools", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.equal(tools.length, 123, `Expected 123 tools, got ${tools.length}`);
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
      "traffic_start",
      "traffic_stop",
      "traffic_status",
      "traffic_flows",
      "traffic_flow",
      "traffic_curl",
      "traffic_breakpoint_set",
      "traffic_breakpoint_release",
      "traffic_replay",
      "traffic_export",
      "netvein_init",
      "netvein_project",
      "capture_session_start",
      "capture_session_stop",
      "capture_session_status",
      "capture_session_list",
      "capture_exec",
      "capture_env",
      "capture_inspect_body",
      "capture_decode_stream",
      "capture_search",
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

test("Update Check", async (t) => {
  const interval = 24 * 3600_000;
  const baseDeps = {
    localVersion: "0.3.0",
    now: () => "2026-10-05T00:00:00.000Z",
    readCache: async () => null,
    writeCache: async () => {},
    intervalMs: interval,
  };

  await t.test("parseVersion reads v-prefixed, bare and short semver tags", () => {
    assert.deepEqual(parseVersion("v0.4.0"), [0, 4, 0]);
    assert.deepEqual(parseVersion("0.4.0"), [0, 4, 0]);
    assert.deepEqual(parseVersion("1.2"), [1, 2, 0]);
  });

  await t.test("parseVersion returns null for a non-version tag", () => {
    assert.equal(parseVersion("nightly"), null);
    assert.equal(parseVersion(""), null);
    assert.equal(parseVersion("v"), null);
  });

  await t.test("compareVersions orders numerically, not lexically", () => {
    assert.equal(compareVersions([0, 10, 0], [0, 9, 0]), 1);
    assert.equal(compareVersions([0, 9, 0], [0, 10, 0]), -1);
    assert.equal(compareVersions([1, 0, 0], [1, 0, 0]), 0);
    assert.equal(compareVersions([1], [1, 0, 0]), 0);
  });

  await t.test("classifyUpdate reports an available update", () => {
    const result = classifyUpdate("0.3.0", ["v0.3.0", "v0.4.0"]);
    assert.equal(result.status, "update-available");
    assert.equal(result.remoteVersion, "0.4.0");
  });

  await t.test("classifyUpdate reports up-to-date when local is the newest tag", () => {
    assert.equal(classifyUpdate("0.4.0", ["v0.3.0", "v0.4.0"]).status, "up-to-date");
  });

  await t.test("classifyUpdate reports ahead when local is newer than every tag", () => {
    assert.equal(classifyUpdate("0.5.0", ["v0.3.0", "v0.4.0"]).status, "ahead");
  });

  await t.test("classifyUpdate ignores unparsable tags", () => {
    assert.equal(classifyUpdate("0.4.0", ["nightly", "v0.4.0"]).status, "up-to-date");
  });

  await t.test("classifyUpdate reports unknown when no tag parses", () => {
    assert.equal(classifyUpdate("0.4.0", ["nightly", "latest"]).status, "unknown");
  });

  await t.test("isCheckDue is true with no previous check", () => {
    assert.equal(isCheckDue(null, "2026-10-05T00:00:00.000Z", interval), true);
  });

  await t.test("isCheckDue is false inside the interval", () => {
    assert.equal(isCheckDue("2026-10-05T00:00:00.000Z", "2026-10-05T01:00:00.000Z", interval), false);
  });

  await t.test("isCheckDue is true past the interval", () => {
    assert.equal(isCheckDue("2026-10-05T00:00:00.000Z", "2026-10-06T01:00:00.000Z", interval), true);
  });

  await t.test("isCheckDue treats an unparsable timestamp as due", () => {
    assert.equal(isCheckDue("not-a-date", "2026-10-05T00:00:00.000Z", interval), true);
  });

  await t.test("checkForUpdate reports an available update", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => ["abc123\trefs/tags/v0.4.0", "def456\trefs/tags/v0.3.0"],
    });
    assert.equal(result.status, "update-available");
    assert.equal(result.remoteVersion, "0.4.0");
    assert.equal(result.localVersion, "0.3.0");
  });

  await t.test("checkForUpdate returns a network failure as unknown and never throws", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => {
        throw new Error("ETIMEDOUT");
      },
    });
    assert.equal(result.status, "unknown");
    assert.ok(result.detail && result.detail.length > 0);
  });

  await t.test("checkForUpdate throttles an unforced call inside the interval without calling out", async () => {
    let called = false;
    const result = await checkForUpdate({
      ...baseDeps,
      now: () => "2026-10-05T01:00:00.000Z",
      readCache: async () => ({ checkedAt: "2026-10-05T00:00:00.000Z" }),
      runLsRemote: async () => {
        called = true;
        return [];
      },
    });
    assert.equal(called, false);
    assert.equal(result.status, "throttled");
  });

  await t.test("checkForUpdate with force bypasses the throttle", async () => {
    let called = false;
    const result = await checkForUpdate({
      ...baseDeps,
      now: () => "2026-10-05T01:00:00.000Z",
      readCache: async () => ({ checkedAt: "2026-10-05T00:00:00.000Z" }),
      runLsRemote: async () => {
        called = true;
        return ["a\trefs/tags/v0.4.0"];
      },
      force: true,
    });
    assert.equal(called, true);
    assert.equal(result.status, "update-available");
  });

  await t.test("checkForUpdate writes the check timestamp to the cache after a real check", async () => {
    let written: { checkedAt: string } | null = null;
    await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => ["a\trefs/tags/v0.3.0"],
      writeCache: async (value) => {
        written = value;
      },
    });
    assert.ok(written);
    assert.equal(written!.checkedAt, "2026-10-05T00:00:00.000Z");
  });

  await t.test("checkForUpdate reports branchDiffers when the remote head differs, even with no tags", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => [],
      runLsRemoteBranch: async () => "aaaa1111",
      readLocalHead: async () => "bbbb2222",
    });
    assert.equal(result.branchDiffers, true);
    assert.equal(result.remoteBranchHead, "aaaa1111");
    assert.equal(result.localHead, "bbbb2222");
    // No tags exist, so the version signal stays honest rather than guessing.
    assert.equal(result.status, "unknown");
  });

  await t.test("checkForUpdate reports branchDiffers false when the heads match", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => [],
      runLsRemoteBranch: async () => "same9999",
      readLocalHead: async () => "same9999",
    });
    assert.equal(result.branchDiffers, false);
  });

  await t.test("checkForUpdate omits branch fields when the branch probes are not provided", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => ["a\trefs/tags/v0.4.0"],
    });
    assert.equal(result.branchDiffers, undefined);
  });

  await t.test("checkForUpdate survives a failing branch probe", async () => {
    const result = await checkForUpdate({
      ...baseDeps,
      runLsRemote: async () => ["a\trefs/tags/v0.4.0"],
      runLsRemoteBranch: async () => {
        throw new Error("no upstream");
      },
      readLocalHead: async () => "bbbb2222",
    });
    assert.equal(result.status, "update-available");
    assert.equal(result.branchDiffers, undefined);
  });

  await t.test("registers check_for_update as a new tool", () => {
    const server = createServer(new CdpSession());
    const tools = Object.keys((server as any)._registeredTools || {});
    assert.ok(tools.includes("check_for_update"));
  });
});

test("Netvein Rename", async (t) => {
  await t.test("package identity is netvein-mcp with a compat bin alias", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(pkg.name, "netvein-mcp");
    assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
    assert.equal(pkg.bin["netvein-mcp"], "./dist/index.js");
    assert.equal(pkg.bin["reverse-engineering-mcp"], "./dist/index.js");
  });

  await t.test("single version source: VERSION matches package.json", async () => {
    const { VERSION } = await import("../src/version.js");
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.equal(VERSION, pkg.version);
  });

  await t.test("MCP handshake carries the single-source version", async () => {
    const { VERSION } = await import("../src/version.js");
    const server = createServer(new CdpSession());
    const info = (server as any).server?._serverInfo;
    assert.equal(info.name, "netvein-mcp");
    assert.equal(info.version, VERSION);
  });

  await t.test("default repo URL points at the renamed repository", async () => {
    const m = await import("../src/updater.js");
    assert.equal(m.DEFAULT_REPO_URL, "https://github.com/dongp06/netvein-mcp");
  });

  await t.test("NETVEIN_UPDATE_CHECK disables the check", async () => {
    const m = await import("../src/updater.js");
    assert.equal(m.isUpdateCheckEnabled({ NETVEIN_UPDATE_CHECK: "0" }), false);
    assert.equal(m.isUpdateCheckEnabled({}), true);
  });

  await t.test("deprecated REVERSE_MCP_UPDATE_CHECK still disables, with a one-time warning", async () => {
    const m = await import("../src/updater.js");
    const warnings: string[] = [];
    const original = console.error;
    console.error = (line?: unknown) => {
      warnings.push(String(line));
    };
    try {
      assert.equal(m.isUpdateCheckEnabled({ REVERSE_MCP_UPDATE_CHECK: "0" }), false);
      assert.equal(m.isUpdateCheckEnabled({ REVERSE_MCP_UPDATE_CHECK: "0" }), false);
      assert.equal(warnings.length, 1, `expected exactly one deprecation warning, got ${warnings.length}`);
      assert.ok(warnings[0].includes("NETVEIN_UPDATE_CHECK"), "warning should name the replacement");
    } finally {
      console.error = original;
    }
  });

  await t.test("NETVEIN_UPDATE_INTERVAL_HOURS wins over the deprecated name", async () => {
    const m = await import("../src/updater.js");
    assert.equal(m.updateIntervalMs({ NETVEIN_UPDATE_INTERVAL_HOURS: "6" }), 6 * 3600_000);
    assert.equal(m.updateIntervalMs({ REVERSE_MCP_UPDATE_INTERVAL_HOURS: "3" }), 3 * 3600_000);
  });

  await t.test("resource URIs moved to the netvein scheme", () => {
    const server = createServer(new CdpSession());
    const resources = Object.keys((server as any)._registeredResources || {});
    assert.ok(resources.includes("netvein://session/status"), `got ${resources.join(", ")}`);
    assert.equal(resources.includes("reverse://session/status"), false);
  });
});


const mk = (over: Partial<FlowSummary>): FlowSummary => ({
  id: "f1", ts: "2026-10-06T00:00:00.000Z", method: "GET", host: "api.example.com",
  path: "/v1/sign", status: 200, bytes: 512, durationMs: 42, held: false, expired: false,
  scheme: "https", ...over,
});

test("Traffic Store", async (t) => {
  await t.test("stripHeaders keeps the curated subset, case-insensitively", () => {
    const out = stripHeaders(
      { "Content-Type": "application/json", "User-Agent": "x", Cookie: "a=b", "X-Mitm-Proxy": "y" },
      "request",
    );
    assert.deepEqual(out, { "content-type": "application/json", "user-agent": "x", cookie: "a=b" });
  });

  await t.test("filterFlows matches host/path/method/status/heldOnly/since", () => {
    const flows = [mk({}), mk({ id: "f2", host: "other.dev", path: "/x" }), mk({ id: "f3", status: 404 }), mk({ id: "f4", held: true })];
    assert.deepEqual(filterFlows(flows, { host: "api.example.com" }).map((f) => f.id).sort(), ["f1", "f3", "f4"]);
    assert.deepEqual(filterFlows(flows, { pathContains: "/x" }).map((f) => f.id), ["f2"]);
    assert.deepEqual(filterFlows(flows, { status: 404 }).map((f) => f.id), ["f3"]);
    assert.deepEqual(filterFlows(flows, { heldOnly: true }).map((f) => f.id), ["f4"]);
    assert.deepEqual(filterFlows(flows, { since: "2026-10-06T00:00:00.500Z" }), []);
    assert.equal(filterFlows(flows, { limit: 2 }).length, 2);
  });

  await t.test("formatFlowList renders one compact line per flow, newest last", () => {
    const text = formatFlowList([mk({}), mk({ id: "f2", method: "POST", status: null, held: true, expired: true })]);
    assert.ok(text.includes("f1 GET api.example.com/v1/sign -> 200 512B 42ms"), text);
    assert.ok(text.includes("f2 POST api.example.com/v1/sign -> - 512B 42ms [HELD expired]"), text);
    assert.ok(text.startsWith("2 flows"));
  });
});

test("Traffic Store shaping II", async (t) => {
  await t.test("beautifyBody pretty-prints JSON bodies", () => {
    assert.equal(beautifyBody('{"sig":"x"}', "application/json", 200), '{\n  "sig": "x"\n}');
  });

  await t.test("beautifyBody truncates to maxChars with marker", () => {
    const out = beautifyBody("x".repeat(50), "text/plain", 20);
    assert.ok(out.length <= 34, `len=${out.length}`);
    assert.ok(out.endsWith("[truncated]"));
  });

  await t.test("beautifyBody passes null and non-text through", () => {
    assert.equal(beautifyBody(null, null, 100), "");
    assert.equal(beautifyBody("b", "application/octet-stream", 100), "[binary 1 bytes]");
  });

  await t.test("buildCurl emits method, url, curated headers and shell-escaped body", () => {
    const detail: FlowDetail = {
      summary: { id: "f9", ts: "2026-10-06T00:00:00Z", method: "POST", host: "api.example.com", path: "/v1/sign?a=1", status: 200, bytes: 9, durationMs: 10, held: false, expired: false, scheme: "https" },
      request: { headers: { "content-type": "application/json", cookie: "sid=x", "accept-encoding": "gzip" }, body: `{"q":"it's"}` },
      response: null,
    };
    const cmd = buildCurl(detail);
    assert.ok(cmd.startsWith("curl -X POST 'https://api.example.com/v1/sign?a=1'"), cmd);
    assert.ok(cmd.includes("-H 'content-type: application/json'"));
    assert.ok(cmd.includes("-H 'cookie: sid=x'"));
    assert.ok(!cmd.includes("accept-encoding"), "noise headers must not leak into the curl");
    assert.ok(cmd.includes(`--data-raw '{"q":"it'\\''s"}'`), `body not escaped: ${cmd}`);
  });

  await t.test("diffReplay compares status and JSON bodies with dot paths", () => {
    const diff = diffReplay(
      { status: 200, body: '{"sig":"a","ts":1}', headers: {} },
      { status: 201, headers: {}, body: '{"sig":"b","nonce":2}' },
      50,
    );
    assert.equal(diff.statusChanged, true);
    assert.equal(diff.statusFrom, 200);
    assert.equal(diff.statusTo, 201);
    assert.deepEqual(diff.body!.changed, ["sig"]);
    assert.deepEqual(diff.body!.added, ["nonce"]);
    assert.deepEqual(diff.body!.removed, ["ts"]);
    assert.equal(diff.truncated, false);
  });

  await t.test("diffReplay degrades when either side is not JSON", () => {
    const diff = diffReplay({ status: 200, body: "plain", headers: {} }, { status: 200, headers: {}, body: "plain2" }, 50);
    assert.equal(diff.statusChanged, false);
    assert.equal(diff.body, null);
  });

  await t.test("diffReplay caps entries and flags truncated", () => {
    const a = {}; const b = {};
    for (let i = 0; i < 80; i++) { (a as any)["k" + i] = 1; (b as any)["k" + i] = 2; }
    const diff = diffReplay({ status: 200, body: JSON.stringify(a), headers: {} }, { status: 200, headers: {}, body: JSON.stringify(b) }, 10);
    assert.equal(diff.body!.changed.length, 10);
    assert.equal(diff.truncated, true);
  });
});

test("Traffic Session Wiring", async (t) => {
  await t.test("buildProxyArgs merges daemon endpoint into extra args", () => {
    assert.deepEqual(buildProxyArgs(null, ["--headless"]), ["--headless"]);
    assert.deepEqual(buildProxyArgs({ proxyPort: 8080, spki: "abc", attachBrowser: false }, ["--headless"]), ["--headless"]);
    assert.deepEqual(buildProxyArgs({ proxyPort: 8080, spki: "abc", attachBrowser: true }), [
      "--proxy-server=127.0.0.1:8080",
      "--ignore-certificate-errors-spki-list=abc",
    ]);
    assert.deepEqual(buildProxyArgs({ proxyPort: 8080, spki: null, attachBrowser: true }, ["-x"]), ["-x", "--proxy-server=127.0.0.1:8080"]);
  });

  await t.test("fresh session reports a stopped traffic daemon", async () => {
    const session = new CdpSession();
    const status = await session.trafficStatus();
    assert.equal(status.state, "stopped");
    assert.equal(status.endpoint, null);
    assert.deepEqual(status.held, []);
    assert.equal(status.stats, null);
  });

  await t.test("trafficStop on a fresh session refuses with ERR_MITM_NOT_RUNNING", async () => {
    const session = new CdpSession();
    await assert.rejects(() => session.trafficStop(), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_NOT_RUNNING");
  });

  await t.test("envelopeFromThrow keeps registry codes and falls back", () => {
    const fromMitm = envelopeFromThrow(new MitmError("ERR_MITM_PORT_BUSY", "127.0.0.1:8080 is already in use."), "ERR_NO_SESSION");
    assert.equal(fromMitm.success, false);
    assert.equal(fromMitm.error_code, "ERR_MITM_PORT_BUSY");
    assert.equal(fromMitm.suggestion, DEFAULT_SUGGESTIONS.ERR_MITM_PORT_BUSY);
    const plain = envelopeFromThrow(new Error("boom"), "ERR_NO_SESSION");
    assert.equal(plain.error_code, "ERR_NO_SESSION");
    const bogus = envelopeFromThrow({ code: "NOT_A_CODE", message: "x" }, "ERR_NO_SESSION");
    assert.equal(bogus.error_code, "ERR_NO_SESSION");
  });
});

test("Traffic tools at the MCP boundary", async (t) => {
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<{ payload: Record<string, unknown>; isError?: boolean }> => {
    const server = createServer(new CdpSession());
    const entry = (server as any)._registeredTools[name];
    const result = await entry.handler(args, {} as never);
    return { payload: JSON.parse(result.content[0].text), isError: result.isError };
  };

  await t.test("traffic_status returns stopped as data, not an error", async () => {
    const { payload, isError } = await call("traffic_status");
    assert.ok(!isError);
    assert.equal(payload.success, true);
    const data = payload.data as Record<string, unknown>;
    assert.equal(data.state, "stopped");
    assert.equal(data.endpoint, null);
  });

  await t.test("traffic_stop on a stopped daemon returns the NOT_RUNNING envelope", async () => {
    const { payload, isError } = await call("traffic_stop");
    assert.ok(isError);
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_MITM_NOT_RUNNING");
    assert.equal(typeof payload.suggestion, "string");
  });

  await t.test("guardedTool surfaces the MitmError code, not the fallback", async () => {
    const net = await import("node:net");
    const squat = net.createServer();
    await new Promise<void>((resolve) => squat.listen(0, "127.0.0.1", resolve));
    const port = (squat.address() as { port: number }).port;
    try {
      const { payload } = await call("traffic_start", { port });
      assert.equal(payload.success, false);
      // Without mitmdump the same throw path must map UNAVAILABLE; with it, PORT_BUSY.
      assert.ok(["ERR_MITM_PORT_BUSY", "ERR_MITM_UNAVAILABLE"].includes(payload.error_code as string), JSON.stringify(payload));
      assert.equal(typeof payload.suggestion, "string");
    } finally {
      squat.close();
    }
  });
});

test("shapeFlowDetail shaping", async (t) => {
  const fixture: FlowDetail = {
    summary: { id: "f9", ts: "2026-10-06T00:00:00.000Z", method: "POST", host: "api.example.com", path: "/v1/sign", status: 200, bytes: 64, durationMs: 12, held: false, expired: false, scheme: "https" },
    request: { headers: { "content-type": "application/json", cookie: "a=b", "x-noise": "z" }, body: '{"q":"hi"}' },
    response: { headers: { "content-type": "application/json", server: "nginx", "x-junk": "y" }, body: '{"sig":"abc"}', status: 200 },
    wsFrames: [{ dir: "up", ts: "2026-10-06T00:00:01Z", payload: "ping" }],
  };

  await t.test("both renders curated headers and pretty JSON on each side", () => {
    const out = shapeFlowDetail(fixture, "both", 5000);
    const req = out.request as { headers: Record<string, string>; body: string };
    const res = out.response as { headers: Record<string, string>; body: string; status: number };
    assert.deepEqual(req.headers, { "content-type": "application/json", cookie: "a=b" });
    assert.match(req.body, /"q": "hi"/);
    assert.deepEqual(res.headers, { "content-type": "application/json", server: "nginx" });
    assert.equal(res.status, 200);
    assert.equal(out.id, "f9");
  });

  await t.test("part narrows the payload", () => {
    assert.equal("response" in shapeFlowDetail(fixture, "request", 5000), false);
    assert.equal("request" in shapeFlowDetail(fixture, "response", 5000), false);
    const ws = shapeFlowDetail(fixture, "ws", 5000);
    assert.deepEqual((ws.wsFrames as unknown[]).length, 1);
    assert.equal("request" in ws, false);
  });

  await t.test("missing response renders null, not crash", () => {
    const inflight: FlowDetail = { ...fixture, response: null };
    const out = shapeFlowDetail(inflight, "both", 5000);
    assert.equal(out.response, null);
  });

  await t.test("body truncation budget respected", () => {
    const big: FlowDetail = { ...fixture, request: { headers: { "content-type": "text/plain" }, body: "x".repeat(100) } };
    const req = shapeFlowDetail(big, "request", 30).request as { body: string };
    assert.ok(req.body.length < 50 && req.body.endsWith("…[truncated]"));
  });
});

test("Traffic list/flow/curl tools at the MCP boundary", async (t) => {
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<{ payload: Record<string, unknown>; isError?: boolean }> => {
    const server = createServer(new CdpSession());
    const entry = (server as any)._registeredTools[name];
    const result = await entry.handler(args, {} as never);
    return { payload: JSON.parse(result.content[0].text), isError: result.isError };
  };

  for (const [name, args] of [["traffic_flows", {}], ["traffic_flow", { id: "f1" }], ["traffic_curl", { id: "f1" }]] as const) {
    await t.test(`${name} on a stopped daemon returns ERR_MITM_NOT_RUNNING`, async () => {
      const { payload, isError } = await call(name, { ...args });
      assert.ok(isError);
      assert.equal(payload.error_code, "ERR_MITM_NOT_RUNNING");
      assert.equal(typeof payload.suggestion, "string");
    });
  }
});

test("Breakpoint tools at the MCP boundary", async (t) => {
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<{ payload: Record<string, unknown>; isError?: boolean }> => {
    const server = createServer(new CdpSession());
    const entry = (server as any)._registeredTools[name];
    const result = await entry.handler(args, {} as never);
    return { payload: JSON.parse(result.content[0].text), isError: result.isError };
  };

  await t.test("breakpoint_set with a valid pattern on a stopped daemon reports NOT_RUNNING", async () => {
    const { payload } = await call("traffic_breakpoint_set", { pattern: ".*api/login.*" });
    assert.equal(payload.success, false);
    assert.equal(payload.error_code, "ERR_MITM_NOT_RUNNING");
  });

  await t.test("breakpoint_set with an invalid regex reports BAD_PATTERN before touching the daemon", async () => {
    const { payload, isError } = await call("traffic_breakpoint_set", { pattern: ".*[" });
    assert.ok(isError);
    assert.equal(payload.error_code, "ERR_MITM_BAD_PATTERN");
    assert.match(payload.message as string, /Invalid regex/);
    assert.equal(typeof payload.suggestion, "string");
  });

  await t.test("breakpoint_release on a stopped daemon reports NOT_RUNNING", async () => {
    const { payload } = await call("traffic_breakpoint_release", { flowId: "f1", action: "pass" });
    assert.equal(payload.error_code, "ERR_MITM_NOT_RUNNING");
  });
});

test("Replay/export tools at the MCP boundary", async (t) => {
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<{ payload: Record<string, unknown>; isError?: boolean }> => {
    const server = createServer(new CdpSession());
    const entry = (server as any)._registeredTools[name];
    const result = await entry.handler(args, {} as never);
    return { payload: JSON.parse(result.content[0].text), isError: result.isError };
  };
  for (const [name, args] of [["traffic_replay", { id: "f1" }], ["traffic_export", { format: "jsonl" }]] as const) {
    await t.test(`${name} on a stopped daemon returns ERR_MITM_NOT_RUNNING`, async () => {
      const { payload, isError } = await call(name, { ...args });
      assert.ok(isError);
      assert.equal(payload.error_code, "ERR_MITM_NOT_RUNNING");
    });
  }
});

import { fileURLToPath } from "node:url";
const ROOT = fileURLToPath(new URL("..", import.meta.url));

test("Netvein Project Workspace (.netvein)", async (t) => {
  const project = await import("../src/project.js");
  const fs = await import("node:fs");
  const os = await import("node:os");
  const path = await import("node:path");

  await t.test("findProjectDir walks upward like codegraph discovery", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nv-ws-"));
    const deep = path.join(root, "a", "b", "c");
    fs.mkdirSync(deep, { recursive: true });
    assert.equal(project.findProjectDir(deep), null);
    fs.mkdirSync(path.join(root, ".netvein"));
    assert.equal(project.findProjectDir(deep), path.join(root, ".netvein"));
    fs.rmSync(root, { recursive: true, force: true });
  });

  await t.test("initProject builds the skeleton and refuses without force", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nv-ws-"));
    const r = project.initProject(root);
    assert.ok(r.created.includes("config.json"));
    for (const rel of ["config.json", ".gitignore", "README.md"]) assert.ok(fs.existsSync(path.join(r.dir, rel)), rel);
    assert.ok(fs.statSync(path.join(r.dir, "capture")).isDirectory());
    assert.ok(fs.statSync(path.join(r.dir, "notes")).isDirectory());
    fs.writeFileSync(path.join(r.dir, "config.json"), "{\"traffic\":{\"port\":9999}}");
    assert.throws(() => project.initProject(root), (e) => e instanceof project.ProjectExistsError);
    const again = project.initProject(root, true);
    assert.deepEqual(again.created, []);
    assert.match(fs.readFileSync(path.join(r.dir, "config.json"), "utf8"), /9999/, "force never overwrites");
    fs.rmSync(root, { recursive: true, force: true });
  });

  await t.test("parseProjectConfig drops wrong-typed values, keeps good ones", () => {
    const input = JSON.stringify({
      cdp: { host: "1.2.3.4", port: "9222" },
      traffic: { port: 8080, capture: "yes", attachBrowser: false, allowHosts: ["^api."] },
    });
    const cfg = project.parseProjectConfig(input);
    assert.deepEqual(cfg, { cdp: { host: "1.2.3.4" }, traffic: { port: 8080, attachBrowser: false, allowHosts: ["^api."] } });
    assert.throws(() => project.parseProjectConfig("[1,2]"));
  });

  await t.test("captureStamp + listCaptures newest-first", () => {
    assert.match(project.captureStamp(new Date("2026-10-06T02:53:12.123Z")), /^flows-2026-10-06T02-53-12-123Z\.jsonl$/);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nv-ws-"));
    const r = project.initProject(root);
    const ws = project.loadWorkspace(r.dir);
    const cap = (name: string, ageMs: number) => {
      const pth = path.join(ws.captureDir, name);
      fs.writeFileSync(pth, "x");
      const t = Date.now() - ageMs;
      fs.utimesSync(pth, new Date(t), new Date(t));
    };
    cap("flows-old.jsonl", 60_000);
    cap("flows-new.jsonl", 1_000);
    cap("export-manual.har", 2_000);
    cap("stray.txt", 0);
    const list = project.listCaptures(ws);
    assert.deepEqual(list.map((c) => c.file), ["flows-new.jsonl", "export-manual.har", "flows-old.jsonl"]);
    fs.rmSync(root, { recursive: true, force: true });
  });

  await t.test("workspace config feeds session defaults (traffic port)", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nv-ws-"));
    const wdir = path.join(root, ".netvein");
    fs.mkdirSync(path.join(wdir, "capture"), { recursive: true });
    fs.writeFileSync(path.join(wdir, "config.json"), '{"traffic":{"port":12345,"capture":false}}');
    const session = new CdpSession({ projectDir: wdir });
    assert.equal(session.workspace?.config.traffic?.port, 12345);
    const view = session.netveinProject();
    assert.equal(view.dir, wdir);
    fs.rmSync(root, { recursive: true, force: true });
  });

  await t.test("CLI parity: init and status subcommands (like codegraph init/status)", async () => {
    const { spawnSync } = await import("node:child_process");
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "nv-cli-"));
    const cli = (args: string[]) => spawnSync(process.execPath, ["--import", "tsx", "src/index.ts", ...args], { cwd: ROOT, encoding: "utf8" });
    const r1 = cli(["init", root]);
    assert.equal(r1.status, 0, r1.stderr);
    assert.match(r1.stdout, /workspace: .*\.netvein/);
    assert.ok(fs.existsSync(path.join(root, ".netvein", "config.json")));
    const r2 = cli(["init", root]);
    assert.equal(r2.status, 1);
    assert.match(r2.stderr, /already exists/);
    const r3 = cli(["status", root]);
    assert.equal(r3.status, 0, r3.stderr);
    assert.match(r3.stdout, /config:/);
    const r4 = cli(["status", fs.mkdtempSync(path.join(os.tmpdir(), "nv-empty-"))]);
    assert.equal(r4.status, 1);
    assert.match(r4.stdout, /no \.netvein workspace/);
    fs.rmSync(root, { recursive: true, force: true });
  });

  await t.test("CLI parity: install and uninstall subcommands (like codegraph install/uninstall)", async () => {
    const { spawnSync } = await import("node:child_process");
    const cli = (args: string[]) => spawnSync(process.execPath, ["--import", "tsx", "src/index.ts", ...args], { cwd: ROOT, encoding: "utf8" });
    const r1 = cli(["install", "--target", "none"]);
    assert.equal(r1.status, 0);
    assert.match(r1.stdout, /Installing Netvein MCP/);
    const r2 = cli(["uninstall", "--target", "none"]);
    assert.equal(r2.status, 0);
    assert.match(r2.stdout, /Uninstalling Netvein MCP/);
  });
});

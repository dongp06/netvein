import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import { CdpSession } from "../src/cdp.js";
import { createServer } from "../src/server.js";
import {
  CaptureSessionManager,
  buildProxyEnvironment,
  inspectBody,
  parseSseStream,
  parseAwsEventStream,
  searchCaptures,
} from "../src/capture/index.js";

test("Capture Session Management", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nv-capture-test-"));
  const netveinDir = path.join(tmpDir, ".netvein");
  fs.mkdirSync(netveinDir, { recursive: true });

  const manager = new CaptureSessionManager(tmpDir);

  await t.test("starts a named capture session with directory skeleton", async () => {
    // Fake MitmManager
    const fakeMitm: any = {
      running: () => false,
      start: async () => {},
      captureConfig: async () => {},
      endpoint: () => ({ proxyPort: 8080 }),
    };

    const session = await manager.start(fakeMitm, {
      name: "stripe-checkout",
      focus: ["stripe.com", "api.example.com"],
      dropTelemetry: true,
      keepSecrets: true,
      storeBodies: true,
    });

    assert.ok(session.id.startsWith("stripe-checkout-"));
    assert.equal(session.name, "stripe-checkout");
    assert.equal(session.status, "active");
    assert.ok(fs.existsSync(session.dir));
    assert.ok(fs.existsSync(session.bodiesDir));
    assert.ok(fs.existsSync(path.join(session.dir, "session.json")));

    // Active session reports live
    const active = manager.activeSession;
    assert.ok(active);
    assert.equal(active.id, session.id);

    // Stop session
    const stopped = await manager.stop(fakeMitm);
    assert.ok(stopped);
    assert.equal(stopped.status, "stopped");
    assert.equal(manager.activeSession, null);

    // List sessions finds the stopped session
    const sessions = manager.listSessions();
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].name, "stripe-checkout");
  });

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Capture Decoder: inspectBody & Decompression", async (t) => {
  await t.test("inspectBody formats plain JSON and text", () => {
    const jsonStr = JSON.stringify({ token: "secret_123", ok: true });
    const b64 = Buffer.from(jsonStr, "utf8").toString("base64");

    const textRes = inspectBody({ rawBase64: b64, format: "text" });
    assert.equal(textRes.format, "text");
    assert.ok(textRes.content.includes("secret_123"));

    const jsonRes = inspectBody({ rawBase64: b64, format: "json" });
    assert.equal(jsonRes.format, "json");
    assert.ok(jsonRes.content.includes('"token": "secret_123"'));
  });

  await t.test("inspectBody auto-decompresses gzip payloads", () => {
    const payload = JSON.stringify({ message: "hello compressed world", count: 42 });
    const gzipped = zlib.gzipSync(Buffer.from(payload, "utf8"));
    const b64 = gzipped.toString("base64");

    const res = inspectBody({ rawBase64: b64, format: "json" });
    assert.equal(res.decompressed, true);
    assert.equal(res.encoding, "gzip");
    assert.ok(res.content.includes('"message": "hello compressed world"'));
  });

  await t.test("inspectBody auto-decompresses deflate payloads", () => {
    const payload = "deflated text payload for capture kit";
    const deflated = zlib.deflateSync(Buffer.from(payload, "utf8"));
    const b64 = deflated.toString("base64");

    const res = inspectBody({ rawBase64: b64, format: "text" });
    assert.equal(res.decompressed, true);
    assert.equal(res.encoding, "deflate");
    assert.equal(res.content, payload);
  });

  await t.test("inspectBody renders hex dump with ASCII table", () => {
    const buf = Buffer.from("Hello, NetVein Capture Kit!\nLine 2", "utf8");
    const res = inspectBody({ rawBase64: buf.toString("base64"), format: "hex" });
    assert.equal(res.format, "hex");
    assert.ok(res.content.includes("48 65 6c 6c 6f"));
    assert.ok(res.content.includes("|Hello, NetVein"));
  });
});

test("Capture Decoder: Streams (SSE & AWS EventStream)", async (t) => {
  await t.test("parseSseStream extracts typed events and auto-parses JSON", () => {
    const sseText = [
      ": heartbeat comment",
      "event: delta",
      "id: evt-1",
      'data: {"role": "assistant", "content": "Hello"}',
      "",
      "event: delta",
      "id: evt-2",
      'data: {"content": " world!"}',
      "",
      "event: done",
      "data: [DONE]",
      "",
    ].join("\n");

    const events = parseSseStream(sseText);
    assert.equal(events.length, 3);
    assert.equal(events[0].event, "delta");
    assert.equal(events[0].id, "evt-1");
    assert.deepEqual(events[0].data, { role: "assistant", content: "Hello" });
    assert.equal(events[1].event, "delta");
    assert.equal(events[2].event, "done");
    assert.equal(events[2].data, "[DONE]");
  });

  await t.test("parseAwsEventStream decodes binary eventstream messages", () => {
    // Construct a synthetic AWS EventStream frame
    // Prelude: Total Length (4B) + Headers Length (4B) + Prelude CRC (4B) = 12B
    // Header: Name Length (1B), Name, Type (1B=7 string), Val Length (2B), Val
    // Payload + Message CRC (4B)
    const headerName = ":message-type";
    const headerVal = "event";
    const headerBuf = Buffer.alloc(1 + headerName.length + 1 + 2 + headerVal.length);
    let hOff = 0;
    headerBuf.writeUInt8(headerName.length, hOff++);
    headerBuf.write(headerName, hOff, "utf8");
    hOff += headerName.length;
    headerBuf.writeUInt8(7, hOff++); // type 7 string
    headerBuf.writeUInt16BE(headerVal.length, hOff);
    hOff += 2;
    headerBuf.write(headerVal, hOff, "utf8");

    const payloadText = '{"event": "stream-chunk"}';
    const payloadBuf = Buffer.from(payloadText, "utf8");

    const totalLen = 12 + headerBuf.length + payloadBuf.length + 4;
    const msg = Buffer.alloc(totalLen);
    msg.writeUInt32BE(totalLen, 0);
    msg.writeUInt32BE(headerBuf.length, 4);
    msg.writeUInt32BE(0x12345678, 8); // CRC placeholder
    headerBuf.copy(msg, 12);
    payloadBuf.copy(msg, 12 + headerBuf.length);
    msg.writeUInt32BE(0x87654321, totalLen - 4); // Msg CRC placeholder

    const events = parseAwsEventStream(msg);
    assert.equal(events.length, 1);
    assert.equal(events[0].event, "event");
    assert.deepEqual(events[0].data, { event: "stream-chunk" });
  });
});

test("Capture Search", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nv-search-test-"));
  const sessionDir = path.join(tmpDir, ".netvein", "captures", "search-test-1");
  fs.mkdirSync(sessionDir, { recursive: true });

  const flowsFile = path.join(sessionDir, "flows.jsonl");
  const flow1 = JSON.stringify({
    id: "flow-101",
    method: "POST",
    url: "https://api.openai.com/v1/chat/completions",
    host: "api.openai.com",
    path: "/v1/chat/completions",
    status: 200,
    request: { headers: { authorization: "Bearer sk-proj-12345" }, body: '{"prompt":"hello ai"}' },
    response: { headers: { "content-type": "application/json" }, body: '{"id":"chatcmpl-abc","model":"gpt-4"}' },
  });
  const flow2 = JSON.stringify({
    id: "flow-102",
    method: "GET",
    url: "https://cdn.example.com/assets/logo.png",
    host: "cdn.example.com",
    path: "/assets/logo.png",
    status: 200,
    request: { headers: {}, body: null },
    response: { headers: {}, body: null },
  });
  fs.writeFileSync(flowsFile, `${flow1}\n${flow2}\n`, "utf8");

  await t.test("finds matches in URLs and bodies", () => {
    const matches = searchCaptures({
      rootDir: tmpDir,
      query: "chatcmpl",
    });

    assert.equal(matches.length, 1);
    assert.equal(matches[0].flowId, "flow-101");
    assert.equal(matches[0].matchIn, "response_body");
    assert.ok(matches[0].snippet.includes("chatcmpl"));
  });

  await t.test("supports regex query", () => {
    const matches = searchCaptures({
      rootDir: tmpDir,
      query: "sk-proj-[0-9]+",
      isRegex: true,
    });

    assert.equal(matches.length, 1);
    assert.equal(matches[0].flowId, "flow-101");
    assert.equal(matches[0].matchIn, "header");
  });

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("Proxy Environment Generation", () => {
  const env = buildProxyEnvironment(8080, null, ["api.test.com"]);
  assert.equal(env.HTTP_PROXY, "http://127.0.0.1:8080");
  assert.equal(env.HTTPS_PROXY, "http://127.0.0.1:8080");
  assert.equal(env.NETVEIN_FOCUS, "api.test.com");
  assert.ok(env.NODE_OPTIONS?.includes("node-proxy.mjs"));
});

test("MCP Boundary: Autonomous Capture Tools", async (t) => {
  const session = new CdpSession();
  const server = createServer(session);

  const call = async (name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
    const entry = (server as any)._registeredTools[name];
    assert.ok(entry, `Tool ${name} not registered`);
    const result = await entry.handler(args, {} as never);
    return JSON.parse(result.content[0].text) as Record<string, unknown>;
  };

  await t.test("capture_session_status returns active null when no session is active", async () => {
    const res = await call("capture_session_status");
    assert.equal(res.success, true);
    assert.equal((res.data as any).active, null);
  });

  await t.test("capture_session_list returns empty list when no captures exist", async () => {
    const res = await call("capture_session_list");
    assert.equal(res.success, true);
    assert.equal((res.data as any).count, 0);
  });

  await t.test("capture_env returns proxy URL and environment keys", async () => {
    const res = await call("capture_env");
    assert.equal(res.success, true);
    const data = res.data as any;
    assert.equal(data.proxyUrl, "http://127.0.0.1:8080");
    assert.ok(data.env.HTTP_PROXY);
  });

  await t.test("capture_inspect_body with non-existent file returns ERR_BODY_NOT_FOUND envelope", async () => {
    const res = await call("capture_inspect_body", { filePath: "/non/existent/path/res.bin" });
    assert.equal(res.success, false);
    assert.equal(res.error_code, "ERR_BODY_NOT_FOUND");
  });

  await t.test("capture_decode_stream with no input returns ERR_INVALID_PARAM envelope", async () => {
    const res = await call("capture_decode_stream", {});
    assert.equal(res.success, false);
    assert.equal(res.error_code, "ERR_INVALID_PARAM");
  });
});

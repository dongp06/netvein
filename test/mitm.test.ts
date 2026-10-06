import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import * as http from "node:http";
import * as net from "node:net";
import test from "node:test";
import { MitmManager, MitmError } from "../src/mitm/manager.js";

const mitmAvailable = spawnSync("mitmdump", ["--version"], { encoding: "utf8" }).status === 0;

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function eventually<T>(fn: () => Promise<T> | T, timeoutMs = 8000, stepMs = 100): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  for (;;) {
    try {
      const value = await fn();
      if (value) return value;
      lastError = new Error("predicate returned falsy");
    } catch (error) {
      lastError = error;
    }
    if (Date.now() > deadline) throw lastError instanceof Error ? lastError : new Error("eventually timed out");
    await wait(stepMs);
  }
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const port = (probe.address() as net.AddressInfo).port;
      probe.close(() => resolve(port));
    });
  });
}

interface Target {
  port: number;
  close(): Promise<void>;
}

/** Local HTTP target: /slow delays, /modme echoes an injected header, /alpha and /beta are plain. */
async function startTarget(): Promise<Target> {
  const server = http.createServer((req, res) => {
    const path = req.url ?? "/";
    const send = (body: string) => {
      res.writeHead(200, { "content-type": "application/json", "x-target-header": "kept" });
      res.end(body);
    };
    if (path.startsWith("/slow")) {
      setTimeout(() => send(JSON.stringify({ body: "slow-body" })), 800);
    } else if (path.startsWith("/modme")) {
      send(JSON.stringify({ inj: req.headers["x-injected"] ?? "none" }));
    } else if (path.startsWith("/alpha")) {
      send(JSON.stringify({ which: "alpha" }));
    } else {
      send(JSON.stringify({ which: "beta" }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  return { port, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}

/** Plain-HTTP request sent proxy-style (absolute URI in the request line). */
function proxyRequest(proxyPort: number, targetPort: number, path: string, options: { method?: string; headers?: Record<string, string> } = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method: options.method ?? "GET",
        path: `http://127.0.0.1:${targetPort}${path}`,
        headers: { host: `127.0.0.1:${targetPort}`, ...options.headers },
        agent: false,
      },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("error", reject);
    req.setTimeout(20000, () => req.destroy(new Error("proxy request timed out")));
    req.end();
  });
}

async function startManager(): Promise<{ manager: MitmManager; proxyPort: number }> {
  const manager = new MitmManager();
  let lastError: unknown;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const { proxyPort } = await manager.start({ port: await freePort() });
      return { manager, proxyPort };
    } catch (error) {
      lastError = error;
      await wait(200);
    }
  }
  throw lastError;
}

test("MitmManager unit (no daemon)", async (t) => {
  await t.test("state starts stopped; stats/held/endpoint are null-safe", async () => {
    const manager = new MitmManager();
    assert.equal(manager.state(), "stopped");
    assert.equal(manager.running(), false);
    assert.equal(manager.endpoint(), null);
    assert.equal(await manager.stats(), null);
    assert.deepEqual(await manager.held(), []);
    await assert.rejects(() => manager.command("stats"), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_NOT_RUNNING");
  });

  await t.test("mitmdump missing on PATH -> ERR_MITM_UNAVAILABLE", async () => {
    const saved = process.env.PATH;
    process.env.PATH = "/nonexistent-netvein-dir";
    try {
      const manager = new MitmManager();
      await assert.rejects(() => manager.start(), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_UNAVAILABLE");
      assert.equal(manager.state(), "stopped");
    } finally {
      process.env.PATH = saved;
    }
  });

  await t.test("occupied port -> ERR_MITM_PORT_BUSY and no zombie child", async () => {
    const squat = net.createServer();
    await new Promise<void>((resolve) => squat.listen(0, "127.0.0.1", resolve));
    const port = (squat.address() as net.AddressInfo).port;
    const manager = new MitmManager();
    try {
      await assert.rejects(() => manager.start({ port }), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_PORT_BUSY");
      assert.equal(manager.state(), "stopped");
      assert.equal(manager.pid, undefined);
    } finally {
      squat.close();
    }
  });
});

test("MitmManager daemon integration", { skip: mitmAvailable ? false : "mitmdump not installed" }, async (t) => {
  await t.test("start -> stats -> stop round-trip", async () => {
    const { manager, proxyPort } = await startManager();
    try {
      assert.equal(manager.state(), "running");
      const endpoint = manager.endpoint();
      assert.ok(endpoint);
      assert.equal(endpoint!.proxyPort, proxyPort);
      const stats = await manager.stats();
      assert.ok(stats);
      assert.equal(stats!.running, true);
      assert.equal(typeof stats!.flows, "number");
      assert.deepEqual(stats!.held, []);
      assert.ok(stats!.spki === null || typeof stats!.spki === "string", "spki is a base64 string once the CA exists, else null");
    } finally {
      await manager.stop();
    }
    assert.equal(manager.state(), "stopped");
    assert.equal(manager.endpoint(), null);
  });

  await t.test("captured flows appear in list and get; filters apply", async () => {
    const target = await startTarget();
    const { manager, proxyPort } = await startManager();
    try {
      const first = await proxyRequest(proxyPort, target.port, "/alpha");
      assert.equal(first.status, 200);
      assert.ok(/alpha/.test(first.body));
      await proxyRequest(proxyPort, target.port, "/beta", { method: "POST", headers: { "content-type": "application/json", "x-test": "yes" } });
      const listed = await eventually(async () => {
        const reply = await manager.command("list");
        const flows = reply.flows as Array<{ path: string; status: number | null }>;
        return flows.length >= 2 ? flows : null;
      });
      assert.ok(listed.some((f) => f.path.startsWith("/alpha") && f.status === 200));
      const filtered = (await manager.command("list", { pathContains: "/alpha" })).flows as Array<{ id: string; path: string }>;
      assert.equal(filtered.length, 1);
      assert.ok(filtered[0].path.startsWith("/alpha"));
      const detailReply = await manager.command("get", { flowId: filtered[0].id });
      const detail = detailReply.detail as { summary: { method: string }; request: { headers: Record<string, string> } };
      assert.equal(detail.summary.method, "GET");
      const withBody = await manager.command("get", { flowId: (await manager.command("list", { method: "POST" })).flows[0].id });
      assert.equal((withBody.detail as { request: { headers: Record<string, string> } }).request.headers["x-test"], "yes");
      await assert.rejects(() => manager.command("get", { flowId: "nope" }), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_FLOW_NOT_FOUND");
    } finally {
      await manager.stop();
      await target.close();
    }
  });

  await t.test("breakpoint holds flow, modify-release rewrites request", async () => {
    const target = await startTarget();
    const { manager, proxyPort } = await startManager();
    try {
      await manager.command("breakpoint_set", { pattern: ".*modme.*", maxHoldMs: 30000 });
      const inflight = proxyRequest(proxyPort, target.port, "/modme");
      const heldId = await eventually(async () => {
        const ids = await manager.held();
        return ids.length > 0 ? ids[0] : null;
      });
      assert.ok(heldId);
      const listed = (await manager.command("list", { heldOnly: true })).flows as Array<{ held: boolean }>;
      assert.ok(listed.length >= 1 && listed.every((f) => f.held));
      const released = await manager.command("breakpoint_release", { flowId: heldId, action: "modify", patch: { headers: { "x-injected": "1" } } });
      assert.equal(released.released, heldId);
      const result = await inflight;
      assert.equal(JSON.parse(result.body).inj, "1");
      await eventually(async () => ((await manager.held()).length === 0 ? true : null));
      const bps = (await manager.command("breakpoints")).breakpoints as Array<{ pattern: string; hits: number }>;
      assert.equal(bps[0].pattern, ".*modme.*");
      assert.ok(bps[0].hits >= 1);
    } finally {
      await manager.stop();
      await target.close();
    }
  });

  await t.test("maxHoldMs expiry auto-passes the original flow", async () => {
    const target = await startTarget();
    const { manager, proxyPort } = await startManager();
    try {
      await manager.command("breakpoint_set", { pattern: ".*slow.*", maxHoldMs: 400 });
      const result = await proxyRequest(proxyPort, target.port, "/slow"); // nobody releases; expiry must save it
      assert.equal(result.status, 200);
      assert.match(result.body, /slow-body/);
      const flow = await eventually(async () => {
        const flows = (await manager.command("list", { pathContains: "/slow" })).flows as Array<{ expired: boolean; held: boolean }>;
        return flows.length > 0 ? flows[0] : null;
      });
      assert.equal(flow.expired, true, "daemon flags the flow expired after auto-pass");
      assert.equal(flow.held, false);
    } finally {
      await manager.stop();
      await target.close();
    }
  });

  await t.test("SIGKILL -> state dead; queued commands reject ERR_MITM_LOST", async () => {
    const { manager } = await startManager();
    const pid = manager.pid;
    assert.ok(pid);
    await manager.stats(); // warm the daemon so it is definitely up
    // Queue a batch and kill immediately; timing decides how many are still
    // in flight, so assert at least one rejects LOST and none hang.
    const batch = Array.from({ length: 30 }, () => manager.command("stats"));
    process.kill(pid, "SIGKILL");
    const settled = await Promise.allSettled(batch);
    assert.ok(settled.some((r) => r.status === "rejected" && r.reason instanceof MitmError && r.reason.code === "ERR_MITM_LOST"), "at least one queued command sees the loss");
    assert.ok(settled.every((r) => r.status === "rejected" || r.value), "every command settles");
    await eventually(async () => (manager.state() === "dead" ? true : null));
    assert.equal(manager.state(), "dead");
    assert.equal(manager.endpoint(), null);
    await assert.rejects(() => manager.command("stats"), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_LOST");
    await manager.stop(); // must not throw on a dead daemon
    assert.equal(manager.state(), "dead");
  });
});

test("Traffic session shaping against a real daemon", { skip: mitmAvailable ? false : "mitmdump not installed" }, async (t) => {
  await t.test("trafficFlows/trafficFlow/trafficCurl through CdpSession", async () => {
    const { CdpSession } = await import("../src/cdp.js");
    const session = new CdpSession();
    const target = await startTarget();
    try {
      await session.mitm.start({ port: await freePort() });
      await proxyRequest(session.mitm.endpoint()!.proxyPort, target.port, "/alpha");
      const listed = await eventually(async () => {
        const view = (await session.trafficFlows({})) as { count: number; list: string };
        return view.count >= 1 ? view : null;
      });
      assert.match(listed.list, /GET 127.0.0.1.*\/alpha -> 200/);
      const full = (await session.trafficFlows({ full: true })) as { flows: Array<{ id: string; path: string }> };
      const id = full.flows[0].id;
      const detail = (await session.trafficFlow(id, "both", 5000)) as { request: { headers: Record<string, string> }; response: { status: number } };
      assert.equal(detail.response.status, 200);
      const curl = (await session.trafficCurl(id)) as { curl: string };
      assert.match(curl.curl, /^curl -X GET 'http:\/\/127\.0\.0\.1:\d+\/alpha'/);
      const table = (await session.trafficBreakpointSet(".*never-match.*", 5000)) as { breakpoints: Array<{ pattern: string }> };
      assert.ok(table.breakpoints.some((b) => b.pattern === ".*never-match.*"));
      await assert.rejects(() => session.trafficBreakpointRelease("ghost", "pass"), (error: unknown) => error instanceof MitmError && error.code === "ERR_MITM_FLOW_NOT_FOUND");
      await assert.rejects(() => session.trafficBreakpointSet(".*[", 5000), (error: unknown) => error instanceof Error && error.message.includes("Invalid regex"));
    } finally {
      await session.mitm.stop();
      await target.close();
    }
  });
});

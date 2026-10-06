# Traffic Interceptor MCP — Design

**Date:** 2026-10-06
**Status:** Approved, pending implementation plan
**Sub-project:** 2 of 5 (Traffic/program plan: A traffic → B mobile → C signing workbench)
**Predecessor:** `2026-10-05-stealth-pruner-design.md`

---

## 1. Purpose — and why a proxy when CDP already sees traffic

The CDP session already captures the attached tab's network. The proxy layer is
not a replacement; it covers what CDP structurally cannot:

| Need | Why CDP can't do it | mitm layer |
|---|---|---|
| **All tabs, all frames, other profiles** | CDP binds one page target; traffic from other tabs never enters the session | the browser's single proxy socket sees everything |
| **Traffic that survives the MCP process** | capture buffers die on `disconnect()` and FIFO-evict under load | flow store is owned by the daemon, not the session |
| **Wire-level ground truth** | CDP reports the browser's *view* of a request; hooks/fetch-patches can make that view differ from the bytes on the wire | what actually left the socket, incl. TLS-altered reality |
| **Replay from outside the page** | `replay_and_verify` runs in page context (same origin, same JS) | replay goes through the proxy, like curl — no page involvement |
| **Break-and-patch in flight** | CDP Fetch pausing blocks the renderer and times out fast | daemon holds the flow; the agent thinks, patches, resumes |
| **Non-browser clients on the same endpoint** | curl/python/other tools bypass CDP entirely | same proxy, same flow store, one authoritative log |

Positioning: CDP tools remain the *surgical* layer (breakpoints, hooks, JS).
The traffic layer is the *wire* layer. The signing workbench (sub-project C)
orchestrates both.

## 2. Scope

In: mitmdump lifecycle owned by netvein; filtered/beautified flow views; a
hold-queue with resume/modify/drop; proxy-side replay; export to HAR and JSONL.

Out: mobile device guidance and Frida (sub-project B), the multi-step signing
workbench (sub-project C), SSL-pinning defeats (impossible via proxy alone),
a persistent on-disk flow database (store is daemon-RAM + export).

## 3. Architecture

```text
┌──────────────┐  stdio   ┌───────────────────────────┐
│  MCP client  │◄────────►│  netvein-mcp (Node)       │
└──────────────┘          │  src/mitm/                │
                          │   manager.ts  spawn+ctl   │
                          │   store.ts    view/filter │
                          │   errors via Envelope     │
                          └───────┬───────────▲───────┘
                    spawn         │           │  JSON-lines
                  (child proc)    ▼           │  control socket
                          ┌───────────────────┴───┐
                          │ mitmdump (python)      │
                          │  + netvein_addon.py    │
                          │  listens: proxy :8080  │
                          │  control: :127.0.1:rnd │
                          └───────────┬────────────┘
                                      │ proxy_server
                          ┌───────────▼───────────┐
                          │ Chromium (launched by │
                          │ launcher with         │
                          │ --proxy-server=...)   │
                          └───────────────────────┘
```

- **`python/netvein_addon.py`** — mitmproxy addon run inside mitmdump. Responsibilities: capture every flow + websocket frame into a RAM ring; serve a line-delimited JSON control socket (`list`, `get`, `filter`, `breakpoint set/list/release`, `replay`, `export`, `stats`); hold flows matching breakpoints and push events. It is a thin servant; all logic and shaping lives in Node.
- **`src/mitm/manager.ts`** — spawn/stop/reconcile of `mitmdump --allow-hosts ... -s addon.py`, control-socket client, daemon health, CA bookkeeping. Refuses to run if `mitmdump` is absent, with an actionable error.
- **`src/mitm/store.ts`** — pure functions: filter DSL, header-strip, beautify, cURL reconstruction, HAR/JSONL serialization. Unit-testable without python or a browser.
- CDP integration: when the daemon is up and `attachBrowser` is requested, `launcher.ts` appends `--proxy-server=127.0.0.1:<port>` and (Linux) `--ignore-certificate-errors-spki-list=<mitm-spki>` **only to netvein-launched browsers**. User-launched browsers are reported as needing manual proxy config; the server never rewrites a running Chrome's flags.

### Trust model (stated plainly)

A MITM proxy terminates TLS. The daemon:
- binds **127.0.0.1 only**; the control socket has no auth because it is loopback + same-user;
- generates its own CA inside a private confdir under `os.tmpdir()`, never touching `~/.mitmproxy` if a custom confdir can be chosen — if the operator's existing `~/.mitmproxy` CA should be reused, `traffic_start(caDir?)` opts in;
- does **not** auto-install into the system trust store. For the netvein-launched Chrome it uses the spki-pin flag (scoped, no system change). Everything else is the operator's explicit choice.

## 4. Tools (10 new; 102 → 112)

All return the `Envelope`; all parameters Zod-described with defaults.

| Tool | Parameters | Behavior |
|---|---|---|
| `traffic_start` | `port?`=8080, `caDir?`, `allowHosts?`(csv regex), `attachBrowser?`=true | Spawn daemon (idempotent; reports `alreadyRunning`), write CA, set up control socket. Returns proxy port + CA path + what the operator must do next. |
| `traffic_stop` | `keepFlowsFile?` | Graceful shutdown; optional export before stop. |
| `traffic_status` | — | daemon up?, flows held, flow count, breakpoint count, uptime, port. |
| `traffic_flows` | `host?`, `pathContains?`, `method?`, `status?`, `since?`(ISO), `limit?`=50, `includeBodies?`=false | **Token-optimized view.** Strips hop-by-hop + noise headers to a curated keep-list; shows `METHOD host path -> status (bytes, dur)` lines with an id per flow. Bodies only on request, truncated to `MAX_STORED_TEXT`. |
| `traffic_flow` | `id`, `part`=`request|response|both|ws` | Beautified full detail for one flow: headers (kept subset + raw), formatted body (pretty-JSON when parseable), ws frame list. |
| `traffic_curl` | `id` | Reconstruct a ready-to-run `curl` (or mitmproxy `--replay`-style) command from the flow, cookies included, with a note when the request had a body needing quoting. Flagship for "phát hiện payload → tái tạo cURL chuẩn chỉ". |
| `traffic_breakpoint_set` | `urlPattern`, `host?`, `maxHoldMs?`=60000, `mode`=`hold` | Hold matching flows in the daemon queue; `maxHoldMs` bounds renderer stalls — on expiry the flow auto-passes and is flagged `expired`. |
| `traffic_breakpoint_release` | `flowId`, `action`=`pass|modify|drop`, `patch?`{`url?,method?,headers?,body?`} | Resolve one held flow. `modify` patches before release. List/queue view is part of `traffic_status` and `traffic_flows(held=true)`. |
| `traffic_replay` | `id`, `overrides?`{method,headers,body,url}, `compare?`=true | Send through the proxy socket outside page context; return new status/body and a diff vs the original (added/removed/changed JSON-pointer summary, bounded). |
| `traffic_export` | `format`=`har|jsonl`, `path?` | Daemon-side export of current store; returns path (temp dir if omitted) + flow count. |

`traffic_flows(held=true)` folds into `traffic_flows` as a flag rather than an
11th tool.

## 5. Data flow examples

**Observation loop:** `traffic_start` → operator browses/replays via the
launched Chrome → `traffic_flows(pathContains:"/sign")` → `traffic_flow(id,both)`
→ `traffic_curl(id)`.

**In-flight patch:** `traffic_breakpoint_set(urlPattern:".*api/login.*")` →
login attempt → daemon holds, pushes event → `traffic_status` shows queue →
`traffic_breakpoint_release(flowId, modify, {body:"{...signed..."})` → server
answers the patched request → `traffic_flow` on the held id shows both
original and patched.

**Replay-from-outside:** `traffic_replay(id, {headers:{...x-token: forged...}})`.

## 6. Failure & edge behavior

- No `mitmdump` binary → `ERR_MITM_UNAVAILABLE` (new error code) with install suggestion (`pipx install mitmproxy`). The daemon is optional infrastructure: nothing else in netvein depends on it.
- Port in use → `ERR_MITM_PORT_BUSY`, suggests explicit `port`.
- Control socket dies → `ERR_MITM_LOST` + status shows `dead`; auto-restart is **not** attempted (flows would be lost silently); operator re-starts explicitly.
- Browser already launched without the proxy → honest report; CDP `set_request_interception` remains available as a degraded, tab-scoped fallback (stated in the tool description, not silently).
- Held flow + renderer hangs: bounded by `maxHoldMs`; expiry passes the original bytes unmodified and flags `expired` in the queue.
- Everything returns the envelope; no handler throws.

## 7. Testing

- **Pure (no browser, no python):** `store.ts` — filter predicate, header-strip keep-list, curl reconstruction (incl. quoting/cookies), HAR + JSONL serialization, replay-diff shaping. Fixture: recorded flow JSON in `test/fixtures/`.
- **Integration (python+mitm present, no browser):** spawn real `mitmdump` on a random port, drive the control socket against a local `http.server` target: capture, filter, breakpoint hold/release/modify, replay compare, export parse. Skips with a reason if `mitmdump` absent — mirrors how browser tests are excluded from default runs.
- **Contract:** 112-tool count assertion; new error codes in registry.

## 8. Risks

| Risk | Mitigation |
|---|---|
| mitm Python addon bugs kill the daemon mid-session | daemon-independent MCP process; `traffic_status` reports `dead` distinctly from `stopped` |
| Holding a request stalls the page and confuses the operator | `maxHoldMs` auto-expiry, flag on expiry, and `traffic_flows(held=true)` shows age |
| CA trust confusion ("why does Chrome complain?") | netvein-launched browsers get the spki pin automatically; everything else gets explicit instructions in `traffic_start` output |
| Feature overlaps CDP `set_request_interception` and operators pick wrong | tool descriptions state the boundary (tab-scoped surgical vs wire-level whole-browser) one line each |

## 9. Follow-on

- **B — Mobile RE:** jadx bridge + Frida/adb. The traffic store is the natural
  join point (mobile device points at the same daemon).
- **C — Signing workbench:** multi-step `extract signing function → candidate
  transforms → replay matrix → verify match`, built on `traffic_curl`,
  `traffic_replay`, and the existing JSRPC/AST engines.

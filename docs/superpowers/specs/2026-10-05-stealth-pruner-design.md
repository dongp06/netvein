# Stealth Browser & Semantic Tree Pruner — Design

**Date:** 2026-10-05
**Status:** Approved, pending implementation plan
**Sub-project:** 1 of 5 (see *Program Context*)

---

## 1. Purpose

Web agent workflows currently pay two costs that this sub-project removes:

1. **Context bloat.** A rendered page pushed into a prompt as HTML costs tens of
   thousands of tokens, most of it SVG, inline CSS, and nested `div`. The model
   also picks worse selectors when it has to reason over that noise.
2. **Detection.** The existing browser tools drive a stock Chrome over CDP. Modern
   bot defense reads `navigator.webdriver`, CDP runtime leaks, and canvas/WebGL/audio
   fingerprint instability, and challenges or blocks the session before any
   reverse engineering can happen.

The outcome is a pruned, ID-addressed semantic view of the page (~1–2k tokens
instead of ~100k) and a stealth layer that keeps a session viable against
fingerprint-based detection.

## 2. Scope

In scope:

- A stealth patch layer with three profiles and deterministic per-identity seeds.
- A semantic pruner built on the CDP `Accessibility` domain, producing an
  integer-addressed flat tree, plus diffing between snapshots.
- Per-identity browser contexts with optional per-context proxy, and portable
  identity export/import.
- Captcha **detection** and a provider hook. No solving.
- A shared structured-error envelope for all new tools.

Out of scope:

- Solving Cloudflare Turnstile, hCaptcha, or reCAPTCHA. See §10.
- Migrating the 88 existing tools to the new error envelope.
- Traffic interception (mitmproxy/Reqable), JADX, Frida — that is a separate
  sub-project in the same program.
- Database, eBPF, and session-mesh subsystems — separate sub-projects.

## 3. What we build on

| Existing asset | Location | Reused for |
|---|---|---|
| `CdpSession` (single persistent tab) | `src/cdp.ts` | All three new modules |
| `Page.addScriptToEvaluateOnNewDocument` | `cdp.ts:1510, 1629, 2433` | Proven stealth-injection path |
| `Input` / `DOM` domain wrappers | `src/cdp.ts` | `interact_semantic` |
| `get_cookies` / `set_cookie` / `get_storage` / `set_storage` | `src/cdp.ts` | Identity export/import |
| `browser_launch` / `findBrowserExecutable` | `src/launcher.ts` | Context isolation |
| `page_snapshot` | `src/server.ts:142` | Left unchanged; `semantic_view` is additive |
| Bounded-buffer policy (`MAX_STORED_TEXT = 20_000`) | `docs/ARCHITECTURE.md` §1 | Applies to all new tools |

`Accessibility` and `Target.createBrowserContext` are **not** used anywhere today.
Both are new capability, both are native CDP, so no new runtime dependency is
introduced.

## 4. Architecture

New modules, all under `src/`:

```text
src/stealth.ts    stealth profiles, patch payloads, seed management, self-probe
src/pruner.ts     AX tree fetch, compression, ID map, snapshot diffing
src/identity.ts   browser context lifecycle, proxy binding, identity export/import
src/errors.ts     ok()/err() envelope + error code registry
```

Tools are registered in `src/server.ts` alongside the existing 88. The
subsystems do not modify existing handlers, `CdpSession`, or `launcher.ts`
beyond additive exports.

Design constraint carried over from `ARCHITECTURE.md` §1: **one coherent
session.** All new tools operate on the same attached tab so that a stealth
patch, a semantic click, a breakpoint, and a call-frame inspection can occur in
one reasoning chain.

## 5. Components

### 5.1 Stealth layer (`src/stealth.ts`)

**Profiles.** `off`, `basic`, `strict`.

- `off` — no patches.
- `basic` — the identity-leak rows: `navigator.webdriver`, CDP runtime leak,
  navigator surface, iframe `contentWindow`.
- `strict` — `basic` plus every fingerprint row (canvas, WebGL, audio) and
  `Function.prototype.toString` integrity.

**Patch set**

| Target | Patch |
|---|---|
| `navigator.webdriver` | Remove from prototype; restore via `defineProperty` getter |
| CDP runtime leak | Trap the `Error.stack` getter used to detect `Runtime.enable`; neutralize the `console.debug` timing probe |
| Canvas | Deterministic per-seed noise on `toDataURL`, `getImageData`, `toBlob` |
| WebGL | Proxy `getParameter` for `UNMASKED_VENDOR_WEBGL`, `UNMASKED_RENDERER_WEBGL`, `SHADING_LANGUAGE_VERSION` |
| AudioContext | Deterministic noise on `AnalyserNode.getFloatFrequencyData`, `getByteFrequencyData` |
| Navigator surface | Consistent `plugins`, `mimeTypes`, `hardwareConcurrency`, `deviceMemory`, `languages`, `platform` |
| Permissions | `permissions.query` result consistent with the spoofed notification/geolocation state |
| iframe | `contentWindow` returns `self` |
| Patch integrity | `Function.prototype.toString` proxied so patched natives stringify as `[native code]` |

**Deterministic seeding.** Each identity carries a seed. All noise is derived
from `PRNG(seed)`, so a given identity presents an identical fingerprint across
navigations and requests. Inconsistent spoofing is itself a detection signal —
this is the most common failure mode in stealth tooling and the reason the seed
is part of identity rather than per-page.

**Injection.** Patches are registered through
`Page.addScriptToEvaluateOnNewDocument`, so they apply before any page script
runs, including on navigation and on new targets in the same context.

**Self-probe.** `stealth_probe()` runs a detection suite in-page and reports
what still leaks, per check, with the observed value. Without this, patch
rot is invisible until a target blocks the session.

### 5.2 Semantic pruner (`src/pruner.ts`)

**Source.** `Accessibility.enable` + `Accessibility.getFullAXTree`. The AX tree
is then merged with `DOM.getDocument` + `DOM.querySelectorAll('*')` to recover
interactive nodes that carry a DOM event handler but no ARIA role (a common
pattern in hand-rolled frontends).

**Compression rules**, applied in order:

1. Drop `ignored`, `generic`, `presentational`, and `none` roles.
2. Drop nodes with no name and no interactive capability.
3. Collapse single-child chains, preserving the surviving node's depth.
4. Drop off-viewport nodes unless `includeOffscreen: true`.
5. Truncate `value` and long names per the existing bounded-text policy.

**Output.** Flat, indented, integer-addressed:

```text
#3  page "Login"
  [12] textbox "Email"        value=""
  [15] textbox "Password"     value=""
  [18] button  "Sign in"
  [21] link    "Forgot password?"
```

**ID lifecycle.** A snapshot produces `Map<number, backendDOMNodeId>` and a
monotonic `version`. The map is invalidated by navigation and by
`DOM.documentUpdated`. `interact_semantic` rejects an ID whose version is stale
and returns the error code `ERR_STALE_NODE_ID` with a suggestion to re-run
`semantic_view`.

**Diffing.** `semantic_diff()` compares the current snapshot against the
previous version and returns added, removed, and changed nodes only, so an agent
loop does not re-read the whole tree after every action.

### 5.3 Identity & session (`src/identity.ts`)

**Isolation.** Each identity owns a `Target.createBrowserContext({ proxyServer,
proxyBypassList })`. Proxy is bound at the context level, so any page opened inside
that context inherits it for every socket the page opens — including subresources and
WebSocket — rather than being limited to interceptable HTTP.

**Scope note (added after implementation review).** The session does not switch into
an identity's context. `identity_use` applies the identity's fingerprint seed to the
stealth layer and returns; all tools continue to drive the tab selected by
`browser_attach`. The isolation above is therefore a property of the created context,
not of the running session, and the proxy carries no traffic until something opens a
page in that context. Switching the active target into the context is future work.

**Portability.** `identity_export(name)` serializes cookies plus localStorage and
sessionStorage into a single JSON document; `identity_import(json, name?)`
restores it into a context, reusing the exported name when `name` is omitted.
Built on the existing cookie and storage tools.

**Captcha.** `captcha_detect()` inspects the current page for Turnstile,
hCaptcha, reCAPTCHA, and Cloudflare interstitial markup, and reports challenge
type, sitekey, and frame target. It reports; it does not solve.
`captcha_provider_hook(provider, apiKey)` registers an external solver endpoint
and is **off by default**. This is the only path by which a solve can occur, and
it is opt-in per session.

### 5.4 Error envelope (`src/errors.ts`)

All new tools return a structured result so the model can self-correct on the
next turn instead of the reasoning chain breaking:

```json
{
  "success": false,
  "error_code": "ERR_STALE_NODE_ID",
  "message": "Node id 15 belongs to snapshot version 2, current version is 4.",
  "suggestion": "Re-run semantic_view and use the ids from the new snapshot."
}
```

`err()` still sets MCP-level `isError: true` for transport-visible failures, so
existing client behavior is unchanged. The 88 existing tools keep their current
error shape; migration is deferred.

Error codes live in a closed registry in `src/errors.ts`. The seed set is
`ERR_STALE_NODE_ID`, `ERR_NO_SESSION`, `ERR_NO_IDENTITY`, `ERR_PROXY_UNREACHABLE`,
`ERR_STEALTH_PATCH_FAILED`, `ERR_AX_TREE_UNAVAILABLE`, and
`ERR_CAPTCHA_PROVIDER_DISABLED`. Any code added during implementation is added to
this registry — no handler may emit an unregistered code. A contract test
enforces that.

## 6. Tool surface

Thirteen new tools, 88 → 101.

**Stealth**

| Tool | Parameters |
|---|---|
| `stealth_enable` | `profile` (`off`/`basic`/`strict`), `seed?` |
| `stealth_status` | — |
| `stealth_probe` | `checks?`, `maxChars?` |

**Pruner**

| Tool | Parameters |
|---|---|
| `semantic_view` | `interactiveOnly?` (default `false`), `includeOffscreen?` (default `false`), `maxNodes?` (default `300`, max `2000`), `maxChars?` (default `20000`) |
| `interact_semantic` | `id`, `action` (`click`/`type`/`hover`/`select`/`focus`), `value?` |
| `semantic_diff` | `maxChanges?` (default `100`) |

**Identity**

| Tool | Parameters |
|---|---|
| `identity_create` | `name`, `proxy?`, `seed?`, `userAgent?` |
| `identity_use` | `name` |
| `identity_list` | — |
| `identity_export` | `name` |
| `identity_import` | `json`, `name?` |

**Captcha**

| Tool | Parameters |
|---|---|
| `captcha_detect` | — |
| `captcha_provider_hook` | `provider`, `apiKey` |

Every parameter carries a Zod schema with an explicit `.describe()`, stated
defaults, and numeric bounds, because the model generates arguments from the
schema text alone.

## 7. Data flow

**Stealth.** `stealth_enable` → seed derived or supplied → patch payload built →
registered via `addScriptToEvaluateOnNewDocument` → applied on every subsequent
document load in the session's context.

**Pruner.** `semantic_view` → `Accessibility.getFullAXTree` + DOM merge →
compress → assign IDs → store `{version, idMap}` → return text. Then
`interact_semantic(id)` → version check → `DOM.resolveNode(backendDOMNodeId)` →
existing `Input` dispatch → optional `semantic_diff` on the next turn.

**Identity.** `identity_create` → context created with proxy → optional
`stealth_enable` with the identity seed → `identity_use` applies that seed. It does
**not** make the context active for tools; the attached tab is unchanged. Likewise
`identity_export` reads cookies and storage out of the currently attached tab, not out
of the identity's context.

## 8. Error handling

- No new tool may throw out of its handler. Every handler returns the envelope.
- Session-absent calls (`semantic_view` with no attached tab) return
  `ERR_NO_SESSION` with a suggestion to call `browser_attach`.
- The AX tree can be unavailable on `about:blank` and on PDF viewers; that is
  `ERR_AX_TREE_UNAVAILABLE`, not a crash.
- Proxy failures surface as `ERR_PROXY_UNREACHABLE` at context creation, before
  any navigation is attempted.
- Stealth injection failures are reported per-patch in `stealth_probe` output
  rather than aborting the whole profile.

## 9. Testing

**Unit, no browser.** The pruner and the error envelope are pure functions.
Compression, ID assignment, version invalidation, and diff calculation are tested
against recorded `Accessibility.getFullAXTree` JSON fixtures checked into
`test/fixtures/`. These run inside the existing `test/index.test.ts` harness
(`node --test`), so `pnpm test` keeps working with no new infrastructure.

**Integration, browser required.** Stealth patches and identity isolation need a
real Chrome. These live in a separate file and are excluded from the default
`test` script; they run against a local detection page that exercises each
patched surface.

**Contract.** A test asserts the tool count and that every new tool's input
schema rejects a missing required field, so the surface cannot drift silently.

## 10. Risks

| Risk | Mitigation |
|---|---|
| Stealth patches rot as vendors update detection | `stealth_probe` gives a feedback loop; profiles are data, not code, so a patch can be revised without touching handlers |
| AX tree omits interactive custom elements | DOM merge in §5.2; `interactiveOnly` keeps the merged set small |
| ID map goes stale mid-task | Version check returns `ERR_STALE_NODE_ID` with a re-read suggestion rather than acting on a wrong node |
| Inconsistent spoofing is itself detectable | Seed lives on the identity, not the page |
| Captcha solving is expected but not delivered | Stated explicitly in §2 and §5.3; `captcha_detect` still lets an agent recognise a block and route around it |

## 11. Program context

Five sub-projects were proposed. This spec covers the first:

1. **Stealth Browser & Semantic Tree Pruner** — this document
2. Traffic Interceptor & Mobile RE (mitmproxy/Reqable, JADX, Frida)
3. Safe Database Sandbox & Query Plan Profiler
4. Linux Profiler & eBPF Triage
5. Multi-Tenant Session & Fingerprint Mesh

Sub-projects 3, 4, and 5 are independent servers and will live as separate
packages in the monorepo. Sub-project 2 extends this server. The monorepo
scaffold and shared core package are introduced when sub-project 3 begins, not
here, because this sub-project adds no new package.

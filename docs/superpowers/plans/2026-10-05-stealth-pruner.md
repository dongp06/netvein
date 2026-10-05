# Stealth Browser & Semantic Tree Pruner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a stealth patch layer, a CDP accessibility-tree pruner with integer node addressing, per-identity browser contexts, captcha detection, and a structured error envelope to the existing 88-tool `reverse-engineering-mcp` server.

**Architecture:** Four new modules under `src/` (`errors.ts`, `stealth.ts`, `pruner.ts`, `identity.ts`). Pure logic lives in exported functions so it can be unit-tested without a browser; the `CdpSession` class gains thin async methods that do CDP I/O and delegate to those functions. New tools are registered in `src/server.ts` beside the existing 88. Nothing in the existing handlers, `CdpSession` state machine, or `launcher.ts` changes behavior — additions are additive only.

**Tech Stack:** TypeScript 5.8, ESM, Node 22+, `@modelcontextprotocol/sdk` 1.31, Zod 3.25, `chrome-remote-interface` 0.34, `node:test` + `node:assert/strict`. **No new runtime dependency is introduced.**

**Spec:** `docs/superpowers/specs/2026-10-05-stealth-pruner-design.md`

## Global Constraints

- No new runtime dependency. `package.json` `dependencies` must be unchanged at the end of the plan.
- ESM with explicit `.js` extensions on all relative imports (`import { CdpSession } from "./cdp.js"`), matching every existing file.
- All new tool parameters use Zod with `.describe()`; numeric parameters carry explicit `.min()`/`.max()` and a stated default.
- Reuse the existing bounded-text policy: import `truncate` behavior by passing `MAX_STORED_TEXT = 20_000` where the spec says so. Do not redefine the constant.
- No new tool handler may throw. Every new handler returns the `Envelope` from `src/errors.ts`.
- Error codes may only come from the closed registry `ERROR_CODES` in `src/errors.ts`. No handler emits an unregistered code.
- Final tool count is 101 (88 existing + 13 new).
- Captcha solving is out of scope. `captcha_detect` reports; `captcha_provider_hook` registers an endpoint and is inert until a caller supplies one.
- Pure functions must not import `chrome-remote-interface` or touch `CdpSession`, so they stay unit-testable without a browser.
- Every commit message ends with a blank line then `Co-Authored-By: Claude Code <noreply@anthropic.com>`. The commit commands below show the subject line only; append the trailer when committing.

## Review Focus

These are the input classes and failure modes the spec implies but whose behavior no task's happy-path test pins. Each is tested in the task that owns the code.

1. **AX tree unavailable** — `semantic_view` on `about:blank`, a PDF viewer, or a crashed renderer must return `ERR_AX_TREE_UNAVAILABLE`, not crash the process. (Task 5)
2. **Stale node id after navigation** — `interact_semantic` given an id from a previous page must reject with `ERR_STALE_NODE_ID` and must not click a node that happens to reuse the same `backendDOMNodeId`. (Task 6)
3. **Stealth before attach** — `stealth_enable` with no attached tab must return `ERR_NO_SESSION` rather than failing inside the patch builder. (Task 3)
4. **Unreachable proxy** — `identity_create` with a proxy that cannot be reached must return `ERR_PROXY_UNREACHABLE` and must not register the identity as usable. (Task 7)
5. **Malformed identity payload** — `identity_import` with invalid JSON or a shape missing `cookies` must return an envelope error and must not leave partially applied storage behind. (Task 8)

---

## File Structure

| File | Responsibility |
|---|---|
| `src/errors.ts` (new) | Error code registry, `ok()`/`err()`, `ToolError`, `toEnvelope()` |
| `src/stealth.ts` (new) | Seeded PRNG, stealth patch registry, `buildStealthScript()` |
| `src/pruner.ts` (new) | AX tree compression, id assignment, semantic formatting, snapshot diffing |
| `src/identity.ts` (new) | Identity records, proxy binding, cookie/storage serialization |
| `src/cdp.ts` (modify) | Session methods that do CDP I/O and delegate to the modules above |
| `src/server.ts` (modify) | 13 new tool registrations |
| `test/index.test.ts` (modify) | Pure-function unit tests + tool contract test |
| `test/fixtures/ax-tree-login.json` (new) | Recorded AX tree used by pruner unit tests |
| `docs/TOOLS.md`, `docs/ARCHITECTURE.md`, `README.md` (modify) | Documentation of the new surface |

---

### Task 1: Structured error envelope

**Files:**
- Create: `src/errors.ts`
- Test: `test/index.test.ts` (append a new `test(...)` block)

**Interfaces:**
- Consumes: nothing.
- Produces: `ERROR_CODES`, `ErrorCode`, `OkEnvelope<T>`, `ErrEnvelope`, `Envelope<T>`, `ok<T>(data)`, `err(code, message, suggestion?)`, `ToolError`, `toEnvelope(error, fallbackCode)`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
import { DEFAULT_SUGGESTIONS, ERROR_CODES, ToolError, err, ok, toEnvelope } from "../src/errors.js";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../src/errors.js'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/errors.ts`:

```typescript
export const ERROR_CODES = {
  ERR_STALE_NODE_ID: "The node id belongs to an outdated accessibility snapshot.",
  ERR_NO_SESSION: "No Chrome target is attached to the session.",
  ERR_NO_IDENTITY: "The requested identity does not exist.",
  ERR_PROXY_UNREACHABLE: "The identity's proxy could not be reached.",
  ERR_STEALTH_PATCH_FAILED: "A stealth patch failed to install.",
  ERR_AX_TREE_UNAVAILABLE: "The accessibility tree is unavailable on this page.",
  ERR_CAPTCHA_PROVIDER_DISABLED: "No captcha provider is registered.",
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

/**
 * Suggestions attached to a fallback envelope, where the throwing site did not
 * supply one. The spec requires every envelope to carry a suggestion, because
 * the suggestion is what lets the model correct itself on the next turn.
 */
export const DEFAULT_SUGGESTIONS: Record<ErrorCode, string> = {
  ERR_STALE_NODE_ID: "Re-run semantic_view and use the ids from the new snapshot.",
  ERR_NO_SESSION: "Call browser_attach to attach a tab, then retry.",
  ERR_NO_IDENTITY: "Call identity_list to see available identities, or identity_create first.",
  ERR_PROXY_UNREACHABLE: "Confirm the proxy is running and reachable from this host.",
  ERR_STEALTH_PATCH_FAILED: "Confirm a tab is attached with browser_attach, then retry stealth_enable.",
  ERR_AX_TREE_UNAVAILABLE: "Navigate to a real page first; the tree is unavailable on about:blank and PDF viewers.",
  ERR_CAPTCHA_PROVIDER_DISABLED: "Call captcha_provider_hook with a provider and key, or rely on captcha_detect alone.",
};

export interface OkEnvelope<T> {
  success: true;
  data: T;
}

export interface ErrEnvelope {
  success: false;
  error_code: ErrorCode;
  message: string;
  suggestion?: string;
}

export type Envelope<T> = OkEnvelope<T> | ErrEnvelope;

export function ok<T>(data: T): OkEnvelope<T> {
  return { success: true, data };
}

export function err(code: ErrorCode, message: string, suggestion?: string): ErrEnvelope {
  if (suggestion === undefined) {
    return { success: false, error_code: code, message };
  }
  return { success: false, error_code: code, message, suggestion };
}

export class ToolError extends Error {
  readonly code: ErrorCode;
  readonly suggestion?: string;

  constructor(code: ErrorCode, message: string, suggestion?: string) {
    super(message);
    this.name = "ToolError";
    this.code = code;
    this.suggestion = suggestion;
  }

  toEnvelope(): ErrEnvelope {
    return err(this.code, this.message, this.suggestion);
  }
}

export function toEnvelope(error: unknown, fallbackCode: ErrorCode): ErrEnvelope {
  if (error instanceof ToolError) return error.toEnvelope();
  const message = error instanceof Error ? error.message : String(error);
  return err(fallbackCode, message, DEFAULT_SUGGESTIONS[fallbackCode]);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test`
Expected: PASS — all `Structured Error Envelope` subtests green, existing tests still green.

- [ ] **Step 5: Commit**

```bash
git add src/errors.ts test/index.test.ts
git commit -m "feat: add structured error envelope for new tools"
```

---

### Task 2: Stealth patch generator (pure)

**Files:**
- Create: `src/stealth.ts`
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: nothing (must not import `cdp.js`).
- Produces: `StealthProfile` (`"off" | "basic" | "strict"`), `createSeededPrng(seed: number): () => number`, `seedFromName(name: string): number`, `STEALTH_PATCHES`, `activePatchIds(profile): string[]`, `buildStealthScript(profile, seed): string`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
import { activePatchIds, buildStealthScript, createSeededPrng, seedFromName } from "../src/stealth.js";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../src/stealth.js'`.

- [ ] **Step 3: Write minimal implementation**

Create `src/stealth.ts`:

```typescript
export type StealthProfile = "off" | "basic" | "strict";

interface StealthPatch {
  id: string;
  level: "basic" | "strict";
  source: string;
}

export function createSeededPrng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function seedFromName(name: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

export const STEALTH_PATCHES: StealthPatch[] = [
  {
    id: "navigator-webdriver",
    level: "basic",
    source: `
// navigator.webdriver
try {
  Object.defineProperty(Navigator.prototype, "webdriver", {
    get: () => undefined,
    configurable: true,
  });
} catch (_) {}`,
  },
  {
    id: "runtime-leak",
    level: "basic",
    source: `
// CDP runtime leak: silence the console.debug timing probe used to detect Runtime.enable
try {
  const nativeDebug = console.debug;
  const silent = function () {};
  Object.defineProperty(silent, "toString", { value: () => nativeDebug.toString() });
  Object.defineProperty(console, "debug", { value: silent, writable: true, configurable: true });
} catch (_) {}`,
  },
  {
    id: "navigator-surface",
    level: "basic",
    source: `
// navigator surface consistency
try {
  const r = makeRand(__seed + 3);
  const plugins = [
    { name: "PDF Viewer", filename: "internal-pdf-viewer" },
    { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer" },
  ];
  Object.defineProperty(Navigator.prototype, "plugins", {
    get: () => plugins.map((p, i) => Object.assign(Object.create(null), { name: p.name, filename: p.filename, length: 1, item: () => null, namedItem: () => null })),
    configurable: true,
  });
  Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, "deviceMemory", { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, "languages", { get: () => ["en-US", "en"], configurable: true });
  void r;
} catch (_) {}`,
  },
  {
    id: "iframe-content-window",
    level: "basic",
    source: `
// iframe contentWindow must not expose the automation frame
try {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "contentWindow");
  if (descriptor && descriptor.get) {
    const nativeGet = descriptor.get;
    Object.defineProperty(HTMLIFrameElement.prototype, "contentWindow", {
      get: function () {
        const win = nativeGet.call(this);
        return win === window ? window : win;
      },
      configurable: true,
    });
  }
} catch (_) {}`,
  },
  {
    id: "canvas-noise",
    level: "strict",
    source: `
// deterministic canvas noise
try {
  const r = makeRand(__seed + 11);
  const nativeGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args) {
    const data = nativeGetImageData.apply(this, args);
    const px = data && data.data;
    if (px && px.length >= 4) {
      const index = (Math.floor(r() * (px.length / 4)) | 0) * 4;
      px[index] = (px[index] + 1) & 0xff;
    }
    return data;
  };
} catch (_) {}`,
  },
  {
    id: "webgl-vendor",
    level: "strict",
    source: `
// deterministic WebGL vendor/renderer spoof
try {
  const nativeGetParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (parameter) {
    if (parameter === 37445) return "Intel Inc.";
    if (parameter === 37446) return "Intel Iris OpenGL Engine";
    return nativeGetParameter.call(this, parameter);
  };
} catch (_) {}`,
  },
  {
    id: "audio-noise",
    level: "strict",
    source: `
// deterministic audio fingerprint noise
try {
  const r = makeRand(__seed + 17);
  const nativeGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
  AnalyserNode.prototype.getFloatFrequencyData = function (array) {
    nativeGetFloatFrequencyData.call(this, array);
    if (array && array.length > 0) {
      const index = (Math.floor(r() * array.length) | 0) % array.length;
      array[index] = array[index] + 1e-7;
    }
  };
} catch (_) {}`,
  },
  {
    id: "to-string-integrity",
    level: "strict",
    source: `
// patched natives must stringify as native code
try {
  const nativeToString = Function.prototype.toString;
  const patched = new WeakSet();
  for (const value of Object.getOwnPropertyNames(window)) {
    try {
      const candidate = window[value];
      if (typeof candidate === "function" && !/^\[native code\]$/.test(nativeToString.call(candidate))) {
        patched.add(candidate);
      }
    } catch (_) {}
  }
  Function.prototype.toString = function () {
    if (patched.has(this)) return "function () { [native code] }";
    return nativeToString.call(this);
  };
  Object.defineProperty(Function.prototype.toString, "toString", {
    value: () => nativeToString.call(nativeToString),
  });
} catch (_) {}`,
  },
];

export function activePatchIds(profile: StealthProfile): string[] {
  if (profile === "off") return [];
  return STEALTH_PATCHES.filter((patch) => patch.level === "basic" || profile === "strict").map((patch) => patch.id);
}

export function buildStealthScript(profile: StealthProfile, seed: number): string {
  const patches = STEALTH_PATCHES.filter((patch) => patch.level === "basic" || profile === "strict");
  if (profile === "off" || patches.length === 0) return "";

  const preamble = `
(() => {
  const __seed = ${seed >>> 0};
  const makeRand = (s) => {
    let a = s >>> 0;
    return () => {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  };`;

  return `${preamble}\n${patches.map((patch) => patch.source).join("\n")}\n})();`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test`
Expected: PASS. If `tsc` complains about `window`/`HTMLIFrameElement` inside the `stealth.ts` template strings, note these are string literals, not executed TypeScript — no DOM lib is required. Confirm with `npm run check`.

- [ ] **Step 5: Commit**

```bash
git add src/stealth.ts test/index.test.ts
git commit -m "feat: add pure stealth patch generator with deterministic seeding"
```

---

### Task 3: Stealth session wiring and three tools

**Files:**
- Modify: `src/cdp.ts` (add three public methods near `antiDebugBypass` at ~2,360)
- Modify: `src/server.ts` (register three tools after `browser_status` at ~line 118)
- Test: `test/index.test.ts` (contract test block)

**Interfaces:**
- Consumes: `activePatchIds`, `buildStealthScript`, `seedFromName`, `StealthProfile` from Task 2; `ToolError`, `toEnvelope` from Task 1; `CdpSession.requireClient()` (private, existing).
- Produces: `CdpSession.applyStealth(profile, seed?)`, `CdpSession.stealthStatus()`, `CdpSession.stealthProbe()`. Tools `stealth_enable`, `stealth_status`, `stealth_probe`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `session.applyStealthEnvelope is not a function`.

- [ ] **Step 3: Implement the session methods**

In `src/cdp.ts`, add the import at the top alongside the other imports:

```typescript
import { activePatchIds, buildStealthScript, seedFromName, type StealthProfile } from "./stealth.js";
import { ToolError, toEnvelope, type Envelope } from "./errors.js";
```

Add these private fields next to `antiDebugBypassScriptId` (search for that declaration and place these immediately after):

```typescript
  private stealthScriptId: string | null = null;
  private stealthProfile: StealthProfile = "off";
  private stealthSeed = 0;
```

Add these public methods after `antiDebugBypass` (around line 2,445, after that method's closing brace):

```typescript
  /**
   * Install a stealth patch profile on the attached target. Patches are registered
   * for all future documents in this target, and applied to the current document
   * immediately so the page does not need a reload.
   */
  async applyStealth(profile: StealthProfile, seed?: number): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const resolvedSeed = seed ?? (this.target?.id ? seedFromName(this.target.id) : 0);

    if (this.stealthScriptId) {
      try {
        await client.Page.removeScriptToEvaluateOnNewDocument({ identifier: this.stealthScriptId });
      } catch (_) {
        // The document may already have been torn down; a stale registration is harmless.
      }
      this.stealthScriptId = null;
    }

    const script = buildStealthScript(profile, resolvedSeed);
    if (script.length === 0) {
      this.stealthProfile = "off";
      this.stealthSeed = resolvedSeed;
      return { profile: "off", patchIds: [], applied: false };
    }

    try {
      const registration = await client.Page.addScriptToEvaluateOnNewDocument({ source: script });
      this.stealthScriptId = registration.identifier;
      await client.Runtime.evaluate({ expression: script, returnByValue: true });
    } catch (error) {
      throw new ToolError(
        "ERR_STEALTH_PATCH_FAILED",
        error instanceof Error ? error.message : String(error),
        "Confirm a tab is attached with browser_attach, then retry stealth_enable.",
      );
    }

    this.stealthProfile = profile;
    this.stealthSeed = resolvedSeed;
    this.addTimeline("browser", "stealth", `stealth: ${profile}`, { profile, seed: resolvedSeed });

    return { profile, patchIds: activePatchIds(profile), seed: resolvedSeed, applied: true };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async applyStealthEnvelope(profile: StealthProfile, seed?: number): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.applyStealth(profile, seed) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /** Report the active stealth profile without performing any CDP I/O. */
  stealthStatus(): { profile: StealthProfile; patchIds: string[]; seed: number; scriptRegistered: boolean } {
    return {
      profile: this.stealthProfile,
      patchIds: activePatchIds(this.stealthProfile),
      seed: this.stealthSeed,
      scriptRegistered: this.stealthScriptId !== null,
    };
  }

  /**
   * Run a detection suite in the page and report what still leaks, per check.
   * Each check returns the observed value so patch rot is visible rather than silent.
   */
  async stealthProbe(maxChars = MAX_STORED_TEXT): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const expression = `(() => {
      const checks = [];
      const push = (id, passed, observed) => checks.push({ id, passed, observed });
      try { push("webdriver", navigator.webdriver === undefined, String(navigator.webdriver)); }
      catch (e) { push("webdriver", false, "threw: " + e.message); }
      try { push("plugins", navigator.plugins && navigator.plugins.length > 0, String(navigator.plugins && navigator.plugins.length)); }
      catch (e) { push("plugins", false, "threw: " + e.message); }
      try {
        const canvas = document.createElement("canvas");
        canvas.width = 64; canvas.height = 32;
        const ctx = canvas.getContext("2d");
        const noise = ctx.getImageData(0, 0, 64, 32).data;
        push("canvas", noise.length === 64 * 32 * 4, "length=" + noise.length);
      } catch (e) { push("canvas", false, "threw: " + e.message); }
      try {
        const gl = document.createElement("canvas").getContext("webgl");
        push("webgl", Boolean(gl), gl ? String(gl.getParameter(37445)) : "no webgl context");
      } catch (e) { push("webgl", false, "threw: " + e.message); }
      const failed = checks.filter((c) => !c.passed).map((c) => c.id);
      return { profile: ${JSON.stringify(this.stealthProfile)}, checks, failed };
    })()`;
    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    const value = (result.result?.value ?? { profile: this.stealthProfile, checks: [], failed: [] }) as {
      profile: StealthProfile;
      checks: Array<{ id: string; passed: boolean; observed: string }>;
      failed: string[];
    };
    return {
      profile: value.profile,
      failed: value.failed,
      checks: value.checks.map((check) => ({
        id: check.id,
        passed: check.passed,
        observed: truncate(check.observed, 200) ?? "",
      })),
    };
  }
```

- [ ] **Step 4: Register the three tools**

In `src/server.ts`, add after the `browser_status` registration (around line 118):

```typescript
  server.registerTool(
    "stealth_enable",
    {
      title: "Enable a stealth patch profile",
      description:
        "Install anti-detection patches on the attached target. Patches apply to the current document immediately and to every future document in this target. Profile 'basic' covers identity leaks; 'strict' adds canvas, WebGL and audio fingerprint noise plus Function.prototype.toString integrity.",
      inputSchema: {
        profile: z.enum(["off", "basic", "strict"]).default("basic").describe("Patch level. 'off' removes all patches."),
        seed: z
          .number()
          .int()
          .min(0)
          .max(4294967295)
          .optional()
          .describe("Deterministic fingerprint seed. Omit to derive one from the attached target id."),
      },
    },
    safeTool(async (args: { profile?: "off" | "basic" | "strict"; seed?: number }) =>
      session.applyStealth(args.profile ?? "basic", args.seed),
    ),
  );

  server.registerTool(
    "stealth_status",
    {
      title: "Report the active stealth profile",
      description: "Return the active stealth profile, the patch ids it activates, and whether a patch script is registered.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.stealthStatus()),
  );

  server.registerTool(
    "stealth_probe",
    {
      title: "Probe the page for stealth leaks",
      description:
        "Run a detection suite in the attached page and report, per check, what still leaks and the observed value. Use this to detect when a stealth patch has gone stale.",
      inputSchema: {
        maxChars: z.number().int().min(1000).max(20000).default(20000).describe("Maximum characters returned."),
      },
    },
    safeTool(async (args: { maxChars?: number }) => session.stealthProbe(args.maxChars ?? 20_000)),
  );
```

- [ ] **Step 5: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS. The `Stealth Tool Registration & Session Guards` block is green and `tsc --noEmit` reports no errors.

- [ ] **Step 6: Commit**

```bash
git add src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: wire stealth profiles into the CDP session and expose three tools"
```

---

### Task 4: Semantic pruner core (pure)

**Files:**
- Create: `src/pruner.ts`
- Create: `test/fixtures/ax-tree-login.json`
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: nothing (pure).
- Produces: `AxNode`, `SemanticNode`, `SemanticSnapshot`, `compressAxTree(nodes, options)`, `formatSemanticView(snapshot)`, `diffSnapshots(previous, current, maxChanges)`.

- [ ] **Step 1: Create the fixture**

Create `test/fixtures/ax-tree-login.json`:

```json
{
  "nodes": [
    {
      "nodeId": "1",
      "ignored": false,
      "role": { "type": "role", "value": "RootWebArea" },
      "name": { "type": "computedString", "value": "Login" },
      "childIds": ["2"]
    },
    {
      "nodeId": "2",
      "ignored": false,
      "role": { "type": "role", "value": "generic" },
      "childIds": ["3", "4", "5", "6"]
    },
    {
      "nodeId": "3",
      "ignored": false,
      "role": { "type": "role", "value": "textbox" },
      "name": { "type": "computedString", "value": "Email" },
      "value": { "type": "string", "value": "" },
      "backendDOMNodeId": 11,
      "childIds": []
    },
    {
      "nodeId": "4",
      "ignored": false,
      "role": { "type": "role", "value": "textbox" },
      "name": { "type": "computedString", "value": "Password" },
      "value": { "type": "string", "value": "" },
      "backendDOMNodeId": 12,
      "childIds": []
    },
    {
      "nodeId": "5",
      "ignored": false,
      "role": { "type": "role", "value": "button" },
      "name": { "type": "computedString", "value": "Sign in" },
      "backendDOMNodeId": 13,
      "childIds": []
    },
    {
      "nodeId": "6",
      "ignored": true,
      "role": { "type": "role", "value": "none" },
      "childIds": []
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

Append to `test/index.test.ts`:

```typescript
import { readFileSync } from "node:fs";
import { compressAxTree, diffSnapshots, formatSemanticView } from "../src/pruner.js";

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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../src/pruner.js'`.

- [ ] **Step 4: Implement the pruner**

Create `src/pruner.ts`:

```typescript
export interface AxNode {
  nodeId: string;
  ignored?: boolean;
  role?: { value?: string };
  name?: { value?: string };
  value?: { value?: string };
  backendDOMNodeId?: number;
  childIds?: string[];
}

export interface SemanticNode {
  id: number;
  role: string;
  name: string;
  value?: string;
  depth: number;
}

export interface SemanticSnapshot {
  version: number;
  nodes: SemanticNode[];
  idMap: Map<number, number>;
  truncated: boolean;
}

export interface CompressOptions {
  version: number;
  interactiveOnly?: boolean;
  maxNodes?: number;
  nameMaxChars?: number;
}

const INTERACTIVE_ROLES = new Set([
  "button",
  "link",
  "textbox",
  "searchbox",
  "checkbox",
  "radio",
  "combobox",
  "listbox",
  "menuitem",
  "option",
  "slider",
  "spinbutton",
  "switch",
  "tab",
]);

const DROPPED_ROLES = new Set(["generic", "none", "presentational", "ignored", "InlineTextBox"]);

function roleOf(node: AxNode): string {
  return node.role?.value ?? "";
}

function isInteractive(node: AxNode): boolean {
  return INTERACTIVE_ROLES.has(roleOf(node));
}

function depthMap(nodes: AxNode[]): Map<string, number> {
  const byId = new Map(nodes.map((node) => [node.nodeId, node]));
  const depths = new Map<string, number>();

  const visit = (nodeId: string, depth: number): void => {
    const node = byId.get(nodeId);
    if (!node) return;
    depths.set(nodeId, depth);
    for (const childId of node.childIds ?? []) {
      const childDepth = DROPPED_ROLES.has(roleOf(byId.get(childId) ?? { nodeId: childId })) ? depth : depth + 1;
      visit(childId, childDepth);
    }
  };

  const roots = nodes.filter((node) => !nodes.some((other) => (other.childIds ?? []).includes(node.nodeId)));
  for (const root of roots) visit(root.nodeId, 0);
  return depths;
}

export function compressAxTree(nodes: AxNode[], options: CompressOptions): SemanticSnapshot {
  const depths = depthMap(nodes);
  const interactiveOnly = options.interactiveOnly ?? false;
  const maxNodes = options.maxNodes ?? 300;
  const nameMaxChars = options.nameMaxChars ?? 200;

  const kept = nodes.filter((node) => {
    if (node.ignored) return false;
    const role = roleOf(node);
    if (role.length === 0 || DROPPED_ROLES.has(role)) return false;
    if (interactiveOnly) return isInteractive(node);
    if (role === "RootWebArea") return true;
    const name = node.name?.value ?? "";
    return name.length > 0 || isInteractive(node);
  });

  const truncated = kept.length > maxNodes;
  const bounded = kept.slice(0, maxNodes);

  const semanticNodes: SemanticNode[] = bounded.map((node, index) => {
    const rawName = node.name?.value ?? "";
    const rawValue = node.value?.value;
    const name =
      rawName.length > nameMaxChars ? `${rawName.slice(0, nameMaxChars)}...` : rawName;
    const value =
      rawValue !== undefined && rawValue.length > nameMaxChars
        ? `${rawValue.slice(0, nameMaxChars)}...`
        : rawValue;
    return {
      id: index + 1,
      role: roleOf(node),
      name,
      ...(value !== undefined && value !== "" ? { value } : {}),
      depth: depths.get(node.nodeId) ?? 0,
    };
  });

  const idMap = new Map<number, number>();
  bounded.forEach((node, index) => {
    if (typeof node.backendDOMNodeId === "number") {
      idMap.set(index + 1, node.backendDOMNodeId);
    }
  });

  return { version: options.version, nodes: semanticNodes, idMap, truncated };
}

export function formatSemanticView(snapshot: SemanticSnapshot): string {
  const lines = [`#${snapshot.version}  semantic snapshot (${snapshot.nodes.length} nodes${snapshot.truncated ? ", truncated" : ""})`];
  for (const node of snapshot.nodes) {
    const indent = "  ".repeat(Math.max(node.depth - 1, 0));
    const value = node.value !== undefined && node.value !== "" ? `  value="${node.value}"` : "";
    lines.push(`${indent}[${node.id}] ${node.role} "${node.name}"${value}`);
  }
  return lines.join("\n");
}

export interface SnapshotDiff {
  added: SemanticNode[];
  removed: SemanticNode[];
  changed: SemanticNode[];
}

export function diffSnapshots(
  previous: SemanticSnapshot,
  current: SemanticSnapshot,
  maxChanges = 100,
): SnapshotDiff {
  const key = (node: SemanticNode): string => `${node.role}\u0000${node.name}`;
  const previousByKey = new Map(previous.nodes.map((node) => [key(node), node]));
  const currentByKey = new Map(current.nodes.map((node) => [key(node), node]));

  const added: SemanticNode[] = [];
  const removed: SemanticNode[] = [];
  const changed: SemanticNode[] = [];

  for (const [nodeKey, node] of currentByKey) {
    const before = previousByKey.get(nodeKey);
    if (!before) {
      added.push(node);
      continue;
    }
    if (before.value !== node.value) changed.push(node);
  }
  for (const [nodeKey, node] of previousByKey) {
    if (!currentByKey.has(nodeKey)) removed.push(node);
  }

  const bound = (list: SemanticNode[]): SemanticNode[] => list.slice(0, maxChanges);
  return { added: bound(added), removed: bound(removed), changed: bound(changed) };
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npm test`
Expected: PASS for all nine `Semantic Pruner` subtests.

- [ ] **Step 6: Commit**

```bash
git add src/pruner.ts test/fixtures/ax-tree-login.json test/index.test.ts
git commit -m "feat: add pure accessibility-tree pruner with integer node addressing"
```

---

### Task 5: Pruner session wiring and `semantic_view`

**Files:**
- Modify: `src/cdp.ts` (add `semanticView` and snapshot state)
- Modify: `src/server.ts` (register `semantic_view`)
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: `compressAxTree`, `formatSemanticView`, `SemanticSnapshot` from Task 4; `ToolError` from Task 1.
- Produces: `CdpSession.semanticView(options)`, `CdpSession.currentSemanticSnapshot()`. Tool `semantic_view`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `session.semanticViewEnvelope is not a function`.

- [ ] **Step 3: Implement the session method**

In `src/cdp.ts`, extend the pruner import:

```typescript
import { compressAxTree, formatSemanticView, type SemanticSnapshot } from "./pruner.js";
```

Add fields next to the stealth fields from Task 3:

```typescript
  private semanticSnapshot: SemanticSnapshot | null = null;
  private semanticVersionCounter = 0;
```

Add these methods after `stealthProbe`:

```typescript
  /**
   * Read the accessibility tree, compress it, and assign short integer ids.
   * The id map is invalidated by navigation and by DOM.documentUpdated, which
   * the existing event handler already observes.
   */
  async semanticView(options: {
    interactiveOnly?: boolean;
    maxNodes?: number;
    maxChars?: number;
  } = {}): Promise<Record<string, unknown>> {
    const client = this.requireClient();

    let nodes: unknown;
    try {
      await client.Accessibility.enable();
      const result = await client.Accessibility.getFullAXTree({});
      nodes = result?.nodes;
    } catch (error) {
      throw new ToolError(
        "ERR_AX_TREE_UNAVAILABLE",
        error instanceof Error ? error.message : String(error),
        "The accessibility tree is unavailable on about:blank, PDF viewers and crashed renderers. Navigate to a real page first.",
      );
    }

    if (!Array.isArray(nodes) || nodes.length === 0) {
      throw new ToolError(
        "ERR_AX_TREE_UNAVAILABLE",
        "The accessibility tree returned no nodes.",
        "Navigate to a real page and retry semantic_view.",
      );
    }

    this.semanticVersionCounter += 1;
    const snapshot = compressAxTree(nodes as never, {
      version: this.semanticVersionCounter,
      interactiveOnly: options.interactiveOnly ?? false,
      maxNodes: options.maxNodes ?? 300,
    });
    this.semanticSnapshot = snapshot;

    const maxChars = Math.min(Math.max(options.maxChars ?? MAX_STORED_TEXT, 1000), MAX_STORED_TEXT);
    const text = truncate(formatSemanticView(snapshot), maxChars) ?? "";

    this.addTimeline("browser", "semantic_view", `semantic_view v${snapshot.version}`, {
      version: snapshot.version,
      nodes: snapshot.nodes.length,
      truncated: snapshot.truncated,
    });

    return { version: snapshot.version, nodeCount: snapshot.nodes.length, truncated: snapshot.truncated, view: text };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async semanticViewEnvelope(options: {
    interactiveOnly?: boolean;
    maxNodes?: number;
    maxChars?: number;
  } = {}): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.semanticView(options) };
    } catch (error) {
      // AX-unavailable is always raised as a ToolError, so the only non-ToolError
      // reaching here is requireClient(), which means no session.
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /** Expose the most recent snapshot so later tasks can validate id versions. */
  currentSemanticSnapshot(): SemanticSnapshot | null {
    return this.semanticSnapshot;
  }
```

Then add an invalidation hook. Find where the session handles navigation completion (search `Page.frameNavigated` or the existing `DOM.documentUpdated` handler inside `installEventHandlers`). Add this line inside that handler, next to the existing buffer resets:

```typescript
    this.semanticSnapshot = null;
```

- [ ] **Step 4: Register the tool**

In `src/server.ts`, add after `stealth_probe`:

```typescript
  server.registerTool(
    "semantic_view",
    {
      title: "Pruned semantic view of the page",
      description:
        "Return a compressed accessibility tree with short integer ids instead of raw HTML. Costs roughly 1-2k tokens where a raw DOM dump costs orders of magnitude more. Ids are valid until the page navigates or the DOM changes; a stale id returns ERR_STALE_NODE_ID.",
      inputSchema: {
        interactiveOnly: z.boolean().default(false).describe("Keep only actionable roles (button, link, textbox, checkbox, ...)."),
        maxNodes: z.number().int().min(1).max(2000).default(300).describe("Maximum nodes returned."),
        maxChars: z.number().int().min(1000).max(20000).default(20000).describe("Maximum characters in the rendered view."),
      },
    },
    safeTool(async (args: { interactiveOnly?: boolean; maxNodes?: number; maxChars?: number }) =>
      session.semanticView(args),
    ),
  );
```

- [ ] **Step 5: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: expose pruned semantic view over the CDP accessibility tree"
```

---

### Task 6: `interact_semantic` and `semantic_diff`

**Files:**
- Modify: `src/cdp.ts` (add `interactSemantic`, `semanticDiff`)
- Modify: `src/server.ts` (register two tools)
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: `diffSnapshots` from Task 4; `ToolError` from Task 1; `currentSemanticSnapshot()` from Task 5; existing `clickSelector` pattern for `Input` dispatch.
- Produces: `CdpSession.interactSemantic(id, action, value?)`, `CdpSession.semanticDiff(maxChanges?)`. Tools `interact_semantic`, `semantic_diff`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `session.interactSemanticEnvelope is not a function`.

- [ ] **Step 3: Implement the session methods**

In `src/cdp.ts`, extend the pruner import to include `diffSnapshots`, then add after `currentSemanticSnapshot`:

```typescript
  /**
   * Act on a node by its short integer id. The id is validated against the
   * version that produced it so an id from a previous page can never be applied
   * to a node that happens to reuse the same backendDOMNodeId.
   */
  async interactSemantic(
    id: number,
    action: "click" | "type" | "hover" | "select" | "focus",
    value?: string,
    versionAtCall?: number,
  ): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const snapshot = this.semanticSnapshot;
    if (!snapshot) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        "No semantic snapshot exists for this page.",
        "Run semantic_view first and use the ids it returns.",
      );
    }
    if (versionAtCall !== undefined && versionAtCall !== snapshot.version) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} belongs to snapshot version ${versionAtCall}, current version is ${snapshot.version}.`,
        "Re-run semantic_view and use the ids from the new snapshot.",
      );
    }

    const backendNodeId = snapshot.idMap.get(id);
    if (backendNodeId === undefined) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} is not addressable in snapshot version ${snapshot.version}.`,
        "Re-run semantic_view; non-interactive nodes have no backendDOMNodeId.",
      );
    }

    const resolved = await client.DOM.resolveNode({ backendNodeId });
    const objectId = resolved?.object?.objectId;
    if (!objectId) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        `Node id ${id} could not be resolved; the element was likely detached.`,
        "Re-run semantic_view and retry with a fresh id.",
      );
    }

    const geometry = await client.Runtime.callFunctionOn({
      objectId,
      functionDeclaration: `function () {
        this.scrollIntoView({ block: "center", inline: "center" });
        const rect = this.getBoundingClientRect();
        return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2, tag: this.tagName.toLowerCase() };
      }`,
      returnByValue: true,
    });
    const point = geometry?.result?.value ?? { x: 0, y: 0, tag: "unknown" };

    if (action === "click") {
      await client.Input.dispatchMouseEvent({ type: "mouseMoved", x: point.x, y: point.y });
      await client.Input.dispatchMouseEvent({ type: "mousePressed", x: point.x, y: point.y, button: "left", clickCount: 1 });
      await client.Input.dispatchMouseEvent({ type: "mouseReleased", x: point.x, y: point.y, button: "left", clickCount: 1 });
    } else if (action === "hover") {
      await client.Input.dispatchMouseEvent({ type: "mouseMoved", x: point.x, y: point.y });
    } else if (action === "focus") {
      await client.DOM.focus({ backendNodeId });
    } else if (action === "type") {
      await client.DOM.focus({ backendNodeId });
      await client.Input.insertText({ text: value ?? "" });
    } else if (action === "select") {
      await client.Runtime.callFunctionOn({
        objectId,
        functionDeclaration: `function (target) {
          this.value = target;
          this.dispatchEvent(new Event("input", { bubbles: true }));
          this.dispatchEvent(new Event("change", { bubbles: true }));
          return this.value;
        }`,
        arguments: [{ value: value ?? "" }],
        returnByValue: true,
      });
    }

    this.addTimeline("browser", "interact_semantic", `${action} on [${id}]`, { id, action, version: snapshot.version });
    return { id, action, version: snapshot.version, tag: point.tag, value };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async interactSemanticEnvelope(
    id: number,
    action: "click" | "type" | "hover" | "select" | "focus",
    value?: string,
    versionAtCall?: number,
  ): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.interactSemantic(id, action, value, versionAtCall) };
    } catch (error) {
      // Every stale-id case is raised as a ToolError with its own code, so the
      // only non-ToolError reaching here is requireClient(): no session.
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /**
   * Compare the current accessibility tree against the previous snapshot and
   * return only added, removed and changed nodes, so an agent loop does not
   * re-read the whole tree after every action.
   */
  async semanticDiff(maxChanges = 100): Promise<Record<string, unknown>> {
    const previous = this.semanticSnapshot;
    if (!previous) {
      throw new ToolError(
        "ERR_STALE_NODE_ID",
        "No previous semantic snapshot to diff against.",
        "Run semantic_view twice, with an action in between, then call semantic_diff.",
      );
    }
    await this.semanticView({});
    const current = this.semanticSnapshot!;
    const diff = diffSnapshots(previous, current, maxChanges);
    return {
      fromVersion: previous.version,
      toVersion: current.version,
      added: diff.added,
      removed: diff.removed,
      changed: diff.changed,
    };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async semanticDiffEnvelope(maxChanges = 100): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.semanticDiff(maxChanges) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }
```

- [ ] **Step 4: Register the two tools**

In `src/server.ts`, add after `semantic_view`:

```typescript
  server.registerTool(
    "interact_semantic",
    {
      title: "Act on a node by semantic id",
      description:
        "Click, type into, hover, focus or select a node using the short integer id from semantic_view. Do not construct CSS selectors or XPath. Pass snapshotVersion from semantic_view to have a stale id rejected instead of applied to the wrong element.",
      inputSchema: {
        id: z.number().int().min(1).describe("Integer id from the most recent semantic_view."),
        action: z.enum(["click", "type", "hover", "select", "focus"]).describe("Interaction to perform."),
        value: z.string().optional().describe("Text for 'type', or option value for 'select'."),
        snapshotVersion: z
          .number()
          .int()
          .min(1)
          .optional()
          .describe("Version returned by semantic_view. When supplied, a mismatched version is rejected."),
      },
    },
    safeTool(async (args: { id: number; action: "click" | "type" | "hover" | "select" | "focus"; value?: string; snapshotVersion?: number }) =>
      session.interactSemantic(args.id, args.action, args.value, args.snapshotVersion),
    ),
  );

  server.registerTool(
    "semantic_diff",
    {
      title: "Diff the semantic view since the last snapshot",
      description:
        "Re-read the accessibility tree and return only the nodes added, removed or changed since the previous snapshot. Use this instead of calling semantic_view again after every action.",
      inputSchema: {
        maxChanges: z.number().int().min(1).max(500).default(100).describe("Maximum entries per change category."),
      },
    },
    safeTool(async (args: { maxChanges?: number }) => session.semanticDiff(args.maxChanges ?? 100)),
  );
```

- [ ] **Step 5: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: add semantic interaction and snapshot diffing"
```

---

### Task 7: Identity contexts and three tools

**Files:**
- Create: `src/identity.ts`
- Modify: `src/cdp.ts` (add context lifecycle methods)
- Modify: `src/server.ts` (register three tools)
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: `seedFromName` from Task 2; `ToolError` from Task 1.
- Produces: `IdentityRecord`, `parseProxyServer(proxy)`, `probeProxy(proxy, timeoutMs)`; `CdpSession.createIdentity`, `useIdentity`, `listIdentities`. Tools `identity_create`, `identity_use`, `identity_list`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
import { parseProxyServer } from "../src/identity.js";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../src/identity.js'`.

- [ ] **Step 3: Implement `src/identity.ts`**

```typescript
import * as net from "node:net";

export interface IdentityRecord {
  name: string;
  browserContextId: string | null;
  proxy?: string;
  seed: number;
  createdAt: string;
  usable: boolean;
}

const PROXY_PATTERN = /^(?:[a-z0-9]+:\/\/)?([a-z0-9.\-]+):(\d{1,5})$/i;

/**
 * Normalise a proxy string to the "host:port" form that
 * Target.createBrowserContext expects. Throws on anything malformed so the
 * caller can surface ERR_PROXY_UNREACHABLE before a context is created.
 */
export function parseProxyServer(proxy: string): string {
  const match = PROXY_PATTERN.exec(proxy.trim());
  if (!match) {
    throw new Error(`Proxy must be in host:port form (optionally scheme://host:port), received "${proxy}".`);
  }
  const port = Number(match[2]);
  if (port < 1 || port > 65535) {
    throw new Error(`Proxy must be in host:port form with a port between 1 and 65535, received "${proxy}".`);
  }
  return `${match[1]}:${port}`;
}

/** Resolve true when a TCP connection to host:port completes within the timeout. */
export function probeProxy(proxy: string, timeoutMs = 3000): Promise<void> {
  return new Promise((resolve, reject) => {
    const normalized = parseProxyServer(proxy);
    const separator = normalized.lastIndexOf(":");
    const host = normalized.slice(0, separator);
    const port = Number(normalized.slice(separator + 1));

    const socket = net.connect({ host, port });
    const finish = (error?: Error): void => {
      socket.removeAllListeners();
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish());
    socket.once("timeout", () => finish(new Error(`Proxy ${normalized} did not accept a connection within ${timeoutMs}ms.`)));
    socket.once("error", (error: Error) => finish(new Error(`Proxy ${normalized} is unreachable: ${error.message}`)));
  });
}
```

- [ ] **Step 4: Add the session methods**

In `src/cdp.ts`, add the import:

```typescript
import { parseProxyServer, probeProxy, type IdentityRecord } from "./identity.js";
```

Add the field next to the stealth fields:

```typescript
  private identities = new Map<string, IdentityRecord>();
```

Add these methods after `semanticDiffEnvelope`:

```typescript
  /**
   * Create an isolated browser context, optionally bound to a proxy. The proxy is
   * verified with a TCP probe before the context is created, so a bad proxy fails
   * at creation rather than mid-navigation.
   */
  async createIdentity(options: { name: string; proxy?: string; seed?: number }): Promise<IdentityRecord> {
    // Validate and probe the proxy before touching the session. A bad proxy must
    // fail as ERR_PROXY_UNREACHABLE whether or not a tab is attached, and no
    // identity is registered on failure.
    let proxyServer: string | undefined;
    if (options.proxy) {
      try {
        proxyServer = parseProxyServer(options.proxy);
      } catch (error) {
        throw new ToolError("ERR_PROXY_UNREACHABLE", error instanceof Error ? error.message : String(error), "Pass a proxy as host:port.");
      }
      try {
        await probeProxy(proxyServer);
      } catch (error) {
        throw new ToolError(
          "ERR_PROXY_UNREACHABLE",
          error instanceof Error ? error.message : String(error),
          "Confirm the proxy is running and reachable from this host.",
        );
      }
    }

    const client = this.requireClient();

    if (this.identities.has(options.name)) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `An identity named "${options.name}" already exists.`,
        "Choose another name or call identity_use to switch to it.",
      );
    }

    const created = await client.Target.createBrowserContext(
      proxyServer ? { proxyServer, proxyBypassList: ["127.0.0.1", "localhost"] } : {},
    );

    const record: IdentityRecord = {
      name: options.name,
      browserContextId: created?.browserContextId ?? null,
      proxy: proxyServer,
      seed: options.seed ?? seedFromName(options.name),
      createdAt: new Date().toISOString(),
      usable: true,
    };
    this.identities.set(options.name, record);
    this.addTimeline("browser", "identity_create", `identity: ${options.name}`, { proxy: proxyServer });
    return record;
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async createIdentityEnvelope(options: { name: string; proxy?: string; seed?: number }): Promise<Envelope<IdentityRecord>> {
    try {
      return { success: true, data: await this.createIdentity(options) };
    } catch (error) {
      return toEnvelope(error, "ERR_PROXY_UNREACHABLE");
    }
  }

  /** Mark an identity active and apply its seed to the stealth layer. */
  async useIdentity(name: string): Promise<Record<string, unknown>> {
    const record = this.identities.get(name);
    if (!record) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `No identity named "${name}".`,
        "Call identity_list, then identity_create, then identity_use.",
      );
    }
    if (!record.usable) {
      throw new ToolError("ERR_NO_IDENTITY", `Identity "${name}" is quarantined.`, "Create a fresh identity.");
    }
    await this.applyStealth(this.stealthProfile === "off" ? "basic" : this.stealthProfile, record.seed);
    return { name: record.name, proxy: record.proxy, seed: record.seed, browserContextId: record.browserContextId };
  }

  listIdentities(): IdentityRecord[] {
    return [...this.identities.values()];
  }
```

- [ ] **Step 5: Register the three tools**

In `src/server.ts`, add after `semantic_diff`:

```typescript
  server.registerTool(
    "identity_create",
    {
      title: "Create an isolated browser identity",
      description:
        "Create a browser context isolated from other identities, optionally bound to a proxy at the context level so the proxy covers every socket including subresources and WebSocket. A proxy is TCP-probed before the context is created.",
      inputSchema: {
        name: z.string().min(1).describe("Unique identity name."),
        proxy: z.string().optional().describe("Proxy in host:port or scheme://host:port form."),
        seed: z.number().int().min(0).max(4294967295).optional().describe("Fingerprint seed. Defaults to a hash of the name."),
      },
    },
    safeTool(async (args: { name: string; proxy?: string; seed?: number }) => session.createIdentity(args)),
  );

  server.registerTool(
    "identity_use",
    {
      title: "Activate an identity",
      description: "Mark an identity active and apply its fingerprint seed to the stealth layer.",
      inputSchema: {
        name: z.string().min(1).describe("Identity name from identity_list."),
      },
    },
    safeTool(async (args: { name: string }) => session.useIdentity(args.name)),
  );

  server.registerTool(
    "identity_list",
    {
      title: "List identities",
      description: "List created identities with their proxy binding, seed and usability.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.listIdentities()),
  );
```

- [ ] **Step 6: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS. The unreachable-proxy subtest passes because port 1 refuses the connection immediately.

- [ ] **Step 7: Commit**

```bash
git add src/identity.ts src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: add isolated browser identities with proxy binding"
```

---

### Task 8: Identity export and import

**Files:**
- Modify: `src/identity.ts` (add `serializeIdentity`, `parseIdentityPayload`)
- Modify: `src/cdp.ts` (add `exportIdentity`, `importIdentity`)
- Modify: `src/server.ts` (register two tools)
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: `CookieRecord`, `StorageItem` from `src/types.ts`; existing `getCookies`, `setCookie`, `getStorage`, `setStorage`, `clearStorage` methods on `CdpSession`.
- Produces: `IdentityPayload`, `serializeIdentity(...)`, `parseIdentityPayload(json)`. `CdpSession.exportIdentity(name)`, `CdpSession.importIdentity(json, name?)`. Tools `identity_export`, `identity_import`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
import { parseIdentityPayload, serializeIdentity } from "../src/identity.js";

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `parseIdentityPayload is not a function`.

- [ ] **Step 3: Implement the pure serialization**

Add to `src/identity.ts`:

```typescript
import type { CookieRecord } from "./types.js";

export interface IdentityPayload {
  version: 1;
  name: string;
  proxy?: string;
  exportedAt: string;
  cookies: CookieRecord[];
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
}

export function serializeIdentity(
  name: string,
  proxy: string | undefined,
  cookies: CookieRecord[],
  localStorage: Record<string, string>,
  sessionStorage: Record<string, string>,
): IdentityPayload {
  const payload: IdentityPayload = {
    version: 1,
    name,
    exportedAt: new Date().toISOString(),
    cookies,
    localStorage,
    sessionStorage,
  };
  if (proxy !== undefined) payload.proxy = proxy;
  return payload;
}

/**
 * Validate an exported identity payload. Throws with an actionable message so
 * the caller can return an envelope error without applying anything partially.
 */
export function parseIdentityPayload(json: string): IdentityPayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new Error(`Identity payload is not valid JSON: ${error instanceof Error ? error.message : String(error)}.`);
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Identity payload must be a JSON object.");
  }

  const candidate = parsed as Partial<IdentityPayload>;

  if (typeof candidate.name !== "string" || candidate.name.length === 0) {
    throw new Error("Identity payload is missing a non-empty name field.");
  }
  if (!Array.isArray(candidate.cookies)) {
    throw new Error("Identity payload is missing a cookies array.");
  }
  if (candidate.localStorage !== undefined && typeof candidate.localStorage !== "object") {
    throw new Error("Identity payload localStorage must be an object when present.");
  }
  if (candidate.sessionStorage !== undefined && typeof candidate.sessionStorage !== "object") {
    throw new Error("Identity payload sessionStorage must be an object when present.");
  }

  return {
    version: 1,
    name: candidate.name,
    ...(candidate.proxy !== undefined ? { proxy: candidate.proxy } : {}),
    exportedAt: candidate.exportedAt ?? new Date().toISOString(),
    cookies: candidate.cookies as CookieRecord[],
    localStorage: (candidate.localStorage as Record<string, string>) ?? {},
    sessionStorage: (candidate.sessionStorage as Record<string, string>) ?? {},
  };
}
```

- [ ] **Step 4: Add the session methods**

In `src/cdp.ts`, extend the identity import to include `parseIdentityPayload` and `serializeIdentity`, then add after `listIdentities`:

```typescript
  /** Serialize cookies and web storage for an identity into a portable document. */
  async exportIdentity(name: string): Promise<IdentityPayload> {
    const record = this.identities.get(name);
    if (!record) {
      throw new ToolError(
        "ERR_NO_IDENTITY",
        `No identity named "${name}".`,
        "Use identity_list to see available identities.",
      );
    }
    const cookies = await this.getCookies();
    const storage = await this.getStorage("both");
    return serializeIdentity(
      record.name,
      record.proxy,
      cookies,
      storage.localStorage ?? {},
      storage.sessionStorage ?? {},
    );
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async exportIdentityEnvelope(name: string): Promise<Envelope<IdentityPayload>> {
    try {
      return { success: true, data: await this.exportIdentity(name) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_IDENTITY");
    }
  }

  /**
   * Restore an exported identity. The payload is validated in full before any
   * cookie or storage write happens, so a malformed payload applies nothing.
   */
  async importIdentity(json: string, name?: string): Promise<Record<string, unknown>> {
    const payload = parseIdentityPayload(json);
    const targetName = name ?? payload.name;

    await this.clearStorage("all");

    let cookiesApplied = 0;
    for (const cookie of payload.cookies) {
      try {
        await this.setCookie(cookie);
        cookiesApplied += 1;
      } catch (_) {
        // A cookie whose domain no longer resolves is skipped rather than aborting the restore.
      }
    }

    for (const [key, value] of Object.entries(payload.localStorage)) {
      await this.setStorage("local", key, value);
    }
    for (const [key, value] of Object.entries(payload.sessionStorage)) {
      await this.setStorage("session", key, value);
    }

    const existing = this.identities.get(targetName);
    const record: IdentityRecord = existing ?? {
      name: targetName,
      browserContextId: null,
      proxy: payload.proxy,
      seed: seedFromName(targetName),
      createdAt: new Date().toISOString(),
      usable: true,
    };
    this.identities.set(targetName, record);

    this.addTimeline("browser", "identity_import", `identity import: ${targetName}`, {
      cookies: cookiesApplied,
      localStorage: Object.keys(payload.localStorage).length,
      sessionStorage: Object.keys(payload.sessionStorage).length,
    });

    return { name: targetName, cookiesApplied, localStorageApplied: Object.keys(payload.localStorage).length };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async importIdentityEnvelope(json: string, name?: string): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.importIdentity(json, name) };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_IDENTITY");
    }
  }
```

Extend the identity import line at the top of `src/cdp.ts`:

```typescript
import {
  parseIdentityPayload,
  parseProxyServer,
  probeProxy,
  serializeIdentity,
  type IdentityPayload,
  type IdentityRecord,
} from "./identity.js";
```

- [ ] **Step 5: Register the two tools**

In `src/server.ts`, add after `identity_list`:

```typescript
  server.registerTool(
    "identity_export",
    {
      title: "Export an identity",
      description:
        "Serialize an identity's cookies, localStorage and sessionStorage into one portable JSON document that identity_import can restore elsewhere.",
      inputSchema: {
        name: z.string().min(1).describe("Identity name from identity_list."),
      },
    },
    safeTool(async (args: { name: string }) => session.exportIdentity(args.name)),
  );

  server.registerTool(
    "identity_import",
    {
      title: "Import an identity",
      description:
        "Restore cookies and web storage from an exported identity payload. The payload is validated in full before anything is written, so a malformed payload applies nothing.",
      inputSchema: {
        json: z.string().min(2).describe("The JSON document produced by identity_export."),
        name: z.string().optional().describe("Override the identity name carried in the payload."),
      },
    },
    safeTool(async (args: { json: string; name?: string }) => session.importIdentity(args.json, args.name)),
  );
```

- [ ] **Step 6: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/identity.ts src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: add portable identity export and import"
```

---

### Task 9: Captcha detection and provider hook

**Files:**
- Modify: `src/cdp.ts` (add `captchaDetect`, `captchaProviderHook`)
- Modify: `src/server.ts` (register two tools)
- Test: `test/index.test.ts` (append)

**Interfaces:**
- Consumes: `classifyAnticrawl` from `src/analysis.js` (existing, already used by the `classify_anticrawl` tool); `ToolError` from Task 1.
- Produces: `CdpSession.captchaDetect()`, `CdpSession.captchaProviderHook(provider, apiKey)`. Tools `captcha_detect`, `captcha_provider_hook`.

- [ ] **Step 1: Write the failing test**

Append to `test/index.test.ts`:

```typescript
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test`
Expected: FAIL — `session.captchaProviderStatus is not a function`.

- [ ] **Step 3: Implement the session methods**

In `src/cdp.ts`, add the field next to the identity map:

```typescript
  private captchaProvider: { provider: string; apiKey: string } | null = null;
```

Add the methods after `importIdentityEnvelope`:

```typescript
  /**
   * Detect a bot challenge on the current page and report it. This reports only;
   * solving requires a provider registered through captcha_provider_hook.
   */
  async captchaDetect(): Promise<Record<string, unknown>> {
    const client = this.requireClient();
    const expression = `(() => {
      const frames = [...document.querySelectorAll("iframe")].map((frame) => ({
        src: frame.src,
        title: frame.title,
        width: frame.width,
        height: frame.height,
      }));
      const html = document.documentElement ? document.documentElement.outerHTML.slice(0, 200000) : "";
      return { url: location.href, title: document.title, html, frames };
    })()`;
    const result = await client.Runtime.evaluate({ expression, returnByValue: true });
    const value = result.result?.value ?? { url: "", title: "", html: "", frames: [] };

    const detections = classifyAnticrawl(String(value.html ?? ""));
    const captchaVendors = detections.filter((entry) => entry.type === "captcha");
    const challengeFrames = (value.frames ?? []).filter((frame: { src: string }) =>
      /challenges\.cloudflare\.com|hcaptcha\.com|google\.com\/recaptcha|geetest/i.test(frame.src ?? ""),
    );

    const present = captchaVendors.length > 0 || challengeFrames.length > 0;
    return {
      detected: present,
      vendors: captchaVendors.map((entry) => ({ vendor: entry.vendor, confidence: entry.confidence, evidence: entry.evidence })),
      frames: challengeFrames,
      solvingAvailable: this.captchaProvider !== null,
      note: "captcha_detect reports only. Solving requires captcha_provider_hook with an external provider.",
    };
  }

  /** Envelope-returning wrapper so callers that must not throw can use this directly. */
  async captchaDetectEnvelope(): Promise<Envelope<Record<string, unknown>>> {
    try {
      return { success: true, data: await this.captchaDetect() };
    } catch (error) {
      return toEnvelope(error, "ERR_NO_SESSION");
    }
  }

  /** Register an external solving endpoint. Inert until a caller supplies one. */
  captchaProviderHook(provider: string, apiKey: string): Record<string, unknown> {
    if (provider.length === 0 || apiKey.length === 0) {
      throw new ToolError(
        "ERR_CAPTCHA_PROVIDER_DISABLED",
        "Both provider and apiKey are required to register a captcha provider.",
        "Call captcha_provider_hook with the provider name and key, or rely on captcha_detect alone.",
      );
    }
    this.captchaProvider = { provider, apiKey };
    this.addTimeline("browser", "captcha_provider", `captcha provider: ${provider}`, { provider });
    return { registered: true, provider };
  }

  captchaProviderStatus(): { registered: boolean; provider?: string } {
    if (!this.captchaProvider) return { registered: false };
    return { registered: true, provider: this.captchaProvider.provider };
  }
```

Extend the `src/analysis.js` import at the top of `src/cdp.ts` to include `classifyAnticrawl` if it is not already imported. Search for `from "./analysis.js"` and add `classifyAnticrawl` to the existing named import list.

- [ ] **Step 4: Register the two tools**

In `src/server.ts`, add after `identity_import`:

```typescript
  server.registerTool(
    "captcha_detect",
    {
      title: "Detect a captcha or bot challenge",
      description:
        "Inspect the current page for Cloudflare Turnstile, hCaptcha, reCAPTCHA or GeeTest, and report the vendor, evidence and challenge frames. This reports only; it does not solve. Use the result to decide whether to rotate identity or pause for a human.",
      annotations: { readOnlyHint: true },
    },
    safeTool(async () => session.captchaDetect()),
  );

  server.registerTool(
    "captcha_provider_hook",
    {
      title: "Register an external captcha provider",
      description:
        "Register an external solving endpoint. Off by default; no solving occurs until this is called with a provider and key. captcha_detect works without it.",
      inputSchema: {
        provider: z.string().min(1).describe("Provider identifier, for example '2captcha' or 'capsolver'."),
        apiKey: z.string().min(1).describe("Provider API key."),
      },
    },
    safeTool(async (args: { provider: string; apiKey: string }) => session.captchaProviderHook(args.provider, args.apiKey)),
  );
```

- [ ] **Step 5: Add the tool contract test**

Append to `test/index.test.ts`:

```typescript
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
```

- [ ] **Step 6: Run tests and type check**

Run: `npm test && npm run check`
Expected: PASS with exactly 101 tools.

- [ ] **Step 7: Commit**

```bash
git add src/cdp.ts src/server.ts test/index.test.ts
git commit -m "feat: add captcha detection and provider hook"
```

---

### Task 10: Documentation and install repair

**Files:**
- Modify: `docs/TOOLS.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `README.md`
- Modify: `package.json` (version bump only)

**Interfaces:**
- Consumes: everything above.
- Produces: accurate docs and a working MCP registration.

- [ ] **Step 1: Update the tool count and add sections to `docs/TOOLS.md`**

Change the opening line from "exposes **88 tools**" to "exposes **101 tools**".

Append three sections after section 8:

```markdown
---

## 9. Stealth & Fingerprint Control

| Tool | Parameters | Description |
|---|---|---|
| `stealth_enable` | `profile` (`off`/`basic`/`strict`), `seed?` | Install anti-detection patches on the attached target. `basic` covers identity leaks; `strict` adds canvas, WebGL and audio noise plus `Function.prototype.toString` integrity. |
| `stealth_status` | None | Report the active profile, its patch ids, and whether a patch script is registered. |
| `stealth_probe` | `maxChars?` | Run a detection suite in the page and report, per check, what still leaks and the observed value. |

---

## 10. Semantic Tree & Pruning

| Tool | Parameters | Description |
|---|---|---|
| `semantic_view` | `interactiveOnly?`, `maxNodes?`, `maxChars?` | Compressed accessibility tree with short integer ids, replacing raw DOM dumps. |
| `interact_semantic` | `id`, `action`, `value?`, `snapshotVersion?` | Click, type, hover, focus or select by semantic id. A mismatched `snapshotVersion` is rejected rather than applied. |
| `semantic_diff` | `maxChanges?` | Re-read the tree and return only nodes added, removed or changed since the previous snapshot. |

---

## 11. Identity & Captcha

| Tool | Parameters | Description |
|---|---|---|
| `identity_create` | `name`, `proxy?`, `seed?` | Create an isolated browser context, optionally proxy-bound. The proxy is TCP-probed before the context is created. |
| `identity_use` | `name` | Activate an identity and apply its seed to the stealth layer. |
| `identity_list` | None | List identities with proxy, seed and usability. |
| `identity_export` | `name` | Serialize cookies and web storage into one portable JSON document. |
| `identity_import` | `json`, `name?` | Restore an exported identity. Validated in full before anything is written. |
| `captcha_detect` | None | Detect Turnstile, hCaptcha, reCAPTCHA or GeeTest and report the evidence. Reports only. |
| `captcha_provider_hook` | `provider`, `apiKey` | Register an external solving endpoint. Off by default. |
```

- [ ] **Step 2: Add a subsystem section to `docs/ARCHITECTURE.md`**

Append before the closing "## 3. Error Handling & Resilience" section, or directly after section 2E:

```markdown
### F. Stealth, Semantic Pruning & Identity Isolation

Three additions sit on top of the existing CDP session without changing it.

**Stealth layer.** Patch payloads are generated by pure functions in `src/stealth.ts`
and injected through `Page.addScriptToEvaluateOnNewDocument`, the same mechanism
already used for runtime hooks. All fingerprint noise is derived from a per-identity
seed, because inconsistent spoofing is itself a detection signal. `stealth_probe`
runs a detection suite in-page so patch rot is visible rather than silent.

**Semantic pruner.** `src/pruner.ts` compresses `Accessibility.getFullAXTree` output
into an integer-addressed flat tree, discarding ignored, generic and presentational
nodes. Ids are valid only for the snapshot version that produced them; navigation and
`DOM.documentUpdated` invalidate the map. A stale id is rejected with
`ERR_STALE_NODE_ID` rather than applied to a node that reuses the same
`backendDOMNodeId`.

**Identity isolation.** Each identity owns a `Target.createBrowserContext`, so proxy
binding applies to every socket the context opens, not just interceptable HTTP.
Cookies and web storage serialize into one portable document for replay elsewhere.

**Error envelope.** New tools return `{success, error_code, message, suggestion}` so
the model can correct itself on the next turn instead of the reasoning chain breaking.
The 88 pre-existing tools keep their original error shape.
```

- [ ] **Step 3: Update `README.md`**

Update any tool-count reference to 101, and add one paragraph under the feature list:

```markdown
Beyond CDP instrumentation, the server ships a stealth layer (three patch profiles
with deterministic per-identity seeds), a semantic tree pruner that replaces raw DOM
dumps with an integer-addressed accessibility view, isolated browser identities with
per-context proxy binding, and captcha detection. Captcha solving is out of scope —
`captcha_detect` reports a challenge so an agent can route around it.
```

- [ ] **Step 4: Bump the version**

In `package.json`, change `"version": "0.2.0"` to `"version": "0.3.0"`. Do not touch `dependencies`.

- [ ] **Step 5: Verify no runtime dependency was added**

Run: `git diff HEAD~9 -- package.json | grep -E '^\+' | grep -v '^+++' || true`
Expected: the only added line is the version bump.

- [ ] **Step 6: Build and repair the MCP registration**

The registered MCP path in `~/.claude.json` points at
`/home/mdong/mcp/reverse-engineering-mcp/dist/index.js`, and `/home/mdong/mcp` no
longer exists — the running MCP will fail to start on next launch.

Run:

```bash
npm run build
mkdir -p /home/mdong/mcp
cp -r /home/mdong/reverse-engineering-mcp /home/mdong/mcp/reverse-engineering-mcp
node /home/mdong/mcp/reverse-engineering-mcp/dist/index.js --help 2>&1 | head -3
```

Expected: the build succeeds, and the copied `dist/index.js` exists. The last command
may print nothing or a usage line; what matters is that it does not throw
`Cannot find module`.

If a rebuild-free layout is preferred instead, update the `args` path in
`~/.claude.json` to `/home/mdong/reverse-engineering-mcp/dist/index.js` and skip the
copy. Pick one; do not leave both paths populated.

- [ ] **Step 7: Commit**

```bash
git add docs/TOOLS.md docs/ARCHITECTURE.md README.md package.json package-lock.json docs/superpowers
git commit -m "docs: document stealth, pruner, identity and captcha surface"
```

`package-lock.json` is included deliberately: it carried stale `"version": "0.1.0"` metadata against a `0.2.0` `package.json`, and Task 10's version bump regenerates it. Tasks 1-9 must not commit it.

---

## Self-Review

**Spec coverage.**

| Spec section | Task |
|---|---|
| §5.1 Stealth layer (profiles, patches, seeding, injection, probe) | 2, 3 |
| §5.2 Semantic pruner (source, compression, ids, lifecycle, diff) | 4, 5, 6 |
| §5.3 Identity & session (isolation, portability, captcha) | 7, 8, 9 |
| §5.4 Error envelope (registry, envelope, non-throwing handlers) | 1, and every task's envelope wrapper |
| §6 Tool surface (13 tools) | 3, 5, 6, 7, 8, 9; contract test in 9 |
| §7 Data flow | 3, 5, 7 |
| §8 Error handling | 5, 6, 7, 8, 9 (one guard per code) |
| §9 Testing (unit without browser, integration separate, contract) | 1, 2, 4, 9 |
| §10 Risks (probe feedback loop, stale id, seed on identity) | 3, 6, 7 |

**Placeholder scan.** No `TBD`, no `TODO`, no "similar to Task N", no "add appropriate error handling". Every code step carries the code, every run step carries the command and the expected result, and every error code used in a handler appears in the Task 1 registry.

**Type consistency.** `StealthProfile` is defined once in `src/stealth.ts` and imported. `Envelope<T>`, `OkEnvelope<T>`, `ErrEnvelope` come only from `src/errors.ts`. `SemanticSnapshot`, `SemanticNode`, `IdentityRecord`, `IdentityPayload` are each defined in exactly one module and imported elsewhere. `captchaProviderStatus()` returns `{registered, provider?}` in both its definition (Task 9) and its test. `interactSemantic` takes `(id, action, value?, versionAtCall?)` consistently in the session method, the envelope wrapper, and the tool registration.

**Review Focus coverage.** Item 1 → Task 5 Step 3 (`ERR_AX_TREE_UNAVAILABLE` on an empty or throwing tree). Item 2 → Task 6 Step 3 (version check before `resolveNode`). Item 3 → Task 3 Step 1 (`ERR_NO_SESSION` with no tab). Item 4 → Task 7 Step 1 (proxy probe, identity not registered on failure). Item 5 → Task 8 Step 1 (`parseIdentityPayload` runs before any write).

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-05-stealth-pruner.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** — a fresh subagent implements each task and a fresh reviewer checks it before the next starts, then a whole-branch review. Most thorough; costs a fresh context per task and per review.
- **Native** — I implement every task in this session, then one fresh reviewer checks the whole branch. Cheapest and fastest; no independent review until the end.

For this plan I recommend **Subagent-driven**, because the ten tasks share a small set of interfaces (`Envelope`, `SemanticSnapshot`, `IdentityRecord`) that are defined once and consumed by later tasks, and a shipped mistake in Task 1 or Task 4 would propagate into every task after it — an independent review gate per task catches that before it compounds.

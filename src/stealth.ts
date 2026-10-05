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
  const pluginList = [
    { name: "PDF Viewer", filename: "internal-pdf-viewer" },
    { name: "Chrome PDF Viewer", filename: "internal-pdf-viewer" },
    { name: "Chromium PDF Viewer", filename: "internal-pdf-viewer" },
  ];
  const mimeList = [
    { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" },
    { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format" },
  ];
  const asArrayLike = (entries, map) =>
    entries.map((entry) => Object.assign(Object.create(null), map(entry)));
  Object.defineProperty(Navigator.prototype, "plugins", {
    get: () => asArrayLike(pluginList, (p) => ({ name: p.name, filename: p.filename, length: 1, item: () => null, namedItem: () => null })),
    configurable: true,
  });
  Object.defineProperty(Navigator.prototype, "mimeTypes", {
    get: () => asArrayLike(mimeList, (m) => ({ type: m.type, suffixes: m.suffixes, description: m.description, enabledPlugin: null, item: () => null, namedItem: () => null })),
    configurable: true,
  });
  Object.defineProperty(Navigator.prototype, "hardwareConcurrency", { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, "deviceMemory", { get: () => 8, configurable: true });
  Object.defineProperty(Navigator.prototype, "languages", { get: () => ["en-US", "en"], configurable: true });
  // language must agree with languages[0]; a mismatch is itself a detection signal.
  Object.defineProperty(Navigator.prototype, "language", { get: () => "en-US", configurable: true });
  // platform must agree with the spoofed WebGL vendor below.
  Object.defineProperty(Navigator.prototype, "platform", { get: () => "Win32", configurable: true });
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
// deterministic canvas noise, keyed on canvas dimensions so repeated reads of the
// same canvas return the same bytes (an unstable read is itself detectable)
try {
  const perturb = (canvas) => {
    try {
      const ctx = canvas.getContext && canvas.getContext("2d");
      if (!ctx || canvas.width < 1 || canvas.height < 1) return;
      const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const px = image.data;
      if (!px || px.length < 4) return;
      const cells = Math.max(1, (px.length / 4) | 0);
      const index = (((canvas.width * 31 + canvas.height * 17) % cells) | 0) * 4;
      px[index] = (px[index] + 1) & 0xff;
      ctx.putImageData(image, 0, 0);
    } catch (_) {}
  };
  const nativeGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = __markPatched(function (...args) {
    return nativeGetImageData.apply(this, args);
  });
  const nativeToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = __markPatched(function (...args) {
    perturb(this);
    return nativeToDataURL.apply(this, args);
  });
  const nativeToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = __markPatched(function (...args) {
    perturb(this);
    return nativeToBlob.apply(this, args);
  });
} catch (_) {}`,
  },
  {
    id: "webgl-vendor",
    level: "strict",
    source: `
// deterministic WebGL vendor/renderer spoof. WebGL2 is patched too: most maintained
// fingerprinting libraries prefer a WebGL2 context, so patching WebGL1 alone is bypassed.
try {
  const VENDOR = 37445;
  const RENDERER = 37446;
  const SHADING = 35724;
  const spoof = (prototype) => {
    if (!prototype || !prototype.getParameter) return;
    const nativeGetParameter = prototype.getParameter;
    prototype.getParameter = __markPatched(function (parameter) {
      if (parameter === VENDOR) return "Intel Inc.";
      if (parameter === RENDERER) return "Intel Iris OpenGL Engine";
      if (parameter === SHADING) return "WebGL GLSL ES 1.0";
      return nativeGetParameter.call(this, parameter);
    });
  };
  spoof(window.WebGLRenderingContext && WebGLRenderingContext.prototype);
  spoof(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
} catch (_) {}`,
  },
  {
    id: "audio-noise",
    level: "strict",
    source: `
// deterministic audio fingerprint noise. Both the float and byte read paths are
// patched; libraries reach for either depending on the analyser configuration.
try {
  const jitter = (array) => {
    if (!array || array.length === 0) return;
    const index = (array.length >> 1) % array.length;
    array[index] = array[index] + 1e-7;
  };
  const nativeGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
  AnalyserNode.prototype.getFloatFrequencyData = __markPatched(function (array) {
    nativeGetFloatFrequencyData.call(this, array);
    jitter(array);
  });
  const nativeGetByteFrequencyData = AnalyserNode.prototype.getByteFrequencyData;
  AnalyserNode.prototype.getByteFrequencyData = __markPatched(function (array) {
    nativeGetByteFrequencyData.call(this, array);
    if (array && array.length > 0) {
      const index = (array.length >> 1) % array.length;
      array[index] = (array[index] + 1) & 0xff;
    }
  });
} catch (_) {}`,
  },
  {
    id: "to-string-integrity",
    level: "strict",
    source: `
// patched natives must stringify as native code. Uses the shared __patched set that
// every patch above registers into, because the methods detectors stringify
// (getImageData, getParameter, getFloatFrequencyData, the navigator getters) all live
// on prototypes and are invisible to a window-globals scan.
try {
  Function.prototype.toString = __markPatched(function () {
    if (__patched.has(this)) return "function () { [native code] }";
    return __nativeToString.call(this);
  });
  Object.defineProperty(Function.prototype.toString, "toString", {
    value: () => __nativeToString.call(__nativeToString),
  });
  for (const descriptor of [Object.getOwnPropertyDescriptor(Function.prototype, "toString")]) {
    if (descriptor && descriptor.value) __markPatched(descriptor.value);
  }
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
  };
  // Every replacement a patch installs is registered here, so Function.prototype.toString
  // can report it as native. Scanning window globals is not enough: the methods that
  // fingerprinting libraries stringify live on prototypes.
  const __patched = new WeakSet();
  const __markPatched = (replacement) => {
    try { __patched.add(replacement); } catch (_) {}
    return replacement;
  };
  const __nativeToString = Function.prototype.toString;`;

  return `${preamble}\n${patches.map((patch) => patch.source).join("\n")}\n})();`;
}

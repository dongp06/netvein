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
      if (typeof candidate === "function" && !/^\\[native code\\]$/.test(nativeToString.call(candidate))) {
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

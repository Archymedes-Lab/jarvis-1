// Main-world probe, registered as a MAIN-world content script at
// document_start so it is in place before page scripts run. Never retain an
// event object or payload; only increment fixed allowlisted counters and note
// origins. A hostile page cannot ask it to perform actions, but it can forge
// or suppress these counters, so every report is untrusted evidence.
(() => {
  const listeners = Object.create(null), surfaces = Object.create(null), transports = Object.create(null);
  const listenerNames = new Set(["mousemove", "pointermove", "scroll", "input", "keydown"]);
  const egress = new Set(), scripts = new Set(), pixels = new Set();
  const inc = (map, name) => { map[name] = Math.min(10000, (map[name] || 0) + 1); };
  const originOf = (value) => {
    try { const u = new URL(value, location.href); return /^https?:$/.test(u.protocol) ? u.origin : null; }
    catch (_) { return null; }
  };
  const note = (set, value) => { const o = originOf(value); if (o && set.size < 64) set.add(o); };

  const originalAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, ...rest) {
    if (listenerNames.has(type)) inc(listeners, type);
    return originalAdd.call(this, type, ...rest);
  };

  // A fingerprinting surface counts when it is read, never because the API
  // exists: every current browser has WebGL, WebGPU, media devices and OPFS,
  // so counting presence flagged every page.
  const wrap = (proto, method, surface, when) => {
    if (!proto || typeof proto[method] !== "function") return;
    const original = proto[method];
    proto[method] = function(...args) {
      if (!when || when(args)) inc(surfaces, surface);
      return original.apply(this, args);
    };
  };
  const getter = (proto, prop, surface) => {
    const d = proto && Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.get || !d.configurable) return;
    Object.defineProperty(proto, prop, {...d, get() { inc(surfaces, surface); return d.get.call(this); }});
  };
  const proto = (name) => window[name] && window[name].prototype;
  wrap(proto("HTMLCanvasElement"), "toDataURL", "canvas");
  wrap(proto("HTMLCanvasElement"), "toBlob", "canvas");
  wrap(proto("CanvasRenderingContext2D"), "getImageData", "canvas");
  for (const name of ["WebGLRenderingContext", "WebGL2RenderingContext"]) {
    wrap(proto(name), "getExtension", "webgl", (a) => a[0] === "WEBGL_debug_renderer_info");
    wrap(proto(name), "readPixels", "webgl");
  }
  wrap(proto("GPU"), "requestAdapter", "webgpu");
  wrap(proto("MediaDevices"), "enumerateDevices", "media_devices");
  wrap(proto("StorageManager"), "getDirectory", "opfs");
  wrap(proto("FontFaceSet"), "check", "fonts");
  getter(proto("Navigator"), "hardwareConcurrency", "hardware");
  getter(proto("Navigator"), "deviceMemory", "hardware");
  // An offline audio context renders sound without playing it: the audio
  // fingerprint. A Proxy keeps subclassing and instanceof working.
  if (typeof window.OfflineAudioContext === "function") {
    window.OfflineAudioContext = new Proxy(window.OfflineAudioContext, {
      construct(target, args, newTarget) { inc(surfaces, "audio"); return Reflect.construct(target, args, newTarget); }
    });
  }

  const originalBeacon = navigator.sendBeacon && navigator.sendBeacon.bind(navigator);
  if (originalBeacon) navigator.sendBeacon = (url, ...rest) => { inc(transports, "beacon"); note(egress, url); return originalBeacon(url, ...rest); };
  const originalFetch = window.fetch;
  if (originalFetch) window.fetch = function(input, ...rest) {
    inc(transports, "fetch"); note(egress, typeof input === "string" ? input : input && input.url);
    return originalFetch.call(this, input, ...rest);
  };
  const open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) { inc(transports, "xhr"); note(egress, url); return open.call(this, method, url, ...rest); };

  // A tracking pixel is a cross-origin image of 2x2 or smaller: it carries no
  // content, only the fact that it was fetched. Scripted pixels (new Image())
  // are caught at the src setter; parser-inserted ones by a sweep at report
  // time. Each element is counted once.
  const counted = new WeakSet();
  const judge = (img) => {
    if (counted.has(img) || !img.complete || img.naturalWidth > 2 || img.naturalHeight > 2 || !img.naturalWidth) return;
    const o = originOf(img.currentSrc || img.src);
    if (!o || o === location.origin) return;
    counted.add(img); inc(transports, "pixel"); if (pixels.size < 64) pixels.add(o);
  };
  const src = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
  if (src && src.set && src.configurable) {
    Object.defineProperty(HTMLImageElement.prototype, "src", {...src, set(value) {
      originalAdd.call(this, "load", () => judge(this), {once: true});
      return src.set.call(this, value);
    }});
  }

  const sweep = () => {
    for (const img of document.images) judge(img);
    for (const s of document.scripts) if (s.src) note(scripts, s.src);
    try {
      for (const e of performance.getEntriesByType("resource")) {
        if (e.initiatorType === "script") note(scripts, e.name);
      }
    } catch (_) { /* resource timing unavailable */ }
  };
  // Third-party origins first, so the page's own origin never crowds out the
  // ones that matter when a list is cut to the report limit.
  const list = (set) => [...set].sort((a, b) => (a === location.origin) - (b === location.origin)).slice(0, 16);
  const send = () => {
    sweep();
    window.postMessage({channel: "jarvis-veil", payload: {
      top_origin: location.origin, egress_origins: list(egress), script_origins: list(scripts),
      pixel_origins: list(pixels), listeners, surfaces, transports
    }}, location.origin);
  };
  setInterval(send, 20000);
  addEventListener("pagehide", send, {once: true});
})();

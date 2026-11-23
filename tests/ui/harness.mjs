// Shared harness: evaluate a page's inline scripts with browser globals
// stubbed, then expose named functions for UI unit tests.
//
// Top-level side effects (tick/refresh/setInterval) run against stubs: fetch
// never settles, timers are dropped, and every DOM node is an absorbing
// proxy. Tests then exercise the pure view functions for real.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

function makeEl() {
  const el = { dataset: {}, style: {}, children: [],
               classList: { add() {}, remove() {}, toggle() {}, contains: () => false } };
  return new Proxy(el, {
    get(t, p) {
      if (p in t) return t[p];
      return (...args) => makeEl();
    },
    set(t, p, v) { t[p] = v; return true; },
  });
}

export function loadPage(relPath, exportNames) {
  const html = readFileSync(join(ROOT, relPath), "utf8");
  // The page's own classic scripts, in order: inline blocks (none are allowed
  // any more under the CSP, see tests/test_static_csp.py) and /static/*.js
  // files. Vendored libraries and remote scripts are not evaluated here.
  const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)].map((m) => {
    const src = /\bsrc="\/static\/([^"]+)"/.exec(m[1]);
    if (/type="module"/.test(m[1])) return "";
    if (src) return src[1].startsWith("vendor/") ? "" : readFileSync(join(ROOT, "jarvis/web/static", src[1]), "utf8");
    return /\bsrc=/.test(m[1]) ? "" : m[2];
  }).filter((s) => s.trim());
  const listeners = [];
  globalThis.__documentListeners = listeners;
  globalThis.document = {
    getElementById: () => makeEl(),
    // Recorded so tests can drive the page's delegated handlers.
    addEventListener: (type, fn) => listeners.push([type, fn]),
    createElement: () => makeEl(),
    querySelector: () => makeEl(),
    querySelectorAll: () => [],
    documentElement: makeEl(),
    body: makeEl(),
    activeElement: makeEl(),
  };
  globalThis.window = globalThis;
  // The application shell wires the router, drawer and media query at load.
  globalThis.addEventListener = () => {};
  globalThis.matchMedia = () => ({ matches: false, addEventListener: () => {} });
  globalThis.location = { hash: "", port: "8787", origin: "http://127.0.0.1:8787", href: "http://127.0.0.1:8787/" };
  globalThis.history = { pushState: () => {} };
  globalThis.scrollTo = () => {};
  globalThis.requestAnimationFrame = () => 0;
  globalThis.localStorage = { getItem: () => null, setItem: () => {} };
  globalThis.fetch = () => new Promise(() => {});
  globalThis.setInterval = () => 0;
  globalThis.clearInterval = () => {};
  globalThis.setTimeout = () => 0;
  globalThis.clearTimeout = () => {};
  const names = exportNames.join(",");
  // Indirect eval keeps "use strict" scripts scoped; re-export explicitly.
  // A leading statement keeps a page's "use strict" from scoping its top-level
  // declarations to this eval: in a browser they are globals, and tests rely on that.
  (0, eval)("void 0;\n" + scripts.join("\n;\n") + `\n;globalThis.__page = {${names}};`);
  // `html` is the page together with its own scripts, so contract checks find
  // wiring wherever it now lives; `markup` is the HTML alone.
  return { html: html + "\n" + scripts.join("\n"), markup: html, page: globalThis.__page };
}

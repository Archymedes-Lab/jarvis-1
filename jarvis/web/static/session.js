// session.js: send a browser without an API session to the pairing page.
//
// Every /api/ route except liveness needs the API token. A browser that has
// no session cookie gets HTTP 403 with an error naming the token; this file
// turns that into one navigation to /pair (which returns here afterwards).
// Loaded before each page's own script, so it covers every fetch and stream
// the page makes. Nothing here reads or stores the token: the cookie is
// HttpOnly and the browser attaches it.
"use strict";
(function () {
  const PAIR = "/pair";
  let leaving = false;

  function goPair() {
    // A framed page (the dashboard's /geo card) leaves this to its parent.
    if (leaving || window.top !== window || location.pathname === PAIR) return;
    leaving = true;
    location.assign(PAIR + "?next=" + encodeURIComponent(location.pathname));
  }

  function isApi(input) {
    const url = typeof input === "string" ? input : (input && input.url) || "";
    try { return new URL(url, location.href).pathname.startsWith("/api/"); } catch (_) { return false; }
  }

  // True when a response is the server's "no or wrong API token" refusal.
  async function tokenRefused(response) {
    if (!response || response.status !== 403) return false;
    try {
      const body = await response.clone().json();
      return /token/i.test(String((body && body.error) || ""));
    } catch (_) { return false; }
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const response = await realFetch(input, init);
    if (isApi(input) && await tokenRefused(response)) goPair();
    return response;
  };

  // An EventSource cannot see the status of a refused stream; when one closes
  // for good, ask a plain API route once and let the check above decide.
  const RealEventSource = window.EventSource;
  if (typeof RealEventSource === "function") {
    let probed = false;
    window.EventSource = function (url, options) {
      const source = new RealEventSource(url, options);
      source.addEventListener("error", () => {
        if (probed || source.readyState !== RealEventSource.CLOSED) return;
        probed = true;
        window.fetch("/api/pulse", { cache: "no-store" }).catch(() => {});
      });
      return source;
    };
    window.EventSource.prototype = RealEventSource.prototype;
    for (const k of ["CONNECTING", "OPEN", "CLOSED"]) window.EventSource[k] = RealEventSource[k];
  }

  window.argusSession = { tokenRefused, goPair };
})();

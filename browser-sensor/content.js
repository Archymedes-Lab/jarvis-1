// This runs in the isolated extension world. It only forwards a bounded summary
// emitted by probe.js (a MAIN-world content script); it never reads page text,
// form values, cookies, pointer positions, keystroke timing, resource paths,
// query strings, or request bodies.
//
// Any script on the page can post a "jarvis-veil" message, so the summary is
// page-controlled: only the known fields are passed on, and the page's origin
// is taken from this world's own location, never from the message. A page can
// forge its own counters, but not report them in another site's name.
const FIELDS = ["egress_origins", "script_origins", "pixel_origins", "listeners", "surfaces", "transports"];
let last = 0;
window.addEventListener("message", (event) => {
  if (event.source !== window || !event.data || event.data.channel !== "jarvis-veil") return;
  const data = event.data.payload;
  if (!data || typeof data !== "object") return;
  const now = Date.now();
  if (now - last < 15000) return; // coarse periodic evidence, not a session replay
  last = now;
  const payload = {top_origin: location.origin};
  for (const key of FIELDS) if (Object.prototype.hasOwnProperty.call(data, key)) payload[key] = data[key];
  chrome.runtime.sendMessage({kind: "veil-report", payload});
});

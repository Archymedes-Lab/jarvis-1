# JARVIS Veil

Status: implemented as an **opt-in, evidence-only foundation** on 2026-09-19;
opt-in blocking of session recorders and tracking pixels added on 2026-09-23.
It is not a claim of installed browser coverage, validated browser blocking, or
protection from every fingerprinting technique. Its status is deliberately
registered as partial in `jarvis/core/assurance.py`.

Veil protects against silent behavioral profiling without becoming an input
logger. The browser-side sensor observes a fixed, bounded set of counters:

- interaction listener registrations (`mousemove`, `pointermove`, `scroll`,
  `input`, `keydown`);
- high-entropy surface **reads** (canvas read-back, the WebGL debug-renderer
  extension or `readPixels`, WebGPU adapter requests, media-device
  enumeration, OPFS, font probing, hardware getters, offline audio
  rendering). Before sensor 0.2, WebGL, WebGPU, media devices and OPFS were
  counted when the API merely existed, which put every page over the
  four-surface threshold; that was a detector bug, not tracking;
- transport method counts (`fetch`, XHR, `sendBeacon`) and cross-origin
  images of 2x2 pixels or smaller (`pixel`);
- top-level, egress, script and pixel **origins only**.

It never intentionally reads or sends page text, form values, typed characters,
keystroke timings, pointer coordinates, screenshots, cookies, resource paths,
query strings, request bodies, or browser/device identifiers. Browser reports
are untrusted evidence. A script may produce misleading counters, so no report
can authorize a response; JARVIS stores a durable observation before any later
policy work.

## Detection policy

Interaction listeners cannot separate a session recorder from an ordinary
framework: React 17+ registers `mousemove`, `pointermove`, `input` and
`keydown` on the root of every React page. Listener aggregation with
cross-origin export is therefore only **low**. A **medium** "session recorder"
finding requires a named session-replay product (Hotjar, Microsoft Clarity,
FullStory, LogRocket, Mouseflow, Smartlook, Contentsquare, Yandex Webvisor and
others in `REPLAY_VENDORS`) among the page's third-party script or egress
origins, matched on domain suffix. Analytics that only *offer* replay
(PostHog, Sentry, Datadog RUM, Heap, Highlight, Amplitude) are named at low
and never blocked. Tracking pixels are low. Fingerprinting is medium only
when four distinct surfaces are read and data leaves cross-origin. These are
privacy-risk indicators, never compromise verdicts.

`clean_link()` removes common URL-decoration parameters for an integration to
use; the extension does not rewrite navigation.

## Opt-in blocking (sensor 0.2)

The options page has two switches, both off by default:

- **Block session recorders**: `rules/replay.json`, exactly the
  `REPLAY_VENDORS` domains (a test keeps them equal).
- **Block tracking pixels**: `rules/pixels.json`, known ad/analytics pixel
  endpoints and mail-open pixels.

Safety contract, enforced by `tests/test_veil_blocking.py`: no rule matches a
top-level page or a frame, so navigation and links always work and the worst
case is a missing survey widget or broken conversion tracking; a site on the
allow list gets an `allowAllRequests` rule at priority 100, above every block
rule; the toolbar badge counts blocked requests on the current tab while
blocking is on; unticking a switch or removing the extension undoes it.
Blocking works without pairing.

Blocking uses the browser's declarativeNetRequest engine. The extension sees
no request content and learns nothing from what it blocks.

## Pairing and operation

1. Run `jarvis veil pair` against the database used by the local dashboard.
2. Load `browser-sensor/` as an unpacked Chromium-compatible extension (Chrome
   111+ for main-world content scripts) and paste the printed token into its
   options page.
3. Keep the dashboard on its loopback-only default (`127.0.0.1:8787`).

The extension posts a maximum 8 KiB aggregate report to a write-only endpoint.
The endpoint requires an exact Host header plus a constant-time checked pairing
token, has no CORS grant, returns no browsing evidence, and does not queue data
when JARVIS is unavailable. Re-pair to rotate the token. The token is sensitive:
do not put it in a support bundle or screenshot.

## Explicit limitations and next safe increments

This source tree does not demonstrate that an extension is installed, that its
main-world hook cannot be bypassed, that the blocking rules are applied by a
live browser, or that a browser's native anti-fingerprinting features are
effective. The JavaScript is exercised under Node with stub browser objects,
which checks the logic, not a browser. First-party deployments defeat both
naming and blocking: a recorder or pixel served from the site's own origin,
through a CNAME-cloaked subdomain, or via server-side tagging looks like the
site itself. Webmail that proxies images (Gmail, Outlook.com) hides the
pixel's host, so mail-open rules only help in clients that fetch directly.
The extension does not inventory extension permissions, resolve CNAMEs,
inspect redirect chains, or proxy email content. HTTPS interception/MITM is
out of scope.

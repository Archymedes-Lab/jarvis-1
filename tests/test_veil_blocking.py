"""Veil browser extension: blocking safety contract and probe behaviour.

The rule files and manifest are checked statically. The JavaScript itself is
exercised under Node with stub browser objects when Node is installed; that
proves the logic, not that a real browser applies the rules.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from jarvis.collectors.host.veil.analysis import REPLAY_CAPABLE, REPLAY_VENDORS

EXT = Path(__file__).resolve().parent.parent / "browser-sensor"
NODE = shutil.which("node")


def _json(name):
    return json.loads((EXT / name).read_text(encoding="utf-8"))


def _node(script):
    out = subprocess.run([NODE, "--input-type=module", "-e", script], cwd=EXT,
                         capture_output=True, text=True, timeout=30)
    if out.returncode:
        raise AssertionError(out.stderr)
    return json.loads(out.stdout)


class BlockingContractTests(unittest.TestCase):
    def setUp(self):
        self.manifest = _json("manifest.json")
        self.rulesets = self.manifest["declarative_net_request"]["rule_resources"]

    def test_every_ruleset_ships_disabled(self):
        self.assertEqual({r["id"] for r in self.rulesets}, {"replay", "pixels"})
        for r in self.rulesets:
            self.assertIs(r["enabled"], False, r["id"])

    def test_no_rule_can_block_a_page_or_frame(self):
        for r in self.rulesets:
            for rule in _json(r["path"]):
                types = set(rule["condition"].get("resourceTypes") or [])
                self.assertTrue(types, "a rule without resourceTypes also matches pages")
                self.assertFalse(types & {"main_frame", "sub_frame"}, rule)
                self.assertEqual(rule["action"]["type"], "block")
                self.assertLess(rule["priority"], 100)

    def test_rule_ids_are_unique_within_each_ruleset(self):
        for r in self.rulesets:
            ids = [rule["id"] for rule in _json(r["path"])]
            self.assertEqual(len(ids), len(set(ids)), r["id"])

    def test_replay_blocklist_is_exactly_the_classifier_vendor_list(self):
        domains = set()
        for rule in _json("rules/replay.json"):
            domains |= set(rule["condition"]["requestDomains"])
        self.assertEqual(domains, set(REPLAY_VENDORS))
        self.assertFalse(domains & set(REPLAY_CAPABLE),
                         "replay-capable analytics must be named, never blocked")

    def test_permissions_stay_narrow(self):
        perms = set(self.manifest["permissions"])
        self.assertEqual(perms, {"storage", "declarativeNetRequest"})
        self.assertNotIn("<all_urls>", self.manifest["host_permissions"])
        self.assertTrue(all("127.0.0.1" in h or "localhost" in h
                            for h in self.manifest["host_permissions"]))

    def test_probe_runs_in_main_world_and_is_not_web_accessible(self):
        scripts = self.manifest["content_scripts"]
        probe = next(s for s in scripts if "probe.js" in s["js"])
        self.assertEqual(probe["world"], "MAIN")
        self.assertEqual(probe["run_at"], "document_start")
        # A web-accessible resource lets any page detect the extension.
        self.assertNotIn("web_accessible_resources", self.manifest)


STUB_CHROME = """
const calls = [];
let dynamic = [{id: 1000}, {id: 1001}];
const api = {declarativeNetRequest: {
  updateEnabledRulesets: async (a) => calls.push(["rulesets", a]),
  getDynamicRules: async () => dynamic,
  updateDynamicRules: async (a) => { calls.push(["dynamic", a]); dynamic = a.addRules; },
  setExtensionActionOptions: async (a) => calls.push(["badge", a]),
}, action: {setTitle: async (a) => calls.push(["title", a])}};
"""


@unittest.skipUnless(NODE, "node is not installed")
class BlockingLogicTests(unittest.TestCase):
    def test_default_state_blocks_nothing_and_clears_old_exceptions(self):
        out = _node(STUB_CHROME + """
import {applyBlocking} from "./blocking.js";
const r = await applyBlocking(api, {});
console.log(JSON.stringify({r, calls}));
""")
        self.assertEqual(out["r"]["enabled"], [])
        rulesets = out["calls"][0][1]
        self.assertEqual(rulesets["enableRulesetIds"], [])
        self.assertEqual(sorted(rulesets["disableRulesetIds"]), ["pixels", "replay"])
        dynamic = out["calls"][1][1]
        self.assertEqual(dynamic["removeRuleIds"], [1000, 1001])
        self.assertEqual(dynamic["addRules"], [])
        self.assertEqual(out["calls"][2][1], {"displayActionCountAsBadgeText": False})
        self.assertIn("not blocking", out["calls"][3][1]["title"])

    def test_toolbar_always_states_that_blocking_is_on(self):
        # The badge stays empty until a request is blocked, so the title is
        # the indicator that is always present while blocking is active.
        out = _node(STUB_CHROME + """
import {applyBlocking} from "./blocking.js";
await applyBlocking(api, {replay: true, pixels: true});
console.log(JSON.stringify(calls));
""")
        title = dict((c[0], c[1]) for c in out)["title"]["title"]
        self.assertIn("blocking session recorders and tracking pixels", title)
        self.assertIn("turn off", title)

    def test_only_an_explicit_true_enables_a_ruleset(self):
        out = _node(STUB_CHROME + """
import {applyBlocking} from "./blocking.js";
const r = await applyBlocking(api, {replay: true, pixels: "yes"});
console.log(JSON.stringify(r));
""")
        self.assertEqual(out["enabled"], ["replay"])

    def test_allowed_sites_outrank_every_block_rule(self):
        out = _node(STUB_CHROME + """
import {applyBlocking, ALLOW_PRIORITY} from "./blocking.js";
await applyBlocking(api, {replay: true, allow: ["Shop.Example", "https://bank.example/login"]});
console.log(JSON.stringify({rules: calls[1][1].addRules, p: ALLOW_PRIORITY}));
""")
        sites = [r["condition"]["requestDomains"][0] for r in out["rules"]]
        self.assertEqual(sites, ["shop.example", "bank.example"])
        for r in out["rules"]:
            self.assertEqual(r["action"]["type"], "allowAllRequests")
            self.assertEqual(r["priority"], out["p"])
            self.assertEqual(r["condition"]["resourceTypes"], ["main_frame", "sub_frame"])

    def test_site_list_drops_anything_that_is_not_a_host_name(self):
        out = _node("""
import {cleanSites} from "./blocking.js";
console.log(JSON.stringify(cleanSites("a.example\\n*.b.example  javascript:alert(1) localhost ../x c.example c.example 1.2.3.4")));
""")
        self.assertEqual(out, ["a.example", "b.example", "c.example"])


PROBE_HARNESS = r"""
import fs from "node:fs";
import vm from "node:vm";
const posted = [];
// Real image elements inherit addEventListener from EventTarget, and the
// probe calls the saved EventTarget method, so load listeners live there.
class EventTarget { addEventListener(t, f) { if (t === "load") (this.onl ||= []).push(f); } }
class HTMLImageElement extends EventTarget {
  constructor() { super(); this._src = ""; this.complete = false; this.naturalWidth = 0; this.naturalHeight = 0; this.onl = []; }
  get currentSrc() { return this._src; }
}
Object.defineProperty(HTMLImageElement.prototype, "src", {configurable: true,
  get() { return this._src; }, set(v) { this._src = v; }});
class HTMLCanvasElement { toDataURL() { return ""; } toBlob() {} getContext() { return {}; } }
class CanvasRenderingContext2D { getImageData() { return {}; } }
class WebGLRenderingContext { getExtension() { return null; } readPixels() {} }
class GPU { requestAdapter() {} }
class MediaDevices { enumerateDevices() { return []; } }
class StorageManager { getDirectory() {} }
class Navigator {}
Object.defineProperty(Navigator.prototype, "hardwareConcurrency", {configurable: true, get() { return 8; }});
class OfflineAudioContext {}
class XMLHttpRequest { open() {} }
const images = [];
const ctx = {
  EventTarget, HTMLImageElement, HTMLCanvasElement, CanvasRenderingContext2D,
  WebGLRenderingContext, GPU, MediaDevices, StorageManager, Navigator,
  OfflineAudioContext, XMLHttpRequest, URL, Proxy, Reflect, WeakSet, Set, Object, Math,
  location: {href: "https://shop.example/a", origin: "https://shop.example"},
  navigator: Object.assign(new Navigator(), {gpu: new GPU(), mediaDevices: new MediaDevices(),
                                              sendBeacon: () => true}),
  document: {images, scripts: [{src: "https://static.hotjar.com/c/hotjar.js"}]},
  performance: {getEntriesByType: () => [{initiatorType: "script", name: "https://www.clarity.ms/tag/x"}]},
  fetch: async () => ({}),
  setInterval: () => 0,
  postMessage: (m) => posted.push(m),
};
ctx.window = ctx;
ctx.addEventListener = () => {};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync("probe.js", "utf8"), ctx);
const send = () => { ctx.__send(); return posted[posted.length - 1].payload; };
"""


@unittest.skipUnless(NODE, "node is not installed")
class ProbeBehaviourTests(unittest.TestCase):
    def _run(self, body):
        # The probe's send function is private; pagehide is the only public
        # trigger, so the harness captures the listener it registers.
        script = PROBE_HARNESS.replace(
            "ctx.addEventListener = () => {};",
            "ctx.addEventListener = (t, f) => { if (t === 'pagehide') ctx.__send = f; };")
        return _node(script + body)

    def test_api_presence_is_not_counted_as_fingerprinting(self):
        out = self._run("console.log(JSON.stringify(send()));")
        self.assertEqual(out["surfaces"], {})

    def test_reading_a_surface_is_counted(self):
        out = self._run("""
const gl = new ctx.WebGLRenderingContext();
gl.getExtension("OES_texture_float");
gl.getExtension("WEBGL_debug_renderer_info");
ctx.navigator.mediaDevices.enumerateDevices();
new ctx.HTMLCanvasElement().toDataURL();
void ctx.navigator.hardwareConcurrency;
new ctx.OfflineAudioContext();
console.log(JSON.stringify(send().surfaces));
""")
        self.assertEqual(out, {"webgl": 1, "media_devices": 1, "canvas": 1,
                               "hardware": 1, "audio": 1})

    def test_cross_origin_one_pixel_image_is_reported_by_origin_only(self):
        out = self._run("""
const px = new ctx.HTMLImageElement();
px.src = "https://www.facebook.com/tr?id=123&ev=PageView";
px.complete = true; px.naturalWidth = 1; px.naturalHeight = 1;
px.onl.forEach((f) => f());
const big = new ctx.HTMLImageElement();
big.src = "https://cdn.example/hero.jpg";
big.complete = true; big.naturalWidth = 1200; big.naturalHeight = 600;
big.onl.forEach((f) => f());
const own = new ctx.HTMLImageElement();
own.src = "/spacer.gif"; own.complete = true; own.naturalWidth = 1; own.naturalHeight = 1;
own.onl.forEach((f) => f());
console.log(JSON.stringify(send()));
""")
        # None of these images is in document.images: only the src-setter
        # path (a scripted new Image()) can have found the pixel.
        self.assertEqual(out["pixel_origins"], ["https://www.facebook.com"])
        self.assertEqual(out["transports"]["pixel"], 1)
        self.assertNotIn("PageView", json.dumps(out))

    def test_parser_inserted_pixel_is_found_by_the_sweep_once(self):
        out = self._run("""
const px = new ctx.HTMLImageElement();
px._src = "https://px.ads.linkedin.com/collect?pid=1";   // parser-set: no setter call
px.complete = true; px.naturalWidth = 1; px.naturalHeight = 1;
images.push(px);
send();
console.log(JSON.stringify(send()));
""")
        self.assertEqual(out["pixel_origins"], ["https://px.ads.linkedin.com"])
        self.assertEqual(out["transports"]["pixel"], 1)

    def test_script_origins_reach_the_report(self):
        out = self._run("console.log(JSON.stringify(send().script_origins));")
        self.assertEqual(sorted(out), ["https://static.hotjar.com", "https://www.clarity.ms"])


CONTENT_HARNESS = r"""
import fs from "node:fs";
import vm from "node:vm";
const sent = [];
let onMessage = null;
const ctx = {
  location: {origin: "https://evil.example"},
  chrome: {runtime: {sendMessage: (m) => sent.push(m)}},
  Date, Object,
};
ctx.window = {addEventListener: (t, f) => { if (t === "message") onMessage = f; }};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync("content.js", "utf8"), ctx);
const post = (payload) => onMessage({source: ctx.window, data: {channel: "jarvis-veil", payload}});
"""


@unittest.skipUnless(NODE, "node is not installed")
class ContentRelayTests(unittest.TestCase):
    """Any page script can post the probe's message: the relay must not let it
    speak for another site or smuggle extra fields to the daemon."""

    def test_page_cannot_forge_the_origin_or_add_fields(self):
        out = _node(CONTENT_HARNESS + """
post({top_origin: "https://bank.example", egress_origins: ["https://x.example"],
      transports: {fetch: 1}, injected: "<img src=x onerror=alert(1)>"});
console.log(JSON.stringify(sent));
""")
        self.assertEqual(len(out), 1)
        payload = out[0]["payload"]
        self.assertEqual(payload["top_origin"], "https://evil.example")
        self.assertNotIn("injected", payload)
        self.assertEqual(payload["egress_origins"], ["https://x.example"])

    def test_non_object_payloads_are_dropped_and_reports_stay_rate_limited(self):
        out = _node(CONTENT_HARNESS + """
post("junk"); post(null);
post({transports: {fetch: 1}}); post({transports: {fetch: 2}});
console.log(JSON.stringify(sent));
""")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["payload"]["transports"], {"fetch": 1})


if __name__ == "__main__":
    unittest.main()

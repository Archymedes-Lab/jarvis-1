"""The interface says ARGUS-INSTINCT, and real object names keep their spelling.

The product was renamed ARGUS-1 on 2026-10-27 and ARGUS-INSTINCT on 2026-11-02. Daemon text still says JARVIS in
places on purpose: finding titles are part of incident identity, acknowledgements
and history. The pages, the desktop UI and the desktop shell therefore re-brand
at display time with one rule, implemented three times (web JS, TypeScript,
Rust). This keeps the copies in step, runs the real web rule, and checks the
static pages themselves. scripts/dev/ui_check.py does the same on rendered pages
in a browser against the live daemon.
"""
import html.parser
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "jarvis" / "web" / "static"
# The page scripts that carry the rule (the pages run no inline script).
BRANDED_PAGES = ("dashboard.js", "geo.js", "coverage.js")
KEEP = ["input hook", "independent health monitor", "connectivity guard", "native sensor",
        "Jarvis"]
CASES = {
    "JARVIS is up": "ARGUS-INSTINCT is up",
    "JARVIS's view of JARVIS": "ARGUS-INSTINCT's view of ARGUS-INSTINCT",
    "JARVIS input hook": "JARVIS input hook",
    "JARVIS independent health monitor stalled": "JARVIS independent health monitor stalled",
    "JARVIS connectivity guard": "JARVIS connectivity guard",
    "JARVIS native sensor": "JARVIS native sensor",
    "JARVIS JarvisSensorDefender collector": "JARVIS JarvisSensorDefender collector",
    "restart jarvis.service": "restart jarvis.service",
    "C:\\ProgramData\\Jarvis\\Broker": "C:\\ProgramData\\Jarvis\\Broker",
    "JARVIS_NET_DIR": "JARVIS_NET_DIR",
    "": "",
}


def block(path):
    text = path.read_text(encoding="utf-8")
    start, end = text.index("// brand:begin"), text.index("// brand:end")
    return text[start:end]


class VisibleText(html.parser.HTMLParser):
    """Text and labels a person sees; not scripts or styles."""

    def __init__(self):
        super().__init__()
        self.skip = 0
        self.out = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        for name, value in attrs:
            if name in ("title", "aria-label", "placeholder", "alt") and value:
                self.out.append(value)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


class BrandRuleTests(unittest.TestCase):
    def test_every_web_page_carries_the_identical_rule(self):
        blocks = {name: block(STATIC / name) for name in BRANDED_PAGES}
        self.assertEqual(len(set(blocks.values())), 1, list(blocks))

    def test_escape_helpers_brand_their_input(self):
        for name in BRANDED_PAGES:
            text = (STATIC / name).read_text(encoding="utf-8")
            esc = re.search(r"const esc = .*", text).group(0)
            self.assertIn("brand(s)", esc, name)

    def test_desktop_copies_keep_the_same_names(self):
        web = re.search(r"BRAND_KEEP = /\^ \((.*?)\)/", block(STATIC / "dashboard.js")).group(1)
        ts = (ROOT / "desktop/ui/src/lib/brand.ts").read_text(encoding="utf-8")
        rs = (ROOT / "desktop/src/brand.rs").read_text(encoding="utf-8")
        self.assertEqual(web.split("|"), KEEP)
        self.assertIn(f"BRAND_KEEP = /^ ({web})/", ts)
        rust = re.findall(r'" ([A-Za-z ]+)"', rs[rs.index("const KEEP"):rs.index("];")])
        self.assertEqual(rust, KEEP)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_the_web_rule_itself(self):
        script = block(STATIC / "dashboard.js") + (
            f"\nconst cases = {json.dumps(list(CASES))};"
            "\nprocess.stdout.write(JSON.stringify(cases.map(brand)));")
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                             timeout=30, check=True).stdout
        self.assertEqual(json.loads(out), list(CASES.values()))

    def run_rule(self, block_text, inputs):
        script = block_text + (f"\nconst cases = {json.dumps(inputs)};"
                               "\nprocess.stdout.write(JSON.stringify(cases.map(brand)));")
        out = subprocess.run(["node", "-e", script], capture_output=True, text=True,
                             timeout=30, check=True).stdout
        return json.loads(out)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_the_rule_is_idempotent(self):
        once = list(CASES.values())
        self.assertEqual(self.run_rule(block(STATIC / "dashboard.js"), once), once)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_the_argus_build_rename_never_produces_argus_1_1(self):
        # archymedes-site/scripts/argus/build.py rewrites JARVIS -> ARGUS in the
        # whole tree (rename_text). The rule then reads \bARGUS\b, which also
        # matches inside "ARGUS-1"; page text already says ARGUS-1.
        renamed = block(STATIC / "dashboard.js").replace("JARVIS", "ARGUS") \
            .replace("Jarvis", "Argus").replace("jarvis", "argus")
        got = self.run_rule(renamed, ["ARGUS-INSTINCT is waking up", "ARGUS is up",
                                      "ARGUS input hook", "ARGUS-INSTINCT's view"])
        self.assertEqual(got, ["ARGUS-INSTINCT is waking up", "ARGUS-INSTINCT is up",
                               "ARGUS input hook", "ARGUS-INSTINCT's view"])

    def test_null_never_renders_as_text(self):
        # brand() feeds esc(); a missing field must stay empty, not "null".
        self.assertIn('String(s ?? "")', block(STATIC / "dashboard.js"))


class StaticTextTests(unittest.TestCase):
    # `(?!-1)`: the Argus build renames JARVIS to ARGUS, and "ARGUS-INSTINCT" is the
    # correct product name there, not a leftover (2026-10-27 renamed suite).
    def test_no_page_shows_the_old_name(self):
        for page in sorted(STATIC.glob("*.html")):
            parser = VisibleText()
            parser.feed(page.read_text(encoding="utf-8"))
            visible = " ".join(parser.out)
            self.assertNotRegex(visible, r"\bJARVIS\b(?!-1)", page.name)
            self.assertIn("ARGUS-INSTINCT", visible, page.name)

    def test_scripts_use_the_old_name_only_in_the_rule(self):
        # Uppercase JARVIS in page code would be visible text sooner or later;
        # the only allowed copies are inside the brand rule itself.
        for page in sorted([*STATIC.glob("*.html"), *STATIC.glob("*.js")]):
            text = page.read_text(encoding="utf-8")
            if "// brand:begin" in text:
                text = text.replace(block(page), "")
            self.assertNotRegex(text, r"\bJARVIS\b(?!_|-1)", page.name)

    def test_desktop_interface_strings(self):
        ui = ROOT / "desktop" / "ui"
        for path in [ui / "index.html", *(ui / "src").rglob("*.svelte")]:
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"\bJARVIS\b(?!-1)", path.name)
        conf = json.loads((ROOT / "desktop/tauri.conf.json").read_text(encoding="utf-8"))
        self.assertEqual(conf["productName"], "ARGUS-INSTINCT")
        # The identifier names the app's data folder: renaming it would orphan
        # the settings of anyone who already ran the app.
        self.assertEqual(conf["identifier"], "local.jarvis.desktop")

    def test_preferences_survive_the_rename(self):
        # localStorage keys are not shown; renaming them would reset every
        # viewer's theme, voice and seen-alert memory.
        text = (STATIC / "dashboard.js").read_text(encoding="utf-8")
        for key in ('"jarvis.theme"', '"jarvis.seenCriticals"', '"jarvis.voice"'):
            self.assertIn(key, text)


if __name__ == "__main__":
    unittest.main()


class PythonRuleTests(unittest.TestCase):
    """jarvis/core/brand.py is the copy for text that leaves the daemon
    (email, webhook, ntfy, syslog, phone, toasts): same cases, same keep list."""

    def test_python_rule_matches_every_case(self):
        from jarvis.core.brand import brand
        for before, after in CASES.items():
            self.assertEqual(brand(before), after, before)
        self.assertEqual(brand("[JARVIS] test alert"), "[ARGUS-INSTINCT] test alert")
        self.assertEqual(brand(brand("JARVIS is up")), "ARGUS-INSTINCT is up")      # idempotent

    def test_python_keep_list_is_the_web_keep_list(self):
        from jarvis.core import brand
        for name in KEEP:
            self.assertIn(name, brand._KEEP.pattern)

    def test_outgoing_alerts_are_branded(self):
        from unittest import mock

        from jarvis.response import alert
        sent = {}
        with mock.patch.object(alert, "channels", return_value=["webhook"]):
            alert.deliver({"webhook_url": "https://x.example"}, "[JARVIS] monitor back", "JARVIS input hook ok",
                          senders={"webhook": lambda: sent.setdefault("ok", True) and ""})
        # senders closes over the arguments, so check the transform directly too
        with mock.patch.object(alert, "channels", return_value=["webhook"]), \
             mock.patch.object(alert, "send_webhook", side_effect=lambda conf, s, t, **kw: sent.update(s=s, t=t) or ""):
            alert.deliver({"webhook_url": "https://x.example"}, "[JARVIS] monitor back", "JARVIS input hook ok")
        self.assertEqual((sent["s"], sent["t"]), ("[ARGUS-INSTINCT] monitor back", "JARVIS input hook ok"))

    def test_the_windows_monitor_carries_the_same_rule(self):
        text = (ROOT / "jarvis-health-monitor.ps1").read_text(encoding="utf-8")
        self.assertIn("(?!-(?:1|INSTINCT)\\b)(?! (input hook|independent health monitor|connectivity guard|native sensor|Jarvis))", text)
        self.assertIn("-Value 'ARGUS-INSTINCT'", text)

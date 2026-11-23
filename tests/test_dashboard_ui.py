"""The dashboard's design system and its self-containment.

The page is one HTML file with its CSS compiled in (Tailwind v4 source in
jarvis/web/styles/dashboard.css, built by scripts/dev/build_ui.sh). These
checks pin what must stay true whatever the design becomes: nothing loads
from another origin, the one vendored font is the pinned file with its
licence, the content policy allows exactly that, and the markup carries no
decorative inline styles that bypass the design system."""

import hashlib
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from jarvis.web import server

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "jarvis" / "web" / "static" / "dashboard.html"
SCRIPT = ROOT / "jarvis" / "web" / "static" / "dashboard.js"
SOURCE = ROOT / "jarvis" / "web" / "styles" / "dashboard.css"
VENDOR = ROOT / "jarvis" / "web" / "static" / "vendor"


class DashboardUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = PAGE.read_text(encoding="utf-8")
        m = re.search(r'<style id="ui">(.*?)</style>', cls.html, re.S)
        cls.css = m.group(1) if m else ""

    def test_compiled_design_system_is_inlined(self):
        self.assertIn("compiled from jarvis/web/styles/dashboard.css", self.css)
        self.assertGreater(len(self.css), 20_000)
        self.assertEqual(self.html.count("<style"), 1, "one stylesheet: the compiled design system")
        for component in (".card", ".prio .big", ".alertbar", ".results", ".segmented", ".pill.critical"):
            self.assertIn(component, self.css)

    def test_source_never_scans_the_page_for_utilities(self):
        # Utilities named like existing classes (ring, static) would restyle them.
        src = SOURCE.read_text(encoding="utf-8")
        self.assertIn('@import "tailwindcss" source(none);', src)
        self.assertNotRegex(self.css, r"(?<![\w.-])\.static\{position:static")

    def test_both_themes_and_the_switch_are_defined(self):
        self.assertIn('[data-theme="light"]', self.css.replace("=light", '="light"'))
        self.assertIn("prefers-color-scheme:light", self.css.replace(": ", ":"))
        for t in ("auto", "light", "dark"):
            self.assertIn(f'data-t="{t}"', self.html)

    def test_nothing_loads_from_another_origin(self):
        external = re.findall(r'(?:src|href)\s*=\s*["\'](https?:)?//', self.html)
        self.assertEqual(external, [])
        self.assertNotRegex(self.css, r"url\(\s*['\"]?(https?:)?//")
        self.assertNotIn("@import url", self.css)

    def test_font_is_pinned_licensed_and_allowed_by_policy(self):
        route = server.COVERAGE_ASSETS["/static/vendor/InterVariable.woff2"]
        name, ctype, digest = route
        body = (VENDOR / "InterVariable.woff2").read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        self.assertEqual(ctype, "font/woff2")
        self.assertIn("SIL OPEN FONT LICENSE", (VENDOR / "InterVariable-LICENSE.txt").read_text().upper())
        self.assertIn("font-src 'self'", server.Handler.CSP_STRICT)
        self.assertNotIn("font-src *", server.Handler.CSP_STRICT)
        self.assertIn('url("/static/vendor/InterVariable.woff2")', self.css.replace("url(/", 'url("/').replace('.woff2)', '.woff2")'))

    def test_markup_has_no_decorative_inline_styles(self):
        body = self.html[self.html.index("</style>"):] + SCRIPT.read_text(encoding="utf-8")
        data_driven = r'(?!width:|--sevc|flex:\$|height:\$|background:var\(--(?:crit|high|med|low)\)|color:\$\{scoreColor)'
        self.assertEqual(re.findall(r'style="' + data_driven + r'[^"]*"', body), [])

    @unittest.skipUnless(shutil.which("node"), "node is not installed")
    def test_page_scripts_parse(self):
        # No inline script remains (tests/test_static_csp.py); the page's code
        # lives in dashboard.js and session.js.
        self.assertEqual(re.findall(r"<script>(.*?)</script>", self.html, re.S), [])
        for script in (SCRIPT, PAGE.parent / "session.js"):
            r = subprocess.run(["node", "--check", str(script)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{script.name}: {r.stderr[:400]}")


if __name__ == "__main__":
    unittest.main()

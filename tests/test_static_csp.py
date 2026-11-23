"""The pages run under a script policy with no 'unsafe-inline': hold them to it.

Every HTML page in jarvis/web/static and every page script is scanned for the
things that policy would block or that would reopen injected-script execution:
inline event-handler attributes (also inside HTML built by script), inline
<script> code and javascript: URLs. Every local script, stylesheet and module
import a page uses must be in the server's asset table (vendored third-party
files with a matching sha256 pin), and every remote one must name an exact
version and carry an SRI hash.
"""

import base64
import hashlib
import re
import unittest
from pathlib import Path

from jarvis.web import server

STATIC = Path(server.STATIC_DIR)
PAGES = sorted(STATIC.glob("*.html"))
SCRIPTS = sorted(STATIC.glob("*.js"))

HANDLER_ATTR = re.compile(r"""\son[a-z]+\s*=\s*["'`$\\{]""", re.I)
JS_URL = re.compile(r"javascript\s*:", re.I)
SCRIPT_TAG = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
LINK_TAG = re.compile(r"<link\b([^>]*)>", re.I)
ATTR = re.compile(r"""([a-z-]+)\s*=\s*"([^"]*)\"""", re.I)
IMPORT = re.compile(r"""^\s*import\b[^'"]*['"]([^'"]+)['"]""", re.M)
EXACT_VERSION = re.compile(r"@\d+\.\d+\.\d+/")


def attrs(text):
    return {k.lower(): v for k, v in ATTR.findall(text)}


def page_refs(text):
    """(kind, url, attributes) for every script and stylesheet a page names."""
    for m in SCRIPT_TAG.finditer(text):
        a = attrs(m.group(1))
        if "src" in a:
            yield "script", a["src"], a
    for m in LINK_TAG.finditer(text):
        a = attrs(m.group(1))
        if a.get("rel", "").lower() == "stylesheet":
            yield "style", a.get("href", ""), a


class NoInlineCodeTests(unittest.TestCase):
    def test_the_pages_exist(self):
        names = {p.name for p in PAGES}
        for name in ("dashboard.html", "coverage.html", "procs.html", "world.html", "geo.html"):
            self.assertIn(name, names)

    def test_no_inline_event_handler_attribute(self):
        for path in PAGES + SCRIPTS:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(HANDLER_ATTR.findall(text), [])

    def test_no_inline_script_code(self):
        for path in PAGES:
            with self.subTest(path=path.name):
                for m in SCRIPT_TAG.finditer(path.read_text(encoding="utf-8")):
                    self.assertIn("src", attrs(m.group(1)), m.group(0)[:80])
                    self.assertEqual(m.group(2).strip(), "", m.group(0)[:80])

    def test_no_javascript_urls(self):
        for path in PAGES + SCRIPTS:
            with self.subTest(path=path.name):
                self.assertIsNone(JS_URL.search(path.read_text(encoding="utf-8")))

    def test_the_detectors_detect(self):
        # The scans above must catch what they are for.
        self.assertTrue(HANDLER_ATTR.search('<button onclick="x()">'))
        self.assertTrue(HANDLER_ATTR.search("`<li onclick=\"${act}\">`"))
        self.assertTrue(HANDLER_ATTR.search("<img src=x onerror='a'>"))
        self.assertFalse(HANDLER_ATTR.search("n.onclick = () => go();"))
        self.assertFalse(HANDLER_ATTR.search('<button data-click="x">'))
        self.assertTrue(JS_URL.search('<a href="JavaScript:alert(1)">'))
        inline = list(SCRIPT_TAG.finditer("<script>\nx()\n</script>"))
        self.assertEqual(inline[0].group(2).strip(), "x()")


class PolicyTests(unittest.TestCase):
    POLICIES = ("CSP_STRICT", "CSP_GEO", "CSP_COVERAGE")

    def directive(self, policy, name):
        for part in policy.split(";"):
            words = part.split()
            if words and words[0] == name:
                return words[1:]
        return None

    def test_no_policy_allows_inline_or_eval_script(self):
        for name in self.POLICIES:
            policy = getattr(server.Handler, name)
            with self.subTest(policy=name):
                script = self.directive(policy, "script-src")
                self.assertIsNotNone(script)
                self.assertIn("'self'", script)
                for bad in ("'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*",
                            "https:", "data:", "blob:"):
                    self.assertNotIn(bad, script)
                self.assertEqual(self.directive(policy, "object-src"), ["'none'"])
                self.assertEqual(self.directive(policy, "base-uri"), ["'none'"])
                self.assertEqual(self.directive(policy, "frame-ancestors"), ["'self'"])

    def test_remote_sources_on_geo_are_exact_versioned_prefixes(self):
        policy = server.Handler.CSP_GEO
        for name in ("script-src", "style-src", "worker-src"):
            for src in self.directive(policy, name) or []:
                if src.startswith("https://"):
                    with self.subTest(directive=name, src=src):
                        self.assertRegex(src, EXACT_VERSION)
                        self.assertTrue(src.endswith("/"))
        for name in ("img-src", "connect-src"):
            for src in self.directive(policy, name) or []:
                if "cdn.jsdelivr.net" in src:
                    self.assertRegex(src, EXACT_VERSION)


class AssetTests(unittest.TestCase):
    def test_every_local_script_stylesheet_and_import_is_served(self):
        for path in PAGES:
            text = path.read_text(encoding="utf-8")
            for kind, url, _ in page_refs(text):
                if url.startswith("/"):
                    with self.subTest(page=path.name, url=url):
                        self.assertIn(url, server.COVERAGE_ASSETS)
        for path in SCRIPTS:
            for url in IMPORT.findall(path.read_text(encoding="utf-8")):
                if url.startswith("/"):
                    with self.subTest(script=path.name, url=url):
                        self.assertIn(url, server.COVERAGE_ASSETS)

    def test_vendored_files_are_pinned_and_match(self):
        for url, (name, _ctype, digest) in server.COVERAGE_ASSETS.items():
            if not name.startswith("vendor/"):
                continue
            with self.subTest(url=url):
                self.assertIsNotNone(digest, "a vendored file must be hash-pinned")
                data = (STATIC / name).read_bytes()
                allowed = (digest,) if isinstance(digest, str) else tuple(digest)
                self.assertIn(hashlib.sha256(data).hexdigest(), allowed)

    def test_every_remote_script_and_stylesheet_is_versioned_and_integrity_pinned(self):
        for path in PAGES:
            for kind, url, a in page_refs(path.read_text(encoding="utf-8")):
                if not url.startswith(("http://", "https://", "//")):
                    continue
                with self.subTest(page=path.name, url=url):
                    self.assertTrue(url.startswith("https://"))
                    self.assertRegex(url, EXACT_VERSION)
                    self.assertRegex(a.get("integrity", ""), r"^sha(256|384|512)-[A-Za-z0-9+/=]+$")
                    self.assertEqual(a.get("crossorigin"), "anonymous")
                    prefix = next((s for s in server.Handler.CSP_GEO.split()
                                   if s.startswith("https://") and url.startswith(s)), None)
                    self.assertIsNotNone(prefix, "the page CSP must name this exact prefix")

    def test_leaflet_is_vendored_with_its_license_and_published_sri(self):
        # The leaflet.js/.css SRI values the Leaflet project publishes for 1.9.4.
        published = {
            "vendor/leaflet/leaflet.js": "20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=",
            "vendor/leaflet/leaflet.css": "p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=",
        }
        for name, sri in published.items():
            data = (STATIC / name).read_bytes()
            self.assertEqual(base64.b64encode(hashlib.sha256(data).digest()).decode(), sri)
        self.assertIn("BSD 2-Clause", (STATIC / "vendor/leaflet/LICENSE.txt").read_text())
        geo = (STATIC / "geo.html").read_text(encoding="utf-8")
        self.assertNotIn("leaflet@", geo)


if __name__ == "__main__":
    unittest.main()

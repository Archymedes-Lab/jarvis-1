"""No customer install ever needs, reads or accepts the seller's payment (Stripe) secret.

Argus is sold through the hosted Archymedes licence service (hosted/licence-cloudflare, at
pay.archymedes.xyz): the computer opens a claim, the browser pays there, and the daemon activates
from a signed lease. The Stripe secret lives only in that Worker's secrets. An older local path
(jarvis/web/billing.py, removed 2026-11-08) read STRIPE_SECRET_KEY from ~/.jarvis/billing.env on the
customer's machine and called api.stripe.com itself; these tests fail if anything like it returns
to the shipped package, the desktop shell, or the web interfaces, and check that the web dashboard
buys through the same claim flow and at the same prices as the desktop app.
"""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.store import Store
from jarvis.licensing import licence
from jarvis.web import token as api_token
from tests.test_api_clients import served_routes
from tests.test_api_hardening import _Server

ROOT = Path(__file__).resolve().parent.parent

# What a seller-key payment path looks like from the customer's side. Each is a sign that the
# daemon or the interface talks to Stripe's API with a key of its own, reads a Stripe secret from
# configuration, or serves a local checkout / webhook route.
SELLER_PATH = {
    "Stripe API host": re.compile(r"api\.stripe\.com"),
    "Stripe secret config key": re.compile(r"STRIPE_(?:SECRET|API|RESTRICTED|WEBHOOK|PRICE)\w*"),
    "Stripe key literal": re.compile(r"\b(?:sk|rk)_(?:live|test)_"),
    "webhook secret literal": re.compile(r"\bwhsec_"),
    "Stripe webhook signature header": re.compile(r"Stripe-Signature", re.I),
    "Stripe SDK": re.compile(r"^\s*(?:import\s+stripe|from\s+stripe\s+import)\b|require\(['\"]stripe['\"]\)", re.M),
    "local billing config": re.compile(r"billing\.env"),
    "local billing route": re.compile(r"/api/billing\b"),
    "Stripe-hosted checkout opened locally": re.compile(r"checkout\.stripe\.com"),
}
TEXT = {".py", ".js", ".mjs", ".ts", ".html", ".json", ".css", ".rs", ".ps1", ".sh", ".toml", ".txt", ".md", ".svelte"}
# The places a customer install is built from. hosted/ is the seller's own service and is not here.
SHIPPED = ("jarvis", "desktop/src", "desktop/ui/src", "desktop/ui/index.html")


def shipped_files():
    for rel in SHIPPED:
        base = ROOT / rel
        if base.is_file():
            yield base
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix in TEXT and "node_modules" not in path.parts \
                    and "__pycache__" not in path.parts and not path.name.endswith(".test.ts"):
                yield path


def seller_path_hits(text):
    return [name for name, rx in SELLER_PATH.items() if rx.search(text)]


class ScanTests(unittest.TestCase):
    def test_the_scan_recognises_a_seller_key_path(self):
        # The detector itself, on the shape of the removed module (so a weakened pattern fails here).
        removed = ('API = "https://api.stripe.com/v1"\nENV_PATH = "~/.jarvis/billing.env"\n'
                   'key = setting("STRIPE_SECRET_KEY")\nif url.path == "/api/billing/checkout":\n')
        self.assertEqual(set(seller_path_hits(removed)), {
            "Stripe API host", "Stripe secret config key", "local billing config", "local billing route"})
        self.assertIn("Stripe key literal", seller_path_hits("default = 'sk_live_" + "x" * 24 + "'"))
        self.assertIn("Stripe SDK", seller_path_hits("import stripe\n"))
        # Ordinary words are not a payment path: the credential scanner's own pattern and prose.
        self.assertEqual(seller_path_hits(r're.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b")'), [])
        self.assertEqual(seller_path_hits("Payment by Stripe. Card details never reach ARGUS-INSTINCT."), [])

    def test_no_shipped_file_has_a_seller_key_payment_path(self):
        files = list(shipped_files())
        self.assertGreater(len(files), 200)          # the scan really covers the package
        self.assertTrue(any(f.parent.name == "assets" and f.suffix == ".js" for f in files),
                        "the built web interface (jarvis/web/ui/assets) must be scanned")
        found = {}
        for path in files:
            hits = seller_path_hits(path.read_text(encoding="utf-8", errors="replace"))
            if hits:
                found[str(path.relative_to(ROOT))] = hits
        self.assertEqual(found, {}, "a seller payment key path is back in the shipped package")

    def test_the_removed_module_and_routes_are_gone(self):
        self.assertFalse((ROOT / "jarvis" / "web" / "billing.py").exists())
        self.assertEqual(sorted(r for r in served_routes() if "billing" in r), [])

    def test_no_doc_tells_anyone_to_put_a_stripe_secret_on_a_customer_machine(self):
        bad = []
        for doc in [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]:
            text = doc.read_text(encoding="utf-8", errors="replace")
            if re.search(r"billing\.env|/api/billing\b|STRIPE_SECRET_KEY=", text):
                bad.append(str(doc.relative_to(ROOT)))
        self.assertEqual(bad, [])


class RouteTests(unittest.TestCase):
    """The real HTTP handler, with a seller key planted in the environment and in the old file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "state.db")
        Store(self.db).close()
        old = api_token._TOKEN
        self.addCleanup(setattr, api_token, "_TOKEN", old)
        self.token = api_token.issue(os.path.join(self.tmp.name, "api.token"))
        home = Path(self.tmp.name) / "home"
        (home / ".jarvis").mkdir(parents=True)
        (home / ".jarvis" / "billing.env").write_text("STRIPE_SECRET_KEY=sk_test_" + "p" * 24 + "\n")
        env = mock.patch.dict(os.environ, {"HOME": str(home), "STRIPE_SECRET_KEY": "sk_test_" + "q" * 24,
                                           "STRIPE_WEBHOOK_SECRET": "whsec_" + "r" * 24})
        env.start()
        self.addCleanup(env.stop)
        self.srv = _Server(self.db)
        self.addCleanup(self.srv.close)
        self.auth = {api_token.HEADER: self.token}

    def test_old_billing_routes_answer_not_found_even_with_a_key_present(self):
        for method, path in (("GET", "/api/billing/status"), ("POST", "/api/billing/checkout"),
                             ("POST", "/api/billing/confirm"), ("POST", "/api/billing/webhook")):
            with self.subTest(path=path):
                status, _, body = self.srv.request(method, path, {"plan": "year", "session_id": "cs_test_" + "a" * 20},
                                                   {**self.auth, "Stripe-Signature": "t=1,v1=00"})
                self.assertEqual(status, 404, body)
                self.assertNotIn(b"stripe.com", body.lower())

    def test_web_purchase_opens_the_hosted_claim_checkout(self):
        claim = "clm_" + "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        with mock.patch.object(licence, "claim_start", return_value={"claim_id": claim, "interval": 5}) as start, \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("no network in this test")):
            for plan, offer in (("desktop", "argus-desktop"), ("desktop-monthly", "argus-desktop-monthly"),
                                ("anything", "argus-desktop")):
                status, _, body = self.srv.request("POST", "/api/licence/upgrade", {"plan": plan}, self.auth)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["open"], f"{licence.PAY_ORIGIN}/buy/{offer}?claim={claim}")
        self.assertEqual(start.call_count, 3)
        self.assertEqual(licence.PAY_ORIGIN, "https://pay.archymedes.xyz")

    def test_a_promo_code_rides_on_the_hosted_checkout_link_and_a_bad_one_opens_no_claim(self):
        claim = "clm_" + "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        with mock.patch.object(licence, "claim_start", return_value={"claim_id": claim, "interval": 5}) as start, \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("no network in this test")):
            status, _, body = self.srv.request("POST", "/api/licence/upgrade",
                                               {"plan": "desktop-monthly", "promo": "SPRING-26"}, self.auth)
            reply = json.loads(body)
            self.assertEqual((status, reply["ok"]), (200, True))
            self.assertEqual(reply["open"], f"{licence.PAY_ORIGIN}/buy/argus-desktop-monthly?claim={claim}&promo=SPRING-26")
            status, _, body = self.srv.request("POST", "/api/licence/upgrade",
                                               {"plan": "desktop", "promo": "x&allow_promotion_codes=false"}, self.auth)
            reply = json.loads(body)
            self.assertEqual((status, reply["ok"], reply["code"]), (200, False, "bad_promo"))
            self.assertNotIn("open", reply)
        self.assertEqual(start.call_count, 1)

    def test_a_failed_claim_is_an_ordinary_answer_not_a_local_fallback(self):
        with mock.patch.object(licence, "claim_start", side_effect=licence.LicenceError("service unreachable", "network")):
            status, _, body = self.srv.request("POST", "/api/licence/upgrade", {"plan": "desktop"}, self.auth)
        reply = json.loads(body)
        self.assertEqual((status, reply["ok"], reply["code"]), (200, False, "network"))
        self.assertNotIn("open", reply)

    def test_licence_routes_still_need_the_token(self):
        status, _, _ = self.srv.request("POST", "/api/licence/upgrade", {"plan": "desktop"})
        self.assertEqual(status, 403)


class WebPricingTests(unittest.TestCase):
    """The classic dashboard (/classic) buys like the app: claim flow, prices from prices.ts."""

    def setUp(self):
        static = ROOT / "jarvis" / "web" / "static"
        self.html = (static / "dashboard.html").read_text(encoding="utf-8")
        self.js = (static / "dashboard.js").read_text(encoding="utf-8")
        prices = (ROOT / "desktop" / "ui" / "src" / "lib" / "prices.ts").read_text(encoding="utf-8")
        m = re.search(r"DESKTOP = \{ yearCents: (\d+), monthCents: (\d+)", prices)
        self.year, self.month = int(m.group(1)) // 100, int(m.group(2)) // 100

    def test_the_classic_dashboard_buys_through_the_hosted_claim_flow(self):
        self.assertIn('postJSON("/api/licence/upgrade"', self.js)
        self.assertIn('"/api/licence/poll"', self.js)
        self.assertIn('fetch("/api/licence"', self.js)
        self.assertIn('const PAY_ORIGIN = "https://pay.archymedes.xyz";', self.js)
        self.assertIn("if (!licencePageOk(link))", self.js)       # validated before it is opened
        self.assertNotRegex(self.js, r"location\.href\s*=\s*r\.data")

    def test_the_classic_dashboard_shows_the_price_book_amounts(self):
        allowed = {self.year, self.month, self.month * 12 - self.year}
        shown = {int(a) for a in re.findall(r"\$(\d+)(?![\d\[])", self.html + self.js)}
        self.assertEqual(shown - allowed, set(), "an amount on the classic Pricing page is not in prices.ts")
        self.assertIn(f"${self.month} <small>per month", self.html)
        self.assertIn(f"${self.year} <small>per year", self.html)

    def test_the_classic_dashboard_offers_an_optional_promo_code_at_list_prices(self):
        self.assertIn('id="lic-promo"', self.html)
        self.assertIn("Promo code (optional)", self.html)
        self.assertIn("Prices shown are before any promo code.", self.html)
        self.assertIn('const PROMO = /^[A-Za-z0-9_-]{1,40}$/;', self.js)
        self.assertIn('...(promo ? { promo } : {})', self.js)
        # a malformed code stops before the daemon is asked
        sub = self.js[self.js.index("async function subscribe(plan)"):]
        self.assertLess(sub.index("if (promo === null)"), sub.index('postJSON("/api/licence/upgrade"'))
        self.assertNotRegex(self.html + self.js, r"(?i)percent_off|amount_off")

    def test_the_classic_dashboard_allow_list_accepts_a_promo_and_nothing_more(self):
        fn = self.js[self.js.index("function licencePageOk(url)"):]
        fn = fn[:fn.index("\n}\n")]
        patterns = [re.compile(p.replace("\\/", "/")) for p in re.findall(r"/(\^buy.*?\$)/\.test", fn)]
        self.assertEqual(len(patterns), 2)
        ok = lambda rest: any(p.search(rest) for p in patterns)  # noqa: E731
        claim = "clm_" + "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        for good in (f"buy/argus-desktop?claim={claim}", f"buy/argus-desktop?claim={claim}&promo=LAUNCH_20-x",
                     "buy/argus-server?promo=FLEET10", f"buy/argus-desktop-monthly?claim={claim}&promo={'A' * 40}"):
            self.assertTrue(ok(good), good)
        for bad in (f"buy/argus-desktop?claim={claim}&promo=", f"buy/argus-desktop?claim={claim}&promo={'A' * 41}",
                    f"buy/argus-desktop?claim={claim}&promo=A&x=1", "buy/argus-desktop?promo=A&claim=x",
                    "buy/argus-watch?promo=A", "buy/argus-desktop?promo=a b", f"buy/argus-desktop?promo=A&claim={claim}"):
            self.assertFalse(ok(bad), bad)
        # What the daemon actually hands the page passes the page's own allow-list (else the purchase stalls).
        from jarvis.web import licenceapi
        with mock.patch.object(licence, "claim_start", return_value={"claim_id": claim, "interval": 5}), \
                mock.patch.object(licenceapi, "_maybe_renew_in_background", lambda path: None), \
                tempfile.TemporaryDirectory() as tmp:
            for plan in ("desktop", "desktop-monthly"):
                for promo in ("", " A ", "x" * 40, "Launch_20-x"):
                    _code, reply = licenceapi.action(os.path.join(tmp, "s.db"), "upgrade", {"plan": plan, "promo": promo})
                    link = reply["open"]
                    self.assertTrue(link.startswith("https://pay.archymedes.xyz/"), link)
                    self.assertTrue(ok(link[len("https://pay.archymedes.xyz/"):]), link)

    def test_the_built_web_interface_carries_the_claim_flow(self):
        # The committed bundle (scripts/dev/build_web_ui.py) is what the daemon serves; a stale build
        # would bring back whatever the source had when it was built.
        bundle = "".join(p.read_text(encoding="utf-8", errors="replace")
                         for p in (ROOT / "jarvis" / "web" / "ui" / "assets").glob("*.js"))
        self.assertIn("/api/licence", bundle)
        self.assertIn("pay.archymedes.xyz", bundle)
        self.assertNotIn("/api/billing", bundle)

    def test_the_allow_list_is_the_same_in_every_interface(self):
        offers = ("buy/argus-server", "buy/argus-desktop", "buy/argus-desktop-monthly")
        rust = (ROOT / "desktop" / "src" / "api.rs").read_text(encoding="utf-8")
        ts = (ROOT / "desktop" / "ui" / "src" / "lib" / "licence.ts").read_text(encoding="utf-8")
        for text in (rust, ts, self.js):
            for offer in offers:
                self.assertIn(f'"{offer}"', text)
            self.assertIn("pay.archymedes.xyz", text)


if __name__ == "__main__":
    unittest.main()

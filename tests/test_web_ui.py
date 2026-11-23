import http.client
import os
import pathlib
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from jarvis.web import server


class UiServingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(cls.tmp.name)
        cls.ui = root / "ui"
        (cls.ui / "assets").mkdir(parents=True)
        (cls.ui / "index.html").write_text("<!doctype html><title>x</title>", encoding="utf-8")
        (cls.ui / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
        (cls.ui / "assets" / "tool.exe").write_bytes(b"MZ")
        (root / "secret.txt").write_text("secret", encoding="utf-8")
        cls.patches = [mock.patch.object(server, "UI_DIR", cls.ui),
                       mock.patch.object(server.api_token, "cookie_header", lambda: "argus_token=" + "ab" * 32 + "; Path=/")]
        for p in cls.patches:
            p.start()
        server.Handler.db_path = os.path.join(cls.tmp.name, "t.db")
        server.Handler.scheduler = None
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        for p in cls.patches:
            p.stop()
        cls.tmp.cleanup()

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}", "Sec-Fetch-Mode": "navigate",
                                           "Sec-Fetch-Site": "none"})
        r = conn.getresponse()
        body = r.read()
        headers = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, headers, body

    def test_root_redirects_to_the_interface_keeps_the_query_and_sets_the_token(self):
        status, h, _ = self.get("/")
        self.assertEqual((status, h["location"]), (302, "/ui/"))
        self.assertIn("argus_token=", h["set-cookie"])
        status, h, _ = self.get("/?session_id=cs_test_abc123")
        self.assertEqual(h["location"], "/ui/?session_id=cs_test_abc123")

    def test_the_interface_and_its_assets_are_served_with_a_strict_policy(self):
        status, h, body = self.get("/ui/")
        self.assertEqual(status, 200)
        self.assertTrue(h["content-type"].startswith("text/html"))
        self.assertIn("script-src 'self'", h["content-security-policy"])
        self.assertNotIn("unsafe-inline'; connect", h["content-security-policy"].split("script-src")[1][:20])
        self.assertIn("argus_token=", h["set-cookie"])
        status, h, _ = self.get("/ui/assets/app.js")
        self.assertEqual((status, h["content-type"].split(";")[0]), (200, "text/javascript"))
        self.assertNotIn("set-cookie", h)

    def test_nothing_outside_the_folder_and_no_unknown_types_are_served(self):
        for path in ("/ui/../secret.txt", "/ui/..%2fsecret.txt", "/ui/%2e%2e/secret.txt", "/ui/assets/..\\..\\secret.txt",
                     "/ui/assets/tool.exe", "/ui/assets/", "/ui/nope.js"):
            status, _, body = self.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn(b"secret", body)

    def test_the_classic_dashboard_is_still_there(self):
        status, h, body = self.get("/classic")
        self.assertEqual(status, 200)
        self.assertIn(b"<html", body.lower())

    def test_without_a_built_interface_root_is_the_classic_dashboard(self):
        with mock.patch.object(server, "UI_DIR", self.ui / "missing"):
            status, h, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<html", body.lower())


if __name__ == "__main__":
    unittest.main()


class HealthSizeTests(unittest.TestCase):
    """A Windows supervisor cannot read more than 64 KiB of a 503 body and calls a
    truncated one "silent" (found 2026-11-02: the daemon was restarted in a loop)."""

    def state(self):
        from jarvis.core.assurance import report
        return {"assurance": report({}), "service": "ARGUS", "live": True, "healthy": False,
                "ready": False, "sources": {"scan": {"state": "stale"}}}

    def test_the_unhealthy_answer_fits_what_the_supervisor_can_read(self):
        import json
        full = len(json.dumps(self.state()))
        slim = len(json.dumps(server.compact_health(self.state())))
        self.assertGreater(full, 64 * 1024, "the fixture should be the case that broke: re-check the limit if this fails")
        self.assertLess(slim, server.HEALTH_BODY_LIMIT)

    def test_the_fields_a_supervisor_and_a_reader_need_survive(self):
        slim = server.compact_health(self.state())
        self.assertEqual((slim["service"], slim["live"], slim["healthy"]), ("ARGUS", True, False))
        self.assertEqual(set(slim["assurance"]["capabilities"]), set(self.state()["assurance"]["capabilities"]))
        one = next(iter(slim["assurance"]["capabilities"].values()))
        self.assertIn("implementation", one)
        self.assertNotIn("blind_spot", one)

    def test_other_shapes_pass_through_untouched(self):
        self.assertEqual(server.compact_health({"live": True}), {"live": True})
        self.assertEqual(server.compact_health({"assurance": "x"}), {"assurance": "x"})

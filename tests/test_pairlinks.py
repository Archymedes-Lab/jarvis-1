"""One-time browser pairing links (jarvis/web/clients.py issue_link, /api/session/link,
/api/session with a code, static/pair.js).

Invariants: a link is minted only for a program presenting a paired token in a
header; a code works once, for LINK_TTL_S on the monotonic clock, and never after a restart; the browser
that redeems it becomes its own revocable client; a bad, reused, expired or
cross-site code sets no cookie; pending codes are bounded; the page strips the
code from the address bar and only follows a same-origin `next`.

Server checks use the real loopback server from test_api_clients; nothing
touches the running daemon.
"""

import json
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.store import Store
from jarvis.web import clients
from jarvis.web import token as api_token
from tests.test_api_clients import _ServerBase

ROOT = Path(__file__).resolve().parent.parent
SAME = {"Sec-Fetch-Site": "same-origin"}


class PairLinkUnitTests(unittest.TestCase):
    """clients.issue_link / redeem_link on a scratch store. `mono` is the
    monotonic clock the code's lifetime runs on."""

    def setUp(self):
        import tempfile
        clients._reset_links()
        self.addCleanup(clients._reset_links)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = str(Path(tmp.name) / "state.db")
        self.store = Store(self.db)
        self.addCleanup(self.store.close)

    def redeem(self, code, mono=None):
        return clients.redeem_link(self.store, code, mono=mono)

    def test_a_code_works_exactly_once(self):
        code = clients.issue_link(now=100.0)
        self.assertTrue(clients._LINK_RE.match(code))
        cid, token = self.redeem(code, mono=101.0)
        self.assertEqual(clients.verify(self.store, token), cid)
        self.assertIsNone(self.redeem(code, mono=101.0))

    def test_a_code_expires_on_the_monotonic_clock(self):
        code = clients.issue_link(now=100.0)
        self.assertIsNone(self.redeem(code, mono=100.0 + clients.LINK_TTL_S))
        self.assertEqual(clients.pending_links(mono=100.0 + clients.LINK_TTL_S), 0)

    def test_a_wall_clock_step_does_not_change_a_codes_lifetime(self):
        code = clients.issue_link()
        with mock.patch.object(clients.time, "time", return_value=0):       # the wall clock jumps back decades
            self.assertIsNotNone(self.redeem(code))

    def test_pending_codes_are_bounded_and_the_oldest_goes_first(self):
        codes = [clients.issue_link(now=100.0 + i) for i in range(clients.LINK_MAX + 3)]
        self.assertEqual(clients.pending_links(mono=120.0), clients.LINK_MAX)
        for old in codes[:3]:
            self.assertIsNone(self.redeem(old, mono=120.0))
        self.assertIsNotNone(self.redeem(codes[-1], mono=120.0))

    def test_malformed_and_unknown_codes_are_refused(self):
        clients.issue_link(now=100.0)
        for bad in ("", None, 7, "x" * 43, "a" * 31, "a" * 65, "é" * 43, "a" * 42 + "+"):
            self.assertIsNone(self.redeem(bad, mono=100.0), repr(bad))

    def test_codes_are_never_kept_in_clear(self):
        code = clients.issue_link(now=100.0)
        self.assertNotIn(code, repr(clients._links))

    def test_concurrent_redeems_succeed_once(self):
        import threading
        code = clients.issue_link()
        wins, start = [], threading.Barrier(16)

        def go():
            start.wait()
            store = Store(self.db)            # one connection per thread, as each request has
            try:
                wins.append(clients.redeem_link(store, code) is not None)
            finally:
                store.close()
        threads = [threading.Thread(target=go) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(wins.count(True), 1)

    def test_a_full_list_retires_only_browsers_this_path_made(self):
        with mock.patch.object(clients, "MAX_ACTIVE", 2):
            clients.pair(self.store, "desktop")
            first, _ = self.redeem(clients.issue_link())
            second, _ = self.redeem(clients.issue_link())        # full: retires `first`, never the desktop
            active = {r["id"]: r["name"] for r in clients.listing(self.store) if not r["revoked_at"]}
            self.assertIn(second, active)
            self.assertNotIn(first, active)
            self.assertIn("desktop", active.values())

    def test_a_list_full_of_other_clients_is_an_error_not_an_expired_link(self):
        with mock.patch.object(clients, "MAX_ACTIVE", 1):
            clients.pair(self.store, "desktop")
            with self.assertRaises(ValueError):
                self.redeem(clients.issue_link())
            self.assertEqual([r["name"] for r in clients.listing(self.store) if not r["revoked_at"]], ["desktop"])


class PairLinkServerTests(_ServerBase):
    def setUp(self):
        super().setUp()
        clients._reset_links()
        self.addCleanup(clients._reset_links)

    def mint(self, headers):
        status, _, body = self.srv.request("POST", "/api/session/link", {}, headers)
        return status, (json.loads(body) if body else {})

    def test_the_app_opens_a_browser_that_pairs_itself(self):
        status, link = self.mint({api_token.HEADER: self.client})
        self.assertEqual(status, 200)
        self.assertEqual(link["expires_in"], clients.LINK_TTL_S)
        status, headers, body = self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith(f"{api_token.CLIENT_COOKIE}=jc1_"))
        for flag in ("HttpOnly", "SameSite=Strict"):
            self.assertIn(flag, cookie)
        new_token = cookie.split(";", 1)[0].split("=", 1)[1]
        self.assertNotIn(new_token.encode(), body, "the token goes only into the HttpOnly cookie")
        # The browser is its own client: listed, and it reads the API.
        store = Store(self.db)
        try:
            names = [(r["id"], r["name"]) for r in clients.listing(store) if not r["revoked_at"]]
        finally:
            store.close()
        cid = json.loads(body)["client"]
        self.assertIn((cid, clients.LINK_CLIENT_NAME), names)
        self.assertNotEqual(cid, self.cid)
        jar = {"Cookie": f"{api_token.CLIENT_COOKIE}={new_token}"}
        self.assertEqual(self.srv.request("GET", "/api/defender", headers=jar)[0], 200)
        # Revoking it closes that browser and nothing else.
        store = Store(self.db)
        try:
            clients.revoke(store, cid)
        finally:
            store.close()
        self.assertEqual(self.srv.request("GET", "/api/defender", headers=jar)[0], 403)
        self.assertEqual(self.srv.request("GET", "/api/defender", headers={api_token.HEADER: self.client})[0], 200)

    def test_a_link_cannot_be_used_twice(self):
        _, link = self.mint({api_token.HEADER: self.client})
        self.assertEqual(self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)[0], 200)
        status, headers, body = self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(json.loads(body)["reason"], "link_expired")

    def test_an_expired_link_is_refused(self):
        _, link = self.mint({api_token.HEADER: self.client})
        import time as _time
        later = _time.monotonic() + clients.LINK_TTL_S + 1
        with mock.patch.object(clients.time, "monotonic", return_value=later):
            status, headers, _ = self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_only_a_header_credential_mints_a_link(self):
        # Anonymous, a wrong token, and a browser's cookie (even same-origin) are all refused.
        jar = {"Cookie": f"{api_token.CLIENT_COOKIE}={self.client}", **SAME}
        for hdr in ({}, {api_token.HEADER: "jc1_" + "0" * 12 + "_" + "A" * 43}, jar):
            with self.subTest(hdr=list(hdr)):
                status, _ = self.mint(hdr)
                self.assertEqual(status, 403)
        self.assertEqual(clients.pending_links(), 0)
        # The per-start token (the CLI on the daemon's own machine) may.
        self.assertEqual(self.mint({api_token.HEADER: self.token})[0], 200)

    def test_a_cross_site_page_cannot_redeem_a_code(self):
        _, link = self.mint({api_token.HEADER: self.client})
        for extra in ({"Sec-Fetch-Site": "cross-site"}, {"Origin": "http://evil.example"}):
            with self.subTest(extra=extra):
                status, headers, _ = self.srv.request("POST", "/api/session", {"code": link["code"]}, extra)
                self.assertEqual(status, 403)
                self.assertNotIn("Set-Cookie", headers)
        # Refused before redeeming: the code still works from the page itself.
        self.assertEqual(self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)[0], 200)

    def test_a_full_client_list_is_reported_and_sets_no_cookie(self):
        _, link = self.mint({api_token.HEADER: self.client})
        with mock.patch.object(clients, "MAX_ACTIVE", 1):
            status, headers, body = self.srv.request("POST", "/api/session", {"code": link["code"]}, SAME)
        self.assertEqual(status, 409)
        self.assertNotIn("Set-Cookie", headers)
        self.assertEqual(json.loads(body)["reason"], "too_many_clients")

    def test_the_token_form_still_works(self):
        status, headers, _ = self.srv.request("POST", "/api/session", {"token": self.client}, SAME)
        self.assertEqual(status, 200)
        self.assertIn(self.client, headers["Set-Cookie"])


class BrowserCommandTests(_ServerBase):
    """`jarvis desktop browser` against the real loopback server."""

    def setUp(self):
        super().setUp()
        clients._reset_links()
        self.addCleanup(clients._reset_links)

    def args(self, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(**{"page": "dashboard", "port": self.srv.port, "no_open": False, **kw})

    def test_it_opens_a_link_that_pairs_a_browser_once(self):
        import contextlib
        import io

        from jarvis.cli.commands import desktop
        opened, out = [], io.StringIO()
        with mock.patch("jarvis.web.apiclient.credential", return_value=self.client), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = desktop.cmd_browser(self.args(page="coverage"), opener=opened.append)
        self.assertEqual(rc, 0)
        url = out.getvalue().strip()
        self.assertEqual(opened, [url])
        before, code = url.split("#code=")
        self.assertEqual(before, f"http://127.0.0.1:{self.srv.port}/pair?next=/coverage")
        self.assertTrue(clients._LINK_RE.match(code))
        self.assertEqual(self.srv.request("POST", "/api/session", {"code": code}, SAME)[0], 200)
        self.assertEqual(self.srv.request("POST", "/api/session", {"code": code}, SAME)[0], 403)

    def test_a_wrong_credential_gets_no_link(self):
        import contextlib
        import io

        from jarvis.cli.commands import desktop
        out = io.StringIO()
        with mock.patch("jarvis.web.apiclient.credential", return_value="jc1_" + "0" * 12 + "_" + "A" * 43), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = desktop.cmd_browser(self.args(no_open=True), opener=self.fail)
        self.assertEqual(rc, 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(clients.pending_links(), 0)


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class PairPageScriptTests(unittest.TestCase):
    def run_js(self, body):
        src = (ROOT / "jarvis" / "web" / "static" / "pair.js").read_text(encoding="utf-8")
        script = src + "\nconst P = globalThis.__pair;\n" + body
        r = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_code_from_the_fragment_and_safe_next(self):
        out = self.run_js("""
          const code = 'A'.repeat(43);
          console.log(JSON.stringify({
            ok: P.codeFromHash('#code=' + code), none: P.codeFromHash(''), short: P.codeFromHash('#code=abc'),
            junk: P.codeFromHash('#code=' + code + '<script>'), other: P.codeFromHash('#x=1&code=' + code),
            next: [P.safeNext('/coverage'), P.safeNext('//evil.example'), P.safeNext('https://evil.example'),
                   P.safeNext('/\\\\evil'), P.safeNext(null)],
          }));""")
        self.assertEqual(out["ok"], "A" * 43)
        self.assertEqual((out["none"], out["short"], out["junk"]), ("", "", ""))
        self.assertEqual(out["other"], "A" * 43)
        self.assertEqual(out["next"], ["/coverage", "/", "/", "/", "/"])

    def test_redeem_posts_only_the_code_and_reports_the_reason(self):
        out = self.run_js("""
          const calls = [];
          const fake = async (url, init) => { calls.push([url, init.body]);
            return { ok: false, json: async () => ({ error: 'used', reason: 'link_expired' }) }; };
          P.redeem('B'.repeat(43), fake).then((r) => console.log(JSON.stringify({ r, calls })));""")
        self.assertEqual(out["calls"], [["/api/session", json.dumps({"code": "B" * 43}, separators=(",", ":"))]])
        self.assertEqual(out["r"], {"ok": False, "message": "used", "reason": "link_expired"})


class PairPageMarkupTests(unittest.TestCase):
    def test_the_page_leads_with_the_app_and_keeps_the_token_fallback(self):
        html = (ROOT / "jarvis" / "web" / "static" / "pair.html").read_text(encoding="utf-8")
        self.assertIn("Open in your browser", html)
        self.assertIn('id="pair"', html)
        self.assertIn('name="referrer" content="no-referrer"', html)
        self.assertNotIn("<script>", html, "the CSP allows only same-origin script files")


if __name__ == "__main__":
    unittest.main()


class UnreadBodyTests(_ServerBase):
    """A POST body the route never reads is drained before the reply (server.py
    _drain_body). Without it the OS resets the connection on close and Windows
    drops the reply the client had not read (WSAECONNRESET), measured 2026-11-09:
    Run again, resume and the pairing link all answer without reading their body."""

    def raw(self, head, body=b"", body_delay=None, read_timeout=10):
        """(reply, seconds until its first byte). A late body is sent from another
        thread, so the clock measures the server, not this client's own delay."""
        import socket
        import threading
        import time as _time
        s = socket.create_connection(("127.0.0.1", self.srv.port), timeout=read_timeout)
        try:
            started = _time.monotonic()
            s.sendall(head)
            sender = None
            if body and body_delay is not None:
                def late():
                    _time.sleep(body_delay)
                    try:
                        s.sendall(body)
                    except OSError:
                        pass
                sender = threading.Thread(target=late)
                sender.start()
            elif body:
                s.sendall(body)
            first, data = None, b""
            while True:
                try:
                    chunk = s.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                if first is None:
                    first = _time.monotonic() - started
                data += chunk
            if sender:
                sender.join()
            return data, (first if first is not None else _time.monotonic() - started)
        finally:
            s.close()

    def head(self, path, length, token=None):
        lines = [f"POST {path} HTTP/1.1", f"Host: 127.0.0.1:{self.srv.port}", "Content-Type: application/json",
                 f"Content-Length: {length}", "Connection: close"]
        if token:
            lines.append(f"{api_token.HEADER}: {token}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    def test_a_refusal_waits_for_the_declared_body_then_answers(self):
        # Refused before any route reads the body (no credential): the server still
        # reads the two declared bytes, arriving late, before it answers.
        data, took = self.raw(self.head("/api/run?job=scan", 2), b"{}", body_delay=0.6)
        self.assertTrue(data.startswith(b"HTTP/1.0 403"), data[:80])
        self.assertGreaterEqual(took, 0.55, "answered before reading the body it was promised")
        self.assertLess(took, 1.5)

    def test_routes_that_ignore_their_body_drain_it(self):
        for path in ("/api/session/link",):
            with self.subTest(path=path):
                data, took = self.raw(self.head(path, 2, self.client), b"{}", body_delay=0.6)
                self.assertIn(b"HTTP/1.0 ", data[:12])
                self.assertGreaterEqual(took, 0.55)

    def test_the_drain_is_bounded_in_size_and_time(self):
        from jarvis.web import server
        # A declared body over DRAIN_MAX is not waited for.
        data, took = self.raw(self.head("/api/run?job=scan", server.Handler.DRAIN_MAX + 1))
        self.assertTrue(data.startswith(b"HTTP/1.0 403"))
        self.assertLess(took, 1.0)
        # A body that never comes costs at most DRAIN_TIMEOUT_S.
        data, took = self.raw(self.head("/api/run?job=scan", 2))
        self.assertTrue(data.startswith(b"HTTP/1.0 403"))
        self.assertLess(took, server.Handler.DRAIN_TIMEOUT_S + 1.5)

    def test_bodies_that_are_read_are_not_read_twice(self):
        body = json.dumps({"token": self.client}).encode()
        data, took = self.raw(self.head("/api/session", len(body)) + body)
        self.assertNotIn(b"HTTP/1.0 403", data[:20])
        self.assertLess(took, 1.0, "a consumed body must not trigger a second (blocking) read")

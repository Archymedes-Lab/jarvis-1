"""The local web API's browser and token defences, exercised on a real loopback server.

Each test drives jarvis.web.server.Handler through a real ThreadingHTTPServer on
127.0.0.1 with a temporary store and token file, so the checks are the ones a
browser or local process meets, not a mirror of the implementation.
"""

import http.client
import json
import os
import socket
import stat
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from jarvis.core.store import Store
from jarvis.web import server
from jarvis.web import token as api_token

# The connection timeout the server ships with, read before any test patches it.
SHIPPED_TIMEOUT = server.Handler.__dict__.get("timeout")
STATIC = Path(server.STATIC_DIR)

# Every state-changing route the server answers. A route added to do_POST must
# be added here, so the "no token, no action" check covers it.
STATE_CHANGING = (
    "/api/run?job=secrets", "/api/ask", "/api/assistant/action", "/api/score-coach",
    "/api/voice", "/api/brief", "/api/geo/here", "/api/geo/zone", "/api/answer",
    "/api/fix/approve", "/api/fix/authorize", "/api/fix/retry", "/api/fix/reject",
    "/api/phone/pair/start", "/api/phone/pair/poll", "/api/phone/pair/confirm",
    "/api/phone/pair/cancel", "/api/phone/revoke", "/api/phone/test",
)


class _Server:
    def __init__(self, db_path, timeout=None):
        self.patches = [mock.patch.object(server.Handler, "db_path", db_path),
                        mock.patch.object(server.Handler, "scheduler", None)]
        if timeout is not None:
            self.patches.append(mock.patch.object(server.Handler, "timeout", timeout))
        for p in self.patches:
            p.start()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        for p in reversed(self.patches):
            p.stop()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            hdrs = {"Host": f"localhost:{self.port}"}
            hdrs.update(headers or {})
            data = json.dumps(body).encode() if body is not None else None
            conn.request(method, path, body=data, headers=hdrs)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "state.db")
        Store(self.db).close()
        old = api_token._TOKEN
        self.addCleanup(setattr, api_token, "_TOKEN", old)
        self.token = api_token.issue(os.path.join(self.tmp.name, "api.token"))
        self.srv = _Server(self.db, **self.server_options())
        self.addCleanup(self.srv.close)

    def server_options(self):
        return {}


class StateChangingRoutesTests(_Base):
    def test_every_state_changing_route_refuses_a_request_without_the_token(self):
        for path in STATE_CHANGING:
            with self.subTest(path=path):
                status, _, body = self.srv.request("POST", path, {"id": "x"})
                self.assertEqual(status, 403)
                self.assertIn("token", json.loads(body)["error"])

    def test_wrong_and_non_ascii_tokens_are_refused_not_crashed(self):
        for value in ("0" * 64, "é" * 64, self.token[:-1]):
            with self.subTest(value=value):
                status, _, _ = self.srv.request(
                    "POST", "/api/answer", {"id": "x"},
                    {api_token.HEADER: value.encode("utf-8").decode("latin-1")})
                self.assertEqual(status, 403)

    def test_the_right_token_reaches_the_handler(self):
        status, _, body = self.srv.request(
            "POST", "/api/answer", {"id": "unknown", "choice": "yes"},
            {api_token.HEADER: self.token})
        self.assertEqual(status, 400)            # reached questions.answer
        self.assertIn("message", json.loads(body))

    def test_the_cookie_works_like_the_header_from_the_dashboards_own_page(self):
        status, _, _ = self.srv.request(
            "POST", "/api/answer", {"id": "unknown", "choice": "yes"},
            {"Cookie": f"{api_token.COOKIE}={self.token}", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 400)

    def test_cross_site_and_rebound_requests_are_refused_even_with_the_token(self):
        good = {api_token.HEADER: self.token}
        cases = (
            {"Sec-Fetch-Site": "cross-site"},
            {"Sec-Fetch-Site": "same-site"},
            {"Origin": "http://evil.example"},
            {"Origin": "null"},
            {"Host": "evil.example"},
            {"Host": f"rebind.example:{self.srv.port}"},
        )
        for extra in cases:
            with self.subTest(extra=extra):
                status, _, _ = self.srv.request("POST", "/api/answer", {"id": "x"},
                                                {**good, **extra})
                self.assertEqual(status, 403)

    def test_oversized_and_malformed_bodies_fail_closed(self):
        good = {api_token.HEADER: self.token}
        status, _, _ = self.srv.request("POST", "/api/answer", {"id": "x" * 5000}, good)
        self.assertEqual(status, 400)
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=10)
        try:
            conn.request("POST", "/api/answer", body=b"{not json",
                         headers={"Host": "localhost", **good})
            self.assertEqual(conn.getresponse().status, 400)
        finally:
            conn.close()

    def test_no_permissive_cors_and_no_foreign_framing(self):
        status, headers, _ = self.srv.request("GET", "/api/nothing-here",
                                              headers={"Origin": "http://evil.example"})
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers.get("X-Frame-Options"), "SAMEORIGIN")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("frame-ancestors 'self'", headers.get("Content-Security-Policy", ""))
        for csp in (server.Handler.CSP_STRICT, server.Handler.CSP_GEO,
                    server.Handler.CSP_COVERAGE):
            self.assertIn("frame-ancestors 'self'", csp)


PAGE = "/ui/" if (server.UI_DIR / "index.html").is_file() else "/"
# What a browser sends when the owner opens the dashboard (typed, bookmark, OS).
NAV = {"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-Dest": "document"}


class DashboardCookieTests(_Base):
    # The dashboard is served at /ui/ ("/" redirects there, query kept); the
    # guarded cookie rides on the page and on the redirect, never to a peer of
    # another account.
    def test_page_cookie_is_httponly_strict_and_carries_the_token(self):
        status, headers, _ = self.srv.request("GET", PAGE, headers=NAV)
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertTrue(cookie.startswith(f"{api_token.COOKIE}={self.token};"))
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_the_real_peer_is_attributed_to_this_account(self):
        # This process is the client, so /proc/net/tcp must name our uid.
        seen = []
        real = api_token.peer_uid

        def spy(client, srv_addr, tables=api_token.PROC_NET):
            seen.append(real(client, srv_addr, tables))
            return seen[-1]
        with mock.patch.object(api_token, "peer_uid", spy):
            _, headers, _ = self.srv.request("GET", PAGE, headers=NAV)
        if os.path.exists("/proc/net/tcp"):
            self.assertEqual(seen, [os.geteuid()])
        self.assertIn("Set-Cookie", headers)

    def test_another_local_account_gets_the_page_but_not_the_token(self):
        with mock.patch.object(api_token, "peer_uid", return_value=os.geteuid() + 4242):
            status, headers, body = self.srv.request("GET", PAGE, headers=NAV)
        self.assertEqual(status, 200)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(self.token.encode(), body)

    def test_root_keeps_the_cookie_and_an_unattributable_peer_does_not(self):
        with mock.patch.object(api_token, "peer_uid", return_value=0):
            _, headers, _ = self.srv.request("GET", PAGE, headers=NAV)
            self.assertIn("Set-Cookie", headers)
        # Fail closed: a peer whose owner cannot be determined (a Windows
        # program across WSL networking) pairs explicitly instead.
        with mock.patch.object(api_token, "peer_uid", return_value=None):
            status, headers, body = self.srv.request("GET", PAGE, headers=NAV)
            self.assertEqual(status, 200)
            self.assertNotIn("Set-Cookie", headers)
            self.assertNotIn(self.token.encode(), body)

    def test_the_redirect_to_the_page_guards_the_cookie_the_same_way(self):
        status, headers, _ = self.srv.request("GET", "/", headers=NAV)
        self.assertIn(status, (200, 302))
        if status == 302:
            self.assertTrue(headers.get("Location", "").startswith("/ui/"))
        self.assertIn("Set-Cookie", headers)
        for uid in (os.geteuid() + 4242, None):
            with self.subTest(uid=uid), mock.patch.object(api_token, "peer_uid", return_value=uid):
                _, headers, body = self.srv.request("GET", "/", headers=NAV)
                self.assertNotIn("Set-Cookie", headers)
                self.assertNotIn(self.token.encode(), body)

    def test_the_token_is_not_in_any_response_body_or_error(self):
        for method, path in (("GET", "/api/defender"), ("GET", "/nope"),
                             ("POST", "/api/answer"), ("GET", "/api/run")):
            with self.subTest(path=path):
                _, _, body = self.srv.request(method, path)
                self.assertNotIn(self.token.encode(), body)


    # QC-ARGUS-1-2026-10-27 blocker 4: the hand-over needs a browser navigation.
    def test_a_request_without_browser_navigation_metadata_gets_no_cookie(self):
        for extra in ({}, {"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Mode": "navigate"},
                      {**NAV, "Sec-Fetch-Mode": "cors"}, {**NAV, "Sec-Fetch-Mode": "no-cors"},
                      {**NAV, "Sec-Fetch-Site": "cross-site"}, {**NAV, "Sec-Fetch-Site": "same-site"}):
            for path in (PAGE, "/"):
                with self.subTest(extra=extra, path=path):
                    status, headers, body = self.srv.request("GET", path, headers=extra)
                    self.assertIn(status, (200, 302, 403))
                    self.assertNotIn("Set-Cookie", headers)
                    self.assertNotIn(self.token.encode(), body)

    def test_a_navigation_followed_from_our_own_page_gets_the_cookie(self):
        _, headers, _ = self.srv.request("GET", PAGE, headers={**NAV, "Sec-Fetch-Site": "same-origin"})
        self.assertIn(f"{api_token.COOKIE}={self.token}", headers.get("Set-Cookie", ""))

    def test_a_service_account_owner_no_longer_receives_the_cookie(self):
        # Formerly JARVIS_OWNER_UID: the owner cannot read the service account's
        # token file, so handing it the cookie was a grant; it pairs instead.
        with mock.patch.dict(os.environ, {"JARVIS_OWNER_UID": str(os.geteuid() + 4242)}), \
                mock.patch.object(api_token, "peer_uid", return_value=os.geteuid() + 4242):
            _, headers, body = self.srv.request("GET", PAGE, headers=NAV)
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn(self.token.encode(), body)


class CookieCredentialTests(_Base):
    """A state-changing request whose only credential is a cookie must carry
    same-origin browser evidence; header tokens need none (CLI, app, supervisors)."""

    def jar(self):
        return {"Cookie": f"{api_token.COOKIE}={self.token}"}

    def test_a_cookie_replayed_without_browser_evidence_is_refused(self):
        for extra in ({}, {"Origin": "http://evil.example"}, {"Sec-Fetch-Site": "none"},
                      {"Origin": "null"}):
            with self.subTest(extra=extra):
                status, _, body = self.srv.request("POST", "/api/answer", {"id": "x"},
                                                   {**self.jar(), **extra})
                self.assertEqual(status, 403)
                self.assertRegex(json.loads(body)["error"], "token|cross-site")

    def test_the_dashboards_own_cookie_requests_reach_the_handler(self):
        port = self.srv.port
        for extra in ({"Sec-Fetch-Site": "same-origin"}, {"Origin": f"http://localhost:{port}"},
                      {"Origin": f"http://127.0.0.1:{port}"}):
            with self.subTest(extra=extra):
                status, _, body = self.srv.request("POST", "/api/answer", {"id": "unknown", "choice": "yes"},
                                                   {**self.jar(), **extra})
                self.assertEqual(status, 400)        # reached questions.answer
                self.assertIn("message", json.loads(body))

    def test_a_header_token_needs_no_origin(self):
        for hdr in ({api_token.HEADER: self.token}, {"Authorization": f"Bearer {self.token}"},
                    {api_token.HEADER: self.token, **self.jar()}):
            with self.subTest(hdr=list(hdr)):
                status, _, _ = self.srv.request("POST", "/api/answer", {"id": "unknown", "choice": "yes"}, hdr)
                self.assertEqual(status, 400)

    def test_a_wrong_cookie_with_browser_evidence_is_still_refused(self):
        status, _, _ = self.srv.request("POST", "/api/answer", {"id": "x"},
                                        {"Cookie": f"{api_token.COOKIE}={'0' * 64}",
                                         "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 403)


class PeerAttributionTests(unittest.TestCase):
    def _table(self, rows):
        fd, path = tempfile.mkstemp()
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as fh:
            fh.write("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
                     "retrnsmt   uid  timeout inode\n")
            fh.writelines(rows)
        return path

    def test_rows_are_matched_on_both_ends(self):
        # client 127.0.0.1:40000 -> server 127.0.0.1:8787 owned by uid 1234;
        # the server's own end of the connection (reversed) belongs to uid 1000.
        path = self._table([
            "   0: 0100007F:2253 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000 0 1\n",
            "   1: 0100007F:9C40 0100007F:2253 01 00000000:00000000 00:00000000 00000000  1234 0 2\n",
        ])
        self.assertEqual(api_token.peer_uid(("127.0.0.1", 40000), ("127.0.0.1", 8787),
                                            (path,)), 1234)
        self.assertIsNone(api_token.peer_uid(("127.0.0.1", 40001), ("127.0.0.1", 8787),
                                             (path,)))

    def test_v4_mapped_rows_in_tcp6_are_matched(self):
        path = self._table([
            "   0: 0000000000000000FFFF00000100007F:9C40 0000000000000000FFFF00000100007F:2253 "
            "01 00000000:00000000 00:00000000 00000000  1234 0 2\n"])
        self.assertEqual(api_token.peer_uid(("127.0.0.1", 40000), ("127.0.0.1", 8787),
                                            (path,)), 1234)

    def test_unreadable_or_garbled_tables_attribute_nobody(self):
        path = self._table(["garbage\n", "   0: zz:zz yy:yy 01 a b c d notanumber\n"])
        self.assertIsNone(api_token.peer_uid(("127.0.0.1", 1), ("127.0.0.1", 2),
                                             (path, "/nonexistent/tcp")))

    def test_real_loopback_connection_is_ours(self):
        if not os.path.exists("/proc/net/tcp"):
            self.skipTest("no /proc/net/tcp")
        lst = socket.socket()
        self.addCleanup(lst.close)
        lst.bind(("127.0.0.1", 0))
        lst.listen(1)
        cli = socket.create_connection(lst.getsockname())
        self.addCleanup(cli.close)
        conn, addr = lst.accept()
        self.addCleanup(conn.close)
        self.assertEqual(api_token.peer_uid(addr, lst.getsockname()), os.geteuid())

    def test_policy(self):
        self.assertFalse(api_token.may_receive(None))
        with mock.patch.dict(os.environ, {"JARVIS_OWNER_UID": "1234"}):
            self.assertFalse(api_token.may_receive(1234))     # the owner pairs (blocker 4)
        self.assertTrue(api_token.may_receive(0))
        self.assertTrue(api_token.may_receive(os.geteuid()))
        self.assertFalse(api_token.may_receive(os.geteuid() + 1))


class StalledClientTests(_Base):
    def server_options(self):
        return {"timeout": 1}

    def test_a_client_that_never_sends_its_body_is_disconnected(self):
        sock = socket.create_connection(("127.0.0.1", self.srv.port), timeout=10)
        try:
            sock.sendall(b"POST /api/answer HTTP/1.1\r\nHost: localhost\r\n"
                         + f"{api_token.HEADER}: {self.token}\r\n".encode()
                         + b"Content-Length: 4000\r\n\r\n{")
            started = time.monotonic()
            data = sock.recv(4096)          # b"" once the server gives up
            self.assertEqual(data, b"")
            self.assertLess(time.monotonic() - started, 8)
        finally:
            sock.close()

    def test_a_client_that_never_sends_a_request_line_is_disconnected(self):
        sock = socket.create_connection(("127.0.0.1", self.srv.port), timeout=10)
        try:
            self.assertEqual(sock.recv(4096), b"")
        finally:
            sock.close()


class ShippedLimitsTests(unittest.TestCase):
    def test_connections_have_a_bounded_timeout(self):
        # Without one, http.server blocks for ever on a stalled client.
        self.assertIsInstance(SHIPPED_TIMEOUT, (int, float))
        self.assertTrue(0 < SHIPPED_TIMEOUT <= 120)


# No inline handler may remain at all (tests/test_static_csp.py is the full check).
CLIENT_CONSTANT_HANDLERS = set()


class DashboardRenderingTests(unittest.TestCase):
    """Server data must never be placed inside inline-handler JavaScript: the
    browser decodes HTML entities there before compiling, so esc() cannot help."""

    def test_no_server_value_is_interpolated_into_an_inline_handler(self):
        import re
        for name in ("dashboard.html", "geo.html", "coverage.html", "procs.html",
                     "world.html", "pair.html", "coverage.js", "procs.js", "procs-scene.js",
                     "world.js", "dashboard.js", "geo.js", "session.js", "pair.js"):
            text = (STATIC / name).read_text(encoding="utf-8")
            with self.subTest(name=name):
                found = re.findall(r"\bon[a-z]+=[\"'][^\"']*\$\{[^}]*\}?", text)
                self.assertEqual([f for f in found if f not in CLIENT_CONSTANT_HANDLERS], [])

    def test_collector_state_is_escaped_in_its_class_attribute(self):
        text = (STATIC / "coverage.js").read_text(encoding="utf-8")
        self.assertNotIn('class="dot ${c.state}"', text)
        self.assertIn('class="dot ${esc(c.state)}"', text)


class TokenFileTests(unittest.TestCase):
    def setUp(self):
        old = api_token._TOKEN
        self.addCleanup(setattr, api_token, "_TOKEN", old)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "api.token")

    def test_a_leftover_world_readable_temp_file_cannot_loosen_the_token(self):
        stale = self.path + ".new"
        with open(stale, "w") as fh:
            fh.write("old")
        os.chmod(stale, 0o644)
        value = api_token.issue(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(api_token.read(self.path), value)

    def test_a_planted_link_is_not_followed(self):
        victim = os.path.join(self.tmp.name, "elsewhere")
        with open(victim, "w") as fh:
            fh.write("untouched")
        os.symlink(victim, self.path + ".new")
        api_token.issue(self.path)
        with open(victim) as fh:
            self.assertEqual(fh.read(), "untouched")
        self.assertFalse(os.path.islink(self.path))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_an_old_loose_token_file_is_replaced_owner_only(self):
        with open(self.path, "w") as fh:
            fh.write("old")
        os.chmod(self.path, 0o644)
        api_token.issue(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_a_failed_write_leaves_no_temp_file_and_no_token(self):
        api_token._TOKEN = None
        with mock.patch.object(api_token.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                api_token.issue(self.path)
        self.assertEqual(os.listdir(self.tmp.name), [])
        self.assertIsNone(api_token.current())
        self.assertFalse(api_token.accepts({api_token.HEADER: ""}))


if __name__ == "__main__":
    unittest.main()

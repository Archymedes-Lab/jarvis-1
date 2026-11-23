"""Paired clients, the all-routes credential gate, liveness-only health, the
browser pairing page, the service-account state directory and the CLI guard.

Server checks run on a real loopback ThreadingHTTPServer with a temporary
store; nothing touches the running daemon.
"""

import contextlib
import io
import json
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.cli import parser as cli_parser
from jarvis.core import statedir
from jarvis.core.store import Store
from jarvis.web import apiclient, clients, server
from jarvis.web import token as api_token
from tests.test_api_hardening import NAV, _Server

ROOT = Path(__file__).resolve().parent.parent

# Every route the server answers, and the protection it must have. A route
# added to server.py without an entry here fails test_every_route_is_in_the_table.
#   token    a credential is required (403 without one)
#   live     open, liveness fields only without a credential
#   page     open HTML shell; the token cookie only for an identified peer's browser navigation
#   asset    open static file
#   session  POST, same-origin, validates a paired client token itself
#   veil     POST, the extension's own pairing token
#   redirect 302 to the interface; the token cookie as for a page
LICENCE_POSTS = ("/api/licence/activate", "/api/licence/deactivate", "/api/licence/refresh",
                 "/api/licence/upgrade", "/api/licence/poll")
ROUTES = {
    "/": "redirect", "/index.html": "redirect", "/ui": "redirect",
    "/ui/": "page", "/ui/index.html": "page", "/classic": "page",
    "/geo": "page", "/pair": "page",
    "/api/health": "live", "/api/live": "live",
    "/api/session": "session", "/api/session/link": "token", "/api/veil/events": "veil",
    "/metrics": "token",
    **{p: "token" for p in LICENCE_POSTS},
    **{p: "token" for p in (
        "/api/licence", "/api/answer", "/api/arena", "/api/ask", "/api/assistant/action", "/api/brief",
        "/api/coverage", "/api/coverage/live", "/api/coverage/stream", "/api/defender",
        "/api/fix/approve", "/api/fix/authorize", "/api/fix/reject", "/api/fix/retry",
        "/api/geo", "/api/geo/here", "/api/geo/zone", "/api/greeting", "/api/posture",
        "/api/posture/path-to-100", "/api/procs/baseline", "/api/procs/stream",
        "/api/pulse", "/api/run", "/api/score-coach", "/api/state", "/api/stream",
        "/api/voice", "/api/world",
        # added by the interface, autopilot and pause work (2026-10-30..11-02)
        "/api/autopilot", "/api/autopilot/authorize", "/api/autopilot/decide",
        "/api/autopilot/notices", "/api/autopilot/policy", "/api/pause", "/api/protection",
        "/api/protection/scan", "/api/resume",
        # the desktop app's update notice (service/selfupdate.py)
        "/api/update")},
}
POST_ONLY = {*LICENCE_POSTS, "/api/answer", "/api/ask", "/api/assistant/action", "/api/brief",
             "/api/fix/approve", "/api/fix/authorize", "/api/fix/reject", "/api/fix/retry",
             "/api/geo/here", "/api/geo/zone", "/api/score-coach", "/api/voice",
             "/api/session", "/api/veil/events",
             "/api/autopilot/authorize", "/api/autopilot/decide", "/api/autopilot/policy",
             "/api/pause", "/api/resume",
             "/api/protection/scan", "/api/session/link"}


def served_routes():
    text = (ROOT / "jarvis" / "web" / "server.py").read_text(encoding="utf-8")
    found = set(re.findall(r'url\.path == "([^"]+)"', text))
    for group in re.findall(r'url\.path in \(([^)]*)\)', text):
        found |= set(re.findall(r'"([^"]+)"', group))
    found |= set(server.LIVENESS_ROUTES)
    return found


class _FakeScheduler:
    hosts = ("wsl",)
    current = None
    fast_current = None
    heartbeat = time.time()
    fast_heartbeat = time.time()

    def is_alive(self):
        return True

    def fast_alive(self):
        return True


class ClientRegistryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(str(Path(self.tmp.name) / "s.db"))
        self.addCleanup(self.store.close)

    def test_pair_verify_revoke(self):
        cid, token = clients.pair(self.store, "desktop")
        self.assertTrue(clients.looks_like(token))
        self.assertEqual(clients.verify(self.store, token), cid)
        self.assertTrue(clients.revoke(self.store, cid))
        self.assertIsNone(clients.verify(self.store, token))
        self.assertFalse(clients.revoke(self.store, cid))          # already revoked
        self.assertEqual(clients.listing(self.store)[0]["id"], cid)  # kept as audit

    def test_only_a_digest_is_stored(self):
        # URL-safe secrets may contain underscores, including near the end.
        # Check the entire secret, rather than a possibly one-character suffix.
        for secret in ("A" * 43, "A" * 41 + "_s", "_" * 43):
            with self.subTest(secret=secret), \
                    mock.patch.object(clients.secrets, "token_urlsafe", return_value=secret):
                _, token = clients.pair(self.store, "cli")
                raw = self.store.get_meta(clients.META_KEY)
                self.assertNotIn(token, raw)
                self.assertNotIn(token.split("_", 2)[2], raw)
                self.assertNotIn("sha256", json.dumps(clients.listing(self.store)))

    def test_forged_malformed_and_unknown_tokens_are_refused(self):
        cid, token = clients.pair(self.store, "desktop")
        forged = token[:-1] + ("A" if token[-1] != "A" else "B")
        other_id = f"jc1_{'0' * 12}_{token.split('_', 2)[2]}"
        for value in (forged, other_id, "", "jc1_x", token + "x", None, 7, token.upper()):
            with self.subTest(value=value):
                self.assertIsNone(clients.verify(self.store, value))

    def test_names_and_the_active_cap_are_bounded(self):
        for bad in ("", "x" * 41, "a;b", "évil"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                clients.pair(self.store, bad)
        with mock.patch.object(clients, "MAX_ACTIVE", 2):
            clients.pair(self.store, "a")
            cid, _ = clients.pair(self.store, "b")
            with self.assertRaises(ValueError):
                clients.pair(self.store, "c")
            clients.revoke(self.store, cid)
            clients.pair(self.store, "c")                     # room again

    def test_a_corrupt_registry_accepts_nobody(self):
        _, token = clients.pair(self.store, "desktop")
        self.store.set_meta(clients.META_KEY, "{not json")
        self.assertIsNone(clients.verify(self.store, token))
        self.assertEqual(clients.listing(self.store), [])


class _ServerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "state.db")
        store = Store(self.db)
        self.cid, self.client = clients.pair(store, "desktop")
        store.close()
        old = api_token._TOKEN
        self.addCleanup(setattr, api_token, "_TOKEN", old)
        self.token = api_token.issue(os.path.join(self.tmp.name, "api.token"))
        sched = mock.patch.object(server.Handler, "scheduler", _FakeScheduler())
        self.srv = _Server(self.db)
        sched.start()
        self.addCleanup(sched.stop)
        self.addCleanup(self.srv.close)
        # Default: the peer cannot be attributed (as from Windows), so no cookie.
        peer = mock.patch.object(api_token, "peer_uid", return_value=None)
        peer.start()
        self.addCleanup(peer.stop)


class PairedClientTests(_ServerBase):
    def test_a_paired_client_reads_and_acts(self):
        for hdr in ({api_token.HEADER: self.client},
                    {"Authorization": f"Bearer {self.client}"}):
            with self.subTest(hdr=list(hdr)):
                self.assertEqual(self.srv.request("GET", "/api/defender", headers=hdr)[0], 200)
                self.assertEqual(self.srv.request(
                    "POST", "/api/answer", {"id": "x", "choice": "yes"}, hdr)[0], 400)

    def test_revoked_and_forged_clients_are_refused(self):
        store = Store(self.db)
        clients.revoke(store, self.cid)
        store.close()
        forged = self.client[:-2] + "zz"
        for value in (self.client, forged):
            with self.subTest(value=value[-4:]):
                hdr = {api_token.HEADER: value}
                self.assertEqual(self.srv.request("GET", "/api/defender", headers=hdr)[0], 403)
                self.assertEqual(self.srv.request(
                    "POST", "/api/answer", {"id": "x"}, hdr)[0], 403)

    def test_an_unidentified_browser_pairs_through_the_session_route(self):
        status, headers, _ = self.srv.request("GET", "/", headers=NAV)
        self.assertIn(status, (200, 302))                       # 302 to /ui/ when it is built
        self.assertNotIn("Set-Cookie", headers)                 # fail closed
        if status == 302:
            status, headers, _ = self.srv.request("GET", "/ui/", headers=NAV)
            self.assertEqual(status, 200)
            self.assertNotIn("Set-Cookie", headers)             # the interface fails closed too
        self.assertEqual(self.srv.request("GET", "/api/state")[0], 403)
        status, headers, body = self.srv.request(
            "POST", "/api/session", {"token": self.client}, {"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        self.assertTrue(cookie.startswith(f"{api_token.CLIENT_COOKIE}={self.client};"))
        for flag in ("HttpOnly", "SameSite=Strict", "Max-Age="):
            self.assertIn(flag, cookie)
        self.assertNotIn(self.client.encode(), body)
        jar = {"Cookie": f"{api_token.CLIENT_COOKIE}={self.client}"}
        self.assertEqual(self.srv.request("GET", "/api/defender", headers=jar)[0], 200)
        # The paired browser's own POSTs carry same-origin metadata; a replay does not.
        self.assertEqual(self.srv.request("POST", "/api/answer", {"id": "x", "choice": "yes"},
                                          {**jar, "Sec-Fetch-Site": "same-origin"})[0], 400)
        self.assertEqual(self.srv.request("POST", "/api/answer", {"id": "x", "choice": "yes"}, jar)[0], 403)

    def _link(self):
        status, _, body = self.srv.request(
            "POST", "/api/session/link", {}, {api_token.HEADER: self.client})
        self.assertEqual(status, 200)
        return json.loads(body)["code"]

    def test_the_app_opens_a_browser_with_a_one_time_code_and_no_typing(self):
        # No credential, no code.
        self.assertEqual(self.srv.request("POST", "/api/session/link", {})[0], 403)
        code = self._link()
        same = {"Sec-Fetch-Site": "same-origin"}
        status, headers, body = self.srv.request("POST", "/api/session", {"code": code}, same)
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Max-Age="):
            self.assertIn(flag, cookie)
        minted = cookie.split(";")[0].split("=", 1)[1]
        self.assertNotIn(minted.encode(), body)
        jar = {"Cookie": f"{api_token.CLIENT_COOKIE}={minted}"}
        self.assertEqual(self.srv.request("GET", "/api/defender", headers=jar)[0], 200)
        # Single use: the same code is spent.
        status, headers, _ = self.srv.request("POST", "/api/session", {"code": code}, same)
        self.assertEqual(status, 403)
        self.assertNotIn("Set-Cookie", headers)

    def test_one_time_codes_expire_and_forged_or_cross_site_codes_fail(self):
        same = {"Sec-Fetch-Site": "same-origin"}
        code = self._link()
        # Expiry runs on the monotonic clock, so a wall-clock step cannot stretch a code.
        with mock.patch.object(clients.time, "monotonic", return_value=time.monotonic() + clients.LINK_TTL_S + 1):
            self.assertEqual(self.srv.request("POST", "/api/session", {"code": code}, same)[0], 403)
        for bad in ("A" * 43, "short", "x" * 100):
            self.assertEqual(self.srv.request("POST", "/api/session", {"code": bad}, same)[0], 403)
        fresh = self._link()
        self.assertEqual(self.srv.request(
            "POST", "/api/session", {"code": fresh}, {"Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_the_session_route_refuses_bad_tokens_and_cross_site_calls(self):
        for body, extra in (({"token": "jc1_" + "0" * 12 + "_" + "A" * 43}, {}),
                            ({"token": self.token}, {}),          # per-start token is not a client
                            ({}, {}),
                            ({"token": self.client}, {"Sec-Fetch-Site": "cross-site"}),
                            ({"token": self.client}, {"Origin": "http://evil.example"})):
            with self.subTest(body=list(body), extra=extra):
                status, headers, _ = self.srv.request("POST", "/api/session", body, extra)
                self.assertEqual(status, 403)
                self.assertNotIn("Set-Cookie", headers)


class RouteTableTests(_ServerBase):
    def test_every_route_is_in_the_table(self):
        self.assertEqual(served_routes() - set(ROUTES), set(),
                         "a new route needs an entry in ROUTES with its protection")
        self.assertEqual(set(ROUTES) - served_routes(), set(), "stale ROUTES entry")

    def test_every_token_route_refuses_an_anonymous_request(self):
        for path, kind in ROUTES.items():
            if kind != "token":
                continue
            method = "POST" if path in POST_ONLY else "GET"
            with self.subTest(path=path):
                status, headers, body = self.srv.request(method, path, {} if method == "POST" else None)
                self.assertEqual(status, 403)
                self.assertIn("token", json.loads(body)["error"])
                self.assertNotIn("Set-Cookie", headers)

    def test_get_token_routes_also_refuse_wrong_credentials(self):
        for path in ("/api/state", "/api/stream", "/api/procs/stream", "/metrics"):
            for hdr in ({api_token.HEADER: "0" * 64},
                        {"Cookie": f"{api_token.COOKIE}=bad; {api_token.CLIENT_COOKIE}=bad"}):
                with self.subTest(path=path, hdr=list(hdr)):
                    self.assertEqual(self.srv.request("GET", path, headers=hdr)[0], 403)

    def test_liveness_is_open_but_says_nothing_else_without_a_credential(self):
        for path in server.LIVENESS_ROUTES:
            with self.subTest(path=path):
                _, _, body = self.srv.request("GET", path)
                anon = json.loads(body)
                self.assertTrue(set(anon) <= set(server.LIVENESS_FIELDS))
                self.assertIn("live", anon)
                self.assertNotIn("sources", anon)
                _, _, body = self.srv.request("GET", path, headers={api_token.HEADER: self.client})
                self.assertIn("sources", json.loads(body))

    def test_pages_and_assets_stay_open(self):
        for path, kind in ROUTES.items():
            if kind == "redirect":
                with self.subTest(path=path):
                    self.assertIn(self.srv.request("GET", path)[0], (200, 302))
                continue
            if kind != "page":
                continue
            with self.subTest(path=path):
                status = self.srv.request("GET", path)[0]
                self.assertIn(status, (200, 500))             # 500 only if a page file is absent
                self.assertNotEqual(status, 403)
        self.assertEqual(self.srv.request("GET", "/pair")[0], 200)
        self.assertEqual(self.srv.request("GET", "/static/pair.js")[0], 200)

    def test_an_identified_peer_gets_the_cookie_on_every_html_page(self):
        with mock.patch.object(api_token, "peer_uid", return_value=os.geteuid()):
            for path in ("/", "/coverage", "/procs", "/world"):
                with self.subTest(path=path):
                    _, headers, _ = self.srv.request("GET", path, headers=NAV)
                    self.assertIn(f"{api_token.COOKIE}={self.token}", headers.get("Set-Cookie", ""))
            _, headers, _ = self.srv.request("GET", "/static/pair.js", headers=NAV)
            self.assertNotIn("Set-Cookie", headers)


class StateDirTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, ".jarvis")
        os.mkdir(self.dir, 0o700)
        os.chmod(self.dir, 0o700)
        for name in ("jarvis.db", "api.token", "config.json"):
            path = os.path.join(self.dir, name)
            with open(path, "w") as fh:
                fh.write("x")
            os.chmod(path, 0o600)

    def test_private_directory_passes(self):
        self.assertEqual(statedir.private_problems(self.dir), [])

    def test_group_or_world_access_is_reported(self):
        for target, mode in ((self.dir, 0o750), (self.dir, 0o701),
                             (os.path.join(self.dir, "jarvis.db"), 0o640),
                             (os.path.join(self.dir, "api.token"), 0o604)):
            with self.subTest(target=os.path.basename(target), mode=oct(mode)):
                old = stat.S_IMODE(os.stat(target).st_mode)
                os.chmod(target, mode)
                try:
                    self.assertTrue(statedir.private_problems(self.dir))
                finally:
                    os.chmod(target, old)

    def test_links_foreign_owners_and_missing_dirs_are_reported(self):
        os.symlink("/etc/hostname", os.path.join(self.dir, "evil.token"))
        self.assertTrue(any("link" in p for p in statedir.private_problems(self.dir)))
        self.assertTrue(statedir.private_problems(self.dir, uid=os.geteuid() + 1))
        self.assertTrue(statedir.private_problems(os.path.join(self.tmp.name, "absent")))

    def _marker(self):
        path = os.path.join(self.tmp.name, "service-account.json")
        with open(path, "w") as fh:
            json.dump({"user": "jarvis", "state_dir": self.dir}, fh)
        return path

    def test_serve_refuses_an_open_state_dir_under_the_service_account(self):
        os.chmod(self.dir, 0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                server._check_state_dir(self.dir, self._marker())
            # Legacy per-user mode: says so, keeps running.
            self.assertFalse(server._check_state_dir(
                self.dir, os.path.join(self.tmp.name, "no-marker.json")))
        os.chmod(self.dir, 0o700)
        self.assertTrue(server._check_state_dir(self.dir, self._marker()))

    def test_cli_refuses_to_read_its_own_store_when_the_daemon_has_its_own_account(self):
        marker = self._marker()
        default = os.path.join(self.tmp.name, "home", ".jarvis", "jarvis.db")
        # We own the state dir: we are the daemon's account, nothing to refuse.
        self.assertIsNone(statedir.cli_refusal(default, default, ["status"], marker))
        foreign = os.stat(self.dir)
        fake = os.stat_result((foreign.st_mode, foreign.st_ino, foreign.st_dev, foreign.st_nlink,
                               os.geteuid() + 1, foreign.st_gid, foreign.st_size,
                               foreign.st_atime, foreign.st_mtime, foreign.st_ctime))
        with mock.patch.object(statedir.os, "stat", return_value=fake):
            msg = statedir.cli_refusal(default, default, ["status", "--json"], marker)
            self.assertIn("sudo -u jarvis -H jarvis status --json", msg)
            # An explicit --db is the caller's choice; no marker means legacy mode.
            self.assertIsNone(statedir.cli_refusal("/tmp/other.db", default, [], marker))
        self.assertIsNone(statedir.cli_refusal(default, default, [], marker + ".absent"))

    def test_cli_main_stops_before_opening_a_store(self):
        with mock.patch.object(statedir, "cli_refusal", return_value="refused"), \
                mock.patch.object(cli_parser, "Store") as store, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli_parser.main(["desktop", "clients"]), 2)
        store.assert_not_called()
        self.assertIn("refused", err.getvalue())


class ApiClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "cfg", "client.token")
        self.good = "jc1_" + "a" * 12 + "_" + "B" * 43

    def test_save_is_owner_only_and_read_back(self):
        apiclient.save_private(self.path, self.good)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(apiclient.read_private(self.path), self.good)
        with self.assertRaises(ValueError):
            apiclient.save_private(self.path, "not-a-token")

    def test_loose_linked_or_malformed_files_are_ignored(self):
        apiclient.save_private(self.path, self.good)
        os.chmod(self.path, 0o644)
        self.assertEqual(apiclient.read_private(self.path), "")
        os.chmod(self.path, 0o600)
        link = self.path + ".link"
        os.symlink(self.path, link)
        self.assertEqual(apiclient.read_private(link), "")
        with open(self.path, "w") as fh:
            fh.write("garbage")
        self.assertEqual(apiclient.read_private(self.path), "")

    def test_credential_order_and_the_unpaired_error(self):
        env = {"JARVIS_CLIENT_TOKEN_FILE": self.path}
        with mock.patch.object(api_token, "read", return_value=""):
            with self.assertRaises(apiclient.Unpaired) as ctx:
                apiclient.credential(env)
            self.assertIn("jarvis desktop pair", str(ctx.exception))
        with mock.patch.object(api_token, "read", return_value="f" * 64):
            self.assertEqual(apiclient.credential(env), "f" * 64)
        apiclient.save_private(self.path, self.good)
        self.assertEqual(apiclient.credential(env), self.good)


class DesktopCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = str(Path(self.tmp.name) / "s.db")

    def run_cli(self, *argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(stdin)), \
                mock.patch.object(statedir, "cli_refusal", return_value=None):
            code = cli_parser.main(["--db", self.db, "desktop", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_pair_prints_only_the_token_on_stdout_then_lists_and_revokes(self):
        code, out, err = self.run_cli("pair", "--name", "desktop")
        self.assertEqual(code, 0)
        token = out.strip()
        self.assertTrue(clients.looks_like(token))
        self.assertNotIn(token, err)
        _, listing, _ = self.run_cli("clients")
        self.assertIn("desktop", listing)
        self.assertNotIn(token, listing)
        cid = token.split("_")[1]
        self.assertIn("revoked", self.run_cli("revoke", cid)[1])
        self.assertIn("no active client", self.run_cli("revoke", cid)[2])
        store = Store(self.db)
        try:
            self.assertIsNone(clients.verify(store, token))
        finally:
            store.close()

    def test_save_reads_stdin_and_never_opens_the_store(self):
        path = os.path.join(self.tmp.name, "c", "client.token")
        good = "jc1_" + "b" * 12 + "_" + "C" * 43
        with mock.patch.object(cli_parser, "Store") as store:
            code, _, _ = self.run_cli("save", "--out", path, stdin=good + "\n")
            bad, _, _ = self.run_cli("save", "--out", path, stdin="nope\n")
        store.assert_not_called()
        self.assertEqual((code, bad), (0, 2))
        self.assertEqual(apiclient.read_private(path), good)


if __name__ == "__main__":
    unittest.main()


class ServiceAccountInstallTests(unittest.TestCase):
    """The install artifacts carry the permission expectations the daemon checks."""

    def setUp(self):
        self.dropin = (ROOT / "systemd" / "service-user.conf").read_text(encoding="utf-8")
        self.script = (ROOT / "scripts" / "repair" / "install-service-user.sh").read_text(encoding="utf-8")
        self.selfcheck = (ROOT / "systemd" / "jarvis-selfcheck-system.service").read_text(encoding="utf-8")

    def test_dropin_runs_as_jarvis_with_a_private_state_directory(self):
        for line in ("User=jarvis", "Group=jarvis", "Environment=HOME=/var/lib/jarvis",
                     "StateDirectoryMode=0700", "UMask=0077",
                     "NoNewPrivileges=yes"):
            self.assertIn(line + "\n", self.dropin)
        # The owner pairs its browser; it is not handed the token (QC blocker 4).
        self.assertNotIn("JARVIS_OWNER_UID", self.dropin)
        # The old readers group exposed the store and token to the owner's processes.
        self.assertNotIn("jarvis-readers", self.dropin)
        self.assertNotIn("JARVIS_CONFIG", self.dropin)       # read by nothing

    def test_installer_makes_every_directory_0700_and_every_file_0600(self):
        s = self.script
        self.assertIn('DST=$HOME_DIR/.jarvis', s)             # where ~/.jarvis resolves
        self.assertIn('find "$DST" -type d -exec chmod 0700 {} +', s)
        self.assertIn('find "$DST" -type f -exec chmod 0600 {} +', s)
        self.assertIn('chown -R jarvis:jarvis "$HOME_DIR"', s)
        self.assertNotIn("jarvis-readers", s)
        self.assertNotIn("0640", s)
        # Stopped before the copy, so a store being written is not torn.
        self.assertLess(s.index("systemctl stop jarvis.service"), s.index("rsync -a"))
        # Preflight changes nothing and exits before the stop.
        self.assertLess(s.index("[[ $mode == --preflight ]] && exit 0"),
                        s.index("systemctl stop jarvis.service"))

    def test_installer_writes_the_marker_the_cli_reads_and_rollback_removes_it(self):
        self.assertIn("MARKER=$MARKER_DIR/service-account.json", self.script)
        self.assertEqual(statedir.MARKER, "/etc/jarvis/service-account.json")
        self.assertIn('"state_dir": "%s"', self.script)
        start = self.script.index("rollback() {")
        rollback = self.script[start:self.script.index("\n}\n", start)]
        for name in ("$DROPIN", "$MARKER", "$SELFCHECK", "$SUDOERS", "$SVC_CLI"):
            self.assertIn(name, rollback)
        self.assertIn("rollback; exit 3", self.script)       # no answer -> automatic rollback

    def test_selfcheck_moves_to_the_service_account(self):
        self.assertIn("User=jarvis\n", self.selfcheck)
        self.assertIn("ExecStart=@EXEC@ selfcheck", self.selfcheck)
        self.assertIn('sed "s/^chris /jarvis /"', self.script)

    def test_scripts_parse(self):
        import shutil
        import subprocess
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("no bash")
        for rel in ("scripts/repair/install-service-user.sh", "install.sh", "quickstart.sh"):
            with self.subTest(rel=rel):
                r = subprocess.run([bash, "-n", str(ROOT / rel)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)


class InRepoCallerTests(unittest.TestCase):
    """Every in-repo API caller presents a credential the daemon accepts."""

    PS_RE = "^jc1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$"

    def test_windows_supervisors_send_a_paired_token_in_the_daemons_format(self):
        ps = re.compile(self.PS_RE)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = Store(os.path.join(tmp.name, "s.db"))
        try:
            token = clients.pair(store, "supervisor")[1]
        finally:
            store.close()
        self.assertTrue(ps.match(token))
        self.assertFalse(ps.match(token + "x") or ps.match(token.upper()))
        for rel in ("jarvis-reviver.ps1", "jarvis-health-monitor.ps1",
                    "windows-sensor/install-isolated.ps1"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(rel=rel):
                self.assertIn(self.PS_RE, text)
                self.assertIn("X-JARVIS-Token", text)
                self.assertIn("JARVIS_CLIENT_TOKEN_FILE", text)
        reviver = (ROOT / "jarvis-reviver.ps1").read_text(encoding="utf-8")
        run = reviver[reviver.index("function Invoke-Run"):]
        self.assertIn("Add-JarvisToken $req", run[:run.index("\n}\n")])

    def test_readiness_probes_use_liveness_and_state_reads_are_authenticated(self):
        for rel in ("quickstart.ps1", "quickstart.sh"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(curl|Invoke-WebRequest)[^\n]*/api/state", rel)
        self.assertIn('apiclient.request("GET", "/api/state"',
                      (ROOT / "quickstart.sh").read_text(encoding="utf-8"))
        brief = (ROOT / "jarvis/cli/commands/brief.py").read_text(encoding="utf-8")
        self.assertIn("apiclient.request(", brief)
        self.assertNotIn("token.read()", brief)
        ui = (ROOT / "scripts/dev/ui_check.py").read_text(encoding="utf-8")
        self.assertIn("apiclient.credential()", ui)

    def test_no_caller_puts_a_credential_in_a_url_or_argument(self):
        for rel in ("quickstart.sh", "install.sh", "scripts/repair/install-service-user.sh",
                    "jarvis-reviver.ps1", "jarvis-health-monitor.ps1"):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(rel=rel):
                self.assertNotRegex(text, r"[?&]token=")
                self.assertNotRegex(text, r"curl[^\n]*X-JARVIS-Token")

"""Phone pairing from the dashboard and the desktop app (jarvis/response/notify/pairing.py,
jarvis/web/phone.py): the invariants in pairing.py's docstring, success and failure paths.

A scripted relay stands in for the network; device keys are real (Identity.generate),
so the SAS and device-id checks run the real crypto.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.response.notify import crypto, devices, pairing, relay
from jarvis.web import phone

try:
    crypto._lib()
    HAVE_CRYPTO = True
except crypto.Unavailable:
    HAVE_CRYPTO = False


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeRelay:
    """Records calls; answers claims for the offered code once `phone_claims` is set."""

    def __init__(self):
        self.calls, self.claim, self.fail = [], None, {}

    def __call__(self, conf, ident, method, path, payload=None, **kw):
        relay.base_url(conf)                 # the real client validates the URL first
        self.calls.append((method, path))
        for (m, prefix), exc in list(self.fail.items()):
            if m == method and path.startswith(prefix):
                if isinstance(exc, list):
                    if exc:
                        raise exc.pop(0)
                else:
                    raise exc
        if method == "GET" and "/claims" in path:
            return [self.claim] if self.claim else []
        return {"ok": True}

    def count(self, method, needle):
        return sum(1 for m, p in self.calls if m == method and needle in p)


def phone_claim(code, device=None, name="Pixel 9"):
    d = device or crypto.Identity.generate()
    return {"code": code, "dev": crypto.key_id(d.sig_pub), "d_sig": crypto.b64u(d.sig_pub),
            "d_enc": crypto.b64u(d.enc_pub), "name": name}


@unittest.skipUnless(HAVE_CRYPTO, "python3-cryptography not installed")
class PairingStateMachine(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.reg = os.path.join(tmp.name, "devices.json")
        p = mock.patch.object(devices, "REGISTRY", self.reg)
        p.start()
        self.addCleanup(p.stop)
        self.relay = FakeRelay()
        p = mock.patch.object(relay, "call", self.relay)
        p.start()
        self.addCleanup(p.stop)
        self.server = crypto.Identity.generate()
        self.clock = Clock()
        self.sent = []
        self.activations = []

        def activate(conf, ident, dev, code):
            self.activations.append(dev)
            return pairing.activate(conf, ident, dev, code, sleep=lambda s: None)

        self.pairings = pairing.Pairings(lambda: {}, lambda: self.server, lambda conf: "laptop",
                                         now=self.clock, activate_fn=activate,
                                         send_fn=lambda conf, s, t: self.sent.append(s) or "")

    def started(self):
        view = self.pairings.start()
        self.assertEqual(view["state"], "waiting")
        return view, self.pairings.session.code

    def claimed(self, **kw):
        view, code = self.started()
        self.relay.claim = phone_claim(code, **kw)
        self.clock.t += pairing.POLL_MIN_S
        view = self.pairings.poll(view["session"])
        self.assertEqual(view["state"], "claimed")
        return view

    def assert_no_secrets(self, view):
        text = json.dumps(view)
        for key in ("d_sig", "d_enc", "sig_priv", "enc_priv", "mb", "token"):
            self.assertNotIn(key, text)
        self.assertNotIn(crypto.b64u(self.server.sig_pub), text)

    def test_pairs_only_after_the_owner_confirms_the_shown_code(self):
        view = self.claimed()
        self.assertRegex(view["sas"], r"^[0-9]{6}$")
        self.assertEqual(view["name"], "Pixel 9")
        self.assert_no_secrets(view)
        self.assertEqual(devices.active(self.reg), [], "nothing recorded before the comparison")
        done = self.pairings.confirm(view["session"], view["sas"], True)
        self.assertEqual(done["state"], "paired")
        self.assertNotIn("warning", done)
        rows = devices.active(self.reg)
        self.assertEqual([d["dev"] for d in rows], [view["device"]])
        self.assertNotIn("relay_pending", rows[0])
        self.assertEqual(self.relay.count("POST", "/activate"), 1)
        self.assertEqual(self.sent, ["laptop is paired"])
        self.assert_no_secrets(done)
        self.assertNotIn("sas", done, "the code is shown only while waiting for the comparison")

    def test_wrong_or_stale_code_is_refused_and_changes_nothing(self):
        view = self.claimed()
        wrong = f"{(int(view['sas']) + 1) % 1_000_000:06d}"
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], wrong, True)
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm("0" * 16, view["sas"], True)
        self.assertEqual(self.pairings.current()["state"], "claimed")
        self.assertEqual(devices.active(self.reg), [])
        self.assertEqual(self.relay.count("POST", "/activate"), 0)
        self.assertEqual(self.pairings.confirm(view["session"], view["sas"], True)["state"], "paired")

    def test_second_confirm_is_refused(self):
        view = self.claimed()
        self.pairings.confirm(view["session"], view["sas"], True)
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], view["sas"], True)
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], view["sas"], False)
        self.assertEqual(self.relay.count("POST", "/activate"), 1)
        self.assertEqual(self.relay.count("DELETE", "/devices/"), 0)

    def test_codes_differ_deletes_the_claim_and_records_nothing(self):
        view = self.claimed()
        done = self.pairings.confirm(view["session"], view["sas"], False)
        self.assertEqual(done["state"], "rejected")
        self.assertEqual(self.relay.count("DELETE", f"/devices/{view['device']}"), 1)
        self.assertEqual(devices.load(self.reg)["devices"], [])

    def test_confirm_without_a_claim_is_refused(self):
        view, _ = self.started()
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], "123456", True)

    def test_one_pairing_at_a_time_until_it_ends_or_expires(self):
        view, _ = self.started()
        with self.assertRaises(pairing.Busy):
            self.pairings.start()
        self.clock.t += pairing.PAIR_WAIT_S
        self.assertEqual(self.pairings.poll(view["session"])["state"], "expired")
        self.assertEqual(self.pairings.start()["state"], "waiting")

    def test_expiry_ends_a_claimed_pairing(self):
        view = self.claimed()
        self.clock.t += pairing.PAIR_WAIT_S
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], view["sas"], True)
        self.assertEqual(self.pairings.current()["state"], "expired")
        self.assertEqual(devices.active(self.reg), [])

    def test_relay_refusing_the_offer_is_an_error_not_a_hang(self):
        self.relay.fail[("PUT", "/v1/pair/")] = relay.RelayError("HTTP 503: down")
        view = self.pairings.start()
        self.assertEqual(view["state"], "error")
        self.assertIn("refused the pairing offer", view["message"])
        self.relay.fail.clear()
        self.assertEqual(self.pairings.start()["state"], "waiting")

    def test_relay_error_while_waiting_is_reported_and_retried(self):
        view, code = self.started()
        self.relay.fail[("GET", "/v1/mailbox/")] = [relay.RelayError("URLError")]
        self.clock.t += pairing.POLL_MIN_S
        v = self.pairings.poll(view["session"])
        self.assertEqual(v["state"], "waiting")
        self.assertIn("URLError", v["notice"])
        self.relay.claim = phone_claim(code)
        self.clock.t += pairing.POLL_MIN_S
        v = self.pairings.poll(view["session"])
        self.assertEqual(v["state"], "claimed")
        self.assertNotIn("notice", v)

    def test_polls_are_rate_limited_to_one_relay_call(self):
        view, _ = self.started()
        self.clock.t += pairing.POLL_MIN_S
        for _ in range(5):
            self.pairings.poll(view["session"])
        self.assertEqual(self.relay.count("GET", "/claims"), 1)

    def test_malformed_claim_or_key_mismatch_pairs_nothing(self):
        for bad in ({"d_sig": "!!", "d_enc": "x", "dev": "y"},
                    {"dev": "wrong-id-for-these-keys"}):
            view, code = self.started()
            claim = phone_claim(code)
            claim.update(bad)
            self.relay.claim = claim
            self.clock.t += pairing.POLL_MIN_S
            v = self.pairings.poll(view["session"])
            self.assertEqual(v["state"], "error", bad)
            self.assertNotIn("sas", v)
            self.assertEqual(devices.load(self.reg)["devices"], [])

    def test_claimed_name_is_made_printable(self):
        view = self.claimed(name="\n\n 123 456\x1b[8m")
        self.assertNotIn("\x1b", view["name"])
        self.assertNotIn("\n", view["name"])

    def test_activation_retry_exhaustion_leaves_a_visible_pending_device(self):
        view = self.claimed()
        self.relay.fail[("POST", "/v1/mailbox/")] = relay.RelayError("URLError")
        done = self.pairings.confirm(view["session"], view["sas"], True)
        self.assertEqual(done["state"], "paired")
        self.assertTrue(done["warning"])
        self.assertIn("did not activate", done["message"])
        self.assertEqual(self.relay.count("POST", "/activate"), pairing.ACTIVATE_TRIES)
        self.assertTrue(pairing.public_devices(self.reg)[0]["pending"])
        self.assertEqual(self.sent, [], "no test message to a phone the relay did not activate")

    def test_restart_loses_the_session_safely(self):
        view = self.claimed()
        restarted = pairing.Pairings(lambda: {}, lambda: self.server, lambda conf: "laptop", now=self.clock)
        with self.assertRaises(pairing.Refused):
            restarted.poll(view["session"])
        with self.assertRaises(pairing.Refused):
            restarted.confirm(view["session"], view["sas"], True)
        self.assertIsNone(restarted.current())
        self.assertEqual(devices.active(self.reg), [])
        self.assertEqual(self.relay.count("POST", "/activate"), 0)

    def test_cancel_removes_a_pending_claim(self):
        view = self.claimed()
        self.assertEqual(self.pairings.cancel(view["session"])["state"], "cancelled")
        self.assertEqual(self.relay.count("DELETE", "/devices/"), 1)
        with self.assertRaises(pairing.Refused):
            self.pairings.confirm(view["session"], view["sas"], True)

    def test_misconfigured_relay_url_is_an_error_state_not_a_crash(self):
        self.pairings.conf_fn = lambda: {"notify_url": "http://relay.example"}
        view = self.pairings.start()
        self.assertEqual(view["state"], "error")
        self.assertEqual(view["relay"], "")

    def test_unwritable_registry_ends_the_pairing_as_an_error(self):
        view = self.claimed()
        with mock.patch.object(devices, "save", side_effect=OSError("read-only")):
            done = self.pairings.confirm(view["session"], view["sas"], True)
        self.assertEqual(done["state"], "error")
        self.assertEqual(self.relay.count("POST", "/activate"), 0)
        self.assertEqual(self.pairings.start()["state"], "waiting")

    def test_device_list_carries_no_key_material(self):
        view = self.claimed()
        self.pairings.confirm(view["session"], view["sas"], True)
        rows = pairing.public_devices(self.reg)
        self.assertEqual(set(rows[0]), {"dev", "name", "paired_at", "revoked_at", "pending"})


@unittest.skipUnless(HAVE_CRYPTO, "python3-cryptography not installed")
class PhoneRoutes(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        p = mock.patch.object(devices, "REGISTRY", os.path.join(tmp.name, "devices.json"))
        p.start()
        self.addCleanup(p.stop)
        self.relay = FakeRelay()
        p = mock.patch.object(relay, "call", self.relay)
        p.start()
        self.addCleanup(p.stop)
        ident = crypto.Identity.generate()
        self.pairings = pairing.Pairings(lambda: {}, lambda: ident, lambda conf: "laptop")

    def post(self, path, body):
        return phone.post(path, body, None, pairings=self.pairings, conf_fn=lambda: {})

    def test_malformed_requests_are_refused_before_the_state_machine(self):
        sid = self.post("/api/phone/pair/start", {})[1]["session"]
        for body in ({}, {"session": "x"}, {"session": sid.upper()}):
            self.assertEqual(self.post("/api/phone/pair/poll", body)[0], 400, body)
        for body in ({"session": sid, "sas": "12345", "same": True},
                     {"session": sid, "sas": "abcdef", "same": True},
                     {"session": sid, "sas": "123456", "same": "yes"},
                     {"session": sid, "sas": "123456"}):
            self.assertEqual(self.post("/api/phone/pair/confirm", body)[0], 400, body)
        self.assertEqual(self.post("/api/phone/revoke", {"device": "../x"})[0], 400)

    def test_busy_and_refused_map_to_conflict(self):
        sid = self.post("/api/phone/pair/start", {})[1]["session"]
        self.assertEqual(self.post("/api/phone/pair/start", {})[0], 409)
        code, body = self.post("/api/phone/pair/confirm", {"session": sid, "sas": "123456", "same": True})
        self.assertEqual(code, 409)
        self.assertIn("nothing to confirm", body["error"])

    def test_missing_crypto_is_unavailable_not_a_crash(self):
        broken = pairing.Pairings(lambda: {}, mock.Mock(side_effect=crypto.Unavailable("no lib")),
                                  lambda conf: "x")
        code, body = phone.post("/api/phone/pair/start", {}, None, pairings=broken, conf_fn=lambda: {})
        self.assertEqual(code, 503)
        self.assertIn("unavailable", body["error"])

    def test_revoke_unknown_device_is_404(self):
        code, body = self.post("/api/phone/revoke", {"device": "abcd1234"})
        self.assertEqual(code, 404)
        self.assertFalse(body["ok"])

    def test_status_shows_no_key_material(self):
        code, body = phone.get("/api/phone/status", None, pairings=self.pairings, conf_fn=lambda: {})
        self.assertEqual(code, 200)
        self.assertEqual(body["relay"], relay.DEFAULT_URL)
        self.assertNotIn("mailbox", json.dumps(body))


class PhoneRoutesOverHttp(unittest.TestCase):
    """The routes sit behind the server's own gates (credential, same origin)."""

    def setUp(self):
        from jarvis.core.store import Store
        from jarvis.web import token as api_token
        from tests.test_api_hardening import _Server
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = os.path.join(tmp.name, "state.db")
        Store(db).close()
        old = api_token._TOKEN
        self.addCleanup(setattr, api_token, "_TOKEN", old)
        self.token = api_token.issue(os.path.join(tmp.name, "api.token"))
        self.srv = _Server(db)
        self.addCleanup(self.srv.close)
        p = mock.patch.object(phone, "PAIRINGS", mock.Mock(start=mock.Mock(return_value={"state": "waiting"}),
                                                           current=mock.Mock(return_value=None)))
        self.pairings = p.start()
        self.addCleanup(p.stop)

    def test_no_credential_no_pairing(self):
        for method, path in (("GET", "/api/phone/status"), ("GET", "/api/phone/pair"),
                             ("POST", "/api/phone/pair/start")):
            status, _, _ = self.srv.request(method, path, {} if method == "POST" else None)
            self.assertEqual(status, 403, path)
        self.pairings.start.assert_not_called()

    def test_cross_site_post_is_refused_even_with_a_credential(self):
        status, _, _ = self.srv.request("POST", "/api/phone/pair/start", {},
                                        {"X-JARVIS-Token": self.token, "Sec-Fetch-Site": "cross-site",
                                         "Content-Type": "application/json"})
        self.assertEqual(status, 403)
        self.pairings.start.assert_not_called()

    def test_credentialed_start_reaches_the_state_machine(self):
        status, _, body = self.srv.request("POST", "/api/phone/pair/start", {},
                                           {"X-JARVIS-Token": self.token, "Content-Type": "application/json"})
        self.assertEqual(status, 200, body)
        self.pairings.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()

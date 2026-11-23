import io
import json
import os
import tempfile
import unittest
from unittest import mock
from unittest.mock import patch

from jarvis.response import alert
from jarvis.response.notify import channel, crypto, devices, relay

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    HAVE = True
except ImportError:          # pragma: no cover - the server edition depends on it
    HAVE = False

VECTORS = os.path.join(os.path.dirname(__file__), "..", "hosted", "notify-cloudflare", "tests", "vectors.json")


@unittest.skipUnless(HAVE, "python3-cryptography not installed")
class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.ident = crypto.Identity.generate()
        self.d_enc = x25519.X25519PrivateKey.generate()
        self.d_sig = ed25519.Ed25519PrivateKey.generate()
        self.device = {"dev": crypto.key_id(crypto._raw(self.d_sig.public_key())),
                       "d_enc": crypto.b64u(crypto._raw(self.d_enc.public_key()))}

    def test_seal_open_round_trip_and_ids_commit_to_keys(self):
        env = crypto.seal(self.ident, self.device, {"title": "é ✓", "severity": "high"}, 1000)
        self.assertEqual(crypto.open_envelope(env, self.d_enc, self.ident.sig_pub), {"title": "é ✓", "severity": "high"})
        self.assertEqual(env["mb"], crypto.key_id(self.ident.sig_pub))
        self.assertEqual(env["expires"] - env["sent"], crypto.ENVELOPE_TTL)

    def test_tampering_and_wrong_keys_are_refused(self):
        env = crypto.seal(self.ident, self.device, {"t": 1}, 1000)
        for field, value in (("ct", env["ct"][:-2] + "AA"), ("dev", "x" * 22), ("expires", env["expires"] + 1)):
            with self.subTest(field=field), self.assertRaises(InvalidSignature):
                crypto.open_envelope({**env, field: value}, self.d_enc, self.ident.sig_pub)
        with self.assertRaises(InvalidSignature):
            crypto.open_envelope(env, self.d_enc, crypto.Identity.generate().sig_pub)     # not this server
        with self.assertRaises(InvalidTag):
            crypto.open_envelope(env, x25519.X25519PrivateKey.generate(), self.ident.sig_pub)  # not this phone

    def test_each_envelope_uses_a_fresh_ephemeral_key_and_iv(self):
        a = crypto.seal(self.ident, self.device, {"t": 1}, 1000)
        b = crypto.seal(self.ident, self.device, {"t": 1}, 1000)
        self.assertNotEqual((a["epk"], a["iv"], a["id"]), (b["epk"], b["iv"], b["id"]))

    def test_payload_size_is_bounded(self):
        with self.assertRaises(ValueError):
            crypto.seal(self.ident, self.device, {"b": "x" * (crypto.MAX_PAYLOAD + 1)}, 1000)

    def test_identity_file_is_owner_only_and_reloads(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "notify", "identity.json")
            a = crypto.Identity.load(path, create=True)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(crypto.Identity.load(path).mailbox, a.mailbox)

    def test_matches_the_shared_vectors(self):
        with open(VECTORS, encoding="utf-8") as fh:
            vec = json.load(fh)
        d_enc = x25519.X25519PrivateKey.from_private_bytes(crypto.unb64u(vec["device"]["d_enc_priv"]))
        self.assertEqual(crypto.open_envelope(vec["envelope"], d_enc, crypto.unb64u(vec["server"]["s_sig"])), vec["payload"])
        self.assertEqual(crypto.sas(*(crypto.unb64u(vec[w][k]) for w, k in (("server", "s_sig"), ("server", "s_enc"),
                                                                           ("device", "d_sig"), ("device", "d_enc")))), vec["sas"])

    def test_codes(self):
        code = crypto.pairing_code()
        self.assertEqual(len(code), 10)
        self.assertTrue(set(code) <= set(crypto.CODE_ALPHABET))
        self.assertEqual(crypto.normalize_code(crypto.format_code(code).lower()), code)
        self.assertEqual(crypto.normalize_code("ab0io-l23x9"), "AB010123X9")


class FakeOpener:
    def __init__(self, status=200, body=b'{"stored":1}'):
        self.status, self.body, self.requests = status, body, []

    def __call__(self, req, timeout):
        self.requests.append(req)
        if self.status >= 400:
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, self.status, "x", {}, io.BytesIO(b'{"error":"nope"}'))
        resp = io.BytesIO(self.body)
        resp.__enter__ = lambda *a: resp
        resp.__exit__ = lambda *a: False
        return resp


@unittest.skipUnless(HAVE, "python3-cryptography not installed")
class ChannelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        ident_path = os.path.join(self.tmp.name, "identity.json")
        reg = os.path.join(self.tmp.name, "devices.json")
        for target, value in ((crypto, ident_path), (devices, reg)):
            p = mock.patch.object(target, "IDENTITY" if target is crypto else "REGISTRY", value)
            p.start()
            self.addCleanup(p.stop)
        self.ident = crypto.Identity.load(create=True)
        self.d_enc = x25519.X25519PrivateKey.generate()
        d_sig = ed25519.Ed25519PrivateKey.generate()
        self.dev = crypto.key_id(crypto._raw(d_sig.public_key()))
        devices.add({"dev": self.dev, "d_enc": crypto.b64u(crypto._raw(self.d_enc.public_key())),
                     "d_sig": crypto.b64u(crypto._raw(d_sig.public_key())), "name": "phone"})

    def test_send_seals_for_each_device_and_signs_the_request(self):
        op = FakeOpener()
        self.assertEqual(channel.send({}, "web-1: high finding", "details", severity="high", opener=op, now=2000), "")
        req = op.requests[0]
        self.assertEqual(req.full_url, f"{relay.DEFAULT_URL}/v1/mailbox/{self.ident.mailbox}/envelopes")
        self.assertEqual(req.get_header("X-notify-key"), crypto.b64u(self.ident.sig_pub))
        [env] = json.loads(req.data)
        payload = crypto.open_envelope(env, self.d_enc, self.ident.sig_pub)
        self.assertEqual((payload["title"], payload["severity"], env["dev"]), ("web-1: high finding", "high", self.dev))
        self.assertNotIn(b"web-1", req.data, "the relay must not see the title")

    def test_relay_errors_are_reported_not_raised(self):
        self.assertIn("HTTP 403", channel.send({}, "s", "t", opener=FakeOpener(status=403)))
        self.assertIn("relay", channel.send({"notify_url": "http://example.com"}, "s", "t", opener=FakeOpener()))

    def test_revoked_device_gets_nothing_and_no_device_is_not_ready(self):
        self.assertTrue(channel.ready())
        devices.revoke(self.dev)
        self.assertFalse(channel.ready())
        self.assertEqual(channel.send({}, "s", "t", opener=FakeOpener()), "no paired device")

    def test_alert_channels_include_notify_only_when_ready(self):
        self.assertIn("notify", alert.channels({}, forwarder=False))
        devices.revoke(self.dev)
        self.assertNotIn("notify", alert.channels({}, forwarder=False))


class RegistryTests(unittest.TestCase):
    def test_owner_only_file_bounded_and_revoke_by_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "n", "devices.json")
            for i in range(devices.MAX_DEVICES):
                devices.add({"dev": f"dev{i:019d}"}, reg)
            self.assertEqual(os.stat(reg).st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                devices.add({"dev": "one-too-many"}, reg)
            self.assertEqual(devices.revoke("dev0000000000000000003", reg), "dev0000000000000000003")
            self.assertEqual(len(devices.active(reg)), devices.MAX_DEVICES - 1)
            self.assertFalse(devices.revoke("nothing", reg))

    def test_empty_short_or_ambiguous_prefix_revokes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            reg = os.path.join(d, "n", "devices.json")
            devices.add({"dev": "abcd1111"}, reg)
            devices.add({"dev": "abcd2222"}, reg)
            for prefix in ("", "a", "abcd"):
                self.assertFalse(devices.revoke(prefix, reg), prefix)
            self.assertEqual(len(devices.active(reg)), 2)
            self.assertEqual(devices.revoke("abcd2", reg), "abcd2222")
            self.assertEqual([x["dev"] for x in devices.active(reg)], ["abcd1111"])


class PairCliTests(unittest.TestCase):
    def test_pairing_refuses_without_a_terminal(self):
        from jarvis.cli.commands import notify as cli
        with mock.patch.object(cli.sys.stdin, "isatty", return_value=False):
            with self.assertRaises(SystemExit) as ctx:
                cli.cmd_pair(mock.Mock(label=None), None)
        self.assertIn("terminal", str(ctx.exception))

    def test_relay_url_must_be_https_except_local_tests(self):
        self.assertEqual(relay.base_url({}), relay.DEFAULT_URL)
        self.assertEqual(relay.base_url({"notify_url": "http://127.0.0.1:9466/"}), "http://127.0.0.1:9466")
        with self.assertRaises(relay.RelayError):
            relay.base_url({"notify_url": "http://relay.example"})
        # A prefix test let plaintext HTTP reach any host named 127.0.0.1.<anything>.
        for bad in ("http://127.0.0.1.attacker.example", "http://127.0.0.1@attacker.example",
                    "https://user:pw@relay.example", "ftp://relay.example", "https://"):
            with self.assertRaises(relay.RelayError, msg=bad):
                relay.base_url({"notify_url": bad})

    def test_claimed_name_cannot_put_escape_sequences_on_the_terminal(self):
        from jarvis.cli.commands import notify as cli
        fake = "\n\n      123 456\x1b[8m"
        shown = cli._printable(fake)
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("\n", shown)
        self.assertEqual(cli._printable("\x07\x1b"), "phone")
        self.assertEqual(cli._printable("Pixel 9"), "Pixel 9")


if __name__ == "__main__":
    unittest.main()


class ActivationTests(unittest.TestCase):
    def test_activation_retries_then_reports_and_404_stops_early(self):
        from jarvis.cli.commands import notify as cli
        calls = []

        def flaky(conf, ident, method, path, payload=None, **kw):
            calls.append(path)
            if len(calls) < 3:
                raise relay.RelayError("URLError")
            return {"ok": True}

        ident = crypto.Identity.generate()
        with patch.object(cli.relay, "call", flaky):
            self.assertEqual(cli.activate({}, ident, "d" * 22, "ABCDEFGH23", sleep=lambda s: None), "")
        self.assertEqual(len(calls), 3)
        calls.clear()
        with patch.object(cli.relay, "call", side_effect=relay.RelayError("HTTP 404: no pending claim")):
            err = cli.activate({}, ident, "d" * 22, "ABCDEFGH23", sleep=lambda s: None)
        self.assertIn("404", err)
        with patch.object(cli.relay, "call", side_effect=relay.RelayError("URLError")) as call:
            err = cli.activate({}, ident, "d" * 22, "ABCDEFGH23", sleep=lambda s: None)
        self.assertEqual(err, "URLError")
        self.assertEqual(call.call_count, cli.ACTIVATE_TRIES)

    def test_pending_devices_are_active_locally_but_visible_until_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "devices.json")
            devices.add({"dev": "x" * 22, "d_sig": "a", "d_enc": "b", "name": "p", "relay_pending": True}, path)
            self.assertTrue(devices.active(path)[0]["relay_pending"])
            devices.mark_active("x" * 22, path)
            self.assertNotIn("relay_pending", devices.active(path)[0])

"""Approving a reversible defense proposal from a paired phone (jarvis/response/notify/replies.py).

The phone is played by the test: an Ed25519/X25519 device, and a P-256 "passkey" whose WebAuthn
assertions are built by hand the way a platform authenticator builds them."""

import hashlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.response import defense
from jarvis.response.actions import base
from jarvis.response.notify import crypto, devices, replies

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
    HAVE = True
except ImportError:          # pragma: no cover
    HAVE = False

NOW = 1_800_000_000


class FakeStore:
    def __init__(self):
        self.meta = {}

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


class FakeOpener:
    """Records requests; answers GET .../replies with `replies`, everything else with {}."""

    def __init__(self, replies=None, status=200):
        self.requests, self.replies, self.status = [], replies or [], status

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        if self.status != 200:
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, self.status, "x", {}, io.BytesIO(b"{}"))
        body = json.dumps(self.replies if req.get_method() == "GET" and req.full_url.endswith("/replies") else {}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda *a: resp
        resp.__exit__ = lambda *a: False
        return resp


class FakeAction:
    id = "quarantine"
    reversible = True


class FakeIrreversible:
    id = "wipe"
    reversible = False


def entry(action="quarantine", status="proposed", target=None, **extra):
    return {"action": action, "title": "Quarantine a dropped file", "target": target or {"path": "/tmp/x"},
            "finding": {"severity": "high", "title": "dropper"}, "job": "files", "preview": "Move /tmp/x aside.",
            "status": status, "at": NOW, **extra}


@unittest.skipUnless(HAVE, "python3-cryptography not installed")
class PhoneTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for target, attr, name in ((crypto, "IDENTITY", "identity.json"), (devices, "REGISTRY", "devices.json")):
            p = mock.patch.object(target, attr, os.path.join(self.tmp.name, name))
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(base, "get", lambda i: {"quarantine": FakeAction(), "wipe": FakeIrreversible()}.get(i))
        p.start()
        self.addCleanup(p.stop)
        self.ident = crypto.Identity.load(create=True)
        self.store = FakeStore()
        self.d_sig = ed25519.Ed25519PrivateKey.generate()
        self.d_enc = x25519.X25519PrivateKey.generate()
        self.passkey = ec.generate_private_key(ec.SECP256R1())
        self.spki = self.passkey.public_key().public_bytes(serialization.Encoding.DER,
                                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        self.dev = crypto.key_id(crypto._raw(self.d_sig.public_key()))
        devices.add({"dev": self.dev, "d_sig": crypto.b64u(crypto._raw(self.d_sig.public_key())),
                     "d_enc": crypto.b64u(crypto._raw(self.d_enc.public_key())), "name": "iPhone",
                     "passkey": crypto.b64u(self.spki)})
        self.counter = 0

    # --- the phone ---
    def assertion(self, challenge, flags=0x05, origin=crypto.ORIGIN, rp=crypto.RP_ID, sign_with=None, sign_count=None):
        # A real authenticator's signature counter rises with every use.
        self.uses = getattr(self, "uses", 0) + 1
        sign_count = self.uses if sign_count is None else sign_count
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")
        client = json.dumps({"type": "webauthn.get", "challenge": crypto.b64u(challenge), "origin": origin,
                             "crossOrigin": False}).encode()
        sig = (sign_with or self.passkey).sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": "cred", "authenticatorData": crypto.b64u(auth), "clientDataJSON": crypto.b64u(client),
                "signature": crypto.b64u(sig)}

    def reply(self, approval_id, decision="approve", counter=None, assertion=None, now=NOW, challenge=None, **over):
        self.counter = counter if counter is not None else self.counter + 1
        payload = {"type": "approval", "approval_id": approval_id, "decision": decision, "counter": self.counter,
                   "at": int(now)}
        if decision == "approve":
            payload["assertion"] = assertion if assertion is not None else self.assertion(challenge)
        payload.update(over)
        return crypto.seal_reply(self.d_sig, self.dev, self.ident.mailbox, crypto.b64u(self.ident.enc_pub), payload, now)

    # --- the server ---
    def offered(self, eid="e1", ent=None, now=NOW):
        self.store.set_meta(defense.LEDGER_META, json.dumps({eid: ent or entry()}))
        op = FakeOpener()
        aid = replies.offer(self.store, {}, eid, (ent or entry()), now=now, opener=op)
        self.assertTrue(aid, "offer should have been made")
        return aid, op

    def challenge_for(self, aid):
        return crypto.unb64u(replies._state(self.store)["pending"][aid]["challenge"])


class WebAuthnTests(PhoneTestCase):
    def test_a_good_assertion_verifies_and_returns_the_counter(self):
        ch = os.urandom(32)
        self.assertEqual(crypto.verify_webauthn(self.spki, self.assertion(ch, sign_count=7), ch), 7)

    def test_every_way_to_get_it_wrong_is_refused(self):
        ch = os.urandom(32)
        cases = {
            "other challenge": self.assertion(os.urandom(32)),
            "not user-verified (UP only)": self.assertion(ch, flags=0x01),
            "not user-present": self.assertion(ch, flags=0x04),
            "other origin": self.assertion(ch, origin="https://evil.example"),
            "other relying party": self.assertion(ch, rp="evil.example"),
            "signed by another key": self.assertion(ch, sign_with=ec.generate_private_key(ec.SECP256R1())),
            "garbage": {"authenticatorData": "x"},
        }
        for name, a in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                crypto.verify_webauthn(self.spki, a, ch)

    def test_reply_round_trip_and_tamper(self):
        rep = self.reply("A" * 22, "deny")
        dsig = crypto._raw(self.d_sig.public_key())
        self.assertEqual(crypto.open_reply(rep, self.ident, dsig)["decision"], "deny")
        from cryptography.exceptions import InvalidSignature
        with self.assertRaises(InvalidSignature):
            crypto.open_reply({**rep, "ct": rep["ct"][:-2] + "AA"}, self.ident, dsig)
        with self.assertRaises(ValueError):
            crypto.open_reply({**rep, "mb": "x" * 22}, self.ident, dsig)

    def test_qr_proof_needs_the_secret_the_relay_never_sees(self):
        k, ds, de = os.urandom(16), os.urandom(32), os.urandom(32)
        proof = crypto.qr_proof(k, ds, de, self.spki)
        self.assertTrue(crypto.check_qr_proof(k, proof, ds, de, self.spki))
        self.assertFalse(crypto.check_qr_proof(os.urandom(16), proof, ds, de, self.spki))
        self.assertFalse(crypto.check_qr_proof(k, proof, os.urandom(32), de, self.spki))


class OfferTests(PhoneTestCase):
    def test_offer_seals_one_approval_for_the_passkey_phone_and_remembers_it(self):
        aid, op = self.offered()
        [env] = json.loads(op.requests[0].data)
        payload = crypto.open_envelope(env, self.d_enc, self.ident.sig_pub)
        self.assertEqual((payload["kind"], payload["approval"], payload["eid"]), ("approval", "approve", "e1"))
        self.assertEqual(payload["expires"], NOW + replies.APPROVAL_TTL)
        want = crypto.approval_challenge(aid, "e1", "quarantine", payload["target"], payload["expires"])
        self.assertEqual(payload["challenge"], crypto.b64u(want), "the phone can recompute the challenge from what it shows")
        self.assertIn(aid, replies._state(self.store)["pending"])

    def test_nothing_is_offered_for_an_irreversible_action_or_a_phone_without_a_passkey(self):
        op = FakeOpener()
        self.assertEqual(replies.offer(self.store, {}, "e2", entry("wipe"), now=NOW, opener=op), "")
        self.assertEqual(replies.offer(self.store, {}, "e3", entry(status="applied"), now=NOW, opener=op), "")
        self.assertEqual(op.requests, [])
        devices.update(self.dev, passkey="")
        self.assertEqual(replies.offer(self.store, {}, "e4", entry(), now=NOW, opener=op), "")
        self.assertEqual(op.requests, [])

    def test_defense_hears_of_phones_only_through_its_listener_list(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(defense))
        names = [a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                 for a in n.names] + [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertFalse([x for x in names if "notify" in x or "replies" in x], names)
        replies.register()
        replies.register()
        self.assertEqual(defense.PROPOSAL_LISTENERS.count(replies.queue_offer), 1)

    def test_only_serious_proposals_are_pushed_to_a_phone(self):
        op = FakeOpener()
        for i, sev in enumerate(("medium", "low", None)):
            e = entry()
            e["finding"] = {"severity": sev, "title": "x"} if sev else {"title": "x"}
            self.assertEqual(replies.offer(self.store, {}, f"m{i}", e, now=NOW, opener=op), "", sev)
        self.assertEqual(op.requests, [])
        crit = entry()
        crit["finding"] = {"severity": "critical", "title": "x"}
        self.assertTrue(replies.offer(self.store, {}, "c1", crit, now=NOW, opener=op))

    def test_the_same_proposal_is_not_offered_twice(self):
        self.offered()
        self.assertEqual(replies.offer(self.store, {}, "e1", entry(), now=NOW + 5, opener=FakeOpener()), "")

    def test_relay_failure_offers_nothing(self):
        self.store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry()}))
        self.assertEqual(replies.offer(self.store, {}, "e1", entry(), now=NOW, opener=FakeOpener(status=503)), "")
        self.assertEqual(replies._state(self.store)["pending"], {})


class ApproveTests(PhoneTestCase):
    def run_poll(self, reply_list, now=NOW + 30):
        op = FakeOpener(replies=reply_list)
        out = replies.poll(self.store, {}, now=now, opener=op)
        return out, op

    def test_approve_applies_once_records_who_and_offers_undo(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=self.challenge_for(aid))
        with mock.patch.object(defense, "approve", return_value=(True, "moved aside")) as approve:
            out, op = self.run_poll([rep])
        approve.assert_called_once()
        self.assertEqual(approve.call_args.args[1], "e1")
        self.assertTrue(approve.call_args.kwargs["by"].startswith("phone:"))
        self.assertEqual(out["handled"], 1)
        st = replies._state(self.store)
        self.assertNotIn(aid, st["pending"], "single use")
        self.assertEqual([p["kind"] for p in st["pending"].values()], ["undo"])
        self.assertEqual(st["audit"][-1]["outcome"], "approved")
        posts = [r for r in op.requests if r.get_method() == "POST"]
        self.assertTrue(any(r.full_url.endswith("/replies/ack") for r in posts), "the reply is acknowledged")
        self.assertTrue(any(r.full_url.endswith("/envelopes") for r in posts), "every phone is told")

    def test_replaying_the_same_reply_does_nothing(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=self.challenge_for(aid))
        with mock.patch.object(defense, "approve", return_value=(True, "ok")) as approve:
            self.run_poll([rep])
            self.run_poll([rep])
        self.assertEqual(approve.call_count, 1)
        self.assertEqual(replies._state(self.store)["audit"][-1]["detail"], "replayed reply")

    def test_biometric_proof_for_another_action_is_refused(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=os.urandom(32))
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep])
        approve.assert_not_called()
        self.assertIn(aid, replies._state(self.store)["pending"], "a bad try does not burn the request")

    def test_no_biometric_proof_no_approval(self):
        aid, _ = self.offered()
        rep = self.reply(aid, assertion={}, challenge=self.challenge_for(aid))
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep])
        approve.assert_not_called()

    def test_an_expired_request_cannot_be_approved(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=self.challenge_for(aid), now=NOW + replies.APPROVAL_TTL + 10)
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep], now=NOW + replies.APPROVAL_TTL + 20)
        approve.assert_not_called()

    def test_a_revoked_or_unknown_phone_is_ignored(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=self.challenge_for(aid))
        devices.revoke(self.dev)
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep])
        approve.assert_not_called()

    def test_a_reply_signed_by_someone_else_is_refused(self):
        aid, _ = self.offered()
        rep = self.reply(aid, challenge=self.challenge_for(aid))
        forged = crypto.seal_reply(ed25519.Ed25519PrivateKey.generate(), self.dev, self.ident.mailbox,
                                   crypto.b64u(self.ident.enc_pub), {"type": "approval", "approval_id": aid,
                                   "decision": "deny", "counter": 99}, NOW)
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([forged, {**rep, "ct": rep["ct"][:-2] + "AA"}])
        approve.assert_not_called()
        self.assertIn(aid, replies._state(self.store)["pending"])

    def test_a_proposal_that_changed_or_became_irreversible_is_not_applied(self):
        aid, _ = self.offered()
        self.store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry(target={"path": "/etc/passwd"})}))
        rep = self.reply(aid, challenge=self.challenge_for(aid))
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep])
        approve.assert_not_called()
        self.assertEqual(replies._state(self.store)["audit"][-1]["outcome"], "rejected")

    def test_deny_needs_no_biometric_and_applies_nothing(self):
        aid, _ = self.offered()
        rep = self.reply(aid, "deny")
        with mock.patch.object(defense, "approve") as approve:
            self.run_poll([rep])
        approve.assert_not_called()
        self.assertNotIn(aid, replies._state(self.store)["pending"])
        self.assertEqual(replies._state(self.store)["audit"][-1]["outcome"], "denied")

    def test_undo_only_for_what_a_phone_approved(self):
        aid, _ = self.offered()
        with mock.patch.object(defense, "approve", return_value=(True, "ok")):
            self.run_poll([self.reply(aid, challenge=self.challenge_for(aid))])
        [(undo_id, undo)] = [(a, p) for a, p in replies._state(self.store)["pending"].items() if p["kind"] == "undo"]
        ledger = {"e1": entry(status="applied", approved_by="operator")}
        self.store.set_meta(defense.LEDGER_META, json.dumps(ledger))
        with mock.patch.object(defense, "undo") as undo_fn:
            self.run_poll([self.reply(undo_id, challenge=crypto.unb64u(undo["challenge"]))], now=NOW + 60)
            undo_fn.assert_not_called()           # approved by the operator, not a phone
        aid2, _ = self.offered("e1", entry(status="proposed"), now=NOW + 100)
        with mock.patch.object(defense, "approve", return_value=(True, "ok")):
            self.run_poll([self.reply(aid2, challenge=self.challenge_for(aid2))], now=NOW + 120)
        [(uid, up)] = [(a, p) for a, p in replies._state(self.store)["pending"].items() if p["kind"] == "undo"]
        self.store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry(status="applied", approved_by="phone:" + self.dev[:10])}))
        with mock.patch.object(defense, "undo", return_value=(True, "restored")) as undo_fn:
            self.run_poll([self.reply(uid, challenge=crypto.unb64u(up["challenge"]))], now=NOW + 140)
        undo_fn.assert_called_once_with(self.store, "e1")

    def test_poll_makes_no_request_when_nothing_is_outstanding(self):
        op = FakeOpener()
        self.assertEqual(replies.poll(self.store, {}, now=NOW, opener=op), {"checked": False, "handled": 0})
        self.assertEqual(op.requests, [])


class QueueTests(PhoneTestCase):
    def test_a_new_proposal_is_queued_and_offered_by_the_next_tick(self):
        self.store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry()}))
        self.assertTrue(replies.queue_offer(self.store, "e1"))
        self.assertFalse(replies.queue_offer(self.store, "e1"), "queued once")
        op = FakeOpener()
        out = replies.tick(self.store, {}, now=NOW, opener=op)
        self.assertEqual(len([r for r in op.requests if r.full_url.endswith("/envelopes")]), 1)
        self.assertEqual(replies._state(self.store)["queue"], [])
        self.assertTrue(replies._state(self.store)["pending"])
        self.assertTrue(out["checked"], "outstanding request: the relay is asked for replies")

    def test_nothing_is_queued_without_a_phone_that_can_approve(self):
        devices.update(self.dev, passkey="")
        self.assertFalse(replies.queue_offer(self.store, "e1"))

    def test_a_proposal_that_was_handled_meanwhile_is_not_offered(self):
        self.store.set_meta(defense.LEDGER_META, json.dumps({"e1": entry(status="applied")}))
        replies.queue_offer(self.store, "e1")
        op = FakeOpener()
        replies.tick(self.store, {}, now=NOW, opener=op)
        self.assertEqual(op.requests, [])

    def test_an_idle_tick_does_no_network_work_and_never_raises(self):
        op = FakeOpener()
        self.assertEqual(replies.tick(self.store, {}, now=NOW, opener=op), {"checked": False, "handled": 0})
        self.assertEqual(op.requests, [])
        self.assertFalse(replies.tick(object(), {}, now=NOW).get("checked"))     # a broken store is swallowed


class QrClaimTests(PhoneTestCase):
    def setUp(self):
        super().setUp()
        from jarvis.cli.commands import notify as cli
        self.cli = cli
        self.secret = os.urandom(16)
        self.d_sig_b, self.d_enc_b = os.urandom(32), os.urandom(32)

    def claim(self, secret=None, passkey=True, swap=None):
        spki = self.spki if passkey else b""
        c = {"proof": crypto.qr_proof(secret or self.secret, self.d_sig_b, self.d_enc_b, spki)}
        if passkey:
            c["passkey"] = crypto.b64u(spki)
        if swap is not None:
            c["passkey"] = swap                 # what a hostile relay might substitute after the fact
        return c

    def test_a_claim_with_the_qr_secret_is_trusted_with_its_passkey(self):
        self.assertEqual(self.cli._qr_claim(self.secret, self.claim(), self.d_sig_b, self.d_enc_b), crypto.b64u(self.spki))
        self.assertEqual(self.cli._qr_claim(self.secret, self.claim(passkey=False), self.d_sig_b, self.d_enc_b), "")

    def test_everything_else_falls_back_to_the_six_digit_check(self):
        for name, c in (("no proof", {"passkey": crypto.b64u(self.spki)}),
                        ("relay-made proof", self.claim(secret=os.urandom(16))),
                        ("passkey swapped by the relay", self.claim(swap=crypto.b64u(os.urandom(91)))),
                        ("not a passkey", self.claim(swap="AAAA"))):
            with self.subTest(name):
                self.assertIsNone(self.cli._qr_claim(self.secret, c, self.d_sig_b, self.d_enc_b))


if __name__ == "__main__":
    unittest.main()

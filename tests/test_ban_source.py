"""Deterrence by cost: time-bounded, escalating inbound bans of guessing sources.

Invariants under test:
  * only a public, literal address from the Windows brute-force detector is
    ever a target; private, loopback, link-local, reserved and owner
    allowlisted addresses never are;
  * a ban is time-bounded: every applied ban carries an expiry, the sweep
    lifts it, and a failed lift stays applied and visible, never "expired";
  * repeat offenders are banned for longer, capped at the last rung;
  * the same address is one ledger entry whatever the attempt count;
  * the number of simultaneous automatic bans is bounded;
  * a human undo is never fought; an expiry is not a human undo.
"""

import os
import tempfile
import unittest
from unittest import mock

from jarvis.core.store import Store
from jarvis.response import defense
from jarvis.response.actions import ban_source, base
from jarvis.response.evidence import paths as evidence_paths

CONF = {"autonomous_defense": True, "auto_ban_source": True}


def guess(ip="45.155.205.7", n=31, sev="high", host="win"):
    return {"category": "bruteforce", "severity": sev, "host": host,
            "title": f"{n} failed Windows logons for admin from {ip} in 24h",
            "detail": "a concentrated logon-guessing attempt — confirm the source",
            "where": "Security log 4625"}


class FakeFirewall:
    """Records rule state the way Get/New/Remove-NetFirewallRule would."""

    def __init__(self):
        self.rules, self.calls, self.fail_remove = set(), [], False

    def __call__(self, script, timeout=30):
        self.calls.append(script)
        name = script.split("$n='", 1)[1].split("'", 1)[0]
        if "New-NetFirewallRule" in script:
            self.rules.add(name)
            return {"ok": True}
        if "Remove-NetFirewallRule" in script:
            if self.fail_remove:
                return None
            self.rules.discard(name)
            return {"ok": True}
        return {"available": True, "blocked": name in self.rules}


class BanSourceActionTests(unittest.TestCase):
    def setUp(self):
        self.action = ban_source.BanSource()

    def test_matches_only_a_public_source_from_the_windows_detector(self):
        self.assertEqual(self.action.match(guess(), "bruteforce"), {"ip": "45.155.205.7"})
        self.assertEqual(self.action.match(guess("2001:db8::1"), "bruteforce"), None)
        self.assertEqual(self.action.match(guess("2a00:1450:4001::1"), "bruteforce"),
                         {"ip": "2a00:1450:4001::1"})
        self.assertIsNone(self.action.match(guess(), "hunt"))
        self.assertIsNone(self.action.match(guess(host="wsl"), "bruteforce"))
        self.assertIsNone(self.action.match({**guess(), "category": "logins"}, "bruteforce"))

    def test_never_targets_non_public_or_unparseable_sources(self):
        for ip in ("10.0.0.5", "192.168.1.20", "172.16.3.4", "127.0.0.1", "169.254.1.1",
                   "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1",
                   "fe80::1", "fd00::1", "local", "-", "", "1.2.3", "45.155.205.7;calc"):
            with self.subTest(ip=ip):
                self.assertIsNone(self.action.match(guess(ip), "bruteforce"))

    def test_a_crafted_username_cannot_choose_the_banned_address(self):
        # The username in the title is the guesser's text; only the detector's
        # trailing "from <ip> in 24h" names the source.
        for user in ("x from 8.8.8.8 in 24h", "a from 1.1.1.1 in 1h b"):
            with self.subTest(user=user):
                f = {**guess(), "title": f"31 failed Windows logons for {user} from 45.155.205.7 in 24h"}
                self.assertEqual(self.action.match(f, "bruteforce"), {"ip": "45.155.205.7"})
        f = {**guess(), "title": "31 failed Windows logons for x from 8.8.8.8 in 24h from local in 24h"}
        self.assertIsNone(self.action.match(f, "bruteforce"))

    def test_owner_allowlist_refuses_the_target(self):
        target = {"ip": "8.8.4.4"}
        self.assertTrue(self.action.permitted(target, {})[0])
        ok, why = self.action.permitted(target, {"ban_allowlist": ["8.8.4.0/24"]})
        self.assertFalse(ok)
        self.assertIn("allowlist", why)
        # A malformed allowlist entry is ignored, never widened to "everything".
        self.assertTrue(self.action.permitted(target, {"ban_allowlist": ["nonsense", 5]})[0])

    def test_ban_length_escalates_and_is_capped(self):
        lengths = [self.action.ttl({"ip": "8.8.8.8"}, n) for n in range(6)]
        self.assertEqual(lengths[:4], list(ban_source.ESCALATION))
        self.assertEqual(lengths[4:], [ban_source.ESCALATION[-1]] * 2)
        self.assertTrue(all(a < b for a, b in zip(lengths[:4], lengths[1:4])))
        self.assertLessEqual(max(lengths), 7 * 86400)

    def test_scripts_interpolate_only_a_validated_literal(self):
        fw = FakeFirewall()
        with mock.patch.object(self.action, "_run", fw):
            ok, record, _ = self.action.apply({"ip": "8.8.8.8"}, None)
            self.assertTrue(ok)
            self.assertEqual(record["name"], "JARVIS-ban-8.8.8.8")
            self.assertIn("-Direction Inbound", fw.calls[-1])
            ok, _, _ = self.action.apply({"ip": "8.8.8.8';calc;'"}, None)
            self.assertFalse(ok)
            self.assertEqual(len(fw.calls), 1)
            self.assertFalse(self.action.undo({"ip": "x"}, {"name": "JARVIS-ban-x'"})[0])
            self.assertEqual(len(fw.calls), 1)

    def test_apply_undo_and_recover_agree_on_rule_state(self):
        fw = FakeFirewall()
        with mock.patch.object(self.action, "_run", fw):
            target = {"ip": "8.8.8.8"}
            self.assertEqual(self.action.recover(target, {})[0], "not_applied")
            ok, record, _ = self.action.apply(target, None)
            self.assertTrue(ok)
            state, rec, _ = self.action.recover(target, {})
            self.assertEqual((state, rec["name"]), ("applied", record["name"]))
            self.assertTrue(self.action.undo(target, record)[0])
            self.assertEqual(fw.rules, set())

    def test_registered_auto_and_reversible(self):
        self.assertIs(base.get("ban_source").__class__, ban_source.BanSource)
        self.assertTrue(self.action.reversible)
        self.assertEqual(self.action.enable_flag, "auto_ban_source")


class BanLadderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.epatch = mock.patch.object(evidence_paths, "EVIDENCE_ROOT",
                                        os.path.join(self.tmp.name, "evidence"))
        self.epatch.start()
        self.fw = FakeFirewall()
        self.rpatch = mock.patch.object(ban_source.BanSource, "_run",
                                        lambda _self, s, timeout=30: self.fw(s, timeout))
        self.rpatch.start()

    def tearDown(self):
        self.rpatch.stop()
        self.epatch.stop()
        self.tmp.cleanup()

    def _bans(self):
        return {k: v for k, v in defense.load(self.store).items() if v["action"] == "ban_source"}

    def test_off_by_default_only_proposes(self):
        out = defense.process(self.store, {}, "bruteforce", [guess()])
        self.assertEqual(out[0]["defense"]["rung"], defense.PROPOSE)
        self.assertEqual(self.fw.rules, set())

    def test_medium_severity_never_bans_unasked(self):
        out = defense.process(self.store, CONF, "bruteforce", [guess(sev="medium")])
        self.assertNotEqual(out[0].get("defense", {}).get("rung"), defense.AUTO)
        self.assertEqual(self.fw.rules, set())

    def test_allowlisted_source_is_never_banned_or_proposed(self):
        conf = {**CONF, "ban_allowlist": ["45.155.205.0/24"]}
        out = defense.process(self.store, conf, "bruteforce", [guess()])
        self.assertNotIn("defense", out[0])
        self.assertEqual(self._bans(), {})

    def test_enabled_ban_carries_an_expiry_and_evidence(self):
        defense.process(self.store, CONF, "bruteforce", [guess()], now=1000)
        (eid, entry), = self._bans().items()
        self.assertEqual(entry["status"], "applied")
        self.assertEqual(entry["expires_at"], 1000 + ban_source.ESCALATION[0])
        self.assertEqual(entry["applications"], 1)
        self.assertTrue(entry["evidence"])
        self.assertEqual(self.fw.rules, {"JARVIS-ban-45.155.205.7"})

    def test_changing_attempt_count_is_the_same_ban(self):
        defense.process(self.store, CONF, "bruteforce", [guess(n=31)], now=1000)
        defense.process(self.store, CONF, "bruteforce", [guess(n=57)], now=1100)
        self.assertEqual(len(self._bans()), 1)
        self.assertEqual(sum("New-NetFirewallRule" in c for c in self.fw.calls), 1)

    def test_expiry_lifts_the_ban_and_recurrence_escalates(self):
        defense.process(self.store, CONF, "bruteforce", [guess()], now=1000)
        self.assertEqual(defense.expire(self.store, now=1000 + 10), [])
        lifted = defense.expire(self.store, now=1000 + ban_source.ESCALATION[0])
        self.assertEqual(len(lifted), 1)
        (eid, entry), = self._bans().items()
        self.assertEqual(entry["status"], "expired")
        self.assertEqual(self.fw.rules, set())
        # The source comes back: expiry is not a human undo, so it is banned
        # again, for the next, longer rung.
        t = 1000 + ban_source.ESCALATION[0] + 60
        out = defense.process(self.store, CONF, "bruteforce", [guess(n=40)], now=t)
        self.assertEqual(out[0]["defense"]["rung"], defense.AUTO)
        entry = self._bans()[eid]
        self.assertEqual(entry["status"], "applied")
        self.assertEqual(entry["applications"], 2)
        self.assertEqual(entry["expires_at"], t + ban_source.ESCALATION[1])

    def test_failed_lift_stays_applied_and_visible(self):
        defense.process(self.store, CONF, "bruteforce", [guess()], now=1000)
        self.fw.fail_remove = True
        lifted = defense.expire(self.store, now=10 ** 9)
        self.assertEqual(lifted, [])
        (_, entry), = self._bans().items()
        self.assertEqual(entry["status"], "applied")
        self.assertIn("could not", entry["expire_error"])
        self.fw.fail_remove = False
        self.assertEqual(len(defense.expire(self.store, now=10 ** 9)), 1)

    def test_human_undo_is_not_fought_after_expiry_logic(self):
        defense.process(self.store, CONF, "bruteforce", [guess()], now=1000)
        (eid, _), = self._bans().items()
        self.assertTrue(defense.undo(self.store, eid)[0])
        self.assertEqual(defense.expire(self.store, now=10 ** 9), [])
        out = defense.process(self.store, CONF, "bruteforce", [guess(n=90)], now=2000)
        self.assertEqual(out[0]["defense"]["rung"], defense.PROPOSE)
        self.assertEqual(self.fw.rules, set())

    def test_approved_ban_is_also_time_bounded_and_respects_allowlist(self):
        defense.process(self.store, {}, "bruteforce", [guess()])
        (eid, _), = self._bans().items()
        ok, why = defense.approve(self.store, eid, now=500,
                                  conf={"ban_allowlist": ["45.155.205.7"]})
        self.assertFalse(ok)
        self.assertIn("allowlist", why)
        self.assertEqual(self.fw.rules, set())
        ok, _ = defense.approve(self.store, eid, now=500, conf={})
        self.assertTrue(ok)
        self.assertEqual(self._bans()[eid]["expires_at"], 500 + ban_source.ESCALATION[0])

    def test_simultaneous_automatic_bans_are_bounded(self):
        with mock.patch.object(ban_source.BanSource, "max_active", 2):
            findings = [guess(f"8.8.8.{i}") for i in range(1, 5)]
            out = defense.process(self.store, CONF, "bruteforce", findings, now=1000)
        rungs = [f["defense"]["rung"] for f in out]
        self.assertEqual(rungs.count(defense.AUTO), 2)
        self.assertEqual(rungs.count(defense.PROPOSE), 2)
        self.assertEqual(len(self.fw.rules), 2)

    def test_interrupted_ban_is_recovered_with_its_expiry(self):
        def boom(_self, target, case):
            self.fw.rules.add("JARVIS-ban-45.155.205.7")
            raise KeyboardInterrupt  # simulated crash after the side effect
        with mock.patch.object(ban_source.BanSource, "apply", boom):
            with self.assertRaises(KeyboardInterrupt):
                defense.process(self.store, CONF, "bruteforce", [guess()], now=1000)
        (eid, entry), = self._bans().items()
        self.assertEqual(entry["status"], "attempting")
        defense.reconcile(self.store, now=1200)
        entry = self._bans()[eid]
        self.assertEqual(entry["status"], "applied")
        self.assertEqual(entry["expires_at"], 1200 + ban_source.ESCALATION[0])
        self.assertEqual(len(defense.expire(self.store, now=10 ** 9)), 1)
        self.assertEqual(self.fw.rules, set())


class SchedulerSweepTests(unittest.TestCase):
    def test_sweep_is_throttled_and_never_raises(self):
        from jarvis.service import scheduler
        sched = scheduler.Scheduler.__new__(scheduler.Scheduler)
        with mock.patch.object(defense, "expire", side_effect=ValueError("corrupt")) as ex:
            sched._sweep_expiry(None, now=100.0)
            sched._sweep_expiry(None, now=100.0 + scheduler.EXPIRY_SWEEP_S - 1)
            self.assertEqual(ex.call_count, 1)
            sched._sweep_expiry(None, now=100.0 + scheduler.EXPIRY_SWEEP_S)
            self.assertEqual(ex.call_count, 2)


if __name__ == "__main__":
    unittest.main()

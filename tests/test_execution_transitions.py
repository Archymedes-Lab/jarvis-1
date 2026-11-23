"""Change-level observability: transitions, identity, invariants."""

import unittest

from jarvis.core import event as event_mod
from jarvis.core.execution import identity, invariants, protected, transitions
from jarvis.intel import visibility


class TransitionVocabularyTests(unittest.TestCase):
    def test_new_transitions_are_canonical(self):
        for pair in (("thread", "start"), ("thread", "exit"),
                     ("process", "image_unload"), ("network", "end"),
                     ("file", "write"), ("file", "rename"),
                     ("service", "created"), ("account", "changed"),
                     ("device", "connected"), ("memory", "protection_changed")):
            self.assertIn(pair[0], event_mod.CATEGORIES)
            self.assertIn(pair[1], event_mod.CATEGORIES[pair[0]])
            self.assertTrue(transitions.is_transition(*pair))

    def test_window_summary_is_bounded_and_cites_seqs(self):
        events = [{"seq": i, "category": "process", "action": "start"}
                  for i in range(10)]
        out = transitions.summarize_window(events, limit=200)
        self.assertEqual(out["changes"], {"process:start": 10})
        self.assertEqual((out["first_seq"], out["last_seq"]), (0, 9))

    def test_mismatch_escalates_deterministically(self):
        self.assertEqual(transitions.level_for("CROSS_VIEW_MISMATCH"), "L2")
        self.assertEqual(transitions.level_for("VERIFIED_PROCESS", "L2",
                                               pressured=True), "L1")


class IdentityTests(unittest.TestCase):
    def test_pid_reuse_splits_identities(self):
        a = identity.process_key(device="d", boot="b1", pid=4832,
                                 start="t0")
        b = identity.process_key(device="d", boot="b2", pid=4832,
                                 start="t0")
        self.assertNotEqual(a, b)

    def test_guid_wins_over_pid(self):
        self.assertTrue(identity.process_key(
            boot="b", pid=1, guid="g").startswith("proc:guid:"))

    def test_connection_binds_exact_execution(self):
        p = identity.process_key(guid="powershell-exec-1")
        c = identity.connection_key(p, remote="203.0.113.7:443")
        self.assertIn("powershell-exec-1", c)


class InvariantTests(unittest.TestCase):
    def test_thread_without_owner_is_violation_not_malware(self):
        out = invariants.check(
            threads=[{"key": "t1", "process_key": "ghost"}],
            known_processes={"real"})
        self.assertEqual(out[0]["violation"], "thread-without-process")
        self.assertNotIn("malware", str(out).lower())

    def test_gapped_coverage_never_fires_creation_gap(self):
        out = invariants.check(snapshots=[{"key": "s1"}],
                               start_keys=set(), coverage_valid=False)
        self.assertEqual(out, [])

    def test_exit_contradiction_cites_sample(self):
        out = invariants.check(
            post_exit_samples=[{"key": "p1", "sample": "cpu@T+2s"}])
        self.assertEqual(out[0]["violation"], "exit-contradiction")

    def test_detector_returns_visibility_records(self):
        out = visibility.detect(
            connections=[{"key": "c1", "process_key": "ghost"}],
            known_processes=set())
        self.assertEqual(out[0]["category"], "visibility")
        self.assertEqual(out[0]["violation"], "connection-without-process")


class ProtectedTests(unittest.TestCase):
    def test_restricted_ppl_is_expected_not_suspicious(self):
        verdict = protected.classify(name="lsass.exe", lifecycle_ok=True,
                                     memory_restricted=True,
                                     protection="PPL-WindowsTCB")
        self.assertEqual(verdict["state"], "EXPECTED_PROTECTED_PROCESS")
        self.assertEqual(verdict["severity"], "ok")

    def test_restriction_alone_never_convicts(self):
        verdict = protected.classify(name="foo.exe", lifecycle_ok=False,
                                     memory_restricted=True)
        self.assertNotEqual(verdict["state"], "EXPECTED_PROTECTED_PROCESS")
        self.assertNotEqual(verdict["severity"], "high")


if __name__ == "__main__":
    unittest.main()

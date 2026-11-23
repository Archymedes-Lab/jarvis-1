"""selfcheck restarts through the root-owned restart gate when it is installed
(service/selfcheck.py): a refusal or the rate limit is final, never bypassed."""

import unittest
from unittest import mock

from jarvis.service import selfcheck as S


class GateRestart(unittest.TestCase):
    def setUp(self):
        self.calls = []
        patches = [mock.patch.object(S, "unit_state", return_value=("system", "active")),
                   mock.patch.object(S.os, "access", side_effect=lambda p, m: p == S.RESTART_GATE),
                   mock.patch.object(S.time, "sleep")]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_with(self, gate_rc, active="active"):
        def fake_run(cmd, env=None):
            self.calls.append(cmd)
            if cmd[:3] == ["sudo", "-n", S.RESTART_GATE]:
                return gate_rc, "refused: the daemon answers its health endpoint" if gate_rc else "restarted", ""
            return 0, "", ""
        with mock.patch.object(S, "_run", side_effect=fake_run), \
                mock.patch.object(S, "check", return_value={"active_state": active, "healthy": False}):
            return S.restart(attempts=3)

    def test_refusal_is_final_and_never_falls_back_to_systemctl(self):
        err = self.run_with(S.GATE_REFUSED)
        self.assertIn("declined", err)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(any("systemctl" in c and "restart" in c for c in self.calls))

    def test_rate_limit_is_final(self):
        self.assertIn("declined", self.run_with(S.GATE_RATE_LIMITED))
        self.assertEqual(len(self.calls), 1)

    def test_success_through_the_gate(self):
        self.assertEqual(self.run_with(0), "")
        self.assertEqual(self.calls[0], ["sudo", "-n", S.RESTART_GATE, "--actor", "selfcheck",
                                         "--reason", "health-silent"])

    def test_reason_follows_the_unit_state(self):
        self.run_with(0, active="failed")
        self.assertEqual(self.calls[0][-1], "unit-down")

    def test_without_the_gate_the_legacy_path_is_unchanged(self):
        with mock.patch.object(S.os, "access", return_value=False), \
                mock.patch.object(S, "_systemctl", return_value=(0, "", "")) as sc, \
                mock.patch.object(S, "check", return_value={"active_state": "active"}):
            self.assertEqual(S.restart(attempts=1), "")
        sc.assert_called_with("restart", S.UNIT, user=False, privileged=True)


if __name__ == "__main__":
    unittest.main()

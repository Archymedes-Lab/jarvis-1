"""Typed observations and bounded coherent confirmation."""

import unittest
from unittest import mock

from jarvis.collectors.host.posture import sections
from jarvis.collectors.process.hidden import sockets
from jarvis.collectors.process.hidden.run import _orphan_finding
from jarvis.core import observation as obs


class ReadingTests(unittest.TestCase):
    SENT = {65535: "not initialized"}

    def test_sentinel_is_unknown_from_a_healthy_sensor(self):
        for raw in (65535, 70000):
            r = obs.reading("age", raw, self.SENT)
            self.assertEqual((r.verdict, r.health, r.value), (obs.UNKNOWN, obs.HEALTHY, None))

    def test_missing_value_is_unavailable_and_malformed_is_degraded(self):
        self.assertEqual(obs.reading("age", None, self.SENT).health, obs.UNAVAILABLE)
        for raw in ("3", True, 2.5):
            with self.subTest(raw=raw):
                r = obs.reading("age", raw, self.SENT)
                self.assertEqual((r.verdict, r.health), (obs.UNKNOWN, obs.DEGRADED))

    def test_judge_only_applies_to_real_values(self):
        safe = obs.judge(obs.reading("age", 1, self.SENT), lambda d: d <= 3)
        stale = obs.judge(obs.reading("age", 20, self.SENT), lambda d: d <= 3)
        unknown = obs.judge(obs.reading("age", 65535, self.SENT), lambda d: True)
        self.assertEqual(safe.verdict, obs.KNOWN_SAFE)
        self.assertEqual(stale.verdict, obs.KNOWN_UNSAFE)
        self.assertEqual(unknown.verdict, obs.UNKNOWN)

    def test_unavailable_sensor_cannot_know(self):
        with self.assertRaises(ValueError):
            obs.Observation("x", obs.KNOWN_SAFE, obs.UNAVAILABLE)
        with self.assertRaises(ValueError):
            obs.Observation("x", "probably_fine", obs.HEALTHY)


class DefenderAgeTests(unittest.TestCase):
    ON = {"RealTimeProtectionEnabled": True, "IsTamperProtected": True,
          "BehaviorMonitorEnabled": True, "AMRunningMode": "Normal"}

    def titles(self, age):
        d = {"defender": {**self.ON, **({} if age is ... else {"AntivirusSignatureAge": age})},
             "mppref": {"PUAProtection": 1, "EnableNetworkProtection": 1}}
        return {(f["severity"], f["title"]) for f in sections._malware_defense(d)}

    def test_sentinel_missing_and_malformed_ages_are_unknown_not_current(self):
        for age in (65535, None, "7", ...):
            with self.subTest(age=age):
                self.assertIn(("low", "Defender signature age is not known yet"),
                              self.titles(age))

    def test_real_ages_are_judged(self):
        self.assertNotIn("Defender signature age is not known yet",
                         {t for _, t in self.titles(1)})
        self.assertIn(("medium", "malware signatures are 7 days old"), self.titles(7))
        self.assertIn(("high", "malware signatures are 20 days old"), self.titles(20))


class ConfirmTests(unittest.TestCase):
    FIRST = {"id": 7, "state": "LISTEN"}

    def run_confirm(self, view, same_epoch=None):
        return obs.confirm(self.FIRST, view, same_epoch=same_epoch, sleep=lambda _: None)

    def test_outcomes(self):
        self.assertEqual(self.run_confirm(lambda: {7: dict(self.FIRST)}).outcome, obs.CONFIRMED)
        self.assertEqual(self.run_confirm(lambda: {}).outcome, obs.TRANSIENT)
        self.assertEqual(self.run_confirm(lambda: {7: {"id": 7, "state": "x"}}).outcome,
                         obs.INCONCLUSIVE)
        self.assertEqual(self.run_confirm(lambda: None).outcome, obs.INCONCLUSIVE)

    def test_failed_requery_is_inconclusive_not_clean(self):
        def boom():
            raise OSError("gone")
        r = self.run_confirm(boom)
        self.assertEqual(r.outcome, obs.INCONCLUSIVE)
        self.assertEqual(r.first, self.FIRST)

    def test_epoch_change_between_views_is_inconclusive(self):
        r = self.run_confirm(lambda: {7: dict(self.FIRST)}, same_epoch=lambda: False)
        self.assertEqual(r.outcome, obs.INCONCLUSIVE)

    def test_first_observation_is_always_kept(self):
        for view in (lambda: {}, lambda: {7: dict(self.FIRST)}, lambda: None):
            self.assertIs(self.run_confirm(view).first, self.FIRST)

    def test_exactly_one_bounded_requery(self):
        calls, slept = [], []
        obs.confirm(self.FIRST, lambda: calls.append(1) or {}, delay=99,
                    sleep=slept.append)
        self.assertEqual(len(calls), 1)
        self.assertEqual(slept, [obs.CONFIRM_MAX_DELAY_S])


class SocketConfirmationTests(unittest.TestCase):
    ROW = {"proto": "tcp", "local_ip": "127.0.0.1", "local_port": 443,
           "remote_ip": "127.0.0.1", "remote_port": 50000, "state": "ESTABLISHED"}

    def orphans(self, second, coherent=True):
        with mock.patch.object(sockets, "_unclaimed_socket_rows",
                               side_effect=[(True, {11: self.ROW}, 0), second]), \
             mock.patch.object(sockets.time, "sleep"), \
             mock.patch.object(sockets.epochs, "coherent", return_value=coherent):
            return sockets.orphan_sockets()

    def test_transient_first_sighting_is_retained_as_low_evidence(self):
        rows, _ = self.orphans((True, {}, 0))
        self.assertEqual(rows[0]["_verification"], obs.TRANSIENT)
        f = _orphan_finding(rows[0], True)
        self.assertEqual((f["severity"], f["title"]),
                         ("low", "unowned socket closed before confirmation"))

    def test_sleep_between_views_keeps_the_original_severity(self):
        rows, _ = self.orphans((True, {11: self.ROW}, 0), coherent=False)
        self.assertEqual(rows[0]["_verification"], obs.INCONCLUSIVE)
        self.assertEqual(_orphan_finding(rows[0], True)["severity"], "high")

    def test_confirmed_stays_high(self):
        rows, _ = self.orphans((True, {11: self.ROW}, 0))
        self.assertEqual(rows[0]["_verification"], obs.CONFIRMED)
        self.assertEqual(_orphan_finding(rows[0], True)["severity"], "high")


if __name__ == "__main__":
    unittest.main()

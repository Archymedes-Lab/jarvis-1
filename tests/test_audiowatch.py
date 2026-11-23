import json
import os
import tempfile
import unittest
from unittest import mock

from jarvis.collectors.host import audiowatch
from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.service.jobs import RUNNERS
from jarvis.service.schedule import JOBS


def sample(render="speaker", capture="mic", pid=100, started="2026-09-26T10:00:00Z"):
    endpoints = [{"id": render, "flow": "render", "state": 1},
                 {"id": capture, "flow": "capture", "state": 1}]
    defaults = [{"flow": flow, "role": role,
                 "id": render if flow == "render" else capture}
                for flow in ("render", "capture")
                for role in ("console", "multimedia", "communications")]
    sessions = [{"endpoint": render, "flow": "render", "state": 1,
                 "pid": pid, "processStart": started, "processSession": 4,
                 "identityKnown": True, "singleProcess": True,
                 "systemSounds": False}]
    burst = {"durationMs": 8000, "elapsedMs": 8100, "samples": 400,
             "endpointsSampled": 1, "sustained": 0, "truncated": False,
             "events": [], "errors": []}
    return {"endpoints": endpoints, "defaults": defaults, "sessions": sessions,
            "errors": [], "truncated": False, "burst": burst}


def beep(endpoint="speaker", pid=100, started="2026-09-26T10:00:00Z",
         duration=200, peak=0.3, known=True, system=False):
    return {"endpoint": endpoint, "startMs": 1000, "durationMs": duration,
            "peak": peak, "pid": pid if known else 0,
            "processStart": started if known else None,
            "identityKnown": known, "systemSounds": system}


class AudioWatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "test.db"))
        self.addCleanup(self.store.close)

    def test_registered_with_bounded_schedule(self):
        self.assertIn("audio", RUNNERS)
        self.assertEqual(JOBS["audio"][0], 300)

    def test_clean_baseline_then_render_and_capture_route_changes(self):
        first = sample()
        next_sample = sample(render="headset", capture="usb-mic")
        next_sample["endpoints"] += first["endpoints"]
        with mock.patch.object(audiowatch, "ps_json", side_effect=[first, next_sample]):
            with collection.observe() as initial:
                first_findings = audiowatch.audit(self.store, hosts=("win",))
            with collection.observe() as changed:
                findings = audiowatch.audit(self.store, hosts=("win",))
        self.assertEqual(initial.status, "complete")
        self.assertEqual(changed.status, "complete")
        self.assertFalse(any(f["title"] == "default audio route changed"
                             for f in first_findings))
        routes = [f for f in findings if f["title"] == "default audio route changed"]
        self.assertEqual(len(routes), 6)
        self.assertEqual({f["severity"] for f in routes}, {"low", "medium"})
        self.assertTrue(any(f["title"] == "audio render session became active"
                            for f in findings))

    def test_pid_reuse_cannot_hide_a_new_session(self):
        before = sample()
        after = sample(started="2026-09-26T11:00:00Z")
        findings = audiowatch.compare(after, dict(before, schema=1))
        self.assertTrue(any(f["title"] == "audio render session became active"
                            for f in findings))

    def test_shared_session_has_no_exact_actor_claim(self):
        data = sample()
        data["sessions"][0]["identityKnown"] = False
        data["sessions"][0]["singleProcess"] = False
        findings = audiowatch.compare(data, dict(sample(), schema=1))
        self.assertFalse(any(f["title"] == "audio render session became active"
                             for f in findings))
        self.assertIn("1 active session(s) without exact process identity",
                      findings[-1]["detail"])

    def test_failure_and_retry_exhaustion_retain_last_clean_evidence(self):
        with mock.patch.object(audiowatch, "ps_json", return_value=sample()):
            audiowatch.audit(self.store, hosts=("win",))
        old = self.store.get_meta(audiowatch._STATE_KEY)
        bad = sample(render="headset")
        bad["errors"] = ["Core Audio session enumeration unavailable"]
        with mock.patch.object(audiowatch, "ps_json", side_effect=[bad, None, bad]):
            for _ in range(3):
                with collection.observe() as observation:
                    findings = audiowatch.audit(self.store, hosts=("win",))
                self.assertNotEqual(observation.status, "complete")
                self.assertEqual(findings[0]["category"], "visibility")
                self.assertEqual(self.store.get_meta(audiowatch._STATE_KEY), old)

    def test_truncation_or_malformed_route_is_not_clean(self):
        for mutation in (lambda d: d.update(truncated=True),
                         lambda d: d["defaults"].pop(),
                         lambda d: d["sessions"][0].update(endpoint="absent")):
            data = sample()
            mutation(data)
            with self.subTest(data=data), mock.patch.object(
                    audiowatch, "ps_json", return_value=data):
                with collection.observe() as observation:
                    findings = audiowatch.audit(self.store, hosts=("win",))
            self.assertNotEqual(observation.status, "complete")
            self.assertEqual(findings[0]["category"], "visibility")

    def test_beep_is_reported_with_exact_process_and_honest_limits(self):
        data = sample()
        data["burst"]["events"] = [beep(), beep(duration=400, peak=0.5)]
        findings = audiowatch.compare(data, {})
        bursts = [f for f in findings if f["title"] == "short audio burst (beep-like)"]
        self.assertEqual(len(bursts), 1)
        self.assertEqual(bursts[0]["severity"], "low")
        self.assertIn("2 burst(s) of 200-400 ms", bursts[0]["detail"])
        self.assertIn("process 100 started 2026-09-26T10:00:00Z", bursts[0]["detail"])
        self.assertIn("not verified", bursts[0]["detail"])
        self.assertIn("a beep outside that window is not seen", findings[-1]["detail"])

    def test_unattributed_and_system_beeps_claim_no_process(self):
        data = sample()
        data["burst"]["events"] = [beep(known=False), beep(known=False, system=True)]
        details = [f["detail"] for f in audiowatch.compare(data, {})
                   if f["title"] == "short audio burst (beep-like)"]
        self.assertEqual(len(details), 2)
        self.assertTrue(any("no exact process identity" in d for d in details))
        self.assertTrue(any("system sounds session" in d for d in details))

    def test_sustained_sound_is_not_called_a_beep(self):
        data = sample()
        data["burst"]["sustained"] = 2
        titles = [f["title"] for f in audiowatch.compare(data, {})]
        self.assertNotIn("short audio burst (beep-like)", titles)
        self.assertIn("continuous audio output during the burst window", titles)

    def test_missing_or_malformed_burst_is_not_clean(self):
        mutations = (lambda d: d.pop("burst"),
                     lambda d: d["burst"].update(events=[beep(endpoint="absent")]),
                     lambda d: d["burst"].update(events=[beep(peak=1.5)]),
                     lambda d: d["burst"].update(events=[beep(duration=5000)]),
                     lambda d: d["burst"].update(events=[beep() for _ in range(33)]),
                     lambda d: d["burst"].update(samples="many"),
                     lambda d: d["burst"].update(events=[dict(beep(), pid=0)]))
        for mutation in mutations:
            data = sample()
            mutation(data)
            with self.subTest(data=data), mock.patch.object(
                    audiowatch, "ps_json", return_value=data):
                with collection.observe() as observation:
                    findings = audiowatch.audit(self.store, hosts=("win",))
            self.assertNotEqual(observation.status, "complete")
            self.assertEqual(findings[0]["category"], "visibility")

    def test_meter_failure_keeps_routes_but_marks_beep_visibility_partial(self):
        for mutation in (lambda d: d["burst"].update(errors=["peak meter unavailable"]),
                         lambda d: d["burst"].update(truncated=True),
                         lambda d: d["burst"].update(endpointsSampled=0),
                         lambda d: d["burst"].update(elapsedMs=100)):
            data = sample()
            mutation(data)
            with self.subTest(data=data), mock.patch.object(
                    audiowatch, "ps_json", return_value=data):
                with collection.observe() as observation:
                    findings = audiowatch.audit(self.store, hosts=("win",))
            self.assertNotEqual(observation.status, "complete")
            self.assertIn("audio beep detection incomplete",
                          [f["title"] for f in findings])
            saved = json.loads(self.store.get_meta(audiowatch._STATE_KEY))
            self.assertEqual(saved["schema"], 1)

    def test_clean_burst_completes_and_events_do_not_repeat_next_pass(self):
        first = sample()
        first["burst"]["events"] = [beep()]
        second = sample()
        with mock.patch.object(audiowatch, "ps_json", side_effect=[first, second]):
            with collection.observe() as one:
                a = audiowatch.audit(self.store, hosts=("win",))
            with collection.observe() as two:
                b = audiowatch.audit(self.store, hosts=("win",))
        self.assertEqual((one.status, two.status), ("complete", "complete"))
        self.assertTrue(any(f["title"] == "short audio burst (beep-like)" for f in a))
        self.assertFalse(any(f["title"] == "short audio burst (beep-like)" for f in b))

    def test_disabled_windows_is_visibility_loss(self):
        with collection.observe() as observation:
            findings = audiowatch.audit(self.store, hosts=("wsl",))
        self.assertEqual(observation.status, "unavailable")
        self.assertEqual(findings[0]["category"], "visibility")


if __name__ == "__main__":
    unittest.main()

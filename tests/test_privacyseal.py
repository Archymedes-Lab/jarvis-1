import json
import os
import tempfile
import time
import unittest
from unittest import mock

from jarvis.cli.commands import privacy as privacy_cli
from jarvis.collectors.host import audiowatch, privacyseal
from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.service.jobs import RUNNERS
from jarvis.service.schedule import JOBS, WINDOWS_ONLY

FT_EPOCH = 116444736000000000


def filetime(unix):
    return int(unix * 1e7) + FT_EPOCH


def cap(glob="Allow", desktop="Allow", apps=(), machine="Allow"):
    return {"user": {"global": glob, "nonpackaged": desktop},
            "machine": {"global": machine, "nonpackaged": None},
            "apps": list(apps)}


def app(name="C:\\Tools\\rec.exe", kind="desktop", start=0, stop=0, value=""):
    return {"name": name, "kind": kind, "hive": "user", "value": value,
            "start": start, "stop": stop}


def sample(**caps):
    base = {name: cap() for name in privacyseal.CAPS}
    base.update(caps)
    return {"build": "26200", "caps": base,
            "policy": {"LetAppsAccessMicrophone": None, "LetAppsAccessCamera": None,
                       "LetAppsAccessLocation": None},
            "devices": [{"id": "USB\\CAM", "name": "HP HD Camera", "class": "Camera",
                         "status": "OK", "problem": 0}],
            "captureEndpoints": [{"id": "a", "name": "Microphone Array", "state": 1},
                                 {"id": "b", "name": "Stereo Mix", "state": 1}],
            "errors": []}


def seal_record(declared, caps=("microphone", "webcam")):
    return {"declared": declared, "caps": {c: "Deny" for c in caps},
            "previous": {c: {"global": "Allow", "nonpackaged": "Allow"} for c in caps},
            "by": "owner cli"}


class PrivacySealTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(os.path.join(self.tmp.name, "t.db"))
        self.addCleanup(self.store.close)

    def titles(self, findings):
        return [f["title"] for f in findings]

    def test_registered_bounded_and_windows_only(self):
        self.assertIn("privacy", RUNNERS)
        self.assertEqual(JOBS["privacy"][0], 300)
        self.assertIn("privacy", WINDOWS_ONLY)

    def test_read_script_never_writes(self):
        self.assertNotRegex(privacyseal.PS_READ, r"Set-ItemProperty|New-Item|Remove-Item")
        self.assertIn("Set-ItemProperty", privacyseal.PS_APPLY)

    def test_open_posture_is_informational_only(self):
        with mock.patch.object(privacyseal, "ps_json", return_value=sample()):
            with collection.observe() as obs:
                findings = privacyseal.audit(self.store, hosts=("win",))
        self.assertIn("privacy", obs.successes)
        self.assertEqual({f["severity"] for f in findings}, {"low"})
        self.assertIn("microphone access is open", self.titles(findings))
        inventory = [f for f in findings if f["title"].endswith("privacy posture")][0]
        self.assertIn("Stereo Mix", inventory["detail"])
        self.assertIn("no seal declared", inventory["detail"])

    def test_broken_seal_is_high_and_unattributed(self):
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(seal_record(time.time() - 600)))
        current = sample(microphone=cap(glob="Deny", desktop="Allow"),
                         webcam=cap(glob="Deny", desktop="Deny"))
        with mock.patch.object(privacyseal, "ps_json", return_value=current):
            findings = privacyseal.audit(self.store, hosts=("win",))
        broken = [f for f in findings if f["title"].startswith("privacy seal broken")]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0]["severity"], "high")
        self.assertIn("microphone", broken[0]["title"])
        self.assertIn("writer is not recorded", broken[0]["detail"])
        self.assertNotIn("camera access is open", self.titles(findings))

    def test_use_after_seal_is_high_even_when_values_read_deny(self):
        declared = time.time() - 3600
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(seal_record(declared)))
        mic = cap(glob="Deny", desktop="Deny",
                  apps=[app(start=filetime(declared + 60), stop=0),
                        app(name="old.exe", start=filetime(declared - 60),
                            stop=filetime(declared - 30))])
        with mock.patch.object(privacyseal, "ps_json",
                               return_value=sample(microphone=mic, webcam=cap("Deny", "Deny"))):
            findings = privacyseal.audit(self.store, hosts=("win",))
        used = [f for f in findings if f["title"] == "microphone used after the privacy seal"]
        self.assertEqual(len(used), 1)
        self.assertEqual(used[0]["severity"], "high")
        self.assertIn("still holding it", used[0]["detail"])
        self.assertNotIn("old.exe", used[0]["detail"])

    def test_finished_use_after_seal_is_reported_once_but_a_held_grant_repeats(self):
        declared = time.time() - 3600
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(seal_record(declared)))
        finished = app(name="done.exe", start=filetime(declared + 60),
                       stop=filetime(declared + 120))
        held = app(name="live.exe", start=filetime(declared + 200), stop=0)
        mic = cap("Deny", "Deny", apps=[finished, held])
        current = sample(microphone=mic, webcam=cap("Deny", "Deny"))
        with mock.patch.object(privacyseal, "ps_json", return_value=current):
            first = privacyseal.audit(self.store, hosts=("win",))
            second = privacyseal.audit(self.store, hosts=("win",))
        used = lambda fs: sorted(f["detail"].split(" app ")[1].split(" started")[0]
                                 for f in fs
                                 if f["title"] == "microphone used after the privacy seal")
        self.assertEqual(used(first), ["done.exe", "live.exe"])
        self.assertEqual(used(second), ["live.exe"])

    def test_policy_forcing_allow_overrides_seal(self):
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(seal_record(time.time())))
        current = sample(microphone=cap("Deny", "Deny"), webcam=cap("Deny", "Deny"))
        current["policy"]["LetAppsAccessCamera"] = privacyseal.POLICY_FORCE_ALLOW
        with mock.patch.object(privacyseal, "ps_json", return_value=current):
            findings = privacyseal.audit(self.store, hosts=("win",))
        hit = [f for f in findings if "policy forces camera" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "high")

    def test_setting_flip_between_samples_is_medium_and_new_app_is_seen(self):
        first = sample()
        second = sample(microphone=cap(glob="Deny", apps=[app(start=filetime(time.time()))]))
        with mock.patch.object(privacyseal, "ps_json", side_effect=[first, second]):
            privacyseal.audit(self.store, hosts=("win",))
            findings = privacyseal.audit(self.store, hosts=("win",))
        changed = [f for f in findings if f["title"] == "microphone access setting changed"]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["severity"], "medium")
        self.assertIn("not attributed", changed[0]["detail"])
        self.assertIn("new app in the microphone ledger", self.titles(findings))

    def test_first_sample_reports_no_changes(self):
        with mock.patch.object(privacyseal, "ps_json", return_value=sample()):
            findings = privacyseal.audit(self.store, hosts=("win",))
        self.assertFalse([f for f in findings if "changed" in f["title"]
                          or f["title"] == "camera device appeared"])

    def test_invalid_or_missing_snapshot_is_visibility_loss_not_clean(self):
        with mock.patch.object(privacyseal, "ps_json", return_value=sample()):
            privacyseal.audit(self.store, hosts=("win",))
        before = self.store.get_meta(privacyseal.STATE_KEY)
        bad = sample()
        bad["caps"]["microphone"]["user"]["global"] = 7
        for value in (None, {}, bad):
            with mock.patch.object(privacyseal, "ps_json", return_value=value):
                with collection.observe() as obs:
                    findings = privacyseal.audit(self.store, hosts=("win",))
            self.assertTrue(obs.failures)
            self.assertEqual(findings[0]["category"], "visibility")
            self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(self.store.get_meta(privacyseal.STATE_KEY), before)

    def test_partial_errors_keep_rows_but_mark_incomplete(self):
        current = sample()
        current["errors"] = ["capture endpoint registry unavailable"]
        with mock.patch.object(privacyseal, "ps_json", return_value=current):
            with collection.observe() as obs:
                findings = privacyseal.audit(self.store, hosts=("win",))
        self.assertTrue(obs.failures)
        self.assertEqual(findings[-1]["title"], "privacy posture visibility incomplete")
        self.assertIn("microphone access is open", self.titles(findings))

    def test_disabled_windows_is_visibility_loss(self):
        findings = privacyseal.audit(self.store, hosts=("wsl",))
        self.assertEqual(findings[0]["category"], "visibility")

    # -- owner actions ---------------------------------------------------

    def test_seal_records_rollback_and_verifies_readback(self):
        calls = []

        def fake_ps(script, timeout=120, payload=None):
            if payload is None:
                return sample()
            calls.append(json.loads(payload))
            return {"result": {c: {"global": v, "nonpackaged": v}
                               for c, v in json.loads(payload)["set"].items()},
                    "errors": []}
        with mock.patch.object(privacyseal, "ps_json", side_effect=fake_ps):
            record = privacyseal.seal(self.store, ("microphone",))
        self.assertEqual(calls, [{"set": {"microphone": "Deny"}}])
        self.assertEqual(record["caps"], {"microphone": "Deny"})
        self.assertEqual(record["previous"]["microphone"],
                         {"global": "Allow", "nonpackaged": "Allow"})
        self.assertIsNotNone(privacyseal.load_seal(self.store))
        history = json.loads(self.store.get_meta(privacyseal.HISTORY_KEY))
        self.assertEqual(history[-1]["event"], "seal")

    def test_seal_fails_closed_when_readback_differs(self):
        def fake_ps(script, timeout=120, payload=None):
            if payload is None:
                return sample()
            return {"result": {"microphone": {"global": "Deny", "nonpackaged": "Allow"}},
                    "errors": []}
        with mock.patch.object(privacyseal, "ps_json", side_effect=fake_ps):
            with self.assertRaises(privacyseal.SealError):
                privacyseal.seal(self.store, ("microphone",))
        self.assertIsNone(privacyseal.load_seal(self.store))

    def test_seal_refuses_unknown_capability_and_writer_errors(self):
        with self.assertRaises(privacyseal.SealError):
            privacyseal._apply({"graphicsCaptureProgrammatic": "Deny"})
        with self.assertRaises(privacyseal.SealError):
            privacyseal._apply({"microphone": "Maybe"})
        with mock.patch.object(privacyseal, "ps_json",
                               return_value={"result": {}, "errors": ["write failed: X"]}):
            with self.assertRaises(privacyseal.SealError):
                privacyseal._apply({"microphone": "Deny"})

    def test_unseal_restores_recorded_values_and_clears_seal(self):
        record = seal_record(time.time())
        record["previous"]["webcam"] = {"global": "Deny", "nonpackaged": "Deny"}
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(record))
        calls = []

        def fake_ps(script, timeout=120, payload=None):
            calls.append(json.loads(payload))
            return {"result": {c: {"global": v, "nonpackaged": v}
                               for c, v in json.loads(payload)["set"].items()},
                    "errors": []}
        with mock.patch.object(privacyseal, "ps_json", side_effect=fake_ps):
            restored = privacyseal.unseal(self.store)
        self.assertEqual(restored, {"microphone": "Allow", "webcam": "Deny"})
        self.assertEqual(calls, [{"set": restored}])
        self.assertIsNone(privacyseal.load_seal(self.store))
        with self.assertRaises(privacyseal.SealError):
            privacyseal.unseal(self.store)

    def test_cli_seal_refuses_without_confirmation_off_tty(self):
        args = mock.Mock(action="seal", mic=False, camera=False, yes=False, json=False)
        with mock.patch("sys.stdin.isatty", return_value=False):
            with mock.patch.object(privacyseal, "seal") as sealer:
                self.assertEqual(privacy_cli.cmd_privacy(args, self.store), 1)
        sealer.assert_not_called()

    def test_cli_seal_with_yes_applies_only_requested_caps(self):
        args = mock.Mock(action="seal", mic=True, camera=False, yes=True, json=False)
        with mock.patch.object(privacyseal, "seal",
                               return_value={"caps": {"microphone": "Deny"}}) as sealer:
            self.assertEqual(privacy_cli.cmd_privacy(args, self.store), 0)
        sealer.assert_called_once_with(self.store, ("microphone",))

    # -- audio collector under a seal ------------------------------------

    def test_capture_session_is_medium_unsealed_and_high_sealed(self):
        session = {"endpoint": "mic", "flow": "capture", "state": 1, "pid": 7,
                   "processStart": "2026-10-21T10:00:00Z", "identityKnown": True,
                   "singleProcess": True, "systemSounds": False}
        current = {"sessions": [session], "endpoints": [], "defaults": [],
                   "burst": {"events": [], "sustained": 0, "samples": 0,
                             "endpointsSampled": 0, "elapsedMs": 0}}
        open_titles = {f["title"]: f["severity"]
                       for f in audiowatch.compare(current, {}, sealed=False)}
        self.assertEqual(open_titles["microphone capture session active"], "medium")
        sealed_titles = {f["title"]: f["severity"]
                         for f in audiowatch.compare(current, {}, sealed=True)}
        self.assertEqual(
            sealed_titles["microphone capture session active despite privacy seal"], "high")
        self.assertNotIn("microphone capture session active", sealed_titles)

    def test_audio_audit_reads_the_seal_from_the_store(self):
        self.store.set_meta(privacyseal.SEAL_KEY, json.dumps(seal_record(time.time())))
        current = {"endpoints": [{"id": "mic", "flow": "capture", "state": 1}],
                   "defaults": [{"flow": f, "role": r, "id": None}
                                for f in ("render", "capture")
                                for r in ("console", "multimedia", "communications")],
                   "sessions": [{"endpoint": "mic", "flow": "capture", "state": 1,
                                 "pid": 7, "processStart": "2026-10-21T10:00:00Z",
                                 "identityKnown": True, "singleProcess": True,
                                 "systemSounds": False}],
                   "errors": [], "truncated": False,
                   "burst": {"durationMs": 8000, "elapsedMs": 8100, "samples": 10,
                             "endpointsSampled": 1, "sustained": 0, "truncated": False,
                             "events": [], "errors": []}}
        with mock.patch.object(audiowatch, "ps_json", return_value=current):
            findings = audiowatch.audit(self.store, hosts=("win",))
        self.assertIn("microphone capture session active despite privacy seal",
                      [f["title"] for f in findings])


if __name__ == "__main__":
    unittest.main()

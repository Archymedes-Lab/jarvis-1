"""Windows spyware evidence mapping from fixture payloads."""

import unittest

from jarvis.core.paths import WIN_SCRIPTS_DIR
from jarvis.core.reasoning import engine
from jarvis.platform import spy_windows as sw


def proc(pid, name, path, **kw):
    base = dict(pid=pid, ppid=100, name=name, path=path, session=1, started="2026-09-30T10:00:00Z",
                window=False, ext=0, sig="valid", signer="Vendor", age=100)
    base.update(kw)
    return base


def payload(procs, consent=None, autostart=()):
    return {"procs": procs, "consent": consent or {}, "autostart": list(autostart)}


class PathClassTests(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(sw.path_class("C:\\Windows\\System32\\x.exe"), "os")
        self.assertEqual(sw.path_class("C:\\Program Files\\A\\a.exe"), "program_files")
        self.assertEqual(sw.path_class("C:\\Program Files\\WindowsApps\\P_1\\a.exe"), "store_package")
        self.assertEqual(sw.path_class("C:\\Users\\me\\AppData\\Local\\Temp\\a.exe"), "temp")
        self.assertEqual(sw.path_class("C:\\Users\\me\\AppData\\Local\\a\\a.exe"), "user_writable")
        self.assertEqual(sw.path_class("D:\\Games\\a.exe"), "unknown")
        self.assertEqual(sw.path_class(None), "unknown")


class BuildTests(unittest.TestCase):
    def test_payload_script_ships_and_is_read_only(self):
        text = (WIN_SCRIPTS_DIR / "spy_evidence.ps1").read_text(encoding="utf-8")
        for verb in ("Set-", "Remove-", "Stop-", "Start-", "New-Item", "Invoke-", "Add-Type", "Out-File"):
            self.assertNotIn(verb, text)

    def test_consent_maps_by_exact_executable_path_within_recent_window(self):
        exe = "C:\\Users\\me\\AppData\\Local\\x\\rec.exe"
        consent = {"microphone": [{"who": exe.replace("\\", "#"), "np": True, "hrs": 1.5}],
                   "webcam": [{"who": exe.replace("\\", "#"), "np": True, "hrs": 500}]}
        subs, cov = sw.build(payload([proc(1000, "rec.exe", exe), proc(1001, "other.exe", "C:\\o.exe")],
                                     consent), "b")
        self.assertEqual(cov["status"], "complete")
        kinds = {s.label: sorted(o.kind for o in s.observations) for s in subs}
        self.assertEqual(kinds["rec.exe"], ["cap.audio.mic", "conceal.no_ui"])   # stale webcam ignored
        self.assertNotIn("cap.audio.mic", kinds["other.exe"])

    def test_store_package_consent_matches_by_package_name(self):
        path = "C:\\Program Files\\WindowsApps\\OpenAI.Codex_1.0_x64__abc\\app\\codex.exe"
        consent = {"graphicsCaptureProgrammatic": [{"who": "OpenAI.Codex_abc", "np": False, "hrs": 0}]}
        s = sw.build(payload([proc(2000, "codex.exe", path, signer="OpenAI OpCo, LLC", window=True)],
                             consent), "b")[0][0]
        self.assertIn("cap.screen.capture", [o.kind for o in s.observations])
        self.assertEqual(engine.assess(s)["verdict"], "EXPECTED_DUAL_USE")

    def test_autostart_and_egress_and_window_state(self):
        exe = "C:\\Users\\me\\AppData\\Roaming\\svc\\helper.exe"
        subs, _ = sw.build(payload([proc(3000, "helper.exe", exe, ext=2, sig="none", age=1)],
                                   autostart=[f'"{exe}" --silent']), "b")
        kinds = sorted(o.kind for o in subs[0].observations)
        self.assertEqual(kinds, ["conceal.no_ui", "egress.external", "persist.autostart"])
        # Egress + autostart + no window without any capture is not a spyware verdict.
        self.assertEqual(engine.assess(subs[0])["verdict"], "NO_SIGNAL")

    def test_session_zero_and_system_pids_do_not_count_as_hidden_ui(self):
        subs, _ = sw.build(payload([proc(4, "System", None), proc(500, "svc.exe", "C:\\Windows\\s.exe",
                                                                  session=0)]), "b")
        self.assertEqual([s.label for s in subs], ["svc.exe"])
        self.assertEqual(subs[0].observations, [])

    def test_unusable_payload_is_unavailable_not_clean(self):
        for bad in (None, {}, {"procs": "x"}, []):
            subs, cov = sw.build(bad)
            self.assertEqual((subs, cov["status"]), ([], "unavailable"))

    def test_unknown_signature_values_collapse_and_pids_bounded(self):
        subs, _ = sw.build(payload([proc(9000, "a.exe", "C:\\a.exe", sig="Weird")]), "b")
        self.assertEqual(subs[0].signature, "unknown")
        many = [proc(1000 + i * 4, f"p{i}.exe", "C:\\p.exe") for i in range(sw.MAX_PROCESSES + 50)]
        self.assertLessEqual(len(sw.build(payload(many))[0]), sw.MAX_PROCESSES)


if __name__ == "__main__":
    unittest.main()


class MasqueradeMappingTests(unittest.TestCase):
    def test_system_name_from_a_temp_folder_becomes_a_concealment_fact(self):
        bad = proc(6000, "svchost.exe", "C:\\Users\\me\\AppData\\Local\\Temp\\svchost.exe", sig="none")
        good = proc(6001, "svchost.exe", "C:\\Windows\\System32\\svchost.exe")
        subs, _ = sw.build(payload([bad, good]), "b")
        by_pid = {s.key.split(":")[2]: s for s in subs}
        self.assertEqual(engine.assess(by_pid["6000"])["verdict"], "VISIBILITY_CONTRADICTION")
        self.assertEqual(engine.assess(by_pid["6001"])["verdict"], "NO_SIGNAL")

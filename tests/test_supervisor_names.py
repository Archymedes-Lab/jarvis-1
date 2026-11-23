"""The Windows supervisor scripts were renamed after the tasks they install.

`deadman-jarvis.ps1` became `jarvis-health-monitor.ps1`, and the other
`<verb>-jarvis.ps1` scripts followed (docs/guides/WINDOWS-SUPERVISOR-NAMES.md).
The live tasks keep running the old layout until each is re-registered, so the
transition must preserve:

  * no false critical: a genuine, unmodified pre-rename task still verifies;
  * tamper detection: any change to an old copy, or old arguments paired with
    anything but the pinned old fingerprint, still fails;
  * monitor liveness: the health monitor's state stays readable from its old
    folder until the new folder exists, and a stale new file is never masked;
  * the broker's elevated results stay usable from the reviewed old copy only;
  * the new scripts still pass their own self-sync gates, and the old copies,
    whose source filename is gone, keep running instead of breaking.
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.paths import win_script
from jarvis.platform import broker
from jarvis.platform.provenance import persistence as mp
from jarvis.service import supervisors

ROOT = Path(__file__).resolve().parents[1]
LOCAL = r"C:\Users\chris\AppData\Local"
DATA = {"currentUser": "DESKTOP\\chris", "localAppData": LOCAL}
CHECKOUT = "/home/chris/jarvis"
OLD_NAMES = ("deadman-jarvis.ps1", "wake-jarvis.ps1", "revive-jarvis.ps1",
             "connectivity-jarvis.ps1", "broker-jarvis.ps1")


def _live(task, arguments, target_hash):
    user = "SYSTEM" if task.principal == "system" else "DESKTOP\\chris"
    return {"name": task.name, "user": user,
            "runLevel": task.run_level.title(), "logonType": task.logon.upper(),
            "actions": [{"execute": r"C:\WINDOWS\System32\conhost.exe",
                         "arguments": (r'--headless "C:\WINDOWS\System32\WindowsPowerShell'
                                       r'\v1.0\powershell.exe" ' + arguments),
                         "targetHash": target_hash}]}


class LegacyTaskLayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.code = self.tmp.name
        for task in mp.MANAGED_TASKS:
            if task.release_script:
                path = os.path.join(self.code, task.release_script)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as fh:
                    fh.write(f"# reviewed {task.name}\n")

    def verify(self, live):
        return mp.verify_task(live, DATA, self.code, CHECKOUT)

    def legacy_live(self, name):
        legacy = mp.legacy_layout(mp.BY_NAME[name])
        return _live(legacy, mp.expected_arguments(legacy, LOCAL, CHECKOUT), legacy.fixed_hash)

    def test_every_renamed_task_has_exactly_one_pinned_legacy_layout(self):
        # Introduced after the rename, under its final name: it has no old
        # layout, and granting it one would admit a script that never shipped.
        never_renamed = {"jarvis native service"}
        renamed = {t.name for t in mp.MANAGED_TASKS
                   if t.release_script.startswith("jarvis-") and t.release_script.endswith(".ps1")
                   } - never_renamed
        self.assertFalse(never_renamed & set(mp.LEGACY_LAYOUTS))
        self.assertEqual(set(mp.LEGACY_LAYOUTS), renamed)
        for name, (script, args, pinned) in mp.LEGACY_LAYOUTS.items():
            self.assertIn(script, OLD_NAMES, name)
            self.assertIn("\\" + script + '"', args, name)
            self.assertRegex(pinned, r"^[0-9a-f]{64}$", name)

    def test_unmodified_pre_rename_task_is_not_critical(self):
        for name in mp.LEGACY_LAYOUTS:
            ok, why = self.verify(self.legacy_live(name))
            self.assertTrue(ok, f"{name}: {why}")
            self.assertIn("re-register", why)

    def test_new_layout_still_verifies_with_its_own_reason(self):
        for name in mp.LEGACY_LAYOUTS:
            task = mp.BY_NAME[name]
            ok, why = self.verify(_live(task, mp.expected_arguments(task, LOCAL, CHECKOUT),
                                        mp.expected_hash(task, self.code)))
            self.assertTrue(ok, f"{name}: {why}")
            self.assertNotIn("pre-rename", why)

    def test_modified_old_copy_is_still_rejected(self):
        for name in mp.LEGACY_LAYOUTS:
            live = self.legacy_live(name)
            live["actions"][0]["targetHash"] = hashlib.sha256(b"tampered").hexdigest()
            ok, why = self.verify(live)
            self.assertFalse(ok, name)
            self.assertIn("fingerprint", why)

    def test_layouts_cannot_be_mixed(self):
        for name in mp.LEGACY_LAYOUTS:
            task, legacy = mp.BY_NAME[name], mp.legacy_layout(mp.BY_NAME[name])
            new_args = mp.expected_arguments(task, LOCAL, CHECKOUT)
            old_args = mp.expected_arguments(legacy, LOCAL, CHECKOUT)
            # Old arguments running the new release script, and new arguments
            # running the pinned old script: neither is a reviewed layout.
            self.assertFalse(self.verify(_live(task, old_args, mp.expected_hash(task, self.code)))[0], name)
            self.assertFalse(self.verify(_live(task, new_args, legacy.fixed_hash))[0], name)

    def test_legacy_arguments_are_exact(self):
        for name in mp.LEGACY_LAYOUTS:
            live = self.legacy_live(name)
            live["actions"][0]["arguments"] += " -EncodedCommand ZQB2AGkAbAA="
            self.assertFalse(self.verify(live)[0], name)

    def test_legacy_layout_does_not_relax_principal_or_run_level(self):
        for name in mp.LEGACY_LAYOUTS:
            task = mp.BY_NAME[name]
            for mutate in (lambda t: t.update(user="DESKTOP\\someoneelse"),
                           lambda t: t.update(runLevel="Limited" if task.run_level == "highest"
                                              else "Highest"),
                           lambda t: t.update(logonType="Password")):
                live = self.legacy_live(name)
                mutate(live)
                self.assertFalse(self.verify(live)[0], name)

    def test_tasks_that_were_not_renamed_have_no_legacy_alias(self):
        for name in ("jarvis input hook", "wsl ide keepalive", "wsl jarvis 24x7"):
            self.assertIsNone(mp.legacy_layout(mp.BY_NAME[name]))


class HealthMonitorStatePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.new = os.path.join(self.tmp.name, "HealthMonitor", "state.json")
        self.old = os.path.join(self.tmp.name, "Deadman", "state.json")
        self.now = 1_800_000_000

    def write(self, path, **state):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(state, fh)

    def audit(self):
        with mock.patch.object(supervisors, "STATE", self.new), \
                mock.patch.object(supervisors, "LEGACY_STATE", self.old):
            path = supervisors.health_monitor_state_path(self.new, self.old)
            return path, {f["title"]: f["severity"]
                          for f in supervisors.audit_health_monitor(path, self.now)}

    def test_monitor_not_yet_re_registered_stays_visible(self):
        self.write(self.old, checkedAt=self.now - 30, healthy=True)
        path, out = self.audit()
        self.assertEqual(path, self.old)
        self.assertEqual(out, {"the independent Windows monitor is checking on JARVIS": "ok"})

    def test_stale_new_state_is_never_masked_by_the_old_folder(self):
        self.write(self.old, checkedAt=self.now - 30, healthy=True)
        self.write(self.new, checkedAt=self.now - 900, healthy=True)
        path, out = self.audit()
        self.assertEqual(path, self.new)
        self.assertEqual(out.get("the independent Windows monitor has stopped checking"), "high")

    def test_neither_folder_reports_the_new_location(self):
        path, out = self.audit()
        self.assertEqual(path, self.new)
        self.assertIn("the independent Windows monitor has never run", out)

    def test_default_paths_name_the_new_and_old_folders(self):
        self.assertTrue(supervisors.STATE.endswith("/Jarvis/HealthMonitor/state.json"))
        self.assertTrue(supervisors.LEGACY_STATE.endswith("/Jarvis/Deadman/state.json"))

    def test_audit_without_a_path_uses_the_resolved_location(self):
        self.write(self.old, checkedAt=self.now - 30, healthy=True)
        with mock.patch.object(supervisors, "STATE", self.new), \
                mock.patch.object(supervisors, "LEGACY_STATE", self.old):
            findings = supervisors.audit_health_monitor(now=self.now)
        self.assertEqual([f["where"] for f in findings], [self.old])


class LegacyBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        for name in broker.SCRIPTS.values():
            shutil.copy(win_script(name), self.tmp)
        p = mock.patch.object(broker, "ROOT", self.tmp)
        p.start()
        self.addCleanup(p.stop)
        self.legacy = os.path.join(self.tmp, broker.LEGACY_BROKER_SCRIPT)

    def stage_legacy(self, text):
        with open(self.legacy, "w", encoding="utf-8") as fh:
            fh.write(text)

    def pinned(self, value):
        script, args, _ = mp.LEGACY_LAYOUTS["jarvis elevated broker"]
        return mock.patch.dict(mp.LEGACY_LAYOUTS,
                               {"jarvis elevated broker": (script, args, value)})

    def test_reviewed_legacy_copy_is_installed_and_not_drifted(self):
        self.stage_legacy("# old reviewed broker\n")
        with self.pinned(mp.normalized_text_hash(self.legacy)):
            self.assertTrue(broker.installed())
            self.assertEqual(broker.drifted(), [])

    def test_modified_legacy_copy_is_drift(self):
        self.stage_legacy("# old reviewed broker\n")
        with self.pinned(mp.normalized_text_hash(self.legacy)):
            self.stage_legacy("# old reviewed broker\nStart-Process evil.exe\n")
            self.assertEqual(broker.drifted(), [broker.LEGACY_BROKER_SCRIPT])

    def test_new_name_wins_once_restaged(self):
        self.stage_legacy("# anything\n")
        shutil.copy(ROOT / broker.BROKER_SCRIPT, self.tmp)
        self.assertEqual(broker.drifted(), [])
        with open(os.path.join(self.tmp, broker.BROKER_SCRIPT), "a") as fh:
            fh.write("\nStart-Process evil.exe\n")
        self.assertEqual(broker.drifted(), [broker.BROKER_SCRIPT])

    def test_nothing_staged_is_not_installed(self):
        self.assertFalse(broker.installed())


class RenamedScriptTests(unittest.TestCase):
    def read(self, name):
        return (ROOT / name).read_text(encoding="utf-8-sig")

    def test_old_names_are_gone_from_the_checkout(self):
        for old in OLD_NAMES:
            self.assertFalse((ROOT / old).exists(), old)

    def test_new_scripts_install_and_sync_under_their_own_names(self):
        for task in mp.MANAGED_TASKS:
            if task.name not in mp.LEGACY_LAYOUTS:
                continue
            text = self.read(task.release_script)
            self.assertIn(f"'{task.release_script}'" if "wake" not in task.name
                          else task.release_script, text, task.name)
            self.assertIn("\\" + task.release_script + '"', task.args, task.name)
            for old in OLD_NAMES:
                self.assertNotIn(old, text, f"{task.release_script} still names {old}")

    def test_self_sync_gates_still_accept_the_renamed_scripts(self):
        # The installed copies overwrite themselves only from a source that
        # passes these gates. A rename that broke them would freeze the
        # installed copy on its current code forever, silently.
        wake = self.read("jarvis-wake-watchdog.ps1")
        self.assertGreater(len(wake), 1500)
        self.assertIn("jarvis wake watchdog", wake)
        self.assertIn("needs a human", wake)
        self.assertIn(r"\jarvis-wake-watchdog.ps1", wake)
        reviver = self.read("jarvis-reviver.ps1")
        self.assertGreater(len(reviver), 2000)
        self.assertIn("Instant revival", reviver)
        self.assertIn(r"\jarvis-reviver.ps1", reviver)

    def test_health_monitor_migrates_state_by_copy_without_overwriting(self):
        text = self.read("jarvis-health-monitor.ps1")
        self.assertIn(r"'Jarvis\HealthMonitor'", text)
        self.assertIn(r"'Jarvis\Deadman'", text)
        body = text[text.index("function Copy-LegacyState"):text.index("if ($Install)")]
        self.assertIn("Copy-Item", body)
        self.assertNotIn("Move-Item", body)
        self.assertNotIn("Remove-Item", body)
        self.assertIn("-not (Test-Path -LiteralPath $to)", body)
        self.assertEqual(set(re.findall(r"'([a-z]+\.json)'", body)), {"mail.json", "state.json"})
        install = text[text.index("if ($Install)"):]
        self.assertLess(install.index("Copy-LegacyState"),
                        install.index("Register-ScheduledTask"))


if __name__ == "__main__":
    unittest.main()

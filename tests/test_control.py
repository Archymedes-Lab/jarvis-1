import os
import unittest

from jarvis.collectors.persistence import trusted_tasks
from jarvis.core import paths


class TrustedScheduledTaskTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "currentUser": r"WORKSTATION\chris",
            "localAppData": r"C:\Users\chris\AppData\Local",
        }

    def _ide_task(self):
        return {
            "name": "WSL IDE Keepalive",
            "path": "\\",
            "user": r"WORKSTATION\chris",
            "logonType": "S4U",
            "runLevel": "Limited",
            "actions": [{
                "execute": "powershell.exe",
                "arguments": (
                    '-NoProfile -NonInteractive -WindowStyle Hidden '
                    '-ExecutionPolicy Bypass -File '
                    '"C:\\Users\\chris\\AppData\\Local\\WSLKeepalive\\'
                    'wsl-ide-keepalive-supervisor.ps1"'),
                "targetHash": trusted_tasks.TRUSTED_IDE_TASKS[
                    "wsl ide keepalive"]["hash"],
            }],
        }

    def test_exact_reviewed_task_is_verified(self):
        ok, detail = trusted_tasks.verified_maintenance_task(
            self._ide_task(), self.data)
        self.assertTrue(ok, detail)

    def test_trusted_name_does_not_override_changed_script(self):
        task = self._ide_task()
        task["actions"][0]["targetHash"] = "0" * 64
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("fingerprint", detail)

    def test_trusted_name_does_not_override_extra_arguments(self):
        task = self._ide_task()
        task["actions"][0]["arguments"] += " -EncodedCommand Z" * 20
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("arguments", detail)

    def test_principal_must_be_limited_current_user(self):
        task = self._ide_task()
        task["runLevel"] = "Highest"
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        self.assertIn("limited", detail)

    def test_headless_conhost_wrapper_is_verified(self):
        task = self._ide_task()
        action = task["actions"][0]
        action["execute"] = r"C:\Windows\System32\conhost.exe"
        action["arguments"] = (r'--headless "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
                               + action["arguments"])
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertTrue(ok, detail)

    def test_headless_conhost_cannot_wrap_other_programs(self):
        task = self._ide_task()
        action = task["actions"][0]
        action["execute"] = r"C:\Windows\System32\conhost.exe"
        action["arguments"] = r'--headless C:\Users\chris\evil.exe ' + action["arguments"]
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)
        task["actions"][0]["execute"] = r"C:\Users\chris\conhost.exe"
        action["arguments"] = (r'--headless "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" '
                               + self._ide_task()["actions"][0]["arguments"])
        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)
        self.assertFalse(ok)

    def test_wake_task_uses_the_actual_checkout_path(self):
        root = str(paths.REPO_ROOT)
        task = {
            "name": "jarvis wake watchdog",
            "path": "\\",
            "user": r"WORKSTATION\chris",
            "logonType": "Interactive",
            "runLevel": "Limited",
            "actions": [{
                "execute": "powershell.exe",
                "arguments": (
                    '-NoProfile -NonInteractive -WindowStyle Hidden '
                    '-ExecutionPolicy Bypass -File '
                    '"C:\\Users\\chris\\AppData\\Local\\WSLKeepalive\\'
                    'jarvis-wake-watchdog.ps1" -Distro "Ubuntu" '
                    f'-RepoRoot "{root}" -RecoverInterop true'),
                "targetHash": trusted_tasks.normalized_text_hash(
                    os.path.join(root, "jarvis-wake-watchdog.ps1")),
            }],
        }

        ok, detail = trusted_tasks.verified_maintenance_task(task, self.data)

        self.assertTrue(ok, detail)


if __name__ == "__main__":
    unittest.main()


class SystemdAliasTests(unittest.TestCase):
    def test_alias_into_a_packaged_unit_is_inventory_but_other_links_stay_medium(self):
        import os
        import tempfile
        from unittest import mock

        from jarvis.collectors.persistence import control
        with tempfile.TemporaryDirectory() as root:
            packaged, etc = os.path.join(root, "pkg") + "/", os.path.join(root, "etc")
            os.makedirs(packaged); os.makedirs(etc)
            open(os.path.join(packaged, "rsyslog.service"), "w").close()
            open(os.path.join(root, "evil.service"), "w").close()
            os.symlink(os.path.join(packaged, "rsyslog.service"), os.path.join(etc, "syslog.service"))
            os.symlink(os.path.join(root, "evil.service"), os.path.join(etc, "evil.service"))
            units = sorted(os.path.join(etc, n) for n in os.listdir(etc))

            def fake_glob(pattern):
                return units if pattern == "/etc/systemd/system/*.service" else []

            with mock.patch.object(control, "PACKAGED_UNIT_DIRS", (packaged,)), \
                 mock.patch.object(control.glob, "glob", side_effect=fake_glob), \
                 mock.patch.object(control, "_run", return_value=""):
                out = {f["where"]: f for f in control.audit_linux()
                       if "systemd" in f["title"] and f["where"] in units}
        # 2026-10-25: an alias into a packaged unit is inventory, reported ok.
        self.assertEqual(out[units[1]]["severity"], "ok")        # syslog -> packaged
        self.assertEqual(out[units[0]]["severity"], "medium")    # evil -> elsewhere
        self.assertEqual(out[units[0]]["title"], "custom systemd service")


class MaskedUnitTests(unittest.TestCase):
    """A unit linked to /dev/null cannot start; it is not persistence. A
    same-named real unit, or a link anywhere else, stays reported."""

    def units(self, root):
        import os
        masked, real = os.path.join(root, "masked.service"), os.path.join(root, "real.service")
        os.symlink(os.devnull, masked)
        with open(real, "w") as fh:
            fh.write("[Service]\nExecStart=/tmp/x/payload\n")
        return masked, real

    def test_control_reports_masked_unit_as_inventory(self):
        import tempfile
        from unittest import mock

        from jarvis.collectors.persistence import control
        with tempfile.TemporaryDirectory() as root:
            masked, real = self.units(root)

            def fake_glob(pattern):
                return [masked, real] if pattern == "/etc/systemd/system/*.service" else []

            with mock.patch.object(control.glob, "glob", side_effect=fake_glob), \
                 mock.patch.object(control, "_run", return_value=""):
                out = {f["where"]: f for f in control.audit_linux()
                       if f["where"] in (masked, real)}
        self.assertEqual((out[masked]["severity"], out[masked]["title"]),
                         ("low", "masked systemd unit"))
        self.assertEqual(out[real]["severity"], "medium")

    def test_backdoor_audit_skips_only_masked_user_units(self):
        import os
        import tempfile
        from unittest import mock

        from jarvis.collectors.persistence import backdoor
        with tempfile.TemporaryDirectory() as home:
            d = os.path.join(home, ".config", "systemd", "user")
            os.makedirs(d)
            self.units(d)
            with mock.patch.object(backdoor, "_home_dirs",
                                   return_value=[("u", home, 1000)]):
                titles = [f["title"] for f in backdoor.check_persistence()
                          if "systemd user unit" in f["title"]]
        self.assertEqual(titles, ["systemd user unit for u: real.service (file evidence)"])


class BootTaskVerificationTests(unittest.TestCase):
    def ran(self, task):
        return {"category": "ran", "severity": "high", "title": "task ran at boot",
                "detail": f"{task} (ran 2026-09-22 22:00:47)", "where": task}

    def test_only_control_verified_tasks_are_lowered(self):
        from jarvis.collectors.persistence import startup
        control_findings = [
            {"title": "verified scheduled task", "where": "\\JARVIS connectivity guard"},
            # Failed verification is reported under another title and must
            # not lower anything, even with a matching name.
            {"title": "scheduled task", "where": "\\jarvis wake watchdog"},
        ]
        out = startup.apply_verified_tasks(
            [self.ran("\\JARVIS connectivity guard"), self.ran("\\jarvis wake watchdog"),
             self.ran("\\Evil")], control_findings)
        self.assertEqual([f["severity"] for f in out], ["low", "high", "high"])
        self.assertIn("verified by the control audit", out[0]["detail"])
        self.assertEqual(startup.apply_verified_tasks([self.ran("\\x")], None)[0]["severity"],
                         "high")

    def test_boot_job_ignores_stale_control_evidence(self):
        import tempfile
        import time
        from pathlib import Path
        from unittest import mock

        from jarvis.collectors.persistence import startup
        from jarvis.core.store import Store
        from jarvis.service import jobs
        from jarvis.service.schedule import JOBS
        task = "\\JARVIS connectivity guard"
        verified = [{"category": "persistence", "severity": "low",
                     "title": "verified scheduled task", "detail": "", "where": task}]
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "j.db")
            store = Store(db)
            store.save_snapshot("control", verified, 1.0, "")
            store.close()
            with mock.patch.object(startup, "audit", return_value=[self.ran(task)]):
                fresh = jobs._boot(("win",), db)
                later = time.time() + 3 * JOBS["control"][0] + 600
                with mock.patch.object(jobs.time, "time", return_value=later):
                    stale = jobs._boot(("win",), db)
        self.assertEqual([f["severity"] for f in fresh if f["where"] == task], ["low"])
        self.assertEqual([f["severity"] for f in stale if f["where"] == task], ["high"])


class HiddenAccountSeverityTests(unittest.TestCase):
    def test_privilege_decides_severity_and_unknown_stays_high(self):
        from jarvis.collectors.persistence.backdoor import _hidden_account_severity as sev
        base = {"exists": True, "enabled": True, "admin": False, "rdp": False}
        self.assertEqual(sev(base)[0], "medium")
        self.assertEqual(sev(dict(base, admin=True))[0], "high")
        self.assertEqual(sev(dict(base, rdp=True))[0], "high")
        self.assertEqual(sev(dict(base, admin=None))[0], "high")     # lookup failed
        self.assertEqual(sev({})[0], "high")                           # old script shape
        self.assertEqual(sev(dict(base, enabled=False))[0], "low")
        self.assertEqual(sev(dict(base, exists=False))[0], "low")


class PrivilegedServiceCodeTests(unittest.TestCase):
    SHOW = ("ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 %s-m app serve ; x }\n"
            "WorkingDirectory=%s\nAmbientCapabilities=%s\nUser=%s\n")

    def run_check(self, workdir, caps="", user="svc", isolated=False):
        from unittest import mock

        from jarvis.collectors.persistence import backdoor
        out = self.SHOW % ("-I " if isolated else "", workdir, caps, user)
        with mock.patch.object(backdoor.glob, "glob", return_value=["/etc/systemd/system/app.service"]), \
             mock.patch.object(backdoor.os.path, "islink", return_value=False), \
             mock.patch.object(backdoor.subprocess, "run",
                               return_value=mock.Mock(stdout=out)):
            return [f["severity"] for f in backdoor.check_service_code()]

    def test_capabilities_or_root_on_user_writable_code_is_high(self):
        import tempfile
        with tempfile.TemporaryDirectory() as mine:      # owned by the test user
            self.assertEqual(self.run_check(mine, caps="cap_sys_ptrace"), ["high"])
            self.assertEqual(self.run_check(mine, user="root"), ["high"])
            self.assertEqual(self.run_check(mine, user=""), ["high"])
            self.assertEqual(self.run_check(mine), [])              # unprivileged
            self.assertEqual(self.run_check(mine, user="root", isolated=True), [])

    def test_root_owned_code_is_not_reported(self):
        self.assertEqual(self.run_check("/usr/lib", user="root"), [])


class RestrictedSudoTests(unittest.TestCase):
    def test_only_fixed_root_owned_non_escape_commands_are_restricted(self):
        from jarvis.collectors.persistence.backdoor import _fixed_sudo_command as fixed
        from jarvis.collectors.persistence.backdoor import _sudo_lines
        self.assertTrue(fixed("/usr/bin/systemctl restart jarvis.service"))
        for cmd in ("/usr/bin/systemctl edit jarvis.service", "/usr/bin/systemctl status x",
                    "/usr/bin/systemctl restart *", "/usr/bin/systemctl restart",
                    "/usr/bin/vim /etc/hosts", "/usr/bin/find . -x", "systemctl restart x",
                    "ALL", "/usr/bin/python3 -c x"):
            self.assertFalse(fixed(cmd), cmd)
        self.assertEqual(len(_sudo_lines("a NOPASSWD: /x y, \\\n   /z w\nb\n")), 2)


class ControlSudoRuleTests(unittest.TestCase):
    def test_restricted_rules_are_inventory_and_open_ones_stay_high(self):
        import tempfile
        from unittest import mock

        from jarvis.collectors.persistence import control
        with tempfile.TemporaryDirectory() as d:
            safe, open_ = f"{d}/safe", f"{d}/open"
            with open(safe, "w") as fh:
                fh.write("# c\nchris ALL=(root) NOPASSWD: /usr/bin/systemctl restart jarvis.service, \\\n"
                         "    /usr/bin/systemctl reset-failed jarvis.service\n")
            with open(open_, "w") as fh:
                fh.write("chris ALL=(ALL) NOPASSWD: ALL\n")

            def fake_glob(pattern):
                return [safe, open_] if pattern == "/etc/sudoers.d/*" else []

            with mock.patch.object(control.glob, "glob", side_effect=fake_glob), \
                 mock.patch.object(control, "_run", return_value=""):
                out = {f["where"]: f for f in control.audit_linux() if f["where"] in (safe, open_)}
        self.assertEqual(out[safe]["severity"], "low")
        self.assertEqual(out[open_]["severity"], "high")

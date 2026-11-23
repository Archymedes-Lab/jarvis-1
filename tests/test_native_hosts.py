"""JARVIS on a machine that is not a WSL guest (docs/architecture/NATIVE-HOSTS.md).

The invariants, each with its failure path:

  * the WSL topology behaves exactly as before the host seam existed;
  * a domain that does not exist is not applicable: never scheduled, never
    scored, never reported healthy and never reported failed;
  * what cannot be known about a path or a file stays unknown;
  * the event log has one writer on every platform;
  * nothing JARVIS does to ask a question sends a signal on Windows;
  * a native daemon is supervised from outside, and says so when it is not.
"""

import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.cli import output
from jarvis.core import filelock, finding, fsperm
from jarvis.core.eventlog import EventLog, LogError
from jarvis.platform import host, linux, privilege
from jarvis.platform import windows as bridge
from jarvis.platform.provenance import persistence
from jarvis.response import alert
from jarvis.response.actions import suspend
from jarvis.response.reporting import score
from jarvis.service import coverage, jobs, schedule, supervisors


def as_kind(kind):
    return mock.patch.object(host, "KIND", kind)


class DetectionTests(unittest.TestCase):
    def test_three_topologies(self):
        self.assertEqual(host._detect("nt", ""), "windows")
        self.assertEqual(host._detect("posix", "6.6.87.2-microsoft-standard-WSL2\n"), "wsl")
        self.assertEqual(host._detect("posix", "6.8.0-45-generic\n"), "linux")
        # An unreadable kernel release is not evidence of a Windows host.
        self.assertEqual(host._detect("posix", ""), "linux")

    def test_domains_exist_only_where_they_can_be_observed(self):
        for kind, want in (("wsl", ("wsl", "win")), ("windows", ("win",)), ("linux", ("wsl",))):
            with as_kind(kind):
                self.assertEqual(host.domains(), want)
                self.assertEqual(host.select(("wsl", "win")), want)
        with as_kind("windows"):
            self.assertEqual(host.select(("wsl",)), ())
            self.assertEqual(host.local_label(), "win")

    def test_local_finding_label_matches_the_running_platform(self):
        self.assertEqual(finding.LOCAL_HOST, "win" if os.name == "nt" else "wsl")
        self.assertEqual(finding.finding("c", "low", "t", "d")["host"], finding.LOCAL_HOST)
        self.assertEqual(finding.finding("c", "low", "t", "d", host="win")["host"], "win")


class PathTests(unittest.TestCase):
    def test_wsl_mapping_is_the_formula_every_collector_used(self):
        with as_kind("wsl"):
            for path in (r"C:\Users\x\AppData", r"D:\a b\c.exe", "c:\\Windows", "C:/Users/x"):
                p = path.replace("\\", "/")
                self.assertEqual(host.local_path(path), "/mnt/" + p[0].lower() + p[2:])
            self.assertEqual(host.windows_path("/mnt/c/Users/x/a.txt"), r"C:\Users\x\a.txt")
            self.assertEqual(host.windows_root(), "/mnt/c")
            self.assertEqual(host.program_data("Jarvis", "Sensor"), "/mnt/c/ProgramData/Jarvis/Sensor")
            self.assertEqual(host.subprocess_cwd(), "/")
            self.assertEqual(host.spawn_options(), {})

    def test_native_windows_names_windows_paths_as_themselves(self):
        env = {"SystemRoot": r"C:\Windows", "ProgramData": r"C:\ProgramData",
               "LOCALAPPDATA": r"C:\Users\u\AppData\Local", "USERPROFILE": r"C:\Users\u",
               "SystemDrive": "C:", "USERNAME": "u"}
        with as_kind("windows"), mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(host.local_path(r"C:\Users\u\x"), r"C:\Users\u\x")
            self.assertEqual(host.windows_root(), "C:\\")
            self.assertEqual(host.local_appdata("Jarvis", "a.json"),
                             r"C:\Users\u\AppData\Local\Jarvis\a.json")
            self.assertEqual(host.program_data("Jarvis"), r"C:\ProgramData\Jarvis")
            self.assertEqual(host.subprocess_cwd(), r"C:\Windows")
            self.assertEqual(host.windows_user(), "u")

    def test_environment_cannot_redirect_system_paths_off_a_drive(self):
        hostile = {"SystemRoot": r"\\evil\share", "ProgramData": "relative", "SystemDrive": "C:"}
        with as_kind("windows"), mock.patch.dict(os.environ, hostile, clear=True):
            self.assertEqual(host.windows_dir(), r"C:\Windows")
            self.assertEqual(host.program_data(), r"C:\ProgramData")

    def test_plain_linux_maps_nothing_rather_than_guessing(self):
        with as_kind("linux"):
            self.assertEqual(host.local_path(r"C:\Windows"), "")
            self.assertEqual(host.windows_path("/home/u/x"), "")
            self.assertEqual(host.windows_root(), "")
            self.assertEqual(host.local_appdata("Jarvis"), "")
            self.assertEqual(host.powershell_candidates(), [])

    def test_non_windows_paths_never_map(self):
        for kind in ("wsl", "windows", "linux"):
            with as_kind(kind):
                for path in ("", None, "/etc/passwd", "relative", "C:relative", 7):
                    self.assertEqual(host.local_path(path), "")


class BridgeTests(unittest.TestCase):
    def test_native_windows_never_resolves_powershell_through_path(self):
        planted = r"C:\Users\u\bin\powershell.exe"
        with as_kind("windows"), \
                mock.patch.object(bridge.shutil, "which", return_value=planted) as which, \
                mock.patch.object(bridge, "FALLBACK_PS", [r"C:\Windows\System32\ps.exe"]), \
                mock.patch.object(bridge.os.path, "exists", return_value=True):
            self.assertEqual(bridge.find_powershell(), r"C:\Windows\System32\ps.exe")
            which.assert_not_called()

    def test_native_windows_needs_no_interop_socket(self):
        with as_kind("windows"), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WSL_INTEROP", None)
            self.assertTrue(bridge.ensure_interop())
            self.assertEqual(bridge.interop_sockets(), [])

    def test_missing_powershell_is_unavailable_not_assumed(self):
        with as_kind("windows"), mock.patch.object(bridge, "_PS", None), \
                mock.patch.object(bridge, "FALLBACK_PS", [r"C:\nope\powershell.exe"]), \
                mock.patch.object(bridge.os.path, "exists", return_value=False):
            self.assertFalse(bridge.available())
            self.assertIsNone(bridge.ps_json("1"))

    def test_plain_linux_has_no_bridge(self):
        with as_kind("linux"), mock.patch.object(bridge, "_PS", None), \
                mock.patch.object(bridge.shutil, "which", return_value="/usr/bin/pwsh.exe"):
            self.assertEqual(bridge.find_powershell(), "")
            self.assertFalse(bridge.available())

    def test_session_probe_decides_desktop_reach_natively(self):
        for reply, want in (("1:1", True), ("0:1", False), ("0:0", False), ("", False)):
            done = SimpleNamespace(stdout=reply)
            with as_kind("windows"), mock.patch.object(bridge, "_PS", "ps"), \
                    mock.patch.object(bridge, "_run_via", return_value=done):
                self.assertEqual(bridge.on_desktop(), want, reply)
        with as_kind("windows"), mock.patch.object(bridge, "_PS", "ps"), \
                mock.patch.object(bridge, "_run_via", return_value=None):
            self.assertFalse(bridge.on_desktop())       # an unanswered probe is not a yes


class ScheduleTests(unittest.TestCase):
    def test_wsl_schedule_is_the_whole_table_in_order(self):
        keep, absent = schedule.applicable(True, True)
        self.assertEqual(list(keep.items()), list(schedule.ALL_JOBS.items()))
        self.assertEqual(absent, {})

    def test_single_domain_jobs_are_declared_against_real_jobs(self):
        named = schedule.WINDOWS_ONLY | schedule.LINUX_ONLY
        self.assertFalse(schedule.WINDOWS_ONLY & schedule.LINUX_ONLY)
        self.assertLessEqual(named, set(schedule.ALL_JOBS))
        self.assertEqual(set(jobs.RUNNERS), set(schedule.ALL_JOBS))

    def test_absent_domain_is_listed_with_a_reason_not_dropped(self):
        keep, absent = schedule.applicable(True, False)
        self.assertEqual(set(absent), schedule.LINUX_ONLY)
        self.assertFalse(set(keep) & schedule.LINUX_ONLY)
        self.assertTrue(all("Linux" in why for why in absent.values()))
        keep, absent = schedule.applicable(False, True)
        # A plain Linux server also drops the workstation-only features (2026-10-25).
        self.assertEqual(set(absent), schedule.WINDOWS_ONLY | schedule.WORKSTATION_ONLY)
        self.assertEqual({absent[n] for n in schedule.WORKSTATION_ONLY},
                         {"a workstation feature; not scheduled on servers"})
        self.assertEqual(set(keep) | set(absent), set(schedule.ALL_JOBS))
        keep, absent = schedule.applicable(True, True)
        self.assertLessEqual(schedule.WORKSTATION_ONLY, set(keep))

    def test_not_applicable_jobs_earn_no_score_and_no_coverage(self):
        keep, absent = schedule.applicable(True, False)
        now = int(time.time())
        fresh = {name: {"ts": now, "findings": []} for name in keep}
        # A stale result for an absent job must not leak in as an observation.
        fresh.update({name: {"ts": now, "findings": []} for name in absent})
        result = score.compute(fresh, keep, now=now)
        counted = sum(a["jobs"] for a in result["areas"])
        self.assertEqual(counted, sum(1 for j in keep if j in score.AREA_OF))
        # Nothing observed at all: absence of Linux jobs is not health.
        blind = score.compute({}, keep, now=now)
        self.assertEqual(blind["score"], 0)
        self.assertEqual(blind["coverage"], 0)

    def test_two_domain_spyware_job_observes_only_the_selected_domains(self):
        with mock.patch.object(jobs.spyware, "audit", return_value=[]) as audit:
            jobs.RUNNERS["spy"](("win",), ":memory:")
            jobs.RUNNERS["spy"](("wsl", "win"), ":memory:")
        self.assertEqual([c.kwargs["hosts"] for c in audit.call_args_list],
                         [("win",), ("wsl", "win")])

    def test_cli_refuses_a_domain_this_machine_does_not_have(self):
        with as_kind("windows"):
            self.assertEqual(output.selected_hosts(SimpleNamespace(host="all")), ("win",))
            self.assertEqual(output.selected_hosts(SimpleNamespace(host="win")), ("win",))
            with self.assertRaises(SystemExit):
                output.selected_hosts(SimpleNamespace(host="wsl"))
        with as_kind("wsl"):
            self.assertEqual(output.selected_hosts(SimpleNamespace(host="all")), ("wsl", "win"))


class LockTests(unittest.TestCase):
    def test_second_holder_is_refused_until_the_first_closes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "writer.lock")
            first = open(path, "a")
            filelock.acquire(first)
            second = open(path, "a")
            try:
                with self.assertRaises(OSError):
                    filelock.acquire(second)
                first.close()
                filelock.acquire(second)        # released by close, not by cleanup code
            finally:
                first.close()
                second.close()

    def test_event_log_has_one_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "eventlog")
            writer = EventLog(root, writer=True)
            try:
                with self.assertRaises(LogError):
                    EventLog(root, writer=True)
            finally:
                writer.close()
            EventLog(root, writer=True).close()     # and it is reusable afterwards


class SignalTests(unittest.TestCase):
    def test_pid_probe_sends_nothing_on_windows(self):
        with mock.patch.object(linux.os, "name", "nt"), mock.patch.object(linux.os, "kill") as kill:
            with self.assertRaises(ProcessLookupError):
                linux.signal_zero(os.getpid())
            kill.assert_not_called()

    @unittest.skipIf(os.name == "nt", "signal 0 is a question only on POSIX")
    def test_pid_probe_still_answers_on_posix(self):
        linux.signal_zero(os.getpid())
        with self.assertRaises(OSError):
            linux.signal_zero(2 ** 22 + 12345)

    def test_suspend_refuses_on_windows_without_signalling(self):
        action = suspend.Suspend() if hasattr(suspend, "Suspend") else None
        if action is None:
            action = next(v() for v in vars(suspend).values()
                          if isinstance(v, type) and hasattr(v, "apply") and hasattr(v, "undo")
                          and v.__module__ == suspend.__name__)
        with mock.patch.object(suspend.os, "name", "nt"), \
                mock.patch.object(suspend.os, "kill") as kill:
            ok, record, why = action.apply({"pid": os.getpid(), "started": 1}, None)
            self.assertFalse(ok)
            self.assertEqual(record, {})
            self.assertIn("Linux", why)
            done, why = action.undo({}, {"pid": os.getpid(), "started": 1})
            self.assertFalse(done)
            kill.assert_not_called()


class PermissionTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "mode bits enforce nothing on NTFS")
    def test_posix_mode_bits_prove_privacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secret")
            open(path, "w").close()
            os.chmod(path, 0o600)
            self.assertTrue(fsperm.owner_only(os.stat(path)))
            os.chmod(path, 0o640)
            self.assertFalse(fsperm.owner_only(os.stat(path)))

    def test_without_enforced_mode_bits_nothing_is_private(self):
        st = SimpleNamespace(st_uid=0, st_mode=0o100600)
        with mock.patch.object(fsperm, "os", SimpleNamespace()):
            self.assertFalse(fsperm.owner_only(st))

    def test_linux_capabilities_are_all_missing_where_they_do_not_exist(self):
        with mock.patch.object(privilege, "os", SimpleNamespace(name="nt")):
            self.assertEqual(privilege.missing(), list(privilege.CAPS))
            self.assertTrue(privilege.drop_ambient())


class NativeServiceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "state.json")

    def audit(self, state=None, pid=4242, now=1000):
        if state is not None:
            import json
            with open(self.path, "w") as fh:
                json.dump(state, fh)
        return supervisors.audit_native_service(self.path, now=now, pid=pid)[0]

    def test_supervised_daemon_is_ok_only_with_fresh_matching_state(self):
        f = self.audit({"checkedAt": 995, "pid": 4242})
        self.assertEqual((f["severity"], f["host"]), ("ok", "win"))

    def test_every_broken_supervision_state_is_named(self):
        self.assertEqual(self.audit()["severity"], "high")                       # not installed
        self.assertEqual(self.audit({"checkedAt": 100, "pid": 4242})["severity"], "high")   # stale
        self.assertEqual(self.audit({"pid": 4242})["severity"], "high")          # never checked
        self.assertEqual(self.audit({"checkedAt": 999, "pid": 4242, "gaveUp": True})["severity"],
                         "high")
        self.assertEqual(self.audit({"checkedAt": 999, "pid": 4242, "paused": True})["severity"],
                         "medium")
        other = self.audit({"checkedAt": 999, "pid": 7})
        self.assertEqual(other["severity"], "medium")
        self.assertIn("not started by the native service", other["title"])
        with open(self.path, "w") as fh:
            fh.write("{truncated")
        self.assertEqual(self.audit()["severity"], "medium")                     # unreadable

    def test_stopped_supervisor_pages_as_an_outage(self):
        f = self.audit({"checkedAt": 100, "pid": 4242})
        self.assertTrue(alert.is_outage(f))

    def test_native_watchdog_job_never_asks_systemd(self):
        ok = [{"category": "daemon", "severity": "ok", "title": "t", "detail": "", "where": "",
               "host": "win"}]
        with as_kind("windows"), \
                mock.patch.object(jobs.alert, "channel_findings", return_value=[]), \
                mock.patch.object(jobs, "_link_findings", return_value=[]), \
                mock.patch.object(jobs.supervisors, "audit_health_monitor", return_value=[]), \
                mock.patch.object(jobs.supervisors, "audit_native_service", return_value=ok) as native, \
                mock.patch.object(jobs.supervisors, "audit_reviver") as reviver, \
                mock.patch.object(jobs.supervisors, "audit_broker", return_value=[]), \
                mock.patch.object(jobs.connectivity, "audit", return_value=[]), \
                mock.patch.object(jobs.selfcheck, "timer_state") as timer:
            self.assertEqual(jobs._watchdogs(("win",), ":memory:"), ok)
            native.assert_called_once()
            reviver.assert_not_called()
            timer.assert_not_called()

    def test_plain_linux_watchdog_job_reads_no_windows_task_state(self):
        with as_kind("linux"), \
                mock.patch.object(jobs.alert, "channel_findings", return_value=[]), \
                mock.patch.object(jobs.supervisors, "audit_health_monitor") as monitor, \
                mock.patch.object(jobs.supervisors, "audit_broker") as broker, \
                mock.patch.object(jobs.selfcheck, "timer_state", return_value=("", "")), \
                mock.patch.object(jobs.selfcheck, "systemd_supervision", return_value=(0, "")):
            out = jobs._watchdogs(("wsl",), ":memory:")
            monitor.assert_not_called()
            broker.assert_not_called()
            # No timer and no systemd watchdog is still a finding.
            self.assertEqual(out[-1]["severity"], "high")

    def test_task_declaration_names_the_staged_script_and_checkout(self):
        task = persistence.BY_NAME["jarvis native service"]
        self.assertIn(task.name, persistence.CRITICAL_ON_MISMATCH)
        self.assertEqual(task.run_level, "limited")
        args = persistence.expected_arguments(task, r"C:\Users\u\AppData\Local", r"C:\jarvis")
        self.assertTrue(args.endswith(
            r'-File "C:\Users\u\AppData\Local\Jarvis\NativeService\jarvis-native-service.ps1" '
            r'-RepoRoot "C:\jarvis"'))
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              task.release_script)
        self.assertTrue(os.path.isfile(script))
        with open(script, encoding="utf-8") as fh:
            text = fh.read()
        # The installer registers exactly the arguments the declaration expects.
        self.assertIn("'\" -RepoRoot \"' + $RepoRoot + '\"'", text)
        self.assertIn("-RunLevel Limited", text)
        self.assertNotIn("-Verb RunAs", text)


class CoverageTests(unittest.TestCase):
    def test_native_bridge_outage_pages_like_the_interop_one(self):
        with as_kind("windows"), mock.patch.object(coverage.collect_windows, "available",
                                                    return_value=False):
            f = coverage.bridge_status()[0]
        self.assertEqual((f["severity"], f["host"]), ("critical", "win"))
        self.assertTrue(alert.is_outage(f))
        self.assertNotIn("WSL", f["detail"])

    def test_absent_jobs_are_stated_and_linux_views_are_not_faked(self):
        absent = {"auditd": "this machine has no Linux domain to observe"}
        with as_kind("windows"), mock.patch.object(coverage, "NOT_APPLICABLE", absent), \
                mock.patch.object(coverage, "bridge_status", return_value=[]), \
                mock.patch.object(coverage.hidden, "view_getdents") as getdents:
            out = coverage.visibility()
            getdents.assert_not_called()
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["severity"], out[0]["category"]), ("low", "limits"))
        self.assertIn("auditd", out[0]["detail"])
        self.assertIn("not scored", out[0]["detail"])

    def test_native_daemon_health_is_the_supervisor_state_not_systemd(self):
        seen = [{"category": "daemon", "severity": "high", "title": "the native service has stopped",
                 "detail": "", "where": "", "host": "win"}]
        with as_kind("windows"), mock.patch.object(supervisors, "audit_native_service",
                                                    return_value=seen), \
                mock.patch.object(coverage.shutil, "which") as which:
            self.assertEqual(coverage.daemon_health(), seen)
            which.assert_not_called()

    def test_limits_name_wsl_only_on_wsl_and_ntfs_only_natively(self):
        with as_kind("wsl"):
            titles = [f["title"] for f in coverage.known_limits()]
        self.assertIn("WSL is not a security boundary", titles)
        self.assertNotIn("file privacy is not verified on NTFS", titles)
        with as_kind("windows"):
            titles = [f["title"] for f in coverage.known_limits()]
        self.assertNotIn("WSL is not a security boundary", titles)
        self.assertIn("file privacy is not verified on NTFS", titles)


if __name__ == "__main__":
    unittest.main()

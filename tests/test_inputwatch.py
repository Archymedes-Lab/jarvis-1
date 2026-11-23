import importlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.host import inputwatch
from jarvis.core.store import Store
from jarvis.core.util import now


class TypingWindowTests(unittest.TestCase):
    def test_punctuation_concentration_is_detected_without_key_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            try:
                store.db.execute(
                    "INSERT INTO input_typing_windows "
                    "(ts,real_keys,real_key_gaps,equals_keys) VALUES(?,?,?,?)",
                    (now(), 40, 39, 22),
                )
                findings = inputwatch._typing_findings(store, None)
                finding = next(f for f in findings if "equals/plus" in f["title"])
                self.assertEqual(finding["severity"], "low")
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertNotIn("key", columns)
                self.assertNotIn("text", columns)
                self.assertNotIn("character", columns)
            finally:
                store.close()

    def test_digit_concentration_is_detected_without_key_content(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "jarvis.db"))
            try:
                store.db.execute(
                    "INSERT INTO input_typing_windows "
                    "(ts,real_keys,real_key_gaps,digit_keys) VALUES(?,?,?,?)",
                    (now(), 40, 39, 22),
                )
                findings = inputwatch._typing_findings(store, None)
                finding = next(f for f in findings if "digit" in f["title"])
                self.assertEqual(finding["severity"], "low")
            finally:
                store.close()

    def test_existing_typing_table_gets_new_punctuation_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "old.db")
            db = sqlite3.connect(path)
            db.execute(
                "CREATE TABLE input_typing_windows ("
                "ts INTEGER PRIMARY KEY, real_keys INTEGER NOT NULL DEFAULT 0, "
                "injected_keys INTEGER NOT NULL DEFAULT 0, "
                "real_key_gaps INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub20 INTEGER NOT NULL DEFAULT 0, "
                "real_key_sub8 INTEGER NOT NULL DEFAULT 0, "
                "cad_run_max INTEGER NOT NULL DEFAULT 0)"
            )
            db.commit()
            db.close()

            store = Store(path)
            try:
                columns = {row[1] for row in store.db.execute(
                    "PRAGMA table_info(input_typing_windows)")}
                self.assertTrue(
                    {"equals_keys", "slash_keys", "period_keys", "digit_keys"}
                    <= columns)
            finally:
                store.close()


class DesktopSessionTests(unittest.TestCase):
    """A hook outside the desktop session heartbeats forever and sees nothing."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(os.path.join(self.tmp.name, "jarvis.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_heartbeat_session_is_recorded(self):
        from unittest import mock

        ingest = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")
        out = os.path.join(self.tmp.name, "input.jsonl")
        with open(out, "w") as fh:
            fh.write('{"ts": 1, "kind": "heartbeat", "pid": 7, "session": 0, "desktop": 2, '
                     '"counters": {}, "window": {}}\n')
        with mock.patch.object(ingest, "_paths", return_value=("C:\\x", out)):
            ingest.ingest(self.store)
        self.assertEqual(self.store.get_meta("input_hook_session"), "0:2")

    def test_only_a_real_mismatch_counts_as_outside(self):
        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        for value, expected in (("0:2", (0, 2)), ("2:2", None), ("0:-1", None), ("", None)):
            with self.subTest(value=value):
                self.store.set_meta("input_hook_session", value)
                self.assertEqual(supervise._outside_desktop(self.store), expected)

    def test_healthy_looking_hook_outside_the_desktop_is_restarted(self):
        from unittest import mock

        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        self.store.set_meta("input_hook_session", "0:2")
        with mock.patch.object(supervise, "_verify_pin", return_value=[]), \
             mock.patch.object(supervise, "ingest"), \
             mock.patch.object(supervise, "liveness", return_value=("fresh", 0)), \
             mock.patch.object(supervise, "_stop_all") as stop_all, \
             mock.patch.object(supervise, "start", return_value="") as start:
            _pids, findings = supervise.supervise(self.store)
        stop_all.assert_called_once()
        start.assert_called_once()
        titles = [f["title"] for f in findings]
        self.assertIn("the input hook was running outside the desktop session", titles)
        self.assertNotIn("the injected-input monitor is healthy", titles)

    def _start_with(self, task_reply, desktop=""):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        paths = ("C:\\Jarvis\\input.jsonl", os.path.join(self.tmp.name, "input.jsonl"))
        with mock.patch.object(helper, "helper_count", return_value=0), \
             mock.patch.object(helper, "_paths", return_value=paths), \
             mock.patch.object(helper, "_stage_helper",
                               return_value=("C:\\Jarvis\\inputhook.ps1", paths[0], "")), \
             mock.patch.object(helper.collect_windows, "available", return_value=True), \
             mock.patch.object(helper.collect_windows, "desktop_interop", return_value=desktop), \
             mock.patch.object(helper, "ps_json", return_value=task_reply) as task, \
             mock.patch.object(helper, "subprocess") as sub:
            return helper.start(), task, sub

    def test_the_scheduled_task_is_the_normal_way_the_hook_starts(self):
        err, task, sub = self._start_with({"registered": True, "started": True})
        self.assertEqual(err, "")
        sub.run.assert_not_called()          # no direct WSL launch needed
        script = task.call_args.args[0]
        for required in ("JARVIS input hook", "-LogonType Interactive", "-RunLevel Limited",
                         "-MultipleInstances IgnoreNew", "-RestartCount 3",
                         "conhost.exe", "--headless", "Start-ScheduledTask"):
            self.assertIn(required, script)

    def test_a_refused_task_falls_back_to_a_desktop_launch(self):
        err, _task, sub = self._start_with({"error": "Access is denied"},
                                           desktop="/run/WSL/3309_interop")
        self.assertEqual(err, "")
        self.assertEqual(sub.run.call_args.kwargs["env"]["WSL_INTEROP"], "/run/WSL/3309_interop")

    def test_no_task_and_no_desktop_connection_is_reported_not_guessed(self):
        err, _task, sub = self._start_with({"error": "Access is denied"}, desktop="")
        self.assertIn("Access is denied", err)
        self.assertIn("desktop", err)
        sub.run.assert_not_called()

    def test_the_task_definition_is_one_jarvis_verifies_as_its_own(self):
        from jarvis.collectors.persistence import trusted_tasks
        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        local = r"C:\Users\chris\AppData\Local"
        arguments = helper.task_arguments(local + r"\Jarvis\inputhook.ps1",
                                          local + r"\Jarvis\input.jsonl")
        task = {"name": helper.TASK_NAME, "runLevel": "Limited", "user": "DESKTOP\\chris",
                "logonType": "Interactive",
                "actions": [{"execute": r"C:\Windows\System32\conhost.exe",
                             "arguments": '--headless "C:\\Windows\\System32\\WindowsPowerShell'
                                          '\\v1.0\\powershell.exe" ' + arguments,
                             "targetHash": trusted_tasks.normalized_text_hash(
                                 str(trusted_tasks.win_script("inputhook.ps1")))}]}
        data = {"currentUser": "DESKTOP\\chris", "localAppData": local}
        self.assertEqual(trusted_tasks.verified_maintenance_task(task, data)[0], True)

        tampered = {**task, "actions": [{**task["actions"][0], "targetHash": "0" * 64}]}
        ok, why = trusted_tasks.verified_maintenance_task(tampered, data)
        self.assertFalse(ok)
        self.assertIn("fingerprint", why)

    def test_start_never_launches_beside_an_existing_or_uncountable_helper(self):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        for count, expected in ((1, "already running"), (-1, "possible duplicate")):
            with self.subTest(count=count), \
                 mock.patch.object(helper, "helper_count", return_value=count), \
                 mock.patch.object(helper.collect_windows, "desktop_interop") as desktop, \
                 mock.patch.object(helper.subprocess, "run") as run:
                self.assertIn(expected, helper.start())
                desktop.assert_not_called()
                run.assert_not_called()

    def test_stop_all_also_targets_heartbeat_pids_it_cannot_see_by_command_line(self):
        from unittest import mock

        helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        with mock.patch.object(helper.collect_windows, "run_in_every_session") as run, \
             mock.patch.object(helper, "_paths", return_value=("C:\\x", os.path.join(self.tmp.name, "input.jsonl"))):
            helper._stop_all(pids=["13544", "7560", "1; Stop-Computer", ""])
        script = run.call_args.args[0]
        self.assertIn("@(13544,7560)", script)
        self.assertNotIn("Stop-Computer", script)
        self.assertIn("ProcessName -eq 'powershell'", script)

    def test_duplicate_reconciliation_stops_the_pids_that_wrote_heartbeats(self):
        from unittest import mock

        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        self.store.set_meta("input_hook_dupe_pids", f"{int(time.time())}:13544,7560")
        with mock.patch.object(supervise, "_verify_pin", return_value=[]), \
             mock.patch.object(supervise, "ingest"), \
             mock.patch.object(supervise, "_stop_all") as stop_all, \
             mock.patch.object(supervise, "start", return_value=""):
            supervise.supervise(self.store)
        stop_all.assert_called_once_with(pids=["13544", "7560"])

    def test_cleanup_runs_through_every_live_socket(self):
        import subprocess
        from unittest import mock

        from jarvis.platform import windows
        with mock.patch.object(windows, "_PS", "powershell.exe"), \
             mock.patch.object(windows, "interop_sockets", return_value=["/run/WSL/2_interop", "/run/WSL/3309_interop"]), \
             mock.patch.object(windows.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(windows.run_in_every_session("Stop-Process -Id 1"), 2)
        self.assertEqual([c.kwargs["env"]["WSL_INTEROP"] for c in run.call_args_list],
                         ["/run/WSL/2_interop", "/run/WSL/3309_interop"])

    def test_desktop_interop_picks_the_socket_that_lands_on_the_desktop(self):
        import stat
        import subprocess
        from unittest import mock

        from jarvis.platform import windows
        replies = {"/run/WSL/531_interop": "0:2\n", "/run/WSL/3309_interop": "2:2\n"}

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, replies[kwargs["env"]["WSL_INTEROP"]], "")

        with mock.patch.object(windows, "_PS", "powershell.exe"), \
             mock.patch.object(windows.os, "listdir", return_value=["531_interop", "3309_interop"]), \
             mock.patch.object(windows.os.path, "getmtime", side_effect=lambda p: 2 if "531" in p else 1), \
             mock.patch.object(windows.os.path, "islink", return_value=False), \
             mock.patch.object(windows.os, "stat", return_value=mock.Mock(st_mode=stat.S_IFSOCK)), \
             mock.patch.object(windows.subprocess, "run", side_effect=fake_run):
            self.assertEqual(windows.desktop_interop(), "/run/WSL/3309_interop")



class OwnHelperScopeTests(unittest.TestCase):
    """2026-10-31: the installed Argus app and this daemon each supervise a hook;
    matching any `inputhook.ps1` made each stop the other's as a duplicate."""

    def test_count_and_stop_match_only_this_installs_output_file(self):
        from jarvis.collectors.host.inputwatch import helper
        own = r"C:\\Users\\u\\AppData\\Local\\Jarvis\\input.jsonl"
        with mock.patch.object(helper, "_paths", return_value=(own, "/tmp/x")):
            clause = helper._own_helper_clause()
            seen = []
            with mock.patch.object(helper, "ps_json", side_effect=lambda s, timeout=60: seen.append(s) or {"n": 0}):
                helper.helper_count()
            with mock.patch.object(helper.collect_windows, "run_in_every_session",
                                   side_effect=lambda s, timeout=90: seen.append(s)):
                helper._stop_all()
        self.assertIn(own, clause)
        self.assertIn("OrdinalIgnoreCase", clause)
        for script in seen:
            self.assertIn(clause, script)
            # never the bare product-agnostic match on its own
            self.assertNotRegex(script, r"Where-Object \{ \$_\.CommandLine -like '\*inputhook\.ps1\*' -and \$_\.ProcessId")

    def test_quote_in_profile_path_cannot_break_out(self):
        from jarvis.collectors.host.inputwatch import helper
        odd = r"C:\\Users\\o'brien\\AppData\\Local\\Jarvis\\input.jsonl"
        with mock.patch.object(helper, "_paths", return_value=(odd, "/tmp/x")):
            clause = helper._own_helper_clause()
        self.assertIn("o''brien", clause)
        self.assertNotIn("o'brien", clause.replace("o''brien", ""))


class HostReportTests(unittest.TestCase):
    """The resident host's heartbeat counters and watchdog lines reach findings."""

    def _store(self):
        from jarvis.core.store import Store
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        return Store(os.path.join(tmp, "j.db"))

    def _ingest(self, store, lines):
        ingest = importlib.import_module("jarvis.collectors.host.inputwatch.ingest")
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "input.jsonl")
        with open(out, "w") as fh:
            fh.write("\n".join(json.dumps(x) for x in lines) + "\n")
        with mock.patch.object(ingest, "_paths", return_value=("C:\\x", out)):
            return ingest.ingest(store)

    def test_watchdog_lines_and_host_counters_become_findings_not_input_events(self):
        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        store = self._store()
        t = 1_800_000_000
        n = self._ingest(store, [
            {"ts": t, "kind": "hook-state", "state": "reinstalling", "unseen_ms": 3400, "fg": "game:12",
             "kb_quiet_ms": 3400, "mouse_quiet_ms": 200},
            {"ts": t + 40, "kind": "hook-state", "state": "still-deaf", "unseen_ms": 9000, "fg": ""},
            {"ts": t + 60, "kind": "heartbeat", "pid": 5, "session": 1, "desktop": 1, "counters": {},
             "hook": {"reinstalls": 1, "out_dropped": 3, "task_faults": 2, "last_fault": "audio: X boom"}},
        ])
        self.assertEqual(n, 0)                    # nothing filed as an injected-key event
        self.assertEqual(store.db.execute("SELECT COUNT(*) c FROM input_events").fetchone()["c"], 0)
        got = {f["title"]: f for f in supervise.host_findings(store, clock=t + 100)}
        drop = next(f for k, f in got.items() if k.startswith("input reached the desktop 1 time"))
        self.assertEqual(drop["severity"], "low")                  # unconfirmed until soaked
        self.assertIn("game:12", drop["detail"])
        self.assertIn("keyboard hook quiet 3 s, mouse hook quiet 0 s", drop["detail"])
        self.assertEqual(got["input kept arriving without a hook callback after a reinstall"]["severity"], "medium")
        self.assertEqual(got["the input hook dropped 3 output line(s)"]["severity"], "medium")
        self.assertIn("audio: X boom", got["2 input-hook task fault(s) since it started"]["detail"])
        # Old watchdog events age out of the 24 h window.
        later = {f["title"] for f in supervise.host_findings(store, clock=t + 2 * 86400)}
        self.assertFalse(any("without a hook callback" in x for x in later))

    def test_a_clean_host_adds_nothing(self):
        supervise = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        store = self._store()
        self._ingest(store, [{"ts": 1, "kind": "heartbeat", "pid": 5, "counters": {},
                              "hook": {"reinstalls": 0, "out_dropped": 0, "task_faults": 0}}])
        self.assertEqual(supervise.host_findings(store, clock=10), [])


class OwnPidHistoryTests(HostReportTests):
    def test_every_helper_pid_of_ours_counts_as_our_hook_for_a_day(self):
        analysis = importlib.import_module("jarvis.collectors.host.inputwatch.analysis")
        store = self._store()
        self._ingest(store, [{"ts": 1, "kind": "heartbeat", "pid": 7076, "counters": {}}])
        self._ingest(store, [{"ts": 2, "kind": "heartbeat", "pid": 19460, "counters": {}}])
        self.assertEqual(sorted(analysis._recent_own_pids(store)), [7076, 19460])
        # Never call analysis.audit() here: it drains the live hook's output
        # file on this machine (2026-11-01: a check doing so took one heartbeat).
        src = Path(analysis.__file__).read_text(encoding="utf-8")
        self.assertIn("watchers.audit(own_pids=tuple(pids or ()) + _recent_own_pids(store))", src)

    def test_own_pids_older_than_a_day_are_forgotten(self):
        common = importlib.import_module("jarvis.collectors.host.inputwatch.common")
        analysis = importlib.import_module("jarvis.collectors.host.inputwatch.analysis")
        store = self._store()
        store.set_meta(common.OWN_PIDS_META, json.dumps({"5": 1}))           # 1970
        self._ingest(store, [{"ts": 9, "kind": "heartbeat", "pid": 6, "counters": {}}])
        self.assertEqual(analysis._recent_own_pids(store), (6,))


class OwnershipTests(unittest.TestCase):
    """One hook per machine (owner decision 2026-10-31), decided by a marker in
    %LOCALAPPDATA% and by the owner's pulse moving, never by product names."""

    def setUp(self):
        self.helper = importlib.import_module("jarvis.collectors.host.inputwatch.helper")
        self.sup = importlib.import_module("jarvis.collectors.host.inputwatch.supervise")
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root, True)
        for d in ("Jarvis", "Argus"):
            os.makedirs(os.path.join(self.root, d))
        self.win = r"C:\Users\u\AppData\Local"
        mine = (self.win + r"\Jarvis\input.jsonl", os.path.join(self.root, "Jarvis", "input.jsonl"))
        p = mock.patch.object(self.helper, "_paths", return_value=mine)
        p.start(); self.addCleanup(p.stop)
        q = mock.patch.object(self.sup, "_paths", return_value=mine)
        q.start(); self.addCleanup(q.stop)
        self.store = Store(os.path.join(self.root, "j.db"))
        v = mock.patch.object(self.sup, "owner_hook_verified", return_value=True)
        self.verified = v.start(); self.addCleanup(v.stop)

    def mark(self, value):
        with open(os.path.join(self.root, self.helper.OWNER_FILE), "w") as fh:
            fh.write(value)

    def pulse(self, folder, mtime):
        path = os.path.join(self.root, folder, "input.alive")
        with open(path, "w") as fh:
            fh.write("1:1")
        os.utime(path, (mtime, mtime))

    def test_no_marker_or_own_marker_means_no_deferral(self):
        self.assertIsNone(self.sup.deferral(self.store))
        self.helper.claim_owner()
        self.assertEqual(self.helper.owner(), self.win + r"\Jarvis\input.jsonl")
        self.assertIsNone(self.sup.deferral(self.store))

    def test_forged_or_foreign_markers_are_ignored(self):
        for bad in (r"D:\x\Argus\input.jsonl", self.win + r"\Argus\evil.ps1",
                    self.win + r"\..\input.jsonl", "", self.win + r"\A:B\input.jsonl"):
            self.mark(bad)
            self.assertEqual(self.helper.owner(), "", bad)
            self.assertIsNone(self.sup.deferral(self.store), bad)

    def test_defers_while_the_owners_pulse_moves_and_takes_over_when_frozen(self):
        self.mark(self.win + r"\Argus\input.jsonl")
        with mock.patch.object(self.sup, "now", return_value=1000):
            self.pulse("Argus", 500)
            self.assertEqual(self.sup.deferral(self.store)[1], 0)          # first sight counts as moving
        with mock.patch.object(self.sup, "now", return_value=1100):
            self.pulse("Argus", 600)
            self.assertEqual(self.sup.deferral(self.store)[1], 0)          # moved
        with mock.patch.object(self.sup, "now", return_value=1100 + self.sup.OWNER_STALE_S + 5):
            other, frozen, _fake, _unread = self.sup.deferral(self.store)    # not moved since
        self.assertGreater(frozen, self.sup.OWNER_STALE_S)

    def test_fake_pulse_or_unread_output_means_take_over(self):
        self.mark(self.win + r"\Argus\input.jsonl")
        self.pulse("Argus", 500)
        self.verified.return_value = False                             # pid is not a hook
        with mock.patch.object(self.sup, "now", return_value=1000):
            other, frozen, fake, _unread = self.sup.deferral(self.store)
        self.assertTrue(fake)
        self.assertGreater(frozen, self.sup.OWNER_STALE_S)
        # A real hook whose output nobody drains (consumer down) is also not usable.
        self.verified.return_value = True
        self.store.set_meta(self.sup._M_OWNER, "")
        out = os.path.join(self.root, "Argus", "input.jsonl")
        for i, t in enumerate((2000, 2000 + self.sup.OWNER_UNREAD_S + 10)):
            with open(out, "a") as fh:
                fh.write("x" * (100 + i))                               # only grows
            self.pulse("Argus", t)                                      # pulse keeps moving
            with mock.patch.object(self.sup, "now", return_value=t):
                _o, frozen, fake, unread = self.sup.deferral(self.store)
        self.assertFalse(fake)
        self.assertGreater(unread, self.sup.OWNER_UNREAD_S)
        self.assertGreater(frozen, self.sup.OWNER_STALE_S)

    def test_missing_owner_pulse_means_take_over_at_once(self):
        self.mark(self.win + r"\Argus\input.jsonl")
        self.assertGreater(self.sup.deferral(self.store)[1], self.sup.OWNER_STALE_S)

    def test_supervise_defers_stops_ours_and_reports_ok(self):
        self.mark(self.win + r"\Argus\input.jsonl")
        self.pulse("Argus", 100)
        self.pulse("Jarvis", 100)                                             # ours is still up
        with mock.patch.object(self.sup, "_stop_all") as stop_all, \
                mock.patch.object(self.sup, "ingest"), \
                mock.patch.object(self.sup, "_verify_pin", return_value=[]), \
                mock.patch.object(self.sup, "start") as start:
            pids, out = self.sup.supervise(self.store)
        stop_all.assert_called_once()
        start.assert_not_called()
        self.assertEqual(pids, [])
        sev = {f["title"]: f["severity"] for f in out}
        self.assertEqual(sev["the input hook is provided by the Argus install"], "low")
        self.assertIn("stopped this install's input hook: Argus owns it", sev)

if __name__ == "__main__":
    unittest.main()

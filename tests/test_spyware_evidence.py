"""Fusion of hook inventory, contradictions and process evidence."""

import unittest
from datetime import datetime, timezone

from jarvis.core.reasoning import engine
from jarvis.intel import spyware_evidence as ev

T0 = int(datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc).timestamp())   # process start

def proc(pid, name, path, started="2026-09-30T10:00:00Z", **kw):
    base = dict(pid=pid, ppid=1, name=name, path=path, session=1, started=started, window=True,
                ext=0, sig="valid", signer="Microsoft Windows", age=500)
    base.update(kw)
    return base


def hook(pid, path, *, start=T0, type_=13, kind="hook", sig="Valid", signer="Microsoft Windows"):
    return {"kind": kind, "type": str(type_), "pid": pid, "start": start, "path": path,
            "sig": sig, "signer": signer, "failed": False}


PAYLOAD = {"procs": [proc(9504, "explorer.exe", "C:\\WINDOWS\\Explorer.EXE"),
                     proc(16664, "powershell.exe", "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                     proc(7000, "keyz.exe", "C:\\Users\\me\\AppData\\Roaming\\k\\keyz.exe",
                          sig="none", signer="", window=False, ext=1, age=2)],
           "consent": {}, "autostart": ["\"C:\\Users\\me\\AppData\\Roaming\\k\\keyz.exe\" /s"],
           "observed_at": "2026-09-30T11:00:00Z"}


_UNSET = object()


def run(watchers, own=(), deep_windows=_UNSET, deep=False):
    src = {"windows": lambda: PAYLOAD, "inputaudit": lambda: {"watchers": watchers},
           "linux": lambda: ([], {"status": "complete"}), "hidden_linux": lambda: []}
    if deep_windows is not _UNSET:
        src["hidden_windows"] = lambda: deep_windows
    subs, cov = ev.gather(("win",), deep=deep, own_pids=own, sources=src)
    return {s.label: engine.assess(s) for s in subs}, cov, subs


class HookFusionTests(unittest.TestCase):
    def test_shell_hook_is_explained_unsigned_keylogger_shape_is_a_chain(self):
        rows, cov, _ = run([hook(9504, "C:\\WINDOWS\\Explorer.EXE", start=T0),
                            hook(7000, "C:\\Users\\me\\AppData\\Roaming\\k\\keyz.exe", sig="NotSigned",
                                 signer="", start=T0)])
        self.assertEqual(cov["keyboard-hooks"], "current")
        self.assertEqual(rows["keyz.exe"]["verdict"], "SUSPECT_CHAIN")
        self.assertEqual(rows["explorer.exe"]["verdict"], "EXPECTED_DECLARED")

    def test_script_host_hook_is_unexplained_unless_it_is_jarvis_own_verified_pid(self):
        w = [hook(16664, "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", start=T0)]
        self.assertEqual(run(w)[0]["powershell.exe"]["verdict"], "UNEXPLAINED_CAPABILITY")
        self.assertEqual(run(w, own=[16664])[0]["powershell.exe"]["verdict"], "EXPECTED_DECLARED")

    def test_own_pid_status_does_not_spread_to_other_processes(self):
        rows, _, _ = run([hook(16664, "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                          hook(7000, "C:\\Users\\me\\AppData\\Roaming\\k\\keyz.exe", sig="NotSigned",
                               signer="")], own=[16664])
        self.assertNotEqual(rows["keyz.exe"]["verdict"], "EXPECTED_DECLARED")

    def test_reused_pid_is_not_credited_with_the_old_watcher(self):
        # The watcher registered at 1790000000; the live pid 7000 started much later.
        rows, _, subs = run([hook(7000, "C:\\gone\\old.exe", start=1790000000)])
        self.assertEqual(rows["keyz.exe"]["capture"], [])
        self.assertIn("old.exe", rows)          # the exited registrant is its own subject

    def test_mouse_hooks_and_foreground_rawinput_are_not_keyboard_watchers(self):
        w = ev.keyboard_watchers([hook(1, "a", type_=14), hook(2, "b", type_=7),
                                  hook(3, "c", kind="rawinput", type_="1/6/0"),
                                  hook(4, "d", kind="rawinput", type_="1/2/256"),
                                  hook(5, "e", kind="rawinput", type_="1/6/1"),
                                  hook(6, "f", kind="rawinput", type_="1/6/256"),
                                  {"kind": "hook", "type": "13", "pid": 8, "failed": True},
                                  "junk", {"kind": "hook", "type": "13", "pid": "x"}])
        self.assertEqual(sorted(p for p, _ in w), [6])

    def test_missing_broker_is_reported_unavailable_not_clean(self):
        src = {"windows": lambda: PAYLOAD, "inputaudit": lambda: None}
        _, cov = ev.gather(("win",), sources=src)
        self.assertEqual(cov["keyboard-hooks"], "unavailable")

    def test_watcher_list_is_bounded(self):
        rows = [hook(100 + i, "C:\\x.exe") for i in range(ev.MAX_WATCHERS + 500)]
        self.assertLessEqual(len(ev.keyboard_watchers(rows)), ev.MAX_WATCHERS)


class ContradictionTests(unittest.TestCase):
    DATA = {"openable": [{"pid": 4444, "image": "x.exe"}], "ghostThreads": [{"pid": 5555}],
            "netpids": [6666], "ghostNet": [{"pid": 6666}],
            "wmi": [{"pid": 7777}, {"pid": 100}], "api": [{"pid": 100}, {"pid": 8888}],
            "tasklist": [{"pid": 100}],
            "wmiOnly": [7777, 100], "apiOnly": [8888, 100], "ghostPerf": [{"pid": 0}]}

    def test_every_confirmed_view_becomes_a_contradiction_and_low_pids_are_ignored(self):
        subs = ev.windows_contradictions(self.DATA, "b")
        self.assertEqual(sorted(s.label for s in subs),
                         ["pid 4444", "pid 5555", "pid 6666", "pid 7777", "pid 8888"])
        self.assertTrue(all(engine.assess(s)["verdict"] == "VISIBILITY_CONTRADICTION" for s in subs))

    def test_raw_disagreement_lists_alone_are_not_contradictions(self):
        # pid 100 is in wmiOnly/apiOnly but present in both views: a race, not hiding.
        subs = ev.windows_contradictions(self.DATA, "b")
        self.assertNotIn("pid 100", [s.label for s in subs])
        self.assertEqual(ev.windows_contradictions({"wmiOnly": [5], "apiOnly": [6]}, ""), [])

    def test_network_owner_listed_by_any_view_is_not_invisible(self):
        data = {**self.DATA, "tasklist": [{"pid": 6666}]}
        self.assertNotIn("pid 6666", [s.label for s in ev.windows_contradictions(data, "b")])

    def test_deep_mode_adds_contradictions_and_records_source_status(self):
        rows, cov, _ = run([], deep=True, deep_windows=self.DATA)
        self.assertEqual(cov["hidden-windows"], "current")
        self.assertEqual(rows["pid 4444"]["verdict"], "VISIBILITY_CONTRADICTION")
        _, cov, _ = run([], deep=True, deep_windows=None)
        self.assertEqual(cov["hidden-windows"], "unavailable")

    def test_linux_contradictions_only_from_confirmed_critical_findings(self):
        f = [{"severity": "critical", "title": "process hidden from /proc listing",
              "detail": "pid 4242 (x) resolves by direct stat()"},
             {"severity": "ok", "title": "process hidden from /proc listing", "detail": "pid 1 "},
             {"severity": "critical", "title": "something else", "detail": "pid 9 "}]
        subs = ev.linux_contradictions(f, "b")
        self.assertEqual([s.label for s in subs], ["pid 4242"])

    def test_gaps_are_declared_never_implied_clean(self):
        self.assertTrue(any("polling" in x for x in ev.NOT_CONNECTED))
        self.assertTrue(any("kernel-level" in x for x in ev.NOT_CONNECTED))


if __name__ == "__main__":
    unittest.main()

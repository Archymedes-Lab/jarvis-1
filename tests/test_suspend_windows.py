"""Windows suspend action: narrow match, identity-checked apply, exact undo, never auto."""

import json
import unittest

from jarvis.response.actions import base, suspend_windows


def finding(title="agent.exe is watching every keyboard event", where=r"C:\Users\u\x\agent.exe",
            sev="high", detail="a low-level keyboard hook registered at t (pid 4242); unsigned"):
    return {"category": "input", "severity": sev, "title": title, "detail": detail,
            "where": where, "host": "win"}


class FakeRunner:
    def __init__(self, alive=True, path=r"C:\Users\u\x\agent.exe", ok=True):
        self.alive, self.path, self.ok, self.calls = alive, path, ok, []

    def __call__(self, script, payload):
        data = json.loads(payload)
        self.calls.append((script is suspend_windows.PS_TOGGLE, data))
        if script is suspend_windows.PS_IDENTITY:
            return {"alive": self.alive, "path": self.path, "start": "2026-10-21T10:00:00Z"}
        return {"ok": self.ok, "reason": None if self.ok else "pid no longer names the same process"}


class MatchTests(unittest.TestCase):
    def setUp(self):
        self.action = base.get("suspend_windows_process")

    def test_registered_as_approval_only_and_reversible(self):
        self.assertEqual(self.action.autonomy, base.APPROVE)
        self.assertTrue(self.action.reversible)
        self.assertFalse(self.action.auto_eligible(finding(), "input", {"pid": 1}))

    def test_matches_only_high_keyboard_watchers_from_the_input_job(self):
        t = self.action.match(finding(), "input")
        self.assertEqual(t, {"pid": 4242, "path": r"C:\Users\u\x\agent.exe", "name": "agent.exe"})
        self.assertIsNone(self.action.match(finding(sev="medium"), "input"))
        self.assertIsNone(self.action.match(finding(), "hunt"))
        self.assertIsNone(self.action.match(finding(title="agent.exe is watching every mouse event"), "input"))
        self.assertIsNone(self.action.match(finding(detail="no pid here"), "input"))

    def test_never_targets_system_or_protected_images(self):
        self.assertIsNone(self.action.match(finding(where=r"C:\Windows\explorer.exe",
                                                    title="explorer.exe is watching every keyboard event"), "input"))
        self.assertIsNone(self.action.match(finding(where=r"C:\Program Files\A\a.exe",
                                                    title="a.exe is watching every keyboard event"), "input"))
        self.assertIsNone(self.action.match(finding(where=r"C:\Users\u\powershell.exe",
                                                    title="powershell.exe is watching every keyboard event"), "input"))


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.action = base.get("suspend_windows_process")
        self.target = {"pid": 4242, "path": r"C:\Users\u\x\agent.exe", "name": "agent.exe"}

    def test_apply_checks_identity_then_suspends_and_records_identity(self):
        runner = FakeRunner()
        self.action._run = runner
        ok, record, detail = self.action.apply(self.target, None)
        self.assertTrue(ok, detail)
        self.assertEqual(record["pid"], 4242)
        self.assertEqual(record["start"], "2026-10-21T10:00:00Z")
        toggle = [d for is_toggle, d in runner.calls if is_toggle]
        self.assertEqual(toggle[0]["resume"], False)
        self.assertEqual(toggle[0]["start"], "2026-10-21T10:00:00Z")

    def test_apply_refuses_a_reused_pid_or_an_exited_process(self):
        self.action._run = FakeRunner(path=r"C:\Windows\notepad.exe")
        ok, record, detail = self.action.apply(self.target, None)
        self.assertFalse(ok)
        self.assertIn("different image", detail)
        self.assertEqual(record, {})
        self.action._run = FakeRunner(alive=False)
        self.assertFalse(self.action.apply(self.target, None)[0])

    def test_undo_resumes_the_recorded_process(self):
        runner = FakeRunner()
        self.action._run = runner
        ok, detail = self.action.undo(self.target, {"pid": 4242, "path": self.target["path"],
                                                   "start": "2026-10-21T10:00:00Z"})
        self.assertTrue(ok, detail)
        self.assertTrue(runner.calls[-1][1]["resume"])
        self.assertFalse(self.action.undo(self.target, {})[0])

    def test_scripts_take_arguments_on_stdin_only(self):
        for script in (suspend_windows.PS_IDENTITY, suspend_windows.PS_TOGGLE):
            self.assertIn("[Console]::In.ReadToEnd()", script)
            self.assertNotIn("{pid}", script)


if __name__ == "__main__":
    unittest.main()

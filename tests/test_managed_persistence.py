"""Declarative managed persistence (EVIDENCE-FABRIC.md, P1).

Every declared task verifies only when the live definition matches the
declaration exactly. Each field the old hand-written checks covered is
mutated here and must still be rejected. Jev estimated a 0.31 chance that
declarations weaken detection; these tests are the answer to that doubt.
"""

import copy
import os
import tempfile
import unittest
from pathlib import Path

from jarvis.collectors.host.inputwatch import helper as inputwatch_helper
from jarvis.platform.provenance import persistence as mp

ROOT = Path(__file__).resolve().parents[1]
LOCAL = r"C:\Users\chris\AppData\Local"
DATA = {"currentUser": "DESKTOP\\chris", "localAppData": LOCAL}
CHECKOUT = "/home/chris/jarvis"


class ManagedPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.code = self.tmp.name
        for task in mp.MANAGED_TASKS:
            if task.release_script:
                path = os.path.join(self.code, task.release_script)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as fh:
                    fh.write(f"# reviewed {task.name}\r\n")

    def live(self, task, wrap=True):
        if task.kind == "wsl_start":
            return {"name": task.name.upper(), "user": "DESKTOP\\chris", "runLevel": "Limited",
                    "logonType": "Interactive",
                    "actions": [{"execute": "wsl.exe", "arguments": task.args}]}
        args = mp.expected_arguments(task, LOCAL, CHECKOUT)
        action = {"execute": "powershell.exe", "arguments": args,
                  "targetHash": mp.expected_hash(task, self.code)}
        if wrap:
            action["execute"] = r"C:\WINDOWS\System32\conhost.exe"
            action["arguments"] = (r'--headless "C:\WINDOWS\System32\WindowsPowerShell\v1.0'
                                   r'\powershell.exe" ' + args)
        user = "SYSTEM" if task.principal == "system" else "DESKTOP\\chris"
        return {"name": task.name.title(), "user": user,
                "runLevel": task.run_level.title(), "logonType": task.logon.upper(),
                "actions": [action]}

    def verify(self, live, checkout=CHECKOUT):
        return mp.verify_task(live, DATA, self.code, checkout)

    def test_every_declared_task_verifies_exactly(self):
        for task in mp.MANAGED_TASKS:
            for wrap in (True, False):
                ok, why = self.verify(self.live(task, wrap))
                self.assertTrue(ok, f"{task.name}: {why}")

    def test_every_field_deviation_is_rejected(self):
        for task in mp.MANAGED_TASKS:
            if task.kind != "powershell":
                continue
            base = self.live(task)
            mutations = {
                "extra arguments": lambda t: t["actions"][0].update(
                    arguments=t["actions"][0]["arguments"] + " -EncodedCommand ZQB2AGkAbAA="),
                "trailing newline": lambda t: t["actions"][0].update(
                    arguments=t["actions"][0]["arguments"] + "\n"),
                "script fingerprint": lambda t: t["actions"][0].update(targetHash="0" * 64),
                "no fingerprint": lambda t: t["actions"][0].pop("targetHash"),
                "other executable": lambda t: t["actions"][0].update(
                    execute=r"C:\Users\chris\AppData\Local\Temp\powershell.exe"),
                "conhost wraps another program": lambda t: t["actions"][0].update(
                    arguments=t["actions"][0]["arguments"].replace(
                        r"WindowsPowerShell\v1.0\powershell.exe", r"Temp\evil.exe")),
                "second action": lambda t: t["actions"].append(
                    {"execute": "cmd.exe", "arguments": "/c evil"}),
                "run level": lambda t: t.update(
                    runLevel="Limited" if task.run_level == "highest" else "Highest"),
                "principal": lambda t: t.update(user="DESKTOP\\someoneelse"),
                "no principal": lambda t: t.update(user=""),
                "logon type": lambda t: t.update(logonType="Password"),
            }
            for label, mutate in mutations.items():
                live = copy.deepcopy(base)
                mutate(live)
                ok, why = self.verify(live)
                self.assertFalse(ok, f"{task.name}: {label} accepted ({why})")

    def test_checkout_is_an_installation_property(self):
        # 2026-09-24: a release recorded its staging clone as the checkout, and
        # these two tasks read as critical. The args must name the real checkout.
        for name in ("jarvis reviver", "jarvis wake watchdog"):
            live = self.live(mp.BY_NAME[name])
            ok, why = self.verify(live, checkout="/home/chris/.cache/jarvis-release-staging/x")
            self.assertFalse(ok)
            self.assertIn("arguments", why)
            self.assertTrue(self.verify(live)[0])

    def test_fingerprint_comes_from_the_sealed_release_only(self):
        task = mp.BY_NAME["jarvis wake watchdog"]
        live = self.live(task)
        with open(os.path.join(self.code, task.release_script), "a") as fh:
            fh.write("Invoke-Expression $payload\n")
        ok, why = self.verify(live)
        self.assertFalse(ok)
        self.assertIn("fingerprint", why)
        os.unlink(os.path.join(self.code, task.release_script))
        self.assertFalse(self.verify(live)[0])

    def test_names_buy_nothing(self):
        impostor = self.live(mp.BY_NAME["jarvis reviver"])
        impostor["name"] = "JARVIS Reviver 2"
        ok, why = self.verify(impostor)
        self.assertFalse(ok)
        self.assertEqual(why, "not a known maintenance task")

    def test_critical_set_covers_every_previously_critical_name(self):
        before = {"jarvis wake watchdog", "jarvis independent health monitor",
                  "jarvis reviver", "jarvis elevated broker", "wsl ide keepalive",
                  "wsl ide keepalive watchdog"}
        self.assertTrue(before <= mp.CRITICAL_ON_MISMATCH)

    def test_declarations_match_what_the_installers_register(self):
        task = mp.BY_NAME["jarvis input hook"]
        script = LOCAL + r"\Jarvis\inputhook.ps1"
        out = LOCAL + r"\Jarvis\input.jsonl"
        self.assertEqual(inputwatch_helper.task_arguments(script, out),
                         mp.expected_arguments(task, LOCAL, CHECKOUT))
        # The PowerShell installers build their argument line by hand; each
        # distinctive piece of the declaration must appear in the installer.
        pieces = {"jarvis reviver": ['-Distro "', '-RepoRoot "'],
                  "jarvis wake watchdog": ['-Distro "', '-RepoRoot "', "-RecoverInterop"],
                  "jarvis connectivity guard": ["-StateRoot"],
                  "jarvis elevated broker": [r"ProgramData", "-Run"]}
        for name, needed in pieces.items():
            task = mp.BY_NAME[name]
            text = (ROOT / task.release_script).read_text(encoding="utf-8-sig")
            self.assertIn("-NoProfile -NonInteractive -WindowStyle Hidden "
                          "-ExecutionPolicy Bypass", text, name)
            for piece in needed:
                self.assertIn(piece, text, f"{name}: installer lacks {piece}")
                self.assertIn(piece, task.args, f"{name}: declaration lacks {piece}")

    def test_manifest_lists_the_expected_state(self):
        rows = {r["name"]: r for r in mp.manifest(LOCAL, self.code, CHECKOUT)}
        self.assertEqual(set(rows), set(mp.BY_NAME))
        self.assertIn('-RepoRoot "/home/chris/jarvis"', rows["jarvis reviver"]["arguments"])
        self.assertEqual(rows["wsl jarvis 24x7"]["fingerprint"], None)
        self.assertTrue(rows["jarvis reviver"]["fingerprint_source"].startswith("sealed"))


if __name__ == "__main__":
    unittest.main()

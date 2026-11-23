"""Windows Security blocks, explained.

Invariants (collectors/host/winblocks.py)
  1. Read-only: the reader and the collector never unblock, exclude or reconfigure.
  2. A failed, malformed or capped read is said; an unknown rule keeps its id.
  3. Naming Argus's own files is for explanation only: it never lowers a finding.
  4. Attack-like blocks keep their weight; Windows' own routine blocks are low.
  5. The reputation rule is advice in the posture check, not a key rule Argus pushes.
"""
import unittest

from jarvis.collectors.host import winblocks
from jarvis.collectors.host.posture.sections import ASR_KEY, ASR_MORE
from jarvis.core.paths import load_win_script
from jarvis.response import fixit

S32 = "C:\\Windows\\System32\\"
REP = winblocks.REPUTATION


def group(rule=REP, path="C:\\Users\\u\\Downloads\\tool.exe", process=S32 + "cmd.exe", eid=1121, count=3):
    return {"id": eid, "rule": rule, "path": path, "process": process, "count": count,
            "last": "2026-11-11T10:00:00.0000000Z"}


def run(groups=(), **over):
    data = {"groups": list(groups), "read": len(groups), "more": False, "since_hours": 24, "errors": []}
    data.update(over)
    return winblocks.audit(reader=lambda: data)


class Explain(unittest.TestCase):
    def test_a_new_program_blocked_by_the_reputation_rule_is_low_and_explained(self):
        f = run([group()])[0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("tool.exe", f["title"])
        self.assertIn("not seen often or for long", f["title"])
        self.assertIn("started by cmd.exe", f["detail"])
        self.assertIn("3 times", f["detail"])
        self.assertIn("leave it blocked", f["detail"])

    def test_a_block_of_argus_itself_is_high_and_says_protection_is_reduced(self):
        for path in ("C:\\Users\\u\\Downloads\\ARGUS-INSTINCT-Setup-windows-x64.exe",
                     "C:\\Users\\u\\AppData\\Local\\Programs\\Argus\\desktop\\argus-desktop.exe",
                     "C:\\ProgramData\\Jarvis\\Sensor\\JarvisSensor.exe"):
            f = run([group(path=path)])[0]
            self.assertEqual(f["severity"], "high", path)
            self.assertIn("part of Argus", f["title"])
            self.assertIn("protection is reduced", f["detail"])
            self.assertIn("opened or started", f["detail"])
            self.assertIn(f"-AttackSurfaceReductionOnlyExclusions '{path}'", f["detail"])
            self.assertIn("do not exclude a whole folder", f["detail"])

    def test_an_argus_looking_name_never_lowers_an_attack_like_block(self):
        lsass = group(rule=winblocks.LSASS, path="C:\\Users\\u\\AppData\\Local\\Temp\\argus-helper.exe", process=S32 + "lsass.exe")
        self.assertEqual(run([lsass])[0]["severity"], "high")
        office = group(rule="d4f940ab-401b-4efc-aadc-ad5f3c50688a", path="C:\\Users\\u\\Downloads\\jarvis-update.exe")
        f = run([office])[0]
        self.assertEqual(f["severity"], "high")
        self.assertNotIn("part of Argus", f["title"])
        self.assertNotIn("part of Argus", f["detail"])             # no allowance is offered either
        self.assertNotIn("Exclusions", f["detail"])
        usb = group(rule="be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", path="E:\\argus-portable.exe")
        self.assertEqual(run([usb])[0]["severity"], "medium")      # the rule's own weight, unchanged by the name

    def test_windows_own_services_reaching_for_secrets_are_low_others_are_high(self):
        routine = group(rule=winblocks.LSASS, path=S32 + "svchost.exe", process=S32 + "lsass.exe")
        self.assertEqual(run([routine])[0]["severity"], "low")
        for path in ("C:\\Users\\u\\Downloads\\dump.exe", "C:\\Windows\\Temp\\svchost.exe",
                     "C:\\Windows\\System32\\evil\\svchost.exe"):
            self.assertEqual(run([group(rule=winblocks.LSASS, path=path, process=S32 + "lsass.exe")])[0]["severity"],
                             "high", path)

    def test_audit_mode_is_would_have_blocked_and_low(self):
        f = run([group(rule="5beb7efe-fd9a-4556-801d-275e5ffc04cc", eid=1122)])[0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("would have blocked", f["title"])
        self.assertIn("audit mode", f["detail"])

    def test_an_unknown_rule_is_reported_with_its_id(self):
        f = run([group(rule="aaaaaaaa-0000-0000-0000-000000000000")])[0]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("aaaaaaaa-0000-0000-0000-000000000000", f["title"])

    def test_controlled_folder_access(self):
        f = run([group(rule="", path="C:\\Users\\u\\Documents", process="C:\\Users\\u\\x.exe", eid=1123)])[0]
        self.assertEqual(f["severity"], "medium")
        self.assertIn("protected folder", f["title"])


class Reading(unittest.TestCase):
    def test_no_answer_malformed_and_reader_errors_are_said(self):
        for bad in (None, {"groups": "x"}, {"groups": [{"id": 7}], "read": 1, "more": False},
                    {"groups": [{"id": 9999, "count": 1}], "read": 1, "more": False}):
            out = winblocks.audit(reader=lambda bad=bad: bad)
            self.assertEqual([f["title"] for f in out], ["Windows Security's block record was not read"], bad)
        out = run(errors=["read failed: UnauthorizedAccessException"])
        self.assertIn("UnauthorizedAccessException", out[0]["detail"])

    def test_a_capped_read_is_said_and_findings_are_bounded(self):
        out = run([group(path=f"C:\\Users\\u\\Downloads\\t{i}.exe") for i in range(60)])
        self.assertEqual(len(out), winblocks.MAX_FINDINGS + 1)
        self.assertEqual(out[-1]["title"], "Windows blocked more than is listed")
        self.assertEqual(run([group()], more=True)[-1]["title"], "Windows blocked more than is listed")

    def test_nothing_blocked_is_nothing_reported_and_linux_only_is_skipped(self):
        self.assertEqual(run([]), [])
        self.assertEqual(winblocks.audit(hosts=("wsl",), reader=lambda: 1 / 0), [])


class ReadOnly(unittest.TestCase):
    def test_the_reader_changes_nothing(self):
        code = "\n".join(line for line in load_win_script("winblocks.ps1").splitlines()
                         if not line.lstrip().startswith("#")).lower()
        for verb in ("set-mppreference", "add-mppreference", "remove-mppreference", "set-", "new-item",
                     "remove-", "start-process", "invoke-expression", "out-file", "wevtutil"):
            self.assertNotIn(verb, code, verb)

    def test_the_collector_never_runs_the_exclusion_it_names(self):
        import inspect
        src = inspect.getsource(winblocks)
        self.assertEqual(src.count("ps_json("), 1)                 # only the reader is ever launched
        self.assertNotIn("subprocess", src)


class Advice(unittest.TestCase):
    def test_argus_no_longer_pushes_the_rule_that_blocks_new_programs(self):
        self.assertNotIn(REP, ASR_KEY)
        self.assertIn(REP, ASR_MORE)                               # still listed, as advice
        self.assertIn("new installers", ASR_MORE[REP])
        self.assertNotIn(REP, fixit._ASR_KEY)
        self.assertNotIn(REP.upper(), fixit._ASR_CMD.upper())
        self.assertEqual(set(fixit._ASR_KEY), set(ASR_KEY))


if __name__ == "__main__":
    unittest.main()


class OwnChecks(unittest.TestCase):
    """Argus's own file checks are told apart from a launch."""

    def test_a_refused_read_by_argus_is_low_and_says_what_it_was(self):
        g = group(path="C:\\Users\\u\\Downloads\\ARGUS-INSTINCT-Setup-windows-x64.exe",
                  process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", count=61)
        g["own_check"] = True
        f = run([g])[0]
        self.assertEqual(f["severity"], "low")
        self.assertIn("refused Argus's check", f["title"])
        self.assertIn("once, not on every pass", f["detail"])
        launch = dict(g, own_check=False, process="C:\\Windows\\explorer.exe")
        self.assertEqual(run([launch])[0]["severity"], "high")          # a person starting it: protection lost

    def test_own_check_only_changes_the_reputation_rule(self):
        g = group(rule=winblocks.LSASS, path="C:\\Users\\u\\Downloads\\dump.exe", process=S32 + "lsass.exe")
        g["own_check"] = True
        self.assertEqual(run([g])[0]["severity"], "high")

    def test_the_reader_marks_own_payloads_by_their_marker(self):
        text = load_win_script("winblocks.ps1")
        self.assertIn("'jarvis-[a-z]+-payload|# jarvis: '", text)
        self.assertIn("own_check=$own", text)

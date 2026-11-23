"""Every collector has to survive bytes it did not choose.

A collector reads the output of `ps`, `journalctl`, `ss` and friends, and that
output carries data an attacker controls: process command lines, file names, log
lines. None of it is guaranteed to be UTF-8.

This stopped being hypothetical on 2026-09-07, when `sysmon_linux` died with
`UnicodeDecodeError: invalid start byte` reading its own journal. The
consequence is worse than a crash: a process whose argv contains one invalid
byte silently takes the Linux syscall-event collector offline, which makes it a
monitor-evasion primitive rather than a nuisance. `subprocess.run(text=True)`
decodes strictly by default, so the fix is `errors="replace"` at every site —
and this test is here so the next site added does not reintroduce it.
"""

import ast
import pathlib
import unittest

PKG = pathlib.Path(__file__).resolve().parent.parent / "jarvis"

# Reads that must stay strict. The evidence manifest is an integrity record:
# replacing an undecodable byte would silently alter the hashes it vouches for,
# so a corrupt manifest is rejected (UnicodeDecodeError is a ValueError, which
# load() already treats as "no manifest") rather than repaired.
STRICT_BY_DESIGN = {"response/evidence/manifest.py"}


class SubprocessDecodingTests(unittest.TestCase):
    def test_no_collector_decodes_subprocess_output_strictly(self):
        offenders = []
        for path in sorted(PKG.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ("run", "check_output", "Popen")):
                    continue
                kwargs = {k.arg for k in node.keywords}
                decodes = bool(kwargs & {"text", "universal_newlines", "encoding"})
                if decodes and "errors" not in kwargs:
                    offenders.append(f"{path.relative_to(PKG).as_posix()}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "these decode subprocess output strictly and will raise "
            "UnicodeDecodeError on a non-UTF-8 byte; add errors='replace'")

    def test_the_sysmon_journal_reader_survives_an_invalid_byte(self):
        from jarvis.collectors.telemetry import sysmon_linux
        out, _rc = sysmon_linux._run(["printf", "before \xff\xfe after\n"])
        self.assertIn("before", out)
        self.assertIn("after", out)


class FileDecodingTests(unittest.TestCase):
    def test_no_collector_opens_a_file_for_text_reading_strictly(self):
        offenders = []
        for path in sorted(PKG.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "open"):
                    continue
                kwargs = {k.arg for k in node.keywords}
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                if "b" in mode:                      # bytes never decode
                    continue
                # Writes encode data this codebase produced itself. A strict
                # failure there is a bug worth seeing, not one to paper over.
                if any(c in mode for c in "wax"):
                    continue
                if ("errors" not in kwargs and
                        path.relative_to(PKG).as_posix() not in STRICT_BY_DESIGN):
                    offenders.append(f"{path.relative_to(PKG).as_posix()}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "these read text files strictly; a single non-UTF-8 byte in a log, "
            "a /proc entry or a config file takes the collector down")


if __name__ == "__main__":
    unittest.main()

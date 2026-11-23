"""V12: collectors launch Windows programs only through the admission gate.

A collector that calls subprocess directly for powershell.exe or another
.exe skips interop_gate: during a relay slowdown its launches pile up, the
owner's watchdog reads /mnt/c as wedged and runs `wsl --shutdown`, and every
source goes unavailable at once (INTEROP-GATE.md, 2026-10-25). This AST check
keeps the gate the only path; each exception names why it must not wait.
"""

import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCOPE = ("jarvis/collectors", "jarvis/service", "jarvis/core")
LAUNCHERS = {"run", "Popen", "check_output", "check_call", "call"}
WINDOWS_HINTS = ("_ps", "powershell", "pwsh", ".exe", "interop_launcher")

# file -> why this launch is deliberately ungated (interop_gate.py docstring).
UNGATED = {
    "jarvis/collectors/host/posture/collect.py": "waits on the owner's elevation prompt",
    "jarvis/collectors/host/inputwatch/helper.py": "restores the input hook (protection)",
}


def ungated_windows_launches(source, path="<src>"):
    """(path, line, call) for each direct subprocess launch of a Windows program."""
    hits = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in LAUNCHERS:
            continue
        if not (isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"):
            continue
        text = ast.unparse(node).lower()
        if any(h in text for h in WINDOWS_HINTS):
            hits.append((path, node.lineno, text[:120]))
    return hits


class WindowsLaunchGateTests(unittest.TestCase):
    def test_detector_flags_a_direct_powershell_launch(self):
        planted = "import subprocess\nsubprocess.run([win._PS, '-Command', 'x'])\n"
        self.assertEqual(len(ungated_windows_launches(planted)), 1)

    def test_detector_ignores_linux_launches_and_the_gated_helper(self):
        clean = ("import subprocess\nsubprocess.run(['ss', '-tnp'])\n"
                 "windows.spawn([_PS, '-Command', 'x'])\n")
        self.assertEqual(ungated_windows_launches(clean), [])

    def test_collectors_use_the_gate(self):
        found = []
        for top in SCOPE:
            for p in sorted((ROOT / top).rglob("*.py")):
                rel = p.relative_to(ROOT).as_posix()
                if rel in UNGATED:
                    continue
                found += ungated_windows_launches(p.read_text(), rel)
        self.assertEqual(found, [], "launch through platform.windows.spawn/ps_json, "
                                    "or add the file to UNGATED with the reason it cannot wait")

    def test_every_exception_still_exists_and_launches(self):
        # A stale allowance is a hole waiting for new code; drop it when unused.
        for rel in UNGATED:
            self.assertTrue(ungated_windows_launches((ROOT / rel).read_text(), rel), rel)


if __name__ == "__main__":
    unittest.main()

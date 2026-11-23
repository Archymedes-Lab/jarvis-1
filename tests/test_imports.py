"""Every relative import must resolve — including the ones inside functions.

Module-level imports are checked the moment a module loads, so a broken one
fails fast and loudly. An import inside a function is only executed when that
function runs: `jarvis serve` took the daemon into a restart loop this way
after a package split, while every other command and the whole test suite
still passed.
"""

import ast
import importlib
import importlib.util
import pkgutil
import unittest
from pathlib import Path

import jarvis

ROOT = Path(jarvis.__file__).parent


def _modules():
    for info in pkgutil.walk_packages(jarvis.__path__, "jarvis."):
        if not info.name.endswith("__main__"):
            yield info.name


def _relative_imports(path, module_name, is_package):
    """(level, module, names, lineno) for each relative import in the file."""
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            yield node.level, node.module, [a.name for a in node.names], node.lineno


class RelativeImportTests(unittest.TestCase):
    def test_every_relative_import_resolves(self):
        broken = []
        for name in _modules():
            spec = importlib.util.find_spec(name)
            if not spec or not spec.origin or not spec.origin.endswith(".py"):
                continue
            path = Path(spec.origin)
            is_pkg = path.name == "__init__.py"
            # A relative import is resolved against the module's package, and
            # __init__.py counts as its own package rather than its parent's.
            base = name if is_pkg else name.rsplit(".", 1)[0]
            for level, mod, names, lineno in _relative_imports(path, name, is_pkg):
                parts = base.split(".")
                if level - 1 > len(parts):
                    broken.append("%s:%d level %d too high" % (name, lineno, level))
                    continue
                anchor = ".".join(parts[:len(parts) - (level - 1)])
                target = "%s.%s" % (anchor, mod) if mod else anchor
                try:
                    importlib.import_module(target)
                except Exception as exc:
                    broken.append("%s:%d -> %s (%s)"
                                  % (name, lineno, target, exc))
                    continue
                # `from X import y` where y is a submodule must also resolve.
                for attr in names:
                    if attr == "*":
                        continue
                    got = importlib.import_module(target)
                    if hasattr(got, attr):
                        continue
                    if importlib.util.find_spec("%s.%s" % (target, attr)) is None:
                        broken.append("%s:%d -> %s has no %s"
                                      % (name, lineno, target, attr))
        self.assertEqual(broken, [], "unresolvable relative imports:\n  "
                         + "\n  ".join(broken))

    def test_every_module_imports_cleanly(self):
        failed = []
        for name in _modules():
            try:
                importlib.import_module(name)
            except Exception as exc:
                failed.append("%s: %r" % (name, exc))
        self.assertEqual(failed, [])


class PackagedDataTests(unittest.TestCase):
    """Paths built from __file__ break silently when a module moves.

    Splitting inputwatch.py into jarvis/inputwatch/ put the module one
    directory deeper, so HOOK_PS1 pointed at jarvis/inputwatch/win/ and the
    supervisor reported the helper as missing. Nothing else noticed: the
    constant still existed and every import still resolved.
    """

    def test_every_shipped_data_file_referenced_by_a_module_exists(self):
        from jarvis.collectors.host.inputwatch import common as iw_common
        from jarvis.collectors.process import memscan
        from jarvis.core import paths

        for label, path in (
            ("inputwatch HOOK_PS1", iw_common.HOOK_PS1),
            ("memscan SCAN_PS1", memscan.SCAN_PS1),
            ("dashboard page", paths.STATIC_DIR / "dashboard.html"),
        ):
            with self.subTest(label):
                self.assertTrue(Path(path).exists(), "%s -> %s" % (label, path))

    def test_every_bundled_powershell_payload_exists(self):
        """Collectors load their PowerShell at import time by file name; a
        typo or a missed file would stop the daemon from starting."""
        names = set()
        for path in ROOT.rglob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "load_win_script"
                        and node.args and isinstance(node.args[0], ast.Constant)):
                    names.add(node.args[0].value)
        self.assertGreaterEqual(len(names), 21)
        for name in sorted(names):
            with self.subTest(name):
                self.assertTrue((ROOT / "platform" / "win" / name).is_file(), name)

    def test_templated_payloads_keep_their_placeholders(self):
        from jarvis.collectors.host.posture import collect as posture_collect
        from jarvis.collectors.network import netwatch

        self.assertIn("__SINCE__", netwatch.PS_NET)
        self.assertIn("[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
                      posture_collect.PS_POSTURE)

    def test_the_helper_resolves_inside_the_installed_package(self):
        from jarvis.collectors.host.inputwatch import common as iw_common

        self.assertEqual(Path(iw_common.HOOK_PS1).parent, ROOT / "platform" / "win")


if __name__ == "__main__":
    unittest.main()

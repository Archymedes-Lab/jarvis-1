"""Every third-party tool Argus runs is registered and licensed for the business model."""

import ast
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.collectors.appcode import tools as appcode_tools
from jarvis.collectors.host import osquery
from jarvis.core import thirdparty

ROOT = Path(__file__).resolve().parent.parent


def programs_looked_up():
    """Every literal name passed to which(...) and every fixed osqueryi path."""
    names = set()
    for path in (ROOT / "jarvis").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) == "which"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                names.add(node.args[0].value)
    names |= {os.path.basename(p) for p in osquery.CANDIDATES}
    return names


class Register(unittest.TestCase):
    def test_register_is_consistent(self):
        self.assertEqual(thirdparty.conformance(), [])

    def test_every_program_argus_looks_up_is_registered_or_platform(self):
        unknown = sorted(n for n in programs_looked_up()
                         if n not in thirdparty.PROGRAMS and n not in thirdparty.PLATFORM)
        self.assertEqual(unknown, [], "register these in jarvis/core/thirdparty.py with their licence")

    def test_no_integrated_program_is_avoided_or_unreviewed(self):
        for program, name in thirdparty.PROGRAMS.items():
            src = thirdparty.BY_NAME[name]
            self.assertIn(src, thirdparty.INTEGRATED, program)
            self.assertIn(src.verdict, ("cleared", "restricted"), program)

    def test_network_copyleft_is_never_integrated(self):
        for s in thirdparty.INTEGRATED:
            self.assertNotIn("AGPL", s.licence.upper(), s.name)

    def test_a_broken_register_is_reported(self):
        bad = thirdparty.Source("x", "engine", "AGPL-3.0", "runs", "avoid")
        with mock.patch.object(thirdparty, "INTEGRATED", thirdparty.INTEGRATED + (bad,)):
            problems = thirdparty.conformance()
        self.assertTrue(any("without conditions" in p for p in problems))
        self.assertTrue(any("integrated but marked avoid" in p for p in problems))

    def test_no_code_selects_semgrep_registry_rules(self):
        registry = re.compile(r"""["'](?:p|r)/[a-z0-9-]+["']|--config[=\s]+["']?auto""")
        hits = [str(p.relative_to(ROOT)) for p in (ROOT / "jarvis").rglob("*.py")
                if "semgrep" in (t := p.read_text(encoding="utf-8")) and registry.search(t)]
        self.assertEqual(hits, [])


class SemgrepRulesGuard(unittest.TestCase):
    def tree(self, licence):
        d = tempfile.mkdtemp()
        os.makedirs(f"{d}/python/lang")
        with open(f"{d}/python/lang/rule.yaml", "w") as fh:
            fh.write("rules: []\n")
        if licence:
            with open(f"{d}/LICENSE", "w") as fh:
                fh.write(licence)
        return d

    def test_a_clone_of_semgrep_rules_is_recognised_from_a_subfolder(self):
        d = self.tree("Semgrep Rules License v1.0. For more details, visit https://semgrep.dev/legal/rules-license")
        self.assertEqual(thirdparty.rules_licence_conflict(f"{d}/python/lang"), thirdparty.SEMGREP_RULES_LICENCE_MARK)
        self.assertEqual(thirdparty.rules_licence_conflict(f"{d}/python/lang/rule.yaml"),
                         thirdparty.SEMGREP_RULES_LICENCE_MARK)

    def test_own_or_permissive_rules_pass(self):
        self.assertEqual(thirdparty.rules_licence_conflict(self.tree("MIT License\n")), "")
        self.assertEqual(thirdparty.rules_licence_conflict(self.tree("")), "")
        self.assertEqual(thirdparty.rules_licence_conflict("/nonexistent/rules"), "")

    def test_appcode_refuses_restricted_rules_and_still_runs_bandit(self):
        d = self.tree("Semgrep Rules License v1.0")
        ran = []

        def run(argv, timeout=0, env=None):
            ran.append(os.path.basename(argv[0]))
            return 0, '{"results": []}'
        out = appcode_tools.run(["/srv/app"], which=lambda n: f"/usr/bin/{n}", run=run, semgrep_rules=d)
        self.assertNotIn("semgrep", ran)
        self.assertIn("bandit", ran)
        self.assertTrue(any("Semgrep Rules License" in f["title"] for f in out))

    def test_appcode_runs_semgrep_with_own_rules(self):
        d = self.tree("MIT License\n")
        ran = []

        def run(argv, timeout=0, env=None):
            ran.append(os.path.basename(argv[0]))
            return 0, '{"results": []}'
        appcode_tools.run(["/srv/app"], which=lambda n: f"/usr/bin/{n}", run=run, semgrep_rules=d)
        self.assertIn("semgrep", ran)


if __name__ == "__main__":
    unittest.main()

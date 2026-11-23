"""The live detection run can only happen on a machine meant to be thrown away.

Invariants (scripts/security/live_bench.py)
  1. Nothing is executed unless every containment condition holds; each missing
     condition is named. A machine with an Argus store or install is never a target.
  2. Every action is local, has an undo, and carries a unique marker.
  3. An action counts as caught only through a finding that was not there before
     and names its marker.
"""
import importlib.util
import os
import re
import tempfile
import unittest
from unittest import mock

from jarvis.core.paths import REPO_ROOT
from jarvis.lab import isolation

spec = importlib.util.spec_from_file_location("live_bench", REPO_ROOT / "scripts" / "security" / "live_bench.py")
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)

HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name

    def refusal(self, sandbox=True, env=HOSTED, uid=0, **kw):
        with mock.patch.object(isolation, "is_sandbox", return_value=sandbox), \
                mock.patch.object(live.os.path, "exists", side_effect=self.exists):
            return live.refusal(env=dict(env), uid=uid, home=self.home, isolated_network=kw.pop("isolated_network", True), **kw)

    present = ()

    def exists(self, path):
        return any(path.endswith(p) for p in self.present)

    def test_every_condition_met_is_the_only_way_through(self):
        self.assertEqual(self.refusal(), "")

    def test_each_missing_condition_refuses_and_says_why(self):
        self.assertIn("not a marked Arena sandbox", self.refusal(sandbox=False))
        self.assertIn("not a GitHub-hosted ephemeral runner", self.refusal(env={}))
        self.assertIn("not a GitHub-hosted", self.refusal(env={"GITHUB_ACTIONS": "true",
                                                              "RUNNER_ENVIRONMENT": "self-hosted"}))
        self.assertIn("run as root", self.refusal(uid=1000))

    def test_network_isolation_is_required_even_for_disposable_vm(self):
        self.assertIn("network is not isolated", self.refusal(disposable_vm=True, isolated_network=False))

    def test_the_sandbox_mark_is_needed_even_with_the_vm_flag(self):
        self.assertIn("not a marked Arena sandbox", self.refusal(sandbox=False, env={}, disposable_vm=True))
        self.assertEqual(self.refusal(env={}, disposable_vm=True), "")

    def test_a_protected_machine_is_never_a_target(self):
        for present in ((".jarvis/jarvis.db",), (".argus/argus.db",), ("/var/lib/argus",)):
            self.present = present
            self.assertIn("never a test target", self.refusal(), present)

    def test_main_refuses_without_running_anything(self):
        with mock.patch.object(live, "refusal", return_value="not here"), \
                mock.patch.object(live, "sh") as sh, mock.patch.object(live, "sweep") as sweep, \
                mock.patch.object(live.sys, "stderr"):
            self.assertEqual(live.main([]), 2)
        sh.assert_not_called()
        sweep.assert_not_called()

    def test_list_runs_nothing(self):
        with mock.patch.object(live, "sh") as sh, mock.patch.object(live, "refusal") as refusal, \
                mock.patch("builtins.print"):
            self.assertEqual(live.main(["--list"]), 0)
        sh.assert_not_called()
        refusal.assert_not_called()

    def test_this_machine_is_refused(self):
        # The real check, on the machine running the tests: never a sandbox.
        with mock.patch.dict(os.environ, {"JARVIS_ARENA_SANDBOX": ""}):
            if not isolation.SANDBOX_MARKER.is_file():
                self.assertTrue(live.refusal())


class Scenarios(unittest.TestCase):
    def test_ids_are_unique_and_every_action_carries_its_marker_and_an_undo(self):
        ids = [s[0] for s in live.SCENARIOS]
        self.assertEqual(len(ids), len(set(ids)))
        for sid, tid, what, do, undo, extra in live.SCENARIOS:
            self.assertRegex(tid, r"^T\d{4}(\.\d{3})?$")
            # Identified in a finding by its marker, or by the named strings where the action
            # changes an existing file that cannot carry one.
            self.assertTrue(f"{live.T}-{sid}" in do or extra, sid)
            self.assertTrue(undo.strip(), sid)
            self.assertTrue(what and isinstance(extra, tuple), sid)

    def test_actions_are_local_and_nothing_is_fetched(self):
        for sid, _tid, _what, do, undo, _extra in live.SCENARIOS:
            for script in (do, undo):
                self.assertIsNone(re.search(r"\b(curl|wget|scp|rsync|ssh |git clone|pip install|apt(-get)? install)\b",
                                            script), sid)
                self.assertNotRegex(script, r"https?://", sid)
                self.assertNotRegex(script, r"rm -rf /(\s|$|\*)", sid)

    def test_no_web_shell_text_is_stored_in_the_repository(self):
        text = (REPO_ROOT / "scripts" / "security" / "live_bench.py").read_text()
        self.assertNotIn("system($_POST", text)

    def test_a_scenario_is_caught_only_by_a_new_finding_naming_its_marker(self):
        scenarios = live.SCENARIOS[:2] + (live.SCENARIOS[7],)             # 01, 02 and the listener (08)
        new = [("backdoor", {"category": "c", "severity": "high", "title": "cron entry runs from /tmp",
                             "detail": f"/etc/cron.d/{live.T}-01", "where": ""}),
               ("scan", {"category": "c", "severity": "medium", "title": "listener on 0.0.0.0:44408",
                         "detail": "", "where": ""}),
               ("posture", {"category": "c", "severity": "low", "title": "unrelated", "detail": "", "where": ""})]
        got = live.attribute(scenarios, new)
        self.assertEqual([j for j, _s, _t in got["01"]], ["backdoor"])
        self.assertEqual(got["02"], [])
        self.assertEqual([j for j, _s, _t in got["08"]], ["scan"])

    def test_finding_keys_differ_when_anything_differs(self):
        a = {"category": "c", "severity": "high", "title": "t", "detail": "d", "where": "w"}
        self.assertEqual(live.key("j", a), live.key("j", dict(a)))
        self.assertNotEqual(live.key("j", a), live.key("j", dict(a, detail="e")))
        self.assertNotEqual(live.key("j", a), live.key("k", a))


class Workflow(unittest.TestCase):
    TEXT = (REPO_ROOT / ".github" / "workflows" / "live-detection.yml").read_text()

    def test_it_runs_only_when_a_person_starts_it_on_a_hosted_runner(self):
        self.assertIn("workflow_dispatch:", self.TEXT)
        for trigger in ("push:", "pull_request", "schedule:"):
            self.assertNotIn(trigger, self.TEXT)
        self.assertIn("runs-on: ubuntu-24.04", self.TEXT)
        self.assertIn("contents: read", self.TEXT)
        self.assertIn("JARVIS_ARENA_SANDBOX=1", self.TEXT)


if __name__ == "__main__":
    unittest.main()

class ExecutionFailures(unittest.TestCase):
    def run_main(self, actions):
        # No scenario is executed: exercise orchestration with deterministic fake subprocesses.
        import subprocess
        scenario = live.SCENARIOS[:1]
        with mock.patch.object(live, 'refusal', return_value=''), \
                mock.patch.object(live, 'SCENARIOS', scenario), \
                mock.patch.object(live, 'job_names', return_value=[]), \
                mock.patch.object(live, 'sweep', return_value=({}, {})), \
                mock.patch.object(live, 'sh', side_effect=actions) as sh, \
                mock.patch.object(live.signal, 'signal'), mock.patch('builtins.print'):
            code = live.main([])
        return code, sh, subprocess

    def test_failed_action_is_still_cleaned_and_measurement_fails(self):
        import subprocess
        bad = subprocess.CompletedProcess([], 1, '', 'partial failure')
        ok = subprocess.CompletedProcess([], 0, '', '')
        code, sh, _ = self.run_main([bad, ok])
        self.assertEqual(code, 1)
        self.assertEqual(sh.call_count, 2)
        self.assertEqual(sh.call_args.args[0], live.SCENARIOS[0][4])

    def test_cleanup_failure_is_not_success(self):
        import subprocess
        ok = subprocess.CompletedProcess([], 0, '', '')
        code, sh, _ = self.run_main([ok, subprocess.TimeoutExpired('undo', 60)])
        self.assertEqual(code, 1)
        self.assertEqual(sh.call_count, 2)

    def test_action_timeout_runs_cleanup(self):
        import subprocess
        ok = subprocess.CompletedProcess([], 0, '', '')
        code, sh, _ = self.run_main([subprocess.TimeoutExpired('action', 60), ok])
        self.assertEqual(code, 1)
        self.assertEqual(sh.call_count, 2)

    def test_collector_selection_is_explicit_and_network_isolated(self):
        self.assertNotIn('updates', live.READ_ONLY)
        self.assertNotIn('coverage', live.READ_ONLY)
        self.assertIn('unshare --net', Workflow.TEXT)
        self.assertIn('GITHUB_ACTIONS="$GITHUB_ACTIONS"', Workflow.TEXT)
        self.assertIn('RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT"', Workflow.TEXT)

class ProcessSafety(unittest.TestCase):
    def test_every_action_and_undo_has_valid_shell_syntax_without_execution(self):
        import subprocess
        for sid, _tid, _what, action, undo, _extra in live.SCENARIOS:
            for script in (action, undo):
                result = subprocess.run(['/bin/sh', '-n'], input=script, text=True,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, (sid, result.stderr))

    def test_background_actions_check_liveness_and_cleanup_binds_executable_identity(self):
        for scenario in (live.SCENARIOS[7], live.SCENARIOS[8], live.SCENARIOS[13]):
            self.assertIn('kill -0', scenario[3])
            self.assertNotIn('pkill', scenario[4])
            self.assertIn('readlink /proc/$pid/exe', scenario[4])
            self.assertIn(live.T, scenario[4])

class Interruption(ExecutionFailures):
    def test_interrupted_partial_action_still_attempts_undo_and_fails(self):
        import subprocess
        ok = subprocess.CompletedProcess([], 0, '', '')
        code, sh, _ = self.run_main([InterruptedError('signal'), ok])
        self.assertEqual(code, 1)
        self.assertEqual(sh.call_count, 2)

class NamespaceEvidence(unittest.TestCase):
    def test_interface_query_uses_current_process_namespace_and_fails_closed(self):
        for interfaces, expected in (([(1, 'lo')], True), ([(1, 'lo'), (2, 'eth0')], False)):
            with mock.patch.object(live.socket, 'if_nameindex', return_value=interfaces) as query:
                self.assertEqual(live.network_isolated(), expected)
                query.assert_called_once_with()
        with mock.patch.object(live.socket, 'if_nameindex', side_effect=OSError('no namespace view')):
            self.assertFalse(live.network_isolated())

    def test_workflow_propagates_refusal_and_requires_report_artifact(self):
        import subprocess
        self.assertIn('shell: bash', Workflow.TEXT)
        self.assertIn('set -euo pipefail', Workflow.TEXT)
        self.assertIn('test -s "$RUNNER_TEMP/live.json"', Workflow.TEXT)
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c',
                                     'exit 2 | tee "$1"', 'test', os.path.join(tmp, 'empty.txt')],
                                    capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)

class EmptyCrontab(unittest.TestCase):
    def test_no_existing_crontab_still_installs_fixture_entry(self):
        # Execute against a fake crontab command and a scratch file, never the host crontab.
        import shutil
        import subprocess
        import sys
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / 'crontab'
            fake.write_text(f'#!{sys.executable}\n'
                            'import os,sys\nfrom pathlib import Path\n'
                            'p=Path(os.environ["FIXTURE_CRONTAB"])\n'
                            'if sys.argv[1] == "-l":\n'
                            ' if not p.exists(): sys.exit(1)\n'
                            ' print(p.read_text(), end="")\n'
                            'else: p.write_text(sys.stdin.read())\n')
            fake.chmod(0o755)
            os.symlink(shutil.which('grep'), root / 'grep')
            state = root / 'state'
            result = subprocess.run(['/bin/sh', '-ec', live.SCENARIOS[12][3]],
                                    env={'PATH': str(root), 'FIXTURE_CRONTAB': str(state)},
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'{live.T}-13', state.read_text())

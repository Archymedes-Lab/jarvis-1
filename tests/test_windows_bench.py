"""Windows benchmark safety gates; every test here runs zero attack actions."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jarvis.core.paths import REPO_ROOT

spec = importlib.util.spec_from_file_location('windows_bench', REPO_ROOT / 'scripts/security/windows_bench.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
HOSTED = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
          'JARVIS_ARENA_SANDBOX': '1', 'RUNNER_TEMP': 'scratch'}


class Gates(unittest.TestCase):
    def test_run_task_service_evidence_reaches_the_campaign(self):
        # These persistence observations are produced by control, not ASEP or
        # backdoor. A successful campaign must not silently omit that source.
        def worker(argv, **kwargs):
            row = {'severity': 'medium', 'title': 'autostart registry entry',
                   'detail': 'fixture-run-value', 'where': 'Run'}
            return __import__('types').SimpleNamespace(
                returncode=0, stderr='', stdout=__import__('json').dumps(
                    [row] if argv[-2] == 'control' else []))
        with mock.patch.object(bench.subprocess, 'run', side_effect=worker):
            findings, failures = bench.sweep(Path('scratch.db'), Path('scratch'))
        self.assertEqual(failures, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(next(iter(findings.values()))[0], 'control')

    def check(self, **over):
        params = dict(env=HOSTED, platform='win32', admin=True, home='scratch', exists=lambda path: False)
        params.update(over)
        return bench.refusal(**params)

    def test_all_conditions_required_and_protected_data_is_refused(self):
        self.assertEqual(self.check(), '')
        self.assertIn('not Windows', self.check(platform='linux'))
        self.assertIn('not an administrator', self.check(admin=False))
        self.assertIn('not a disposable', self.check(env={}))
        self.assertIn('sandbox mark', self.check(env=dict(HOSTED, JARVIS_ARENA_SANDBOX='')))
        self.assertIn('protected', self.check(exists=lambda path: True))
        self.assertIn('not a disposable', self.check(env=dict(HOSTED, RUNNER_ENVIRONMENT='self-hosted')))

    def test_refusal_calls_no_powershell_no_worker_and_no_fixture_actions(self):
        with mock.patch.object(bench, 'refusal', return_value='protected'), \
                mock.patch.object(bench, 'powershell') as ps, mock.patch.object(bench, 'sweep') as sweep, \
                mock.patch.object(bench, 'cases') as cases, mock.patch.object(bench.sys, 'stderr'):
            self.assertEqual(bench.main([]), 2)
        ps.assert_not_called()
        sweep.assert_not_called()
        cases.assert_not_called()

    def test_list_runs_nothing(self):
        with mock.patch.object(bench, 'powershell') as ps, mock.patch.object(bench, 'refusal') as gate, \
                mock.patch('builtins.print'):
            self.assertEqual(bench.main(['--list']), 0)
        ps.assert_not_called()
        gate.assert_not_called()

    def test_setup_requires_hosted_mark_and_refuses_sensor_replacement(self):
        text = (REPO_ROOT / 'scripts/security/windows_bench_setup.ps1').read_text()
        self.assertIn("$env:RUNNER_ENVIRONMENT -ne 'github-hosted'", text)
        self.assertIn('Protected installation/data exists', text)
        self.assertIn('Existing Sysmon installation; refusing replacement', text)
        self.assertIn('Get-AuthenticodeSignature', text)
        self.assertIn('00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54', text)
        for forbidden in ('Add-MpPreference', 'DisableRealtimeMonitoring', 'ExecutionPolicy Bypass', 'wsl --shutdown'):
            self.assertNotIn(forbidden, text)

    def test_fixture_argv_does_not_override_execution_policy_or_dump_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, script, proof = bench.cases(Path(tmp))
            self.assertEqual(len({row[0] for row in rows}), len(rows))
            for sid, _tid, _what, action, undo, verify in rows:
                self.assertTrue(undo and verify, sid)
                self.assertNotIn('ExecutionPolicy', str(action))
            self.assertIn('Get-Process -Name lsass', script.read_text())
            self.assertNotIn('ReadProcessMemory', script.read_text())
            self.assertFalse(proof.exists())

    def test_worker_environment_contains_no_remote_advisory_or_job_credential(self):
        with mock.patch.dict(bench.os.environ, {'TYPESAFE_API_KEY': 'fixture-secret', 'ACTIONS_RUNTIME_TOKEN': 'fixture-token'}):
            env = bench.worker_env(Path('scratch'))
        self.assertNotIn('TYPESAFE_API_KEY', env)
        self.assertNotIn('ACTIONS_RUNTIME_TOKEN', env)
        self.assertEqual(env['JARVIS_NO_ALERTS'], '1')

    def test_network_refuses_unverified_or_inactive_policy(self):
        with mock.patch.object(bench, 'powershell', return_value={'rules': 2, 'invalid': 0, 'inactive_profiles': 0}), \
                mock.patch.object(bench.socket, 'socket') as sock:
            with self.assertRaisesRegex(RuntimeError, 'did not verify'):
                bench.verify_network('fixture')
        sock.assert_not_called()

    def test_current_machine_is_refused(self):
        self.assertTrue(bench.refusal())

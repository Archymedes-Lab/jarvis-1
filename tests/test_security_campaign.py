"""Campaign failure containment and truthful coverage, tested with real children."""

import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts.security import campaign, checks


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def run_child(self, code, **kwargs):
        return campaign.execute(campaign.Step('fixture', 'dast', (sys.executable, '-c', code)),
                                self.home, **kwargs)

    def test_all_methods_and_no_production_target_interface(self):
        self.assertEqual({step.method for step in campaign.plan()}, set(campaign.METHODS))
        with self.assertRaises(SystemExit):
            campaign.main(['--target', 'https://example.invalid'])
        self.assertTrue(all(step.gap or step.argv for step in campaign.plan()))

    def test_success_and_nonzero_exit_are_measured(self):
        good = self.run_child("print('synthetic')")
        self.assertEqual(good['status'], 'passed')
        self.assertGreater(good['output_bytes'], 0)
        self.assertEqual(len(good['output_sha256']), 64)
        self.assertNotIn('synthetic', json.dumps(good))
        self.assertEqual(self.run_child('raise SystemExit(1)')['status'], 'failed')
        self.assertEqual(self.run_child('raise SystemExit(2)')['status'], 'incomplete')

    def test_no_credentials_proxies_or_user_state_in_child(self):
        with mock.patch.dict(os.environ, {'TYPESAFE_API_KEY': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic',
                                          'HTTPS_PROXY': 'https://example.invalid', 'JARVIS_HOME': '/no'}):
            result = self.run_child(
                "import os; from pathlib import Path; "
                "assert not any(k in os.environ for k in ['TYPESAFE_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'HTTPS_PROXY', 'JARVIS_HOME']); "
                "assert os.environ['HOME'] == os.environ['USERPROFILE']; "
                "assert Path.home().is_dir(); assert not (Path.home() / '.jarvis').exists()")
        self.assertEqual(result['status'], 'passed')

    def test_missing_tool_and_pending_review_never_pass(self):
        result = campaign.execute(campaign.Step('missing', 'sast', ('/no-such-argus-tool',)), self.home)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(campaign.exit_code([result]), 2)
        pending = campaign.execute(campaign.Step('human', 'manual', gap='needs review'), self.home)
        self.assertEqual(campaign.exit_code([pending]), 2)
        self.assertEqual(campaign.exit_code([]), 2)
        self.assertEqual(campaign.exit_code([{'status': 'failed'}, pending]), 1)

    def test_timeout_even_after_stdout_is_closed(self):
        result = self.run_child('import os,time; os.close(1); os.close(2); time.sleep(10)', timeout=0.2)
        self.assertEqual(result['status'], 'timeout')
        self.assertLess(result['seconds'], 5)

    def test_unbounded_output_is_killed_and_not_retained(self):
        result = self.run_child("import os;\nwhile True: os.write(1,b'x'*1000)", output_limit=4096)
        self.assertEqual(result['status'], 'output_limit')
        self.assertEqual(result['output_bytes'], 4097)
        self.assertLess(len(json.dumps(result)), 500)

    @unittest.skipUnless(hasattr(os, 'fork'), 'POSIX process groups')
    def test_timeout_kills_descendants_holding_the_pipe(self):
        pidfile = self.home / 'child.pid'
        # No user input is interpolated into shell code; this is a Python literal.
        code = ("import os,time; from pathlib import Path; pid=os.fork(); "
                f"Path({str(pidfile)!r}).write_text(str(pid)) if pid else None; "
                "time.sleep(30)")
        # Allow interpreter startup under full-suite load before testing cleanup.
        result = self.run_child(code, timeout=3)
        self.assertEqual(result['status'], 'timeout')
        pid = int(pidfile.read_text())
        for _ in range(100):
            try:
                state = Path(f'/proc/{pid}/stat').read_text().split()[2]
            except (FileNotFoundError, ProcessLookupError):
                break
            if state == 'Z':  # dead, awaiting init reaping
                break
            time.sleep(0.01)
        else:
            os.kill(pid, signal.SIGKILL)
            self.fail('descendant survived timeout')

    def test_keyboard_interrupt_cleans_up_process(self):
        started = time.monotonic()
        with mock.patch.object(campaign.selectors, 'DefaultSelector', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_child('import time; time.sleep(10)')
        self.assertLess(time.monotonic() - started, 5)

    def test_report_is_private_and_replacement_preserves_valid_json(self):
        path = self.home / 'report.json'
        campaign.save_report(path, {'complete': False, 'results': []})
        campaign.save_report(path, {'complete': False, 'results': [{'status': 'timeout'}]})
        self.assertEqual(json.loads(path.read_text())['results'][0]['status'], 'timeout')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(path.with_suffix('.tmp').exists())

    def test_skipped_and_empty_test_suites_are_incomplete(self):
        with mock.patch.object(checks.unittest.defaultTestLoader, 'loadTestsFromNames', return_value=unittest.TestSuite()):
            self.assertEqual(checks.run_tests(['empty']), 2)
        case = unittest.FunctionTestCase(lambda: None)
        case.runTest = unittest.skip('synthetic skipped evidence')(case.runTest)
        with mock.patch.object(checks.unittest.defaultTestLoader, 'loadTestsFromNames', return_value=unittest.TestSuite([case])):
            self.assertEqual(checks.run_tests(['skipped']), 2)

    def test_expected_failure_is_still_an_open_security_finding(self):
        class KnownBug(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail('synthetic open finding')

        with mock.patch.object(checks.unittest.defaultTestLoader, 'loadTestsFromNames',
                               return_value=unittest.TestSuite([KnownBug()])):
            self.assertEqual(checks.run_tests(['known-bug']), 1)

    def test_formal_solver_must_validate_both_positive_and_negative_control(self):
        with mock.patch.object(checks.shutil, 'which', return_value=None):
            self.assertEqual(checks.formal(), 2)
        with mock.patch.object(checks.shutil, 'which', return_value='/fixture/z3'):
            for output, expected in [(b'unsat\nsat\n', 0), (b'unsat\nunsat\n', 1), (b'unknown\nsat\n', 1)]:
                result = mock.Mock(returncode=0, stdout=output)
                with mock.patch.object(checks.subprocess, 'run', return_value=result):
                    self.assertEqual(checks.formal(), expected)

    def test_source_change_or_incomplete_snapshot_cannot_pass(self):
        file = self.home / 'source.py'
        file.write_text('old')
        listing = mock.Mock(stdout=b'source.py\0')
        with mock.patch.object(campaign, 'ROOT', self.home), \
                mock.patch.object(campaign.subprocess, 'run', return_value=listing):
            old = campaign.source_snapshot()
            file.write_text('new')
            self.assertNotEqual(old['sha256'], campaign.source_snapshot()['sha256'])
            file.unlink()
            file.symlink_to('/no-such-protected-path')
            self.assertEqual(campaign.source_snapshot()['status'], 'measured')
            listing.stdout = b'x' * (campaign.MAX_OUTPUT + 1)
            self.assertEqual(campaign.source_snapshot()['status'], 'incomplete')

    def test_development_assurance_grants_no_runtime_validation(self):
        from jarvis.core import assurance
        self.assertEqual(assurance.SECURITY_TESTING['status'], 'partial')
        self.assertFalse(assurance.SECURITY_TESTING['runtime_validated'])
        self.assertNotIn('security_testing', assurance.CAPABILITIES)

    def test_stale_source_and_interrupted_campaign_preserve_evidence(self):
        step = campaign.Step('fixture', 'sast', (sys.executable,))
        old = {'status': 'measured', 'sha256': 'old'}
        new = {'status': 'measured', 'sha256': 'new'}
        real_mkdtemp = tempfile.mkdtemp

        def directory_factory(*args, **kwargs):
            if kwargs.get('prefix') == 'argus-security-':
                return str(self.home)
            return real_mkdtemp(*args, **kwargs)

        with mock.patch.object(campaign, 'plan', return_value=[step]), \
                mock.patch.object(campaign.tempfile, 'mkdtemp', side_effect=directory_factory), \
                mock.patch.object(campaign, 'source_snapshot', side_effect=[old, new]), \
                mock.patch.object(campaign, 'execute', return_value={'status': 'passed'}):
            self.assertEqual(campaign.main(['--method', 'sast']), 2)
        report = json.loads((self.home / 'report.json').read_text())
        self.assertFalse(report['source_stable'])
        self.assertFalse(report['complete'])
        with mock.patch.object(campaign, 'plan', return_value=[step]), \
                mock.patch.object(campaign.tempfile, 'mkdtemp', side_effect=directory_factory), \
                mock.patch.object(campaign, 'source_snapshot', return_value=old), \
                mock.patch.object(campaign, 'execute', side_effect=KeyboardInterrupt):
            self.assertEqual(campaign.main(['--method', 'sast']), 130)
        report = json.loads((self.home / 'report.json').read_text())
        self.assertTrue(report['interrupted'])
        self.assertEqual(report['active_step'], 'fixture')
        self.assertFalse(report['complete'])


ROOT = Path(__file__).resolve().parents[1]
BIDI = tuple(chr(c).encode() for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))
# Non-test files whose scanner hits were individually reviewed as public or synthetic.
REVIEWED_NON_TEST = {'release/vmtest/fetch_image.py', 'release/vmtest/guest.py',
                     'hosted/notify-cloudflare/wrangler.jsonc', 'jarvis/service/attackmap.py'}


class SourceHygieneTests(unittest.TestCase):
    def tracked(self):
        import subprocess
        out = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, timeout=60)
        if out.returncode:
            self.skipTest('not a git checkout')
        return [name for name in out.stdout.decode().split('\0') if name]

    def test_no_tracked_file_contains_bidirectional_controls(self):
        # Trojan-source: bidi overrides make reviewed text differ from parsed text.
        # Detectors that need these code points must spell them as escapes.
        offenders = []
        for name in self.tracked():
            path = ROOT / name
            if path.is_symlink() or not path.is_file():
                continue
            data = path.read_bytes()
            if any(mark in data for mark in BIDI):
                offenders.append(name)
        self.assertEqual(offenders, [])

    def test_gitleaks_dispositions_are_exact_and_scoped(self):
        import re
        lines = (ROOT / '.gitleaksignore').read_text(encoding='utf-8').splitlines()
        entries = [line for line in lines if line.strip() and not line.startswith('#')]
        self.assertTrue(entries)
        shape = re.compile(r'^[0-9a-f]{40}:([^:*?\s]+):([a-z0-9-]+):([1-9][0-9]*)$')
        for index, line in enumerate(lines):
            if not line.strip() or line.startswith('#'):
                continue
            match = shape.match(line)
            self.assertIsNotNone(match, 'disposition must be commit:file:rule:line, no globs')
            path = match.group(1)
            self.assertTrue(path.startswith('tests/') or '/tests/' in path or path in REVIEWED_NON_TEST, path)
            self.assertTrue(index and lines[index - 1].startswith('# '), 'each disposition needs a reason')
        self.assertEqual(len(entries), len(set(entries)))
        # Negative control: a broad allowlist line is rejected by the same shape.
        self.assertIsNone(shape.match('*:jarvis/core/secret.py:generic-api-key:1'))


if __name__ == '__main__':
    unittest.main()

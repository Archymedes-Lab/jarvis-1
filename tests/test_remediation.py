import json
import tempfile
import unittest
from unittest.mock import patch

from jarvis.core import collection
from jarvis.core.store import Store
from jarvis.response import remediation as r


class RemediationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + '/db')
        self.finding = {'category':'sysmon-linux', 'severity':'high', 'host':'wsl',
                        'title':'Sysmon for Linux is installed but stopped', 'where':'systemctl'}
        self.healthy = {'category':'telemetry','severity':'ok','title':'delivered events'}
        self.clock = patch('time.time', return_value=1000000)
        self.now = self.clock.start()
        self.executor = patch.object(r, 'execute', return_value=True)
        self.execute = self.executor.start()

    def tearDown(self):
        self.executor.stop(); self.clock.stop(); self.store.close(); self.tmp.cleanup()

    def run_repair(self, collect=None, error='', conf=None):
        return r.process(self.store, conf or {}, 'sysmon_linux', [self.finding], error,
                         collect or (lambda: [self.healthy]))

    def test_only_verified_repair_clears_and_persists_audit(self):
        findings, error = self.run_repair()
        self.assertEqual(findings, [self.healthy])
        self.assertEqual(json.loads(self.store.get_meta(r.META))['telemetry']['status'], 'verified')

    def test_success_exit_without_positive_observation_is_not_resolution(self):
        findings, _ = self.run_repair(lambda: [])
        self.assertEqual(findings[0]['remediation']['status'], 'failed')

    def test_partial_scan_keeps_original_evidence(self):
        def partial():
            collection.failed('sysmon', 'unreadable')
            return [self.healthy]
        findings, _ = self.run_repair(partial)
        self.assertEqual(findings[0]['title'], self.finding['title'])
        self.assertEqual(findings[0]['remediation']['status'], 'failed')

    def test_failure_and_crash_budget_survive_store_reopen(self):
        self.execute.side_effect = RuntimeError('failure')
        self.run_repair()
        self.store.close(); self.store = Store(self.tmp.name + '/db')
        findings, _ = self.run_repair()
        self.execute.assert_called_once()
        self.assertEqual(findings[0]['remediation']['status'], 'blocked')
        for _ in range(2):
            self.now.return_value += 3601
            self.run_repair()
        self.now.return_value += 3601
        self.run_repair()
        self.assertEqual(self.execute.call_count, 3)

    def test_disabled_or_failed_collection_never_executes(self):
        self.run_repair(conf={'auto_remediate':False})
        self.run_repair(error='incomplete')
        self.execute.assert_not_called()

    def test_untrusted_text_and_wrong_collector_cannot_select_commands(self):
        self.assertEqual(r.action_for('intrusion', self.finding), '')
        self.assertEqual(r.action_for('sysmon_linux', {**self.finding,
                         'title':self.finding['title'] + '; arbitrary command'}), '')
        f={'category':'rules','host':'win','title':'permissive inbound rule',
           'detail':'any remote address'}
        self.assertEqual(r.action_for('firewall', f), '')

    def test_corrupt_history_fails_closed(self):
        self.store.set_meta(r.META, '[]')
        findings, _ = self.run_repair()
        self.execute.assert_not_called()
        self.assertEqual(findings[0]['remediation']['status'], 'blocked')

    def test_failed_verification_retains_new_threats(self):
        threat = {'category':'intrusion','severity':'critical','title':'new evidence'}
        findings, _ = self.run_repair(lambda: [self.finding, threat])
        self.assertIn(threat, findings)

    def test_verified_repair_does_not_mail_original_outage(self):
        from jarvis.response import alert
        from jarvis.response.reporting import notifications
        findings, error = self.run_repair()
        with patch.object(alert, 'send_email') as send:
            notifications.dispatch(self.store, {}, 'sysmon_linux', findings, error)
        send.assert_not_called()

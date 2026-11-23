import json
import os
import tempfile
import unittest
from unittest.mock import patch

from jarvis.collectors.network.internetwatch import analyze, audit, firewall_summary, latest, scope
from jarvis.core.store import Store


class InternetWatchTests(unittest.TestCase):
    def setUp(self):
        # Unit tests must not read the live elevated broker's output.
        broker_patch = patch('jarvis.platform.broker.result', return_value=(None, 'not in tests'))
        broker_patch.start()
        self.addCleanup(broker_patch.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def store(self):
        store = Store(os.path.join(self.directory.name, 'test.db'))
        self.addCleanup(store.close)
        return store
    def test_ipv4_mapped_loopback_is_local(self):
        self.assertEqual(scope('::ffff:127.0.0.1'), 'loopback')
        self.assertEqual(scope('::'), 'wildcard')
        self.assertEqual(scope('bad'), 'unknown')

    def test_direction_requires_matching_process_address_and_port(self):
        listener = dict(pid=1, proto='tcp', local_ip='0.0.0.0', local_port=8080, state='LISTEN')
        incoming = dict(listener, local_ip='192.168.1.5', remote_ip='8.8.8.8', remote_port=1234, state='ESTABLISHED')
        outgoing = dict(incoming, pid=2)
        findings, rows = analyze('win', {'connections': [listener, incoming, outgoing]})
        self.assertEqual(rows[1]['direction'], 'likely inbound')
        self.assertEqual(rows[2]['direction'], 'unknown')
        self.assertEqual(sum(f['title'] == 'likely inbound connection' for f in findings), 1)

    def test_payload_and_commands_do_not_persist(self):
        _, rows = analyze('win', {'connections': [dict(pid=1, state='BOUND', proto='udp', payload='SECRET')],
                                'apps': [dict(pid=1, name='app', cmdline='SECRET', flags=[])]})
        self.assertNotIn('SECRET', json.dumps(rows))
        self.assertEqual(rows[0]['direction'], 'unknown')

    def test_log_fields_are_named_and_allow_is_not_attack(self):
        counts = firewall_summary({'fields': '#Fields: date action path protocol',
                                   'lines': ['2026-09-05 DROP RECEIVE TCP', '2026-09-05 ALLOW SEND UDP']})
        self.assertEqual(counts, {'allow': 1, 'drop': 1, 'inbound': 1})

    def test_windows_failure_is_not_clean_or_history_overwrite(self):
        store = self.store()
        store.set_meta('internetwatch_history_v1_win', '[{"ts": 1}]')
        with patch('jarvis.collectors.network.internetwatch.ps_json', return_value=None):
            findings = audit(store, hosts=('win',))
        self.assertEqual(findings[0]['category'], 'collectors')
        self.assertEqual(store.get_meta('internetwatch_history_v1_win'), '[{"ts": 1}]')
        self.assertEqual(latest(store)['win']['status'], 'unavailable')

    def test_powershell_extended_log_strings(self):
        counts = firewall_summary({
            'fields': '#Fields: date action path protocol',
            'lines': [{'value': '2026-09-05 DROP RECEIVE TCP', 'PSPath': 'log'},
                      {'value': '# comment'}, '2026-09-05 ALLOW SEND UDP']})
        self.assertEqual(counts, {'allow': 1, 'drop': 1, 'inbound': 1})

    def test_malformed_log_keeps_socket_sample_and_reports_partial(self):
        for log in ({'fields': '#Fields: action path', 'lines': [{}]},
                    {'fields': '', 'lines': []},
                    {'fields': '#Fields: action path', 'lines': None}):
            with self.subTest(log=log):
                store = self.store()
                with patch('jarvis.collectors.network.internetwatch.ps_json', return_value={
                    'logs': [log], 'connections': [dict(pid=1, state='BOUND', proto='udp')]}):
                    findings = audit(store, hosts=('win',))
                self.assertEqual(latest(store)['win']['status'], 'partial')
                self.assertEqual(len(latest(store)['win']['connections']), 1)
                self.assertTrue(any(f['category'] == 'visibility' for f in findings))

    def test_failed_tcp_query_preserves_saved_sample(self):
        store = self.store()
        store.set_meta('internetwatch_history_v1_win', '[{"ts": 1, "connections": []}]')
        with patch('jarvis.collectors.network.internetwatch.ps_json', return_value={
            'errors': ['TCP socket inventory unavailable'], 'connections': []}):
            audit(store, hosts=('win',))
        self.assertEqual(latest(store)['win']['ts'], 1)
        self.assertEqual(latest(store)['win']['status'], 'unavailable')

    def test_logging_failure_labels_socket_data_partial(self):
        store = self.store()
        with patch('jarvis.collectors.network.internetwatch.ps_json', return_value={
            'errors': ['Firewall traffic log unreadable'], 'connections': []}):
            audit(store, hosts=('win',))
        self.assertEqual(latest(store)['win']['status'], 'partial')

    def test_non_network_processes_not_counted_as_network_apps(self):
        findings, _ = analyze('wsl', {'apps': [{'pid': 42, 'name': 'offline'}], 'connections': []})
        self.assertIn('0 attributed network apps', findings[-1]['detail'])

    def test_history_retention_and_unsafe_flag_detection(self):
        store = self.store()
        with patch('jarvis.collectors.network.internetwatch.collect_linux.collect', return_value=[
            dict(pid=1, name='browser', exe='/browser', conns=[], cmdline='browser --no-sandbox secret')]):
            for _ in range(62):
                findings = audit(store, hosts=('wsl',))
        history = json.loads(store.get_meta('internetwatch_history_v1_wsl'))
        self.assertEqual(len(history), 60)
        self.assertTrue(any(f['severity'] == 'high' for f in findings))
        self.assertNotIn('secret', json.dumps(history))

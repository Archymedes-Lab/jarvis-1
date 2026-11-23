import json
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from jarvis.core import assurance
from jarvis.core.store import Store
from jarvis.response import llm, privacy
from jarvis.service.protection import health


class AssuranceTests(unittest.TestCase):
    def test_no_register_entry_can_masquerade_as_live_validation(self):
        report = assurance.report()
        self.assertFalse(report['complete'])
        self.assertFalse(report['absence_of_alerts_proves_safety'])
        for entry in report['capabilities'].values():
            self.assertFalse(entry['validated_containment'])
            self.assertIsNone(entry['last_validation'])
            self.assertTrue(entry['blind_spot'])

    def test_healthy_collectors_do_not_claim_complete_assurance(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(directory + '/state.db')
            store.save_snapshot('scan', [])
            scheduler = SimpleNamespace(heartbeat=0, hosts=('wsl',), current=None,
                                        is_alive=lambda: True)
            scheduler.heartbeat = time.time()
            result = health(store.path, scheduler)
            store.close()
        self.assertTrue(result['healthy'])
        self.assertFalse(result['assurance']['complete'])

    def test_current_sensor_receipts_are_not_mistaken_for_validation(self):
        observations = {name: {'status': 'complete'} for name in
                        ('scan', 'bridge', 'sysmon', 'native')}
        report = assurance.report(observations)
        sensor = report['capabilities']['sensor_integrity']
        self.assertEqual(sensor['live_telemetry'], 'current')
        self.assertIsNone(sensor['last_validation'])
        self.assertFalse(sensor['validated_containment'])

    def test_assurance_gaps_separate_mapping_from_implementation(self):
        observations = {source: {'status': 'complete'} for required in
                        assurance.OBSERVATION_REQUIREMENTS.values() for source in required}
        result = assurance.report(observations)
        gaps = result['evidence_gaps']
        # 2026-10-23: +3 unverified entries (firmware_audit_log,
        # live_process_view, agent_reference_monitor); none is validated.
        # 2026-10-24: +5 unverified Linux server entries (server_exposure_audit,
        # server_packet_sensor, server_login_audit, package_integrity,
        # alert_channels; the last is delivery, so it has no observing job).
        # 2026-10-25: +1 unverified metrics_export (a read-out, no observing job),
        # +1 unverified interop_backpressure (self-protection, no observing job).
        # +2 unverified off_box_heartbeat and patch_cve_awareness (W10, W11).
        # 2026-10-28: +1 unverified server_ssh_watch (sshwatch job).
        # 2026-10-28: +1 unverified app_code_vulnerabilities (appcode, osv; W12).
        # 2026-10-29: +1 unverified server_ops_health (opshealth job).
        # 2026-10-29: +1 unverified linux_boot_chain (bootchain job).
        # 2026-10-29: +1 unverified linux_keyboard_readers (keyreaders job).
        # 2026-10-29: +1 unverified friday_defender_reviews (friday_defender job).
        # 2026-10-29: +3 partial guided_assistant, detector_health and
        # plain_language_overview (browser- and daemon-exercised on one machine,
        # not validated, no observing job).
        # 2026-10-29: +2 partial in_app_notifications and investigation_reports.
        # 2026-10-30: +2 unverified signed_detection_content and
        # self_tamper_evidence (selfguard job); neither is validated.
        # 2026-10-30: +1 unverified bruteforce_deterrence (bruteforce job).
        # 2026-10-31: +1 unverified wsl_process_manifest (wslmanifest job).
        # 2026-11-02: +1 unverified link_plane (watchdogs job).
        # 2026-11-02: +1 unverified software_updates (updates job).
        # 2026-11-02: +1 unverified host_applicability (scheduler applicability, no
        # observing job of its own, not validated).
        # 2026-11-01: +1 unverified sensor_positive_control (sensorprobe job);
        # source-tested and measured by hand once, never run in the daemon.
        # Recomputed on the merged release tree (release/argus-instinct, 2026-11-03).
        # 2026-11-04: +1 unverified phone_approvals (scheduler housekeeping, no job;
        # local end to end only, never against the deployed relay or a real phone).
        # 2026-11-06: +1 unverified daemon_stop_attribution (restarts job, merged from 810217b).
        # 2026-11-06: +1 unverified osquery_cross_view (osquery job, merged from 88f1fac).
        # 2026-11-10: +2 unverified critical_ack_confirmation, upgrade_failsafe (no job).
        # 2026-11-10: +1 unverified community_rules (sysmon, sysmon_linux jobs).
        # 2026-11-10: +1 unverified registry_family_watch (sysmon job).
        # 2026-11-10: +1 unverified powershell_script_blocks (psscript job).
        # 2026-11-10: +1 unverified file_content_rules (content job).
        # 2026-11-11: +1 unverified windows_block_explainer (winblocks job).
        # 2026-11-11: +1 unverified linux_system_integrity (linuxguard job).
        self.assertEqual(gaps['implementation_unverified'], 46)
        self.assertEqual(gaps['implementation_partial'], 25)
        self.assertEqual(gaps['observation_mapping_missing'], 26)   # +1 phone_approvals (2026-11-04)
        self.assertEqual(gaps['containment_not_validated'], 71)   # +1 osquery_cross_view (2026-11-06), +1 phone_approvals (2026-11-04), +1 daemon_stop_attribution (2026-11-06)
        self.assertEqual(gaps['validation_date_missing'], 71)   # +1 osquery_cross_view (2026-11-06), +1 phone_approvals (2026-11-04), +1 daemon_stop_attribution (2026-11-06)
        self.assertFalse(result['complete'])

    def test_bruteforce_deterrence_claims_no_live_ban(self):
        report = assurance.report({name: {'status': 'complete'} for required in
                                   assurance.OBSERVATION_REQUIREMENTS.values() for name in required})
        entry = report['capabilities']['bruteforce_deterrence']
        self.assertEqual(entry['implementation'], 'unverified')
        self.assertFalse(entry['validated_containment'])
        self.assertIsNone(entry['last_validation'])
        self.assertEqual(assurance.OBSERVATION_REQUIREMENTS['bruteforce_deterrence'], ('bruteforce',))
        for limit in ('elevat', 'rotat', 'allowlist'):
            self.assertIn(limit, entry['blind_spot'], limit)

    def test_assistant_detector_health_and_overview_claim_no_more_than_was_measured(self):
        report = assurance.report({name: {'status': 'complete'} for required in
                                   assurance.OBSERVATION_REQUIREMENTS.values() for name in required})
        for name in ('guided_assistant', 'detector_health', 'plain_language_overview', 'in_app_notifications',
                     'investigation_reports'):
            entry = report['capabilities'][name]
            self.assertEqual(entry['implementation'], 'partial', name)
            self.assertFalse(entry['validated_containment'], name)
            self.assertIsNone(entry['last_validation'], name)
            self.assertNotIn(name, assurance.OBSERVATION_REQUIREMENTS)     # a UI/service view, not a sensor
            self.assertEqual(entry['live_telemetry'], 'unverified', name)
        gap = {n: report['capabilities'][n]['blind_spot'] for n in
               ('guided_assistant', 'detector_health', 'plain_language_overview', 'in_app_notifications',
                'investigation_reports')}
        # The limits that were found must stay written down.
        self.assertIn('Ollama was not installed', gap['guided_assistant'])
        self.assertIn('simulated errors only', gap['guided_assistant'])
        self.assertIn('Jev advisory review has not been run', gap['guided_assistant'])
        self.assertIn('keyword based', gap['detector_health'])
        self.assertIn('simulated through schedule applicability', gap['detector_health'])
        self.assertIn('best-effort', gap['plain_language_overview'])
        self.assertIn('no per-finding confidence score and none is invented', gap['plain_language_overview'])
        self.assertIn('there is no background service', gap['in_app_notifications'])
        self.assertIn('were not exercised with real permission states', gap['in_app_notifications'])
        self.assertIn('not wrapped in it', gap['investigation_reports'])
        self.assertIn('Execution started is not a separately observable state', gap['guided_assistant'])
        for text in gap.values():
            self.assertNotRegex(text.lower(), r'validated on|fully validated|proven|guarantee')

    def test_missing_or_stale_optional_sensor_is_explicit(self):
        self.assertEqual(assurance.report()['capabilities']['browser_privacy_veil']['live_telemetry'],
                         'not_reporting')
        report = assurance.report({'veil': {'status': 'stale'}})
        self.assertEqual(report['capabilities']['browser_privacy_veil']['live_telemetry'], 'degraded')

    def test_remote_model_rejected_before_any_transport(self):
        for url in ('https://example.com', 'http://127.0.0.1:11434@evil.test',
                    'http://localhost:11434/path', 'http://127.0.0.2:11434'):
            with self.subTest(url=url), mock.patch.object(llm, '_open') as transport, \
                    mock.patch.object(llm, '_bridge') as bridge:
                _, error = llm._request({'ollama_url': url}, b'{}', 1)
                self.assertTrue(error)
                transport.assert_not_called()
                bridge.assert_not_called()

    def test_redirects_rejected(self):
        with self.assertRaises(llm.urllib.error.URLError):
            llm._NoRedirect().redirect_request(None, None, 307, '', {}, 'https://evil.test')

    def test_credentials_removed_from_all_model_message_roles(self):
        secret = 'ghp_' + 'A' * 36
        def request(conf, body, timeout):
            self.assertNotIn(secret, body.decode())
            self.assertNotIn('hunter2', body.decode())
            self.assertNotIn('private-material', body.decode())
            self.assertEqual(len(json.loads(body)['messages']), 4)
            return {'message': {'content': 'advice'}}, None
        with mock.patch.object(llm, '_request', side_effect=request):
            llm.chat({}, secret, 'password=hunter2', examples=[(
                '-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----', secret)])

    def test_urls_keep_only_domain_and_no_userinfo(self):
        value = privacy.redact('https://user:pass@example.com/secret?code=abc#key')
        self.assertIn('example.com', value)
        for secret in ('user:', 'pass@', 'secret?', 'abc', '#key'):
            self.assertNotIn(secret, value)

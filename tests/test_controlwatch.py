import json
import os
import tempfile
import unittest

from jarvis.collectors.host.controlwatch import audit, compare
from jarvis.core.store import Store


class ControlWatchTests(unittest.TestCase):
    def test_brightness_change_is_not_an_intrusion_claim(self):
        before = {'schema': 2, 'brightness': [{'id': 'screen', 'value': 40}]}
        after = {'brightness': [{'id': 'screen', 'value': 60, 'active': True}]}
        changes = [f for f in compare(after, before)
                   if f['title'] == 'display brightness changed']
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]['severity'], 'low')
        self.assertIn('not attributed', changes[0]['detail'])

    def test_unsupported_monitor_is_not_clean(self):
        findings = compare({'brightness': []}, {})
        self.assertTrue(any(f['title'] == 'brightness control is not observable'
                            for f in findings))

    def test_initial_device_inventory_is_not_an_arrival(self):
        findings = compare({'devices': [{'id': 'keyboard', 'status': 'OK'}]}, {})
        self.assertFalse(any(f['title'] == 'control device appeared'
                             for f in findings))

    def test_live_microphone_use_is_reported_with_the_app(self):
        cur = {'liveUse': [{'cap': 'microphone', 'app': 'zoom.exe',
                            'since': '2026-09-05T20:00:00'}]}
        findings = compare(cur, {})
        hit = [f for f in findings if f['title'] == 'microphone in use right now']
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]['severity'], 'medium')
        self.assertIn('zoom.exe', hit[0]['detail'])

    def test_monitor_count_and_display_mode_changes_surface(self):
        before = {'schema': 2, 'monitors': 2,
                  'displays': [{'id': 'v0', 'name': 'GPU', 'mode': '2560x1440@60',
                                'driver': '31.0'}]}
        after = {'monitors': 1,
                 'displays': [{'id': 'v0', 'name': 'GPU', 'mode': '1920x1080@60',
                               'driver': '31.0'}]}
        titles = {f['title'] for f in compare(after, before)}
        self.assertIn('monitor count changed', titles)
        self.assertIn('display mode changed', titles)

    def test_new_capture_endpoint_alerts_once_then_is_remembered(self):
        before = {'schema': 2, 'audioCapture': [{'id': 'mic-a', 'status': 'OK'}]}
        after = {'audioCapture': [{'id': 'mic-a', 'status': 'OK'},
                                  {'id': 'mic-b', 'status': 'OK'}]}
        first = [f for f in compare(after, before)
                 if f['title'] == 'audio capture endpoint appeared']
        self.assertEqual(len(first), 1)
        # Once mic-b is in the ever-seen set, re-observing it is not an arrival.
        second = [f for f in compare(after, before, seen={'mic-a', 'mic-b'})
                  if f['title'] == 'audio capture endpoint appeared']
        self.assertEqual(second, [])

    def test_removed_device_surfaces(self):
        before = {'schema': 2, 'devices': [{'id': 'kbd', 'status': 'OK'},
                                          {'id': 'cam', 'status': 'OK'}]}
        after = {'devices': [{'id': 'kbd', 'status': 'OK'}]}
        titles = [f['title'] for f in compare(after, before)]
        self.assertIn('control device removed', titles)

    def test_audit_persists_baseline_and_seen_set(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, 'jarvis.db'))
            sample = {'brightness': [{'id': 's', 'value': 50, 'active': True}],
                      'devices': [{'id': 'kbd', 'class': 'Keyboard', 'status': 'OK'}],
                      'audioCapture': [{'id': 'mic-a', 'status': 'OK'}],
                      'errors': []}
            import unittest.mock as mock
            with mock.patch('jarvis.collectors.host.controlwatch.ps_json', return_value=sample):
                audit(store, hosts=('win',))
            self.assertIn('mic-a',
                          json.loads(store.get_meta('controlwatch_seen_v1')))
            self.assertEqual(
                json.loads(store.get_meta('controlwatch_latest_v1'))['brightness'],
                sample['brightness'])
            store.close()

    def test_windows_disabled_is_flagged_not_silent(self):
        findings = audit(store=None, hosts=('wsl',))
        self.assertEqual(findings[0]['title'], 'Windows controls are not monitored')


if __name__ == '__main__':
    unittest.main()

import tempfile
import unittest
from unittest.mock import patch

from jarvis.response.evidence.manifest import Manifest
from jarvis.response.flash import analyze, save


def event(kind, time, record, **data):
    return {'id': kind, 'time': time, 'recordId': record, 'data': data}


class FlashTraceTests(unittest.TestCase):
    def trace(self, procs):
        return {'windows': [
            {'channel': 'TaskScheduler', 'status': 'ok', 'events': [
                event(129, '2026-09-13T12:05:00+00:00', 1, TaskName='watchdog', ProcessID='42')]},
            {'channel': 'Sysmon', 'status': 'ok', 'events': procs}]}

    def test_parent_guid_links_children_and_reused_pid_is_excluded(self):
        root = event(1, '2026-09-13T12:05:00+00:00', 2, ProcessId='42', ProcessGuid='root', Image='powershell.exe')
        child = event(1, '2026-09-13T12:05:01+00:00', 3, ProcessId='43', ProcessGuid='child', ParentProcessGuid='root', Image='wsl.exe')
        reused = event(1, '2026-09-13T13:05:00+00:00', 4, ProcessId='42', ProcessGuid='different', Image='cmd.exe')
        result = analyze(self.trace([root, child, reused]))['executions'][0]
        self.assertEqual(result['processGuid'], 'root')
        self.assertEqual([p['guid'] for p in result['descendants']], ['child'])

    def test_ambiguous_pid_does_not_attribute(self):
        procs = [event(1, '2026-09-13T12:05:00+00:00', n, ProcessId='42', ProcessGuid=str(n)) for n in (2, 3)]
        self.assertEqual(analyze(self.trace(procs))['executions'][0]['correlation'], 'ambiguous')

    def test_zero_guid_is_not_a_shared_process_identity(self):
        root = event(1, '2026-09-13T12:05:00Z', 2, ProcessId='42',
                     ProcessGuid='{00000000-0000-0000-0000-000000000000}')
        self.assertEqual(analyze(self.trace([root]))['executions'][0]['correlation'], 'unmatched')

    def test_visible_observations_and_caps_are_reported(self):
        trace = {'windows': [{'pid': 4, 'process': 'cmd'}], 'capped': True}
        result = analyze({'visibleWindowTrace': trace})
        self.assertEqual(result['visibleWindowTrace'], trace)
        self.assertIn('Visible SHOW', result['verdict'])
        self.assertTrue(result['limitations'])

    def test_visible_pid_and_exact_task_arguments_match(self):
        proc = event(1, '2026-09-13T12:05:00Z', 2, ProcessId='42',
                     ProcessGuid='root', Image='C:\\Windows\\powershell.exe',
                     CommandLine='"C:\\Windows\\powershell.exe" -File "C:\\watch.ps1"')
        data = self.trace([proc])
        data['tasks'] = [{'name': 'watch', 'path': '\\', 'actions': [
            {'execute': 'powershell.exe', 'arguments': '-File "C:\\watch.ps1"'}]}]
        data['visibleWindowTrace'] = {'windows': [{'pid': 42, 'time': '2026-09-13T12:05:00.5Z'}]}
        self.assertEqual(analyze(data)['windowAttributions'][0]['matchingConfiguredTasks'], ['\\watch'])
        data['tasks'][0]['actions'][0]['arguments'] += ' -Changed'
        self.assertEqual(analyze(data)['windowAttributions'][0]['matchingConfiguredTasks'], [])

    def test_retention_caps_and_disabled_logs_are_not_clean_results(self):
        data = {'windows': [{'channel': 'Sysmon', 'label': 'startup', 'status': 'disabled', 'capped': True,
                            'oldestTime': '2026-09-13T13:00:00Z', 'start': '2026-09-13T12:00:00Z'}]}
        result = analyze(data)
        self.assertEqual(len(result['limitations']), 3)
        self.assertIn('cannot', result['verdict'])

    def test_hidden_repeating_task_remains_a_candidate(self):
        data = {'tasks': [{'name': 'watchdog', 'path': '\\', 'hidden': True, 'logonType': 'Interactive',
                          'actions': [{'execute': 'powershell.exe', 'arguments': '-WindowStyle Hidden'}],
                          'triggers': [{'type': 'Time', 'interval': 'PT5M'}]}]}
        self.assertEqual(len(analyze(data)['candidates']), 1)

    def test_overlapping_windows_deduplicate_record_ids(self):
        proc = event(1, '2026-09-13T12:05:00Z', 2, Image='cmd.exe')
        window = {'channel': 'Sysmon', 'status': 'ok', 'events': [proc]}
        self.assertEqual(len(analyze({'windows': [window, window]})['consoleProcesses']), 1)

    def test_evidence_is_hashed_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory, patch('jarvis.response.flash.case_dir', return_value=directory):
            save({'errors': ['unavailable']}, 'case')
            ok, changed, missing = Manifest(directory).verify()
            self.assertEqual(len(ok), 2)
            self.assertEqual((changed, missing), ([], []))
            with self.assertRaises(FileExistsError):
                save({}, 'case')


if __name__ == '__main__':
    unittest.main()

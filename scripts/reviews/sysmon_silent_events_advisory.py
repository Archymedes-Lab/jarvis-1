"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'judge four Sysmon event families the baseline already records but no detector read '
            '(driver loads 6, file creation 11, named pipes 17/18, WMI subscriptions 19-21), and '
            'report WinEvent hook holders the Win32k trace already counts',
    'rules': {
        'driver': 'critical when unsigned or loaded from a user-writable path, high when the '
                  'signature status is not Valid; signed valid drivers silent',
        'startup_drop': 'high when a non-installer process writes under Start Menu\\Programs\\Startup; '
                        'msiexec, TrustedInstaller, drvinst, Windows Update images silent',
        'drivers_folder': 'high when a program outside C:\\Windows writes into System32\\drivers',
        'pipes': 'critical on any of the seven pipe names the policy records (PAExec, RemCom, CsExec, '
                 'lsadump, cachedump, WCE, Cobalt Strike postex_); each name belongs to one tool',
        'wmi': 'critical on a created filter, consumer or binding with the consumer command line in '
               'the detail; medium on deletion',
        'winevent': 'low inventory of processes holding SetWinEventHook, naming unsigned ones',
    },
    'boundaries': 'no new policy volume (all four families were already recorded); first findings '
                  'carry ATT&CK ids T1014/T1068, T1547, T1543, T1559/T1021/T1003, T1546; two '
                  'attack-map probes added so the techniques are validated by replay; no containment',
    'unknowns': 'live volume of WinEvent hook holders on this desktop is unmeasured; WMI events have '
                'never been seen on this host since the policy was applied, so the field names are '
                'from the Sysmon schema, not from a live record',
    'validation': 'unit tests per rule with benign counterparts; full staged suite to follow',
}
QUESTIONS = {
    'pipe_certainty': {'type': 'noul', 'instructions':
        'Given rules.pipes, is "critical, this is the tool running, not a heuristic" an honest claim '
        'for a Sysmon PipeEvent whose name is pre-filtered by the policy to those seven tool names?',
        'criteria': {'true': 'Honest', 'false': 'Overclaims'}},
    'startup_noise': {'type': 'noul', 'instructions':
        'Will the startup_drop rule, with the stated installer exceptions, report ordinary software '
        'installs often enough to train the owner to ignore high findings?',
        'criteria': {'true': 'Yes, too noisy', 'false': 'No, acceptable'}},
    'wmi_field_risk': {'type': 'noul', 'instructions':
        'Given unknowns, is the WMI detector at real risk of silently reporting nothing because a '
        'field name differs on the live host, so that a replay of one real event should be required '
        'before counting T1546 as validated?',
        'criteria': {'true': 'Yes, require a live or recorded event', 'false': 'Schema names suffice'}},
    'priority': {'type': 'choice', 'instructions':
        'Which of these newly judged families most improves protection of a single laptop against spyware?',
        'criteria': {'driver': 'unsigned or staged driver loads', 'startup_drop': 'Startup folder drops',
                     'pipes': 'attack-tool named pipes', 'wmi': 'WMI subscriptions',
                     'winevent': 'window-event hook inventory'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

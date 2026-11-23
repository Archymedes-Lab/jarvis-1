"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'report attempts to blind or disarm Windows defenses, mapped to current ATT&CK IDs',
    'alternatives': [
        'run a read-only tamper audit (Windows event logs and ETW autologger registry) inside the existing evasion job',
        'add a separate scheduled collector job for the tamper audit',
        'rely only on the native sensor event stream with per-event rules',
    ],
    'selected': 'inside the existing evasion job, live runs only',
    'measured_baseline': {
        'defender_config_changes_24h': '63, all routine (diagnostics, cloud lookup timestamps, service start states)',
        'audit_cost': 'one PowerShell call, 11 s',
        'real_hit_on_first_run': 'one secondary Defender component crash, exception 0xc0000409, during host memory exhaustion',
        'job_table': 'differs between checkout and live release; evasion module identical in both',
    },
    'decisions': {
        'T1679': 'validated: a Defender exclusion added is observed directly, with the writing process when recorded',
        'T1687': 'held at claimed: a security product crash is the symptom MITRE lists; no exploit observed',
        'single_secondary_crash': 'medium; core engine crash or repeated crash: high',
        'retired_T1562': 'findings tagged T1685 (Disable or Modify Tools) and T1685.005 for log clearing',
    },
    'invariants': [
        'unreadable sources are unknown, never clean',
        'routine records measured on this machine stay quiet',
        'probe replays never read Windows',
        'a failing tamper read does not cost the evasion audit',
        'read-only; nothing changes the machine',
    ],
    'limits': [
        'a crash cannot be told apart from a low-memory abort by exception code alone',
        'writer attribution depends on Sysmon recording the registry write',
        'nothing has exercised a real exclusion or ETW tamper on this machine',
    ],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best meets the goal under the invariants with the least new moving parts?',
        'criteria': {'evasion': 'Inside the existing evasion job', 'job': 'Separate collector job',
                     'stream': 'Native sensor per-event rules only', 'uncertain': 'Insufficient information'}},
    'hold_t1687': {'type': 'noul', 'instructions':
        'Given only crashes are observed and no exploit, is holding T1687 at claimed rather than '
        'validated the more accurate statement of coverage?',
        'criteria': {'true': 'Holding at claimed is more accurate', 'false': 'It should count as validated'}},
    'crash_severity': {'type': 'noul', 'instructions':
        'Is medium a reasonable severity for one crash of a secondary security component whose '
        'exception code also occurs when a program aborts under low memory?',
        'criteria': {'true': 'Medium is reasonable', 'false': 'It should be high'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Since no real exclusion or ETW tamper has been exercised on this machine, should the claim '
        'stay limited to synthetic replays plus a quiet real baseline?',
        'criteria': {'true': 'Limit the claim', 'false': 'The claim can be broader'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = json.loads(sys.stdin.read() or '{}')
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

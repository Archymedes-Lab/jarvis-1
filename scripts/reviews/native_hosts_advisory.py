"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'run the same defender on a Windows machine with no WSL, and on plain Linux',
    'alternatives': [
        'one platform seam: detected execution domain decides observable hosts, '
        'PowerShell transport, path mapping, locks and supervision',
        'separate Windows edition with its own entry point and collectors',
        'compatibility shim that fakes the WSL mount and /proc layout on Windows',
    ],
    'selected': 'one platform seam',
    'measured_baseline': {
        'native_windows_import': 'fails: POSIX-only modules imported at load',
        'platform_checks_before': 0,
        'files_naming_wsl': 108,
        'windows_collectors': 'PowerShell payloads already run on Windows; only the transport is WSL interop',
    },
    'invariants': [
        'WSL behaviour and finding identity unchanged',
        'a domain that does not exist is reported not applicable, never healthy and never failed',
        'no score credit for a domain that was not observed',
        'single event-log writer enforced on every platform',
        'unknown platform fact stays unknown',
        'native supervision restarts a dead or wedged daemon with a bounded rate',
        'no elevation, firewall, policy or service change during install without explicit owner action',
    ],
    'limits': [
        'Linux-only detections (/proc views, auditd, systemd persistence) do not exist on native Windows',
        'owner-only file modes are not enforced by chmod on NTFS',
        'native install not exercised on a machine without WSL in this change',
    ],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best preserves the stated invariants with the least duplicated security logic?',
        'criteria': {'seam': 'One platform seam', 'edition': 'Separate Windows edition',
                     'shim': 'Compatibility shim', 'uncertain': 'Insufficient information'}},
    'absent_domain': {'type': 'noul', 'instructions':
        'Would reporting an absent execution domain as healthy or as failed misstate protection?',
        'criteria': {'true': 'Either label misstates protection; not applicable is required',
                     'false': 'Healthy or failed is an accurate label'}},
    'file_modes': {'type': 'noul', 'instructions':
        'Is an explicit owner-only access-control check still required on NTFS before trusting '
        'a secret or evidence file, given chmod does not enforce it there?',
        'criteria': {'true': 'A separate access-control check is required',
                     'false': 'chmod alone is sufficient'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Is validation on a machine that also has WSL installed insufficient to claim the '
        'native path works on a machine without WSL?',
        'criteria': {'true': 'A machine without WSL remains an unverified claim',
                     'false': 'It is sufficient evidence'}},
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

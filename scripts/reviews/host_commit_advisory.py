"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'see Windows memory commit exhaustion before it kills the WSL VM, and attribute what grew',
    'measured_baseline': {
        'wsl_guest_panics': '2 in 11 h on 2026-10-10/11, "Fatal machine check" in the same second as '
                            'Windows "Virtual Memory Minimum Too Low"; Hyper-V-Worker 18590',
        'host': '15.6 GB RAM, commit limit 24.9 GB, system-managed pagefile on a 99.8% full C:',
        'reading_at_review': 'commit 24.5 of 24.9 GB (98%); vmmemWSL 9.7 GB commit, of which guest '
                             'file cache about 5.7 GB; guest /proc/meminfo reported 8.8 GB available',
        'existing_check': 'resourcewatch reads only guest /proc/meminfo, so it reported no pressure',
        'resourcewatch_cadence': 'one run every few minutes inside the daemon',
    },
    'alternatives': [
        'extend resourcewatch with one bounded PowerShell performance-counter read per run '
        '(commit used/limit, vmmem commit, top Windows apps by commit) plus guest cache split',
        'new dedicated one-minute collector job registered in the scheduler',
        'new Windows scheduled task sampling commit every minute to a local file, read by JARVIS',
    ],
    'selected': 'extend resourcewatch',
    'invariants': [
        'unmeasured host commit is reported as unmeasured, never as healthy',
        'implausible counters (zero limit, used above limit) are unmeasured, not clamped',
        'one PowerShell call with a timeout; no new persistence or scheduled task',
        'metadata only: numbers and process names, no command lines',
        'resource findings are capacity signals, never compromise verdicts',
        'existing guest memory, disk and CPU findings unchanged',
    ],
    'thresholds': {'medium_commit_pct': 85, 'high_commit_pct': 95},
    'limits': [
        'a sampler inside WSL cannot record the moment the VM dies',
        'scheduler.py is being edited by a concurrent lane',
    ],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best meets the goal under the stated invariants and limits, with the '
        'least new moving parts?',
        'criteria': {'extend': 'Extend resourcewatch', 'job': 'New one-minute collector job',
                     'task': 'New Windows scheduled sampler', 'uncertain': 'Insufficient information'}},
    'unmeasured': {'type': 'noul', 'instructions':
        'When the Windows commit reading is unavailable on a host that has Windows, would '
        'reporting system resource headroom as healthy misstate what was observed?',
        'criteria': {'true': 'Yes; it must be reported as unmeasured',
                     'false': 'No; healthy is accurate'}},
    'threshold': {'type': 'noul', 'instructions':
        'Given guest panics occurred when commit reached its limit and the reading at review was '
        '98%, is a high severity at 95% commit and medium at 85% a reasonable starting point?',
        'criteria': {'true': 'Reasonable starting thresholds', 'false': 'Thresholds are unreasonable'}},
    'blind_spot': {'type': 'noul', 'instructions':
        'Does a sampler that runs inside the WSL VM leave the crash moment itself unobserved, so '
        'the Windows event log and crash reports remain needed to confirm a panic?',
        'criteria': {'true': 'Yes, the crash moment stays a blind spot',
                     'false': 'No, the in-VM sampler covers it'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Is one live reading near the limit insufficient to show the thresholds predict panics, '
        'so the claim must stay limited to measuring and attributing commit?',
        'criteria': {'true': 'Insufficient; limit the claim', 'false': 'Sufficient to claim prediction'}},
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

"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'use an operator-installed osquery as an independent second reader so a filter on '
            "Argus's own view of processes, listeners and kernel modules becomes visible",
    'design': {
        'trust': 'only a root-owned osqueryi at a fixed path; never installed or found through PATH',
        'containment': 'three fixed queries, no shell, empty environment with a private temporary home, '
                       'extensions and events off, 30 s timeout, 4 MiB cap',
        'compare': "Argus reads before and after osquery; missing from both Argus reads and still alive "
                   'is high, present in both Argus reads but missing from osquery is medium',
        'failure': 'failed or malformed answers are reported as not compared, never as agreement',
    },
    'measured': {
        'tests': '24 unit tests and 10 register tests; mutations caught',
        'container': 'disposable container, osquery 5.24.0 (dynamically linked): clean agreed; 15 runs '
                     'under churn raised nothing; system-wide port and process hiders each reported '
                     'high as root and unprivileged; a hider inside Argus no longer hides anything',
        'fixed_after_measurement': 'Argus socket reads moved to raw syscalls; a wrong unprivileged '
                                   'suppression rule removed after measuring that unprivileged '
                                   'osquery lists other accounts listeners',
        'licence': 'osquery Apache-2.0 OR GPL-2.0, run as an operator-installed separate program',
    },
    'limits': ['a kernel rootkit filtering every reader fools both views',
               'unprivileged osquery compares port numbers only',
               'no osquery packs (rootkit artefacts, compliance) yet'],
}
QUESTIONS = {
    'design_sound': {'type': 'noul', 'instructions':
        'Does this comparison detect a filter on Argus\'s own reads without raising alarms from '
        'ordinary process churn?', 'criteria': {'true': 'Yes', 'false': 'There is a hole'}},
    'top_gap': {'type': 'choice', 'instructions': 'Which gap most deserves the next measured test?',
        'criteria': {'live_run': 'Run against a real osquery on a real host',
                     'kernel': 'Kernel-level filtering that fools both views',
                     'packs': 'Use osquery query packs for rootkit artefacts',
                     'ports_only': 'Port-only comparison without owners'}},
    'claim_level': {'type': 'noul', 'instructions':
        'Should this stay unverified until it has compared a real osquery answer on a real host?',
        'criteria': {'true': 'Yes', 'false': 'Tests suffice'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

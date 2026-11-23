"""Bounded metadata-only advisory. Contains no protected history or credentials."""
import json
import sys

from jarvis.response import jev

STATE = {
    'selected': 'permissioned per-origin signed chains and encrypted minimized process projections',
    'alternatives': ['public consensus blockchain', 'permissioned signed chains', 'remote WORM only'],
    'invariants': ['no raw data upload', 'explicit enrollment', 'authenticated encryption',
                   'durable contiguous commit before receipt', 'no pruning', 'bounded retries',
                   'signed challenge responses', 'independent checkpoint for recovery'],
    'limits': ['pseudonymous not anonymous', 'peer administrators can delete copies',
               'receipts are historical not current availability', 'origin can lie or equivocate',
               'sampled sources miss transient processes', 'no deployed peers'],
    'authority': 'advisory only; deterministic checks govern',
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best fits privacy, bounded resources and explicit enrollment in this state?',
        'criteria': {'permissioned': 'Permissioned signed chains', 'public': 'Public consensus',
                     'worm': 'Remote WORM only', 'uncertain': 'Insufficient information'}},
    'privacy': {'type': 'noul', 'instructions':
        'Do connection metadata, timing and stable identities prevent a claim of full anonymity?',
        'criteria': {'true': 'Full anonymity remains unproven', 'false': 'Full anonymity is proven'}},
    'survival': {'type': 'noul', 'instructions':
        'Can administrator deletion and key loss still defeat recovery despite signed historical receipts?',
        'criteria': {'true': 'Recovery remains conditional', 'false': 'Recovery is guaranteed'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if '--implementation' in sys.argv:
        STATE['measured_validation'] = {
            'focused_tests_passed': 31, 'full_suite_passed': 1946,
            'architecture_tests_passed': 6,
            'local_witnesses': 2, 'replicated_and_recovered_blocks': 3,
            'publish_wall_seconds': 1.82, 'publish_peak_mib': 37.8,
            'recovery_wall_seconds': 0.73,
            'refinements': ['verify touched source payloads before export',
                           'retain minimized bounded selection only',
                           'compact signed-request references in receipts'],
            'deployment_limit': 'same-host experiment; no scheduled publisher or independent peers',
        }
    try:
        response = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': response.get('model'), 'answers': response['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

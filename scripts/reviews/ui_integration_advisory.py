"""Fixed public engineering metadata only; no findings, payloads or credentials."""
import json

from jarvis.response import jev

STATE = {
    'invariants': ['preserve findings and provenance', 'no model authority',
                   'no directory ACL assumptions from names', 'bounded read-only collection',
                   'no score policy change without representative replay'],
    'choices': {
        'retain_severity': 'Keep orphaned firewall rules at current severity until ACL evidence exists; all remain listed.',
        'prefix_only': 'Lower orphaned rules based solely on a system-directory prefix.',
        'new_acl_collector': 'Add new privileged directory ACL collection as part of this UI merge.'},
    'repairs': ['removed prefix-only firewall downgrade', 'restored bounded npm package traversal',
                'normalized package paths before classifying library source',
                'removed ineffective global Store-identity cache, retained covering-index query'],
    'validation': {'ui_tests': 72, 'ui_type_errors': 0, 'ui_build': 'pass',
                   'native_window': 'unverified', 'translations': 'native review pending',
                   'detector_tests': 'independent traversal, bad-signature, missing-ACL and committed-write controls',
                   'production': 'not deployed'},
    'windows': {'initial_applied': 5, 'initial_found': 1, 'telemetry': 'delivered',
                'harness_error': 'omitted actual Run/task/service collector',
                'fix': 'include actual collector and rerun identical fixtures, no detector changes'},
}
QUESTIONS = {
    'firewall': {'type': 'choice', 'instructions': 'Which option meets the invariants for this UI integration?', 'criteria': STATE['choices']},
    'review': {'type': 'noul', 'instructions': 'Given the listed repairs and pending gates, does the metadata establish a reason to suppress findings or change critical policy thresholds now?',
               'criteria': {'true': 'Sufficient reason to suppress or change thresholds', 'false': 'Keep observations and policy unchanged pending representative evidence'}},
    'windows': {'type': 'noul', 'instructions': 'Does successful telemetry delivery plus one marker-linked finding justify claiming all five Windows fixtures were detected?',
                'criteria': {'true': 'All five detections established', 'false': 'Only measured findings established; rerun the corrected harness'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

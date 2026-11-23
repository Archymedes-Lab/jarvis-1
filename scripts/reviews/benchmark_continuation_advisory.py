"""Bounded fixed engineering metadata; advisory only, no protected host data."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'complete an interrupted local security-monitor benchmark implementation',
    'options': {
        'skip_large': 'Evaluate only complete stable files <= 2 MiB; report oversized files as unknown.',
        'prefix': 'Evaluate first 2 MiB with ordinary boolean absence conditions.',
        'three_valued': 'Implement streaming or three-valued semantics for partially read files.',
    },
    'controls': ['each pathname component opened relative to a non-link directory descriptor',
                 'cache keys contain device, inode, change time, modification time, size and rule generation',
                 'entry/read/byte/time caps; incomplete discovery and prior stale positives reported',
                 'script blocks exempted only by exact complete script hash, never process id',
                 'partial script blocks reported as gaps and not evaluated',
                 'community matches advisory even after persistence',
                 'live runner uses an explicit read-only job allowlist and reports failed cleanup'],
    'evidence': {'replay_tests': 1745, 'replay_matches': 707, 'benign_controls': 24,
                 'benign_findings': 0, 'detector_crashes': 0},
    'limits': ['no production deployment', 'no live attack measurement yet',
               'bounded discovered subset can starve under continuous file churn',
               'exact script hashes do not exclude nested compiled blocks automatically',
               'script log wrapping can lose records between polls'],
}
QUESTIONS = {
    'file_design': {'type': 'choice',
                    'instructions': 'Which option in `options` is the simplest safe initial file scanner?',
                    'criteria': STATE['options']},
    'validation_priority': {'type': 'choice',
                            'instructions': 'Given `controls`, `evidence` and `limits`, which validation gap needs priority?',
                            'criteria': {'path_races': 'ancestor symlinks, replacement races and stale evidence tests',
                                         'live_execution': 'isolated real execution and collector observation',
                                         'more_rules': 'increase literal rule count'}},
    'claim': {'type': 'noul',
              'instructions': 'Does `evidence` establish production end-to-end attack detection?',
              'criteria': {'true': 'Production telemetry and detection were measured',
                           'false': 'Only replay matching is measured; production coverage remains unverified'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

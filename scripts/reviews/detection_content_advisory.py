"""Fixed engineering metadata only; advisory, never deployment authorization.

The design trade-offs of signed detection content and self-protection checks
(docs/architecture/DETECTION-CONTENT.md). No code, keys, paths of the protected
user or evidence leave this machine; only the summary below.
"""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'keep detection useful after the full source of several versions leaked: content that '
            'updates without a program release, and checks an attacker cannot evade by knowing them',
    'measured': {
        'regex_cost': 'Python re worst case on a 4 KiB adversarial subject: one .* 46 ms, two unbounded '
                      'repeats over 10 s; static subset alone cannot bound time, a killed child can',
        'selfguard_cost': 'release tree of 962 files hashed in 1.2 s cold, 0.1 s warm; live host had no '
                          'tamper findings beyond a first-run inventory of 2 startup hooks',
        'tests': '32 rule-pack tests (signature, schema, subset, deadline child, rollback, '
                 'equivocation, expiry, atomic install, non-blocking consumer, no authority) and '
                 '26 self-protection tests',
    },
    'key_alternatives': {
        'same_releasers': 'rule packs signed by the same pinned release keys, separate namespace',
        'separate_keys': 'a separate rules key pinned in the signed program, separate namespace; '
                         'release keys can still rotate it by shipping a program release',
    },
    'selected_keys': 'separate_keys',
    'content_limits': 'data only; image-bound process rules; severity capped at high; findings marked '
                      'so the response ladder only proposes; built-in rules always run',
    'freshness': 'monotonic version, same-version different bytes refused, 45-day maximum lifetime, '
                 'expiry stops pack rules and is reported',
    'limits': [
        'no key created, no pack hosted, nothing run end to end on a real host',
        'timing limit is host dependent; packs built with a 10x margin',
        'local state and accepted-version floor live in the same account the attacker may hold',
    ],
}
QUESTIONS = {
    'keys': {'type': 'choice', 'instructions':
        'Given that rule packs will be issued more often than program releases and must never be able '
        'to authorize actions, which signing arrangement better limits the damage of one key being stolen '
        'while keeping operation simple for a one-person owner?',
        'criteria': {'same_releasers': 'Reuse the pinned release keys with a separate namespace',
                     'separate_keys': 'A separate rules key, pinned in the signed program',
                     'uncertain': 'Insufficient information'}},
    'regex_bound': {'type': 'noul', 'instructions':
        'Is a static safe-regex subset plus timing every pattern in a killed-on-deadline child process at '
        'load time, with a per-rule runtime suspension that is reported, an adequate bound on matching '
        'cost for signed but possibly mistaken rule content?',
        'criteria': {'true': 'Adequate for a first slice', 'false': 'A different engine is needed first'}},
    'severity_cap': {'type': 'noul', 'instructions':
        'Is capping pack severity at high and never letting pack findings trigger automatic response the '
        'right balance between usefulness and the rule that content cannot authorize action?',
        'criteria': {'true': 'Right balance', 'false': 'Too restrictive or too permissive'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Should both capabilities stay unverified until a real pack is signed, hosted, fetched and matched '
        'on a live host and the self-protection job has run in the live daemon?',
        'criteria': {'true': 'Stay unverified', 'false': 'Partial is already justified'}},
    'next_risk': {'type': 'choice', 'instructions':
        'Which remaining risk most deserves the next deterministic test or build step?',
        'criteria': {'floor_in_user_state': 'Accepted-version floor kept where the same account can reset it',
                     'pyc_unhashed': 'Bytecode of listed modules not hashed against the manifest',
                     'suspension_evasion': 'An attacker suspending a pack rule with a slow command line',
                     'first_run_baseline': 'Tampering before the first run learned as baseline',
                     'none': 'None stands out'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

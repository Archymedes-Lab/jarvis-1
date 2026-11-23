"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'prove or remove the remaining claimed ATT&CK techniques and add detections from streams already ingested',
    'live_before': {'validated': 72, 'claimed': 33, 'blind': 81, 'total': 186},
    'projected': {'validated': 91, 'claimed': 23, 'blind': 62, 'total': 176},
    'change': [
        'probes hand synthetic evidence to existing collectors through explicit data parameters',
        'two claims with no detector behind them removed and now blind',
        'parent-and-child process rules report the effect of exploitation, not the exploit',
        'outbound public file-share connection and non-existent-name burst rules on existing events',
        'mapping to a retired technique is reported',
    ],
    'effect_only_mappings': {
        'client execution exploit': 'document application starts a script host',
        'public-facing application exploit': 'server process starts a shell',
        'privilege escalation exploit': 'print spooler or LSASS starts a shell, or exploitable driver loaded',
        'valid accounts': 'successful remote logon recorded',
    },
    'measured': {
        'events_replayed_through_real_detector': 687887,
        'false_positives_from_new_rules': 0,
        'live_positive_controls': 'one Linux and one Windows discovery burst reported within a minute',
        'unit_tests': '2070 passed',
    },
    'limits': [
        'effect-only rules miss an exploit that does not start a new process',
        'a successful remote logon with stolen credentials looks like a legitimate one',
        'synthetic evidence only, no adversary emulation',
        'not deployed',
    ],
}
QUESTIONS = {
    'effect_mapping': {'type': 'choice', 'instructions':
        'How should a technique be counted when the only detection is a visible after-effect of it?',
        'criteria': {'validated_with_effect_note': 'Validated, with the evidence stating it is the effect that is seen',
                     'claimed': 'Claimed until the technique itself is observed',
                     'validated_plain': 'Validated with no note', 'uncertain': 'Insufficient information'}},
    'valid_accounts': {'type': 'noul', 'instructions':
        'Does reporting every successful remote logon detect use of valid accounts by an attacker, '
        'given it cannot tell a stolen credential from the owner?',
        'criteria': {'true': 'It surfaces the event for human judgment, which is detection of the technique occurring',
                     'false': 'It does not detect the technique'}},
    'removal': {'type': 'noul', 'instructions':
        'Is removing a coverage claim that no detector can be made to fire more accurate than keeping it?',
        'criteria': {'true': 'Removal is more accurate', 'false': 'Keeping it is more accurate'}},
    'seams': {'type': 'noul', 'instructions':
        'Does letting a probe pass already-collected evidence to a collector risk the probe testing '
        'something other than the production rules?',
        'criteria': {'true': 'Material risk of divergence', 'false': 'The same rule code runs either way'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

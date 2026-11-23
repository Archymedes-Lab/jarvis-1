"""Fixed engineering metadata only; advisory, never deployment authorization.

Bounded Jev review (2026-11-10) of how community detection rules are judged
before they become findings. No rule text, command lines, findings or host data
are sent: only counts measured on replayed public test text and on a read-only
replay of the development host.
"""
import json

from jarvis.response import jev

STATE = {
    'product': 'a local security monitor that reads process-start and registry events',
    'measured': {
        'benchmark_public_attack_tests': 1745,
        'caught_by_built_in_rules': 392,
        'caught_with_community_rules': 997,
        'benign_control_commands_flagged': 0,
        'development_host_replay': '18 hours, about 27 thousand process starts: 28 community rules '
                                   'matched about 11.5 thousand times, nearly all the monitor\'s own '
                                   'scheduled PowerShell audits',
    },
    'designs': {
        'learn_shapes': 'for the first 7 days on an install, each new (rule, program, parent program) '
                        'combination is recorded and reported once as low-severity inventory; after that '
                        'only combinations never seen before alert, and nothing more is ever learned; on the '
                        'replay this left 38 learned combinations and no alert',
        'name_exemption': 'ignore matches whose process or parent is named like the monitor itself',
        'own_launch_ledger': 'the monitor records a hash of every command it launches itself and only those '
                             'exact launches are ignored; needs a change to its command runner and does not '
                             'cover other software that is noisy on a given machine',
        'shadow_only': 'count matches but never show them as findings until a later release',
        'raw': 'report every match as a finding',
    },
    'learn_shapes_limits': ['an attacker whose activity has the same combination as a learned one is not '
                            'reported by this layer', 'anything already present in the first week is '
                            'inventory rather than an alert'],
    'severity_policy': 'a community rule match is never critical; critical becomes high, high becomes medium',
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Given `measured` and `designs`, which design should ship first to give real detection gain '
        'without flooding people with false alarms or creating an allowance an attacker can abuse by name?',
        'criteria': {
            'learn_shapes': 'per-install learning of combinations during a fixed first week',
            'name_exemption': 'exempt by the monitor\'s own name',
            'own_launch_ledger': 'exempt only the monitor\'s exact own launches',
            'shadow_only': 'shadow mode only',
            'raw': 'report every match',
        }},
    'ledger_too': {'type': 'noul', 'instructions':
        'Should `own_launch_ledger` be added later so that the monitor\'s own activity is excluded '
        'exactly instead of being learned as a combination an attacker could imitate?',
        'criteria': {'true': 'Yes, add it', 'false': 'Not worth it'}},
    'week_ok': {'type': 'noul', 'instructions':
        'Is a fixed 7-day learning window, with each learned combination reported once as low-severity '
        'inventory, an acceptable balance between false alarms and an attacker who is already present?',
        'criteria': {'true': 'Acceptable', 'false': 'Not acceptable'}},
    'severity_cap': {'type': 'noul', 'instructions':
        'Is `severity_policy` right for third-party rule content matched on a single event?',
        'criteria': {'true': 'Right', 'false': 'Too cautious or too loose'}},
    'biggest_gap': {'type': 'choice', 'instructions':
        'Which validation gap matters most before community rules are enabled on a customer machine?',
        'criteria': {
            'more_hosts': 'false-alarm replay on more than one machine and for longer than 18 hours',
            'real_execution': 'run the attack tests for real in a disposable virtual machine',
            'imitation': 'measure how easily an attacker can imitate a learned combination',
        }},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

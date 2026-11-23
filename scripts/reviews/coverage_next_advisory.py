"""Jev as a guide for which detections to add next, and how to count them.

Fixed engineering metadata only. For each candidate Jev judges how the
technique should be counted given what the rule can actually see, and whether
the rule would fire on ordinary use of a developer's personal machine. Code
applies the policy below; Jev decides nothing.
"""
import json
import sys

from jarvis.response import jev

STATE = {
    'map_levels': {
        'validated': 'a probe makes the real detector fire for at least one way of doing the technique',
        'claimed': 'something is mapped or fires, but the technique itself is not shown to be caught',
        'blind': 'nothing looks for it',
    },
    'policy': ['an after-effect may count as validated only if the evidence says it is the effect',
               'a rule that would fire on ordinary use is not added at a severity that lowers the score'],
    'machine': 'a single developer laptop running Windows with a Linux guest; not joined to a domain',
}

CANDIDATES = {
    'T1674 Input Injection': 'an existing collector hooks keyboard and mouse input and reports events '
                             'flagged by Windows as injected by software rather than typed',
    'T1566 Phishing': 'a new rule reports a script host or program started from a mail client\'s '
                      'attachment cache or from an archive extraction temp folder',
    'T1189 Drive-by Compromise': 'a new rule reports a web browser starting a script host such as '
                                 'PowerShell, mshta or wscript',
    'T1563 Remote Service Session Hijacking': 'a new rule reports the tscon command connecting one '
                                              'session to another',
    'T1484 Domain or Tenant Policy Modification': 'a new rule reports Group Policy cmdlets that create, '
                                                  'link or change a policy object',
    'T1207 Rogue Domain Controller': 'a new rule reports the command syntax of one specific attack tool',
    'T1606 Forge Web Credentials': 'a new rule reports the command syntax of two specific token-forging tools',
    'T1495 Firmware Corruption': 'an existing collector reports when the measured firmware code changed '
                                 'between boots with no firmware version change',
}

COUNT = {'validated': 'Count as validated: the rule catches a real way of doing this technique',
         'validated_effect': 'Count as validated with a note that only the after-effect is seen',
         'claimed': 'Count as claimed: it fires, but does not show the technique is caught',
         'not_mapped': 'Do not map it to this technique at all'}
BUILD = ('validated', 'validated_effect')
NOISE_LIMIT = 0.5


def questions():
    out = {}
    for key, text in CANDIDATES.items():
        out[f'{key}__count'] = {
            'type': 'choice',
            'instructions': f'Technique: {key}. Detection: {text}. How should the technique be counted '
                            'on the coverage map?',
            'criteria': COUNT}
        out[f'{key}__noise'] = {
            'type': 'noul',
            'instructions': f'Detection: {text}. Would it fire during ordinary, legitimate use of '
                            '`machine`?',
            'criteria': {'true': 'It would fire on ordinary use', 'false': 'It would stay quiet on ordinary use'}}
    return out


if __name__ == '__main__':
    try:
        result = jev._call(STATE, questions(), timeout=40)
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
        sys.exit(0)
    answers = result['answers']
    for key in CANDIDATES:
        count, noise = answers[f'{key}__count'], answers[f'{key}__noise']['noul']
        print(json.dumps({'candidate': key, 'count': count['choice'], 'confidence': round(count['confidence'], 2),
                          'probabilities': {k: round(v, 2) for k, v in count['probabilities'].items()},
                          'noise': round(noise, 2),
                          'build_as': count['choice'] if count['choice'] in BUILD else 'held',
                          'measure_noise_first': noise >= NOISE_LIMIT}))

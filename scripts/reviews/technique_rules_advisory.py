"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'raise measured ATT&CK coverage without claiming detection that does not exist',
    'before': {'validated': 11, 'claimed': 34, 'blind': 141, 'total': 186},
    'projected_after_deploy': {'validated': 96, 'claimed': 9, 'blind': 71, 'total': 176},
    'change': [
        'image-keyed process-creation rules for known tool-and-argument procedures',
        'discovery commands reported only as a burst of 5 distinct techniques from one '
        'identified parent in 10 minutes',
        'probes replay each rule sample through the real detector entry points',
        'probes added for four detectors that already existed but were unmapped',
        'ten retired ATT&CK entries no longer counted',
    ],
    'meaning_of_validated': 'one procedure of the technique fires and its collector is reporting',
    'measured': {
        'windows_process_starts_replayed': 256397,
        'linux_process_starts_replayed': 35583,
        'findings_after_tuning': 'under ten, all real administrative actions by the owner',
        'discovery_bursts_in_history': 0,
        'benign_lookalikes_tested': 88,
    },
    'limits': [
        'a renamed tool, an API call or a COM path evades an image-keyed rule',
        'coverage counts techniques, not the share of procedures within each',
        'no adversary emulation was run; samples are synthetic command lines',
        'rules depend on Sysmon logging the process start',
        'not deployed; the live map is unchanged until the owner deploys',
    ],
}
QUESTIONS = {
    'headline': {'type': 'noul', 'instructions':
        'Would presenting the new validated share as proof that half of the attack surface is '
        'detected overstate what was measured?',
        'criteria': {'true': 'It overstates: one procedure per technique was proven',
                     'false': 'It is an accurate summary'}},
    'counting': {'type': 'choice', 'instructions':
        'Which treatment of a technique whose only proof is one tool-and-argument rule best '
        'matches the stated meaning of validated?',
        'criteria': {'validated_with_caveat': 'Count as validated and state the one-procedure limit',
                     'claimed': 'Keep as claimed until emulation proves it',
                     'validated_plain': 'Count as validated with no caveat',
                     'uncertain': 'Insufficient information'}},
    'bursts': {'type': 'noul', 'instructions':
        'Is reporting discovery commands only as a multi-technique burst, and never singly, a '
        'proportionate way to avoid alerting on ordinary administration?',
        'criteria': {'true': 'Proportionate', 'false': 'Disproportionate or unsafe'}},
    'emulation': {'type': 'noul', 'instructions':
        'Is isolated adversary emulation still required before any of these techniques may be '
        'described as tested against a real attack?',
        'criteria': {'true': 'Emulation is still required', 'false': 'Replay is sufficient'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

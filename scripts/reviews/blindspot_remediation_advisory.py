"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'turn a measured blind-spot register into accurate findings and owner actions without weakening any gate',
    'changes': {
        'gaps': 'revoked ATT&CK ids judged under their successor; techniques scoped only to cloud/SaaS/network/mobile reported low as not applicable',
        'supervisors': 'a deliberately paused mail.json (stamped .bak beside a missing mail.json) reads low "paused since <date>" instead of medium "email path failing"',
        'sysmon_baseline': 'record ConsentStore registry writes, excluding only LastUsedTime stamps; detector rule reports a switch to Allow with the writing process',
    },
    'measured': {
        'gap_findings_live': '186, 8 high; T1043 and T1064 (revoked) and T1578 (IaaS) among the highs',
        'mail_pause': 'mail.json.paused-20260929T131238Z.bak present, mail.json absent, ItemNotFoundException hourly',
        'consent_store': 'no Sysmon rule today; privacy seal drift unattributed',
        'disk': 'C: 97.7% full; WSL image 252 GB, 209 GB used inside',
    },
    'invariants': ['a retired id is never silently dropped: it is covered or a gap under its successor',
                   'a pause is reported, never hidden; a missing stamp still reads as a failing path',
                   'the Allow/Deny switch is always recorded; only per-use stamps are excluded',
                   'nothing here changes the machine; policy re-apply is an owner action'],
}
QUESTIONS = {
    'not_applicable_low': {'type': 'noul', 'instructions': 'Is reporting a cloud-only technique as a low "not applicable" finding (visible, unscored) better than dropping it from the gap list entirely?',
                           'criteria': {'true': 'Visible low is better', 'false': 'Drop it'}},
    'pause_low': {'type': 'noul', 'instructions': 'Given outage email is a notification path, is low the right severity for a pause the owner made deliberately with a dated marker?',
                  'criteria': {'true': 'Low is right', 'false': 'It should stay medium'}},
    'stamp_exclusion': {'type': 'noul', 'instructions': 'Does excluding only LastUsedTime value writes under ConsentStore keep every security-relevant consent change recorded?',
                        'criteria': {'true': 'Yes, the Allow/Deny Value write is still recorded', 'false': 'No, something relevant is lost'}},
    'next_gate': {'type': 'choice', 'instructions': 'Which deterministic check most deserves to run before this ships?',
                  'criteria': {'replay': 'Replay retained Sysmon history through the new consent rule for false positives',
                               'gapcount': 'Compare live gap counts before and after on the real store',
                               'pause': 'Exercise the pause path on the installed monitor',
                               'none': 'None stands out'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

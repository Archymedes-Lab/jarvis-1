"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'every daemon notification (email, phone, webhook, ntfy, syslog, desktop toast) reads in '
            'plain words: what happened and what to do, with the exact facts kept',
    'design': {
        'chosen': 'one deterministic module: per-category sentences copied from the app guide (kept '
                  'identical by a test), kind-based fallbacks; messages open with the plain part, then '
                  '"What it saw / Where / How serious", then the unchanged detailed report',
        'alternative_runtime_json': 'read desktop guide.json at runtime; rejected, the daemon release '
                                    'does not ship the desktop interface',
        'alternative_rewrite_titles': 'reword finding titles themselves; rejected, titles are dedupe and '
                                      'acknowledgement keys and are facts',
    },
    'tests': 'jargon word list over every email kind, phone, webhook, ntfy, syslog, outage/recovery, '
             'updates, test message and toasts; facts present; no compromise or safety claim; length '
             'limits (phone title 90, toast 90/160); mutation checks confirmed the tests fail on jargon '
             'and on a safety claim',
    'limits': [
        'subjects are clipped to 90 characters, the full title is in the body',
        'finding titles may themselves contain technical words; they are kept as facts',
        'the persona opener line in emails is unchanged apart from three words',
    ],
}
QUESTIONS = {
    'facts_safe': {'type': 'noul', 'instructions':
        'Given the design, could a reader lose a fact (title, place, severity) they had before?',
        'criteria': {'true': 'A fact can be lost', 'false': 'Facts are kept'}},
    'overclaim_risk': {'type': 'noul', 'instructions':
        'Is there a material risk that the fixed plain sentences read as a confirmed attack or as a '
        'promise the computer is safe?',
        'criteria': {'true': 'Material risk', 'false': 'No material risk'}},
    'next_gate': {'type': 'choice', 'instructions': 'Which additional validation is most valuable next?',
        'criteria': {'phone': 'Render real messages on a paired phone',
                     'owner': 'Owner reads sample messages for each event',
                     'html': 'Check the email HTML in common mail clients',
                     'none': 'No further validation needed'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

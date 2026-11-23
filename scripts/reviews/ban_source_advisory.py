"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'deter password guessing against a personal Windows machine by cost, never by counter-attack',
    'design': {
        'trigger': 'a high-severity finding from the Windows failed-logon detector naming one public source '
                   'address; private, loopback, link-local, multicast and owner-allowlisted addresses never',
        'action': 'a Windows Firewall inbound block rule for that one address; nothing is sent to it',
        'duration': '1 hour, then 6 hours, 24 hours and 7 days each time the same address returns after a ban lifts',
        'expiry': 'a sweep once a minute lifts expired rules with the same undo a human uses; a failed lift '
                  'stays active and visible and is retried',
        'bounds': 'at most 256 automatic bans at once, after that every new ban needs owner approval',
        'authority': 'off unless the owner sets two configuration flags; a human undo turns every later '
                     'recurrence into a proposal; with the monitor down, rules stay until removed',
        'parsing': 'the source address is taken only from the detector-written end of the finding text; the '
                   'logon user name is attacker-chosen text and can contain separators',
    },
}
QUESTIONS = {
    'escalation': {'type': 'choice', 'instructions':
        'Which ban duration ladder best deters a returning password-guessing source on a personal machine '
        'while limiting harm when the source was a legitimate user who mistyped?',
        'criteria': {'as_designed': '1 h, 6 h, 24 h, 7 days', 'shorter': 'Shorter, capped at a day',
                     'longer': 'Longer, up to permanent', 'uncertain': 'Insufficient information'}},
    'cap_256': {'type': 'noul', 'instructions':
        'Is a cap of 256 simultaneous automatic inbound bans, falling back to owner approval, a safe bound '
        'for a personal Windows firewall?', 'criteria': {'true': 'Yes', 'false': 'No'}},
    'stays_when_down': {'type': 'noul', 'instructions':
        'Is it acceptable that a time-bounded inbound ban stays in force past its expiry while the monitor '
        'that lifts it is not running?', 'criteria': {'true': 'Acceptable', 'false': 'Not acceptable'}},
    'needs_default_allowlist': {'type': 'noul', 'instructions':
        'Should automatic banning stay disabled until the owner has listed their own outside addresses '
        '(VPN exit, work network) in an allowlist?', 'criteria': {'true': 'Yes', 'false': 'No'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

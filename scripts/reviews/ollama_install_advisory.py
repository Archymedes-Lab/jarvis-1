"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'let a security monitor install a third-party local model runtime for its owner, only with approval',
    'design': {
        'trigger': 'a command the owner runs; the daemon and web pages never install, they only point to it',
        'approval': 'the full plan (version, file, size, source, SHA-256, undo) is printed; the owner types a word, '
                    'or passes an explicit flag; non-interactive callers without the flag are refused',
        'selection': 'newest non-prerelease release at least seven days old',
        'integrity': 'the platform digest and the vendor checksum list must agree and match the downloaded bytes; '
                     'HTTPS to the code host only, redirects included, size capped; on Windows the installer must '
                     'carry a valid code signature naming the vendor before it runs',
        'install': 'per user, no administrator or root; on Linux a user service bound to loopback',
        'record': 'each install and uninstall is appended to an audit list in the local store',
    },
}
QUESTIONS = {
    'approval_enough': {'type': 'noul', 'instructions':
        'Is a typed confirmation of a printed plan, or an explicit flag, adequate approval for installing a '
        'large third-party runtime per user?', 'criteria': {'true': 'Adequate', 'false': 'Not adequate'}},
    'age_rule': {'type': 'noul', 'instructions':
        'Does preferring a release at least seven days old meaningfully reduce supply-chain risk here?',
        'criteria': {'true': 'Meaningfully', 'false': 'Not meaningfully'}},
    'next_gap': {'type': 'choice', 'instructions':
        'Which remaining gap matters most for this installer?',
        'criteria': {'linux_signature': 'Linux archives carry no vendor signature, only checksums from the same release',
                     'model_pull': 'The model download after install is not verified the same way',
                     'gui_approval': 'Non-technical users need the approval in the desktop app, not a command',
                     'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'have a host security monitor periodically run an LLM security reviewer over local codebases',
    'design': {
        'consent': 'off until the owner runs an interactive terminal command and answers yes; that command may '
                   'install the reviewer; the daemon can only read or withdraw consent',
        'execution': 'detached headless run, defender mode where any change needs an approval nobody can give; '
                     'one review at a time; 20 minute deadline; spending budget; deferrable when the host is busy',
        'cadence': 'each codebase at most weekly, round-robin over discovered codebases',
        'integrity': 'folder fingerprint (path, size, mtime) before and after; any change is critical and '
                     'withdraws consent',
        'output': 'findings from a fixed JSON block, capped at medium severity, secrets masked, transcript deleted',
        'knowledge': 'the reviewer uses a signed, reviewed defensive corpus; the monitor reports its freshness',
        'privacy': 'code goes to the model provider the owner configured in the reviewer',
    },
}
QUESTIONS = {
    'cap_medium': {'type': 'noul', 'instructions':
        'Is capping model-reported findings at medium severity the right default for an unattended review '
        'whose output nobody has verified?', 'criteria': {'true': 'Yes', 'false': 'No'}},
    'mtime_fingerprint': {'type': 'noul', 'instructions':
        'Could a review change a file without changing its size or modification time often enough that '
        'the fingerprint should hash contents instead?', 'criteria': {'true': 'Yes, hash contents', 'false': 'No'}},
    'weekly': {'type': 'choice', 'instructions':
        'What cadence per codebase best balances cost and value for unattended LLM security reviews?',
        'criteria': {'daily': 'Daily', 'weekly': 'Weekly', 'on_change': 'Only after the code changes',
                     'uncertain': 'Insufficient information'}},
    'consent_enough': {'type': 'noul', 'instructions':
        'Is a single interactive yes, recorded with the folders and budget, sufficient consent for sending '
        'code to a third-party model provider on a recurring schedule?',
        'criteria': {'true': 'Sufficient', 'false': 'Needs more, such as per-provider confirmation'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'an unelevated Windows installer hands work to one UAC-elevated shell without letting a '
            'same-user process change what the elevated shell runs',
    'design': {
        'handoff': 'the elevated shell receives fixed inline code as an encoded command; no script file is '
                   'staged in the user temp folder; user name and paths travel as base64 JSON data',
        'integrity': 'every file the elevated shell runs is hashed before the prompt, copied into an '
                     'administrator-only Program Files folder, re-hashed there and refused on any mismatch',
        'reuse': 'the verified copies stay in Program Files so uninstall runs them, never the user-writable '
                 'install folder; without them uninstall runs nothing and says what to remove by hand',
        'sensor': 'the service source is compiled only when its hash matches one fixed before elevation',
        'removal': 'uninstall revokes the logon-as-a-service right and event-log-reader group membership by '
                   'computed SID and reads both back',
        'delete': 'the recursive folder delete requires an absolute non-root non-profile path holding the '
                  'installer marker files and passes the path as data',
        'limit': 'the hashes are computed by the same unelevated user, so this closes the window between '
                 'staging and elevation, not a compromise of the installer before it runs',
    },
}
QUESTIONS = {
    'toctou_closed': {'type': 'noul', 'instructions':
        'Does hashing before the prompt and re-checking the administrator-only copy close the window in '
        'which a same-user process could swap a file the elevated shell runs?',
        'criteria': {'true': 'Closed', 'false': 'Still open'}},
    'keep_copies': {'type': 'noul', 'instructions':
        'Is keeping verified copies of the uninstall scripts in an administrator-only folder safer than '
        're-verifying the user-writable copies at uninstall time?',
        'criteria': {'true': 'Safer', 'false': 'Not safer'}},
    'next_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most deserves the next fix for this installer handoff?',
        'criteria': {'signing': 'Sign the release so the pre-elevation hashes have an independent anchor',
                     'programdata': 'Move broker files out of ProgramData, where users can pre-create folders',
                     'vm_test': 'Run the elevated paths end to end in a disposable Windows VM',
                     'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

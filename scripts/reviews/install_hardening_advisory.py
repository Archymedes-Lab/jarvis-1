"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'elevated install and broker paths run only administrator-protected, verified copies',
    'alternatives': {
        'elevation': [
            'elevated bootstrap (encoded command) copies staged files into a folder created with an '
            'admin-only ACL, checks SHA-256 against the checkout, runs only those copies',
            'keep running the staged script from the user TEMP folder and rely on post-install drift checks',
            'move the broker to Program Files with a signed MSI',
        ],
        'vault_inbox': [
            'open each inbox file once, check final path and link count through the handle, read via the handle',
            'check every path component for reparse points before reading by path',
        ],
    },
    'selected': {'elevation': 'bootstrap with verified admin-only copies',
                 'vault_inbox': 'handle checks'},
    'measured': {
        'outer_command_line_chars': 14230,
        'windows_limit_chars': 32767,
        'regression_tests': 22,
        'powershell_parse_of_changed_scripts': 'no errors (parse only, nothing executed)',
    },
    'invariants': [
        'nothing elevated runs from a user-writable location',
        'the verified copy is the copy that runs',
        'paths and names reach PowerShell as quoted data, never code',
        'elevated paths do not come from user environment variables',
        'a pre-created broker folder is set aside, not trusted or deleted',
    ],
    'limits': [
        'nothing was executed elevated; static review and unit tests only',
        'a handle opened on a squatted folder before install can keep its access',
        'the broker task now runs as SYSTEM; per-user reads use HKEY_USERS of the recorded SID '
        'and are empty when that hive is not loaded',
        'site-repo installers are reported, not fixed',
    ],
}
QUESTIONS = {
    'elevation_design': {'type': 'choice', 'instructions':
        'Which alternative in `alternatives.elevation` best meets `goal` under `invariants` with the '
        'fewest new moving parts for this release?',
        'criteria': {'bootstrap': 'Verified admin-only copies via bootstrap',
                     'drift': 'Run from TEMP with post-install drift checks',
                     'msi': 'Signed MSI into Program Files', 'uncertain': 'Insufficient information'}},
    'vault_design': {'type': 'choice', 'instructions':
        'Which alternative in `alternatives.vault_inbox` closes a time-of-check to time-of-use race '
        'between checking an inbox path and reading it?',
        'criteria': {'handle': 'Checks through the open handle', 'components': 'Per-component reparse checks',
                     'uncertain': 'Insufficient information'}},
    'runtime_gap': {'type': 'noul', 'instructions':
        'Given `limits`, must the fix be described as statically verified only until the broker is '
        'reinstalled and its task results are read back on a real Windows host?',
        'criteria': {'true': 'Describe as statically verified only', 'false': 'Can be called validated now'}},
    'system_principal': {'type': 'noul', 'instructions':
        'With the broker task moved to SYSTEM and per-user registry state read from the recorded '
        "user's HKEY_USERS hive, should an unloaded hive be reported as unknown rather than as an "
        'absent setting?',
        'criteria': {'true': 'Report as unknown', 'false': 'Absent is acceptable'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

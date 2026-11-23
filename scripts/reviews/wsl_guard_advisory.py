"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'see every way across the WSL trust boundary (root from Windows, registration changes, '
            'custom kernel, boot command, distro import/unregister) and every change to the boundary itself',
    'measured': {
        'root_gate': 'wsl.exe -u root -- id -u printed 0 from an ordinary Windows user process, no prompt',
        'windows_side': 'Windows Sysmon records every wsl.exe command line with parent and user',
        'linux_side': 'the same launch is a root process with ParentImage "-" and a zero parent GUID; '
                      '19,882 root process starts in 20 h, 9,155 unresolved image, 5,458 runc',
        'api': 'loopback API reachable from Windows; Windows-originated connections arrive as 127.0.0.1',
        'registration': 'HKCU Lxss DefaultUid 0x3e8, Flags 0xf, Plugins key empty, no WSL policy key',
        'tests': '21 unit tests: posture facts, drift severity, offline drift, lost evidence, broken chain, '
                 'registration changes, malformed rows, invalid and partial Windows reads, job registration; '
                 'rule samples and benign look-alikes run through the existing technique test',
    },
    'alternatives': [
        'Linux-side Sysmon rule on root processes with an unresolved parent',
        'Linux-side rule narrowed by CurrentDirectory and TerminalSessionId',
        'Windows-side command-line and registry rules plus a five-minute sampler for facts no event carries',
    ],
    'selected': 'Windows-side rules plus sampler',
    'decisions': {
        'root_launch': 'high; --unregister critical; --shutdown high (the owner uses it; acknowledgeable)',
        'root_by_default_registry': 'high (rule and sampler)',
        'plugins': 'critical on write, high while present',
        'no_checkpoint': 'low visibility, with the accept command',
        'docker_socket': 'low informational',
        'api_from_windows': 'not changed: a token or peer gate is readable by the same user through '
                            'the wsl.localhost share; recorded as an owner decision',
    },
    'invariants': [
        'the guard never writes WSL state; the only writer is the owner accept command',
        'unreadable sources are visibility loss, never unchanged; previous evidence kept',
        'first sample reports posture only, so a fresh install does not flood change findings',
        'no claim that the boundary is sealed: same user on both sides',
    ],
    'limits': [
        'policy additions not applied on the live host; file-create path format for the share unmeasured',
        'a change undone within five minutes is unseen by the sampler',
        'the job has not run in the live daemon',
    ],
}
QUESTIONS = {
    'design': {'type': 'choice', 'instructions':
        'Which alternative best meets the goal with the fewest false positives given the measurements?',
        'criteria': {'linux_unresolved': 'Linux-side rule on unresolved-parent root processes',
                     'linux_narrowed': 'Linux-side rule narrowed by directory and session',
                     'windows_sampler': 'Windows-side rules plus sampler',
                     'uncertain': 'Insufficient information'}},
    'shutdown_high': {'type': 'noul', 'instructions':
        'Is high the right severity for wsl.exe --shutdown or --terminate seen from Windows, '
        'given the owner runs it sometimes and can acknowledge it, and it stops the protection engine?',
        'criteria': {'true': 'High is right', 'false': 'It should be medium or lower'}},
    'api_decision': {'type': 'noul', 'instructions':
        'Is leaving the loopback API trust model unchanged, with acknowledgements visible as low findings, '
        'an acceptable outcome of this change rather than a gap that must be closed before release?',
        'criteria': {'true': 'Acceptable as an owner decision', 'false': 'Must be closed before release'}},
    'validation_gap': {'type': 'noul', 'instructions':
        'Should the capability stay at unverified until the job has run in the live daemon and the '
        'Sysmon policy additions are applied and seen to record a real Lxss write?',
        'criteria': {'true': 'Stay unverified', 'false': 'Partial is already justified'}},
    'hidden_risk': {'type': 'choice', 'instructions':
        'Which remaining risk most deserves a further deterministic test before release?',
        'criteria': {'flood': 'Repeated change findings every five minutes after a legitimate change',
                     'noise': 'The Lxss registry include adding volume at every VM start',
                     'first_sample': 'A reinstalled store treating the current state as new',
                     'none': 'None stands out'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

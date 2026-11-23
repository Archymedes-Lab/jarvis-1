"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'monitor SSH on Linux servers beyond successful/failed login records, and ship the Linux '
            'server edition as compiled bytecode without source or Windows payloads',
    'existing': ['journal Accepted records (logins)', 'failure counts (bruteforce)',
                 'keys in ~/.ssh/authorized_keys of uid>=1000 and root, five sshd_config regexes (backdoor)'],
    'added_sshwatch': [
        'effective sshd config parsed from files: Include followed, first value wins, Match blocks apart, '
        'defaults applied',
        'every AuthorizedKeysFile path for every passwd account, learned once, then added/removed keys',
        'host key fingerprints learned once, change reported high',
        'sshd listeners beyond its configured ports reported as remote forwards; ssh client -R/-D/-w tunnels',
        'config writable by non-root and host private keys readable by others, stat only',
    ],
    'alternatives_config': ['parse files (selected)', 'sshd -T (needs root and host keys; the daemon has '
                            'only CAP_DAC_READ_SEARCH, CAP_SYS_PTRACE, CAP_SYSLOG)'],
    'cadence': 'every 5 minutes, about 20 ms measured on a host without sshd',
    'first_run': 'learns existing keys without paging; risky-in-itself keys (service account, '
                 'authorized_keys2, weak) still reported',
    'packaging': 'server edition ships .pyc only plus the readable root-ownership launcher; Windows '
                 'PowerShell payloads dropped; a missing payload loads as a script that throws',
}
QUESTIONS = {
    'config_source': {'type': 'choice', 'instructions':
        'Which source of the effective sshd configuration best fits least privilege for an unprivileged '
        'monitoring daemon?',
        'criteria': {'files': 'Parse the config files with sshd semantics',
                     'sshd_t': 'Run sshd -T', 'uncertain': 'Insufficient information'}},
    'first_run_blind': {'type': 'noul', 'instructions':
        'Does learning existing keys silently on the first run leave a key planted before install '
        'unreported, so a separate review of the learned keys is needed?',
        'criteria': {'true': 'Yes, a pre-existing key needs separate review',
                     'false': 'No, it is covered'}},
    'poll_gap': {'type': 'noul', 'instructions':
        'Can a short-lived SSH tunnel opened and closed between two 5-minute polls go unseen by this design?',
        'criteria': {'true': 'Yes, it can be missed', 'false': 'No'}},
    'throwing_stub': {'type': 'noul', 'instructions':
        'Is replacing a missing Windows payload with a script that throws safer than returning an empty '
        'script, because the collector then reports unavailable instead of clean?',
        'criteria': {'true': 'Yes, safer', 'false': 'No'}},
    'next_gate': {'type': 'choice', 'instructions':
        'Which validation should come first before claiming the SSH watch works?',
        'criteria': {'real_server': 'Run on a real server with a live sshd and planted test key and tunnel',
                     'more_units': 'More unit tests',
                     'fuzz': 'Fuzz the config parser',
                     'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

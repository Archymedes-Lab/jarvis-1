"""Fixed engineering metadata only; advisory, never deployment authorization.

Security review 2026-10-30 (ARGUS-2026-002 draft): network protocols, browser
extension and parsers of untrusted input, after the source leak."""
import json
import sys

from jarvis.response import jev

STATE = {
    'context': 'a self-hosted host-security monitor whose full source was public for a week; attackers know '
               'exactly how it parses untrusted input',
    'changes': {
        'safe_reads': 'files in folders other users control are opened non-blocking, the file type is checked on '
                      'the open descriptor (regular files only), reads are capped, and the repository scanner '
                      'refuses symbolic links at open time instead of trusting an earlier lstat',
        'parser_depth': 'deeply nested JSON/TOML in one scanned lockfile or one advisory is skipped instead of '
                        'aborting the whole scan',
        'private_key_scan': 'a quadratic lazy regex for private key blocks replaced by a linear scan proven equal '
                            'on random inputs',
        'ssh_failures': 'the source address of failed SSH logins is taken from the end of the sshd line, and '
                        'journal lines count only when journald stamps the writer as uid 0',
        'heredoc': 'a quoted heredoc is treated as inert data only when no shell or interpreter reads it',
        'browser_extension': 'the isolated content script takes the page origin from its own location and '
                             'forwards only known fields',
        'phone_relay': 'not changed in protocol; the relay serves the phone web app, so the relay operator is '
                       'trusted code; the 6-digit pairing comparison lacks a commit-then-reveal step',
    },
    'validation': {'regression_tests_fail_before_and_pass_after': True, 'relay_deployed': False},
}
QUESTIONS = {
    'uid_filter_risk': {'type': 'noul', 'instructions':
        'Could counting only journal entries written by uid 0 plausibly hide genuine SSH login failures on '
        'common Linux distributions?',
        'criteria': {'true': 'Plausibly hides genuine failures', 'false': 'Unlikely to hide genuine failures'}},
    'heredoc_tradeoff': {'type': 'choice', 'instructions':
        'For the heredoc change, which outcome is the larger remaining risk?',
        'criteria': {'evasion': 'An interpreter not in the list still runs a quoted heredoc unseen',
                     'false_alarms': 'Benign file-writing heredocs now raise download-and-run alerts',
                     'uncertain': 'Insufficient information'}},
    'relay_priority': {'type': 'choice', 'instructions':
        'Which phone-relay improvement should come first?',
        'criteria': {'independent_code': 'Deliver the phone app independently of the relay (signed bundle or '
                                         'native app)',
                     'sas_commit': 'Add a commit-then-reveal nonce to the 6-digit pairing comparison',
                     'both_together': 'Both together; either alone leaves the other gap open',
                     'uncertain': 'Insufficient information'}},
    'next_gate': {'type': 'choice', 'instructions':
        'Which further validation would most raise confidence in these parser fixes?',
        'criteria': {'fuzzing': 'Coverage-guided fuzzing of the parsers with hostile files',
                     'live_readback': 'Live readback on a real server after deploy',
                     'race_test': 'A stress test racing file swaps against the scanner',
                     'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))
    sys.exit(0)

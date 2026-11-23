"""Fixed engineering metadata only; advisory, never deployment authorization.

Bounded Jev review (2026-11-10) of two changes: critical findings cannot be
acknowledged through the local API, and the server installer never leaves a
watched server unwatched. No tokens, source, findings or host data are sent.
"""
import json

from jarvis.response import jev

STATE = {
    'product': 'a local security monitor; a daemon stores findings, a loopback API with a token '
               'serves a dashboard and desktop app, a command line reads the same store',
    'critical_ack': {
        'problem': 'any program holding the API token could answer yes to a critical finding, '
                   'which acknowledged it and stopped alerts about it',
        'built': 'acknowledging a critical finding is refused unless the caller records a '
                 'confirmation made outside the API; the only confirmer is the command line after '
                 'the person types the finding id at an interactive terminal; a yes over the API '
                 'changes no state and returns the command to run; stored acknowledgements of '
                 'critical findings without the confirmation record stop applying',
        'known_limits': ['where the daemon runs as the protected user, a program running as that '
                         'user can write the store directly or open a pseudo-terminal',
                         'no notice is sent to other channels when a critical is acknowledged',
                         'the app still shows a yes button whose press returns the refusal text'],
        'alternatives': {
            'phone_signed': 'require a signed approval from a paired phone with a passkey; exists '
                            'for defense proposals, not yet for acknowledgements; no real phone paired',
            'notice_only': 'allow the API acknowledgement and send a notice to every alert channel',
            'wait_for_service_account': 'change nothing until the daemon runs as its own account',
        },
        'effect_on_existing_users': 'criticals acknowledged earlier return to full severity until '
                                    'confirmed again at a terminal; the score can only go down',
    },
    'installer': {
        'problem': 'an upgrade stopped the running service before verifying the new copy, and a '
                   'failed verification restored the files without restarting the service',
        'built': 'the new copy verifies itself from a root-owned staging directory before the '
                 'service is stopped; after the switch, any failure or a new version that does not '
                 'answer its health check within 60 seconds restores the previous program, version '
                 'file and unit and restarts it; a previous version that fails to start is reported '
                 'as an unwatched server',
        'tested': 'the real script run against a scratch root with stand-ins for system tools, ten '
                  'scenarios, four negative controls; not yet run as root on a real systemd host',
        'known_limits': ['self-verification is run by the copy being verified',
                         'the installer does not check the download signature itself',
                         'settings files are not rolled back'],
    },
}
QUESTIONS = {
    'ack_design': {'type': 'choice', 'instructions':
        'Given `critical_ack`, which design is the best step to take now for stopping a local '
        'program from silencing critical findings, given what exists today?',
        'criteria': {
            'terminal_gate': 'the built terminal-confirmation gate, with its stated limits',
            'phone_signed': 'require a phone-signed approval instead',
            'notice_only': 'allow it and notify every channel',
            'wait': 'wait for the service account',
        }},
    'ack_reset_acceptable': {'type': 'noul', 'instructions':
        'Is `critical_ack.effect_on_existing_users` an acceptable cost for a security product, '
        'provided the release notes say so?',
        'criteria': {'true': 'Acceptable', 'false': 'Not acceptable'}},
    'ack_next_gap': {'type': 'choice', 'instructions':
        'Which of the `critical_ack.known_limits` most deserves to be closed next?',
        'criteria': {
            'same_user_store': 'the same-user direct store write (needs a service account)',
            'notice': 'send a notice on every channel when a critical is acknowledged',
            'button': 'replace the yes button in the app for critical findings',
        }},
    'rollback_on_health': {'type': 'noul', 'instructions':
        'In `installer.built`, is rolling back when the new version does not answer within 60 '
        'seconds safer for an unattended server than leaving the new version in place starting?',
        'criteria': {'true': 'Rolling back is safer', 'false': 'Leaving it is safer'}},
    'installer_gap': {'type': 'choice', 'instructions':
        'Which validation gap in `installer` matters most before this installer ships?',
        'criteria': {
            'real_host': 'run it as root on a real systemd host, including a failed upgrade',
            'signature': 'make the installer check the download signature itself',
            'settings': 'roll back settings files too',
        }},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

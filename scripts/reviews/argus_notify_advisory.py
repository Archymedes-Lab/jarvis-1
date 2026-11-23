"""Fixed engineering metadata only; advisory, never deployment authorization.

ARGUS-NOTIFY.md v1: sealed relay for phone notifications."""
import json
import sys

from jarvis.response import jev

STATE = {
    'goal': 'deliver a self-hosted server monitor alerts to the owner phone through a hosted relay, '
            'without the relay or push providers being able to read or forge them',
    'design': 'server only makes outbound HTTPS; per-device envelopes sealed with ephemeral X25519, HKDF, '
              'AES-256-GCM and signed with the server Ed25519 key; relay stores ciphertext; empty web push '
              'wakes the phone app which fetches, verifies and decrypts; ids are hashes of signing keys',
    'pairing': 'server prints a 10-character single-use code valid 10 minutes; phone fetches the offer from '
               'the relay and posts its keys; both show a 6-digit code derived from all four public keys; '
               'the owner confirms equality on the server before the device is activated',
    'accounts': 'none; a phone is its device keys; one phone can pair with several servers',
    'alternatives': ['QR code pairing', 'encrypted web push payloads (RFC 8291)', 'email plus passkey accounts',
                     'relay-trusted pairing without the 6-digit comparison'],
}
QUESTIONS = {
    'sas_needed': {'type': 'noul', 'instructions':
        'Is the 6-digit code comparison confirmed on the server necessary to stop a malicious relay from '
        'inserting its own device or substituting the server keys during pairing?',
        'criteria': {'true': 'Necessary', 'false': 'Not necessary'}},
    'empty_push': {'type': 'choice', 'instructions':
        'Which push design better limits what push providers learn while staying reliable on iOS and Android?',
        'criteria': {'empty_wakeup': 'Empty wake-up push, the app fetches and decrypts',
                     'encrypted_payload': 'Encrypted push payload carrying the alert',
                     'uncertain': 'Insufficient information'}},
    'typed_code_ok': {'type': 'noul', 'instructions':
        'Is a typed 10-character single-use code with a 10-minute lifetime and 10 attempts an acceptable '
        'pairing method for a mobile-first app, given the 6-digit comparison protects against substitution?',
        'criteria': {'true': 'Acceptable', 'false': 'Not acceptable'}},
    'no_accounts': {'type': 'noul', 'instructions':
        'Does having no user accounts on the relay materially reduce the harm of a relay breach for this product?',
        'criteria': {'true': 'Materially reduces', 'false': 'No meaningful reduction'}},
    'top_risk': {'type': 'choice', 'instructions':
        'Which remaining risk in this design most needs a test or control before launch?',
        'criteria': {'stolen_phone': 'An unlocked stolen phone reading alerts',
                     'relay_dos': 'Relay abuse or flooding of mailboxes',
                     'key_loss': 'Server or phone key loss requiring re-pairing',
                     'metadata': 'Relay metadata revealing which servers alert when',
                     'uncertain': 'Insufficient information'}},
}
if __name__ == '__main__':
    STATE['phase'] = 'implementation' if '--implementation' in sys.argv else 'design'
    if STATE['phase'] == 'implementation':
        STATE['validation'] = json.loads(sys.stdin.read() or '{}')
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

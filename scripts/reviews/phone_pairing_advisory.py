"""Fixed engineering metadata only; advisory, never deployment authorization."""
import json

from jarvis.response import jev

STATE = {
    'goal': 'let the owner pair a phone for end-to-end encrypted alerts from the desktop app or the '
            'local dashboard, without a terminal, keeping the 6-digit comparison that stops a '
            'malicious relay from adding its own device',
    'design': {
        'shared_steps': 'offer, find claim, check claim keys against the device id, reject, accept '
                        'and activate with retries; one module used by the CLI and the API',
        'session': 'one in-memory pairing at a time, 10-minute monotonic expiry, states waiting, '
                   'claimed, confirming, paired, rejected, expired, cancelled, error',
        'confirm': 'pairs only when the page sends back the exact comparison code this session '
                   'showed, while claimed; a wrong, stale or repeated confirm is refused',
        'polling': 'no thread; each page poll makes at most one relay call, at most every 2 s, '
                   'never two concurrently',
        'exposure': 'page sees session id, pairing code, relay URL, device id, sanitised name, '
                    'comparison code; never keys',
        'gates': 'credential on every route, same-origin on POST, desktop commands validate '
                 'argument formats before forwarding',
        'restart': 'a daemon restart drops the session; the relay claim stays pending, never activated',
    },
    'measured': {
        'tests': '21 state-machine and route tests (wrong and stale code, double confirm, reject '
                 'deletes claim, busy, expiry, relay errors, malformed and mismatched claims, '
                 'activation exhaustion, restart, no-credential and cross-site refused over HTTP)',
        'ui': 'screens rendered in both modes against a mocked API; locale tests pass for 11 languages',
    },
    'limits': [
        'never paired a real phone through the new path',
        'a local process holding the API credential can drive the pairing, but still needs the '
        'owner to read the code on the phone and click in the app',
        'the in-memory session is lost on restart; the owner must start again',
    ],
}
QUESTIONS = {
    'design_sound': {'type': 'noul', 'instructions':
        'Given the design and tests, does moving pairing from a terminal prompt to an authenticated '
        'app button keep the protection of the 6-digit comparison against a malicious relay?',
        'criteria': {'true': 'Yes', 'false': 'No, the comparison is weakened'}},
    'top_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most deserves the next measured test or change?',
        'criteria': {'real_phone': 'An end-to-end pairing with a real phone and the real relay',
                     'local_malware': 'A local process with the API credential driving the pairing',
                     'restart': 'Session loss on daemon restart',
                     'ui_clarity': 'Whether owners actually compare the codes before clicking'}},
    'claim_level': {'type': 'noul', 'instructions':
        'Should this capability stay unverified until a real phone is paired through the desktop '
        'app and receives a sealed test alert?',
        'criteria': {'true': 'Yes, keep it unverified until then', 'false': 'The tests suffice'}},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

"""Fixed engineering metadata only; advisory, never deployment authorization.

Bounded Jev review of the local web API / API token hardening (2026-10-30).
No token values, source, request contents or security evidence are sent.
"""
import json

from jarvis.response import jev

STATE = {
    'service': 'loopback-only HTTP dashboard and API of a local security daemon; '
               'state-changing POST routes need a per-start random token',
    'token_delivery': 'the dashboard page load sets the token as a cookie; the desktop app '
                      'reads it the same way; the CLI reads a 0600 file',
    'changes': [
        'token file written via mkstemp (O_EXCL, 0600) then rename; a leftover loose temp '
        'file or a planted link can no longer loosen or redirect it',
        'no token issued means every state-changing request is refused (was: accepted)',
        'token compared as bytes in constant time; non-ASCII header is a mismatch, not a crash',
        'cookie gains HttpOnly; page script never read it',
        'cookie withheld when the connecting socket is owned by another local account '
        '(uid looked up in /proc/net/tcp); root, own account and unattributable peers keep it',
        'per-connection socket timeout of 30 s; previously none',
        'frame-ancestors self, X-Frame-Options SAMEORIGIN, nosniff on every response',
        'server ids moved from inline onclick JavaScript strings to data attributes',
    ],
    'unchanged': 'Host allow-list, Sec-Fetch-Site/Origin check, body size caps, no CORS, '
                 'read-only GET routes stay unauthenticated, script-src unsafe-inline remains '
                 'because the page has 50 inline handlers',
    'validation': '34 new Python tests on a real loopback server and 1 JS test; they fail '
                  'on the previous code; related suites and static gate pass',
}
QUESTIONS = {
    'unattributable_peer_policy': {'type': 'noul', 'instructions':
        'Is giving the cookie to a peer whose owning account cannot be determined (rather than '
        'refusing it) an acceptable interim policy, given that refusing would break the owner '
        'desktop app reaching the daemon across the WSL boundary, and that it is documented as '
        'residual exposure?',
        'criteria': {'true': 'Acceptable interim', 'false': 'Should fail closed now'}},
    'timeout_risk': {'type': 'noul', 'instructions':
        'Could a 30 second per-connection socket timeout plausibly break long-lived '
        'server-sent-event streams whose server writes a keepalive every few seconds?',
        'criteria': {'true': 'Plausibly breaks them', 'false': 'Unlikely to break them'}},
    'biggest_gap': {'type': 'choice', 'instructions':
        'Which remaining gap most deserves the next hardening step?',
        'criteria': {
            'reads': 'unauthenticated read-only GET routes expose the full security state to '
                     'any local process',
            'csp': 'script-src unsafe-inline on the dashboard',
            'same_account': 'any process of the same account can read the token file',
            'cdn': 'the geo page loads third-party CDN scripts into the same origin',
        }},
}
if __name__ == '__main__':
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({'model': result.get('model'), 'answers': result['answers']}))
    except jev.JevError as exc:
        print(json.dumps({'unavailable': str(exc)}))

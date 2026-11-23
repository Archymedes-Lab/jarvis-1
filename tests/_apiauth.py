"""A credential for tests whose subject is a route's behaviour, not its gate.

The gate itself is covered by tests/test_api_clients.py and
tests/test_api_hardening.py; tests of what a route returns present the
per-start token the way every real client must.
"""

from jarvis.web import token as api_token

TOKEN = "a1" * 32


def grant(testcase):
    """Put a per-start token in force for this test; returns the header to send."""
    old = api_token._TOKEN
    api_token._TOKEN = TOKEN
    testcase.addCleanup(setattr, api_token, "_TOKEN", old)
    return {api_token.HEADER: TOKEN}

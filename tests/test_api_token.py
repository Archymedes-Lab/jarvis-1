"""The per-start API token: issued 0600, required on state-changing routes."""

import os
import stat
import tempfile
import unittest

from jarvis.web import token


class TokenTests(unittest.TestCase):
    def setUp(self):
        token._TOKEN = None

    def tearDown(self):
        token._TOKEN = None

    def test_no_token_in_force_refuses_everything(self):
        # Fail closed: a Handler run without serve() issuing a token accepts
        # no state-changing request at all.
        self.assertFalse(token.accepts({}))
        self.assertFalse(token.accepts({token.HEADER: ""}))

    def test_issue_writes_owner_only_file_and_gates_requests(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "api.token")
            value = token.issue(path)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(token.read(path), value)
            self.assertFalse(token.accepts({}))
            self.assertFalse(token.accepts({token.HEADER: "wrong"}))
            self.assertTrue(token.accepts({token.HEADER: value}))
            self.assertTrue(token.accepts({"Cookie": f"a=b; {token.COOKIE}={value}"}))
            self.assertIn(value, token.cookie_header())
            self.assertIn("SameSite=Strict", token.cookie_header())
            self.assertIn("HttpOnly", token.cookie_header())

    def test_reissue_changes_the_token(self):
        with tempfile.TemporaryDirectory() as d:
            a = token.issue(os.path.join(d, "t"))
            b = token.issue(os.path.join(d, "t"))
            self.assertNotEqual(a, b)
            self.assertFalse(token.accepts({token.HEADER: a}))


if __name__ == "__main__":
    unittest.main()

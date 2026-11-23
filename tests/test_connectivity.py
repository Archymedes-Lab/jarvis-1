import json
import os
import tempfile
import unittest

from jarvis.service import connectivity


class ConnectivityAuditTest(unittest.TestCase):
    NOW = 1_800_000_000

    def audit(self, state):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'state.json')
            if state is not None:
                with open(path, 'w') as f:
                    json.dump(state, f)
            return connectivity.audit(path, now=self.NOW)[0]

    def base(self, **kw):
        return {'checkedAt': self.NOW - 30, 'internetTcpReachable': True,
                'application': {'healthy': True}, 'applicationFailures': 0, **kw}

    def test_healthy(self):
        self.assertEqual(self.audit(self.base())['severity'], 'ok')

    def test_missing_or_stale_state(self):
        self.assertEqual(self.audit(None)['severity'], 'high')
        self.assertEqual(self.audit(self.base(checkedAt=self.NOW - 900))['severity'], 'high')

    def test_single_application_failure_is_only_confirming(self):
        out = self.audit(self.base(application={'healthy': False}, applicationFailures=1))
        self.assertEqual(out['severity'], 'medium')

    def test_repeated_application_failures_alert(self):
        out = self.audit(self.base(application={'healthy': False}, applicationFailures=3))
        self.assertEqual(out['title'], 'internet application connectivity is degraded')

    def test_tcp_down(self):
        self.assertEqual(self.audit(self.base(internetTcpReachable=False))['severity'], 'high')

    def test_paused(self):
        self.assertEqual(self.audit(self.base(action='paused'))['severity'], 'low')


if __name__ == '__main__':
    unittest.main()

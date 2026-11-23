"""Exercise every literal POST route, including ones added after the older list.

Synthetic loopback server only. Route discovery expands coverage automatically;
exception routes have separate credentials and explicit denial checks.
"""

import ast
import inspect
import textwrap
import threading
from unittest import mock

from jarvis.web import phone, server
from tests import test_api_hardening as api

SPECIAL = {'/api/session', '/api/veil/events'}


def post_routes():
    tree = ast.parse(textwrap.dedent(inspect.getsource(server.Handler.do_POST)))
    routes = {node.value for node in ast.walk(tree)
              if isinstance(node, ast.Constant) and isinstance(node.value, str)
              and node.value.startswith('/api/')}
    return routes | set(phone.ROUTES_POST)


class PostRouteBoundaryTests(api._Base):
    def test_all_discovered_dashboard_routes_require_credentials(self):
        routes = post_routes() - SPECIAL
        self.assertGreater(len(routes), 25)
        # A missing gate would reach this scheduler on /api/run, pause or resume.
        scheduler = mock.Mock()
        with mock.patch.object(server.Handler, 'scheduler', scheduler):
            for route in sorted(routes):
                with self.subTest(route=route):
                    status, _, _ = self.srv.request('POST', route, {'id': 'synthetic'})
                    self.assertEqual(status, 403)
            self.assertEqual(scheduler.mock_calls, [])

    def test_cross_site_requests_with_valid_token_never_reach_scheduler(self):
        scheduler = mock.Mock()
        with mock.patch.object(server.Handler, 'scheduler', scheduler):
            for route in sorted(post_routes() - SPECIAL):
                with self.subTest(route=route):
                    status, _, _ = self.srv.request('POST', route, {'id': 'synthetic'}, {
                        'X-JARVIS-Token': self.token, 'Sec-Fetch-Site': 'cross-site',
                        'Origin': 'https://example.invalid',
                    })
                    self.assertEqual(status, 403)
            self.assertEqual(scheduler.mock_calls, [])

    def test_unpaired_extension_route_refuses_report(self):
        status, _, _ = self.srv.request('POST', '/api/veil/events', {'id': 'synthetic'})
        self.assertEqual(status, 403)

    def test_denied_request_never_enters_json_parser_or_job_scheduler(self):
        seen = set()
        codes = {getattr(server.Handler, name).__code__: name
                 for name in ('do_POST', '_authorized', '_json_body')}
        before = threading.getprofile()

        def profile(frame, event, arg):
            if event == 'call' and frame.f_code in codes:
                seen.add(codes[frame.f_code])

        scheduler = mock.Mock()
        try:
            threading.setprofile(profile)
            with mock.patch.object(server.Handler, 'scheduler', scheduler):
                status, _, _ = self.srv.request('POST', '/api/run?job=secrets', {'id': 'synthetic'})
        finally:
            threading.setprofile(before)
        self.assertEqual(status, 403)
        self.assertEqual(seen, {'do_POST', '_authorized'})
        self.assertEqual(scheduler.mock_calls, [])

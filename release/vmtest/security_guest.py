"""Synthetic loopback probes INSIDE the verified disposable server VM only."""
import http.client
import json
import time


def probes(port, token):
    checks = []

    def request(name, path, method='GET', headers=None, body=None, expected=(403,)):
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=8)
        started = time.monotonic()
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read(65537)
            checks.append({'name': name, 'status': response.status,
                           'ok': response.status in expected and len(data) <= 65536,
                           'seconds': round(time.monotonic() - started, 3)})
        except Exception as exc:
            checks.append({'name': name, 'ok': False, 'error_type': type(exc).__name__})
        finally:
            connection.close()

    request('unauthenticated-state', '/api/state')
    request('unauthenticated-run', '/api/run?job=synthetic-security-probe', 'POST')
    request('unauthenticated-approval', '/api/fix/approve', 'POST', body=b'{"id":"synthetic"}')
    request('wrong-token', '/api/state', headers={'X-ARGUS-Token': 'synthetic-invalid'})
    request('dns-rebinding', '/api/state', headers={'X-ARGUS-Token': token, 'Host': 'example.invalid'})
    request('cross-site-authorized-write', '/api/run?job=synthetic-security-probe', 'POST',
            headers={'X-ARGUS-Token': token, 'Origin': 'https://example.invalid', 'Sec-Fetch-Site': 'cross-site'})
    # Traversal must not disclose synthetic guest /etc/passwd via static routes.
    request('static-traversal', '/ui/../../etc/passwd', expected=(400, 403, 404))
    request('encoded-traversal', '/ui/%2e%2e/%2e%2e/etc/passwd', expected=(400, 403, 404))
    request('invalid-json', '/api/ask', 'POST', headers={'X-ARGUS-Token': token},
            body=b'{', expected=(400, 413, 503))
    request('oversized-json', '/api/ask', 'POST', headers={'X-ARGUS-Token': token},
            body=json.dumps({'synthetic': 'x' * 65536}).encode(), expected=(400, 413, 503))
    return {'checks': checks, 'passed': sum(check['ok'] for check in checks),
            'total': len(checks), 'scope': 'synthetic localhost probes inside disposable VM'}

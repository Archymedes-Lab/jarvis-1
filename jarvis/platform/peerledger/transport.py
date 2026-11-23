"""Explicitly pinned HTTPS transport and bounded witness request handling."""
import http.server
import json
import sqlite3
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from .protocol import (
    MAX_WIRE,
    MeshError,
    hex_bytes,
    response,
    validate_request,
    validate_response,
    wire,
)
from .store import Ledger, identity

TIMEOUT = 5
ATTEMPTS = 2


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise MeshError('peer redirects forbidden')


def peer(value):
    try:
        url, key = value.rsplit(',', 1)
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or
                parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/') or
                not 1 <= (parsed.port or 443) <= 65535):
            raise ValueError()
        hex_bytes(key, 32)
    except (ValueError, TypeError) as exc:
        raise MeshError('peer must be https://HOST:PORT,PINNED_PUBLIC_HEX') from exc
    return url.rstrip('/') + '/v1/mesh', key


def exchange(url, key, req, context=None):
    # Validate URL on every call, including callers outside CLI.
    url, _ = peer(url.removesuffix('/v1/mesh') + ',' + key)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    for attempt in range(ATTEMPTS):
        try:
            request = urllib.request.Request(url, data=wire(req),
                                             headers={'Content-Type': 'application/json',
                                                      'User-Agent': 'JarvisEvidenceMesh/1.0',
                                                      'Accept': 'application/json'})
            with opener.open(request, timeout=TIMEOUT) as res:
                raw = res.read(MAX_WIRE + 1)
            if len(raw) > MAX_WIRE:
                raise MeshError('peer response capacity exceeded')
            result = json.loads(raw)
            return validate_response(result, req, key)
        except (urllib.error.HTTPError, MeshError, ValueError) as exc:
            raise MeshError('peer rejected or invalid response') from exc
        except (OSError, urllib.error.URLError) as exc:
            if attempt + 1 == ATTEMPTS:
                raise MeshError('peer unreachable after bounded retries') from exc
            time.sleep(0.05)


def handle(req, ledger, private, allowed):
    validate_request(req, allowed)
    ledger.verify(req['stream'])
    if req['op'] == 'put':
        ledger.append(req['block'])
        block = ledger.get(req['stream'], req['height'])
    elif req['op'] == 'get':
        block = ledger.get(req['stream'], req['height'])
    else:
        block = ledger.head(req['stream'])
    return response(req, block, private)


def server(root, allowed, cert, key, host='127.0.0.1', port=9443, budget=None):
    if not 1 <= len(allowed) <= 32:
        raise MeshError('enroll between 1 and 32 producers')
    for producer in allowed:
        hex_bytes(producer, 32)
    owner = identity(root)

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def setup(self):
            self.request.settimeout(TIMEOUT)
            super().setup()

        def log_message(self, *_):
            pass  # Never log raw requests, peer addresses or paths.

        def do_POST(self):
            try:
                if (self.path != '/v1/mesh' or self.headers.get('Transfer-Encoding') or
                        self.headers.get('Content-Type') != 'application/json' or
                        len(self.headers.get_all('Content-Length', [])) != 1):
                    raise MeshError('invalid transport')
                length = int(self.headers['Content-Length'])
                if not 1 <= length <= MAX_WIRE:
                    raise MeshError('request capacity exceeded')
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise MeshError('interrupted request')
                kwargs = {} if budget is None else {'budget': budget}
                with Ledger(root, **kwargs) as ledger:
                    result = handle(json.loads(raw), ledger, owner['signing'], set(allowed))
                data, status = wire(result), 200
            except (ValueError, KeyError, TypeError, OSError, sqlite3.Error):
                # Fixed response; neither raw evidence nor filesystem details leave.
                data, status = b'{"error":"request refused"}', 409
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    class BoundedServer(http.server.HTTPServer):
        request_queue_size = 8

        def get_request(self):
            raw, address = self.socket.accept()
            raw.settimeout(TIMEOUT)
            try:
                return context.wrap_socket(raw, server_side=True), address
            except (OSError, ssl.SSLError):
                raw.close()
                raise

        def handle_error(self, *_):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return BoundedServer((host, port), Handler)

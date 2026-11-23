"""The local API's request parsing, called at handler level: no socket, no daemon.

Never start the server or contact 127.0.0.1:8787 from here; the handler methods
are called on an object built without __init__ (no connection is made)."""

import io
import json

from jarvis.web import clients, token
from jarvis.web.server import Handler
from tests.fuzz.engine import Target


class _Headers(dict):
    def get(self, key, default=None):
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


def _handler(body, headers):
    h = Handler.__new__(Handler)
    h.headers = _Headers(headers)
    h.rfile = io.BytesIO(body)
    return h


def run_json_body(body):
    """_json_body must return a dict or None for any body within its limit (it runs
    before the token check on /api/veil/events, which browser pages can reach)."""
    h = _handler(body, {"Content-Length": str(len(body))})
    out = Handler._json_body(h, 8192)
    assert out is None or isinstance(out, dict), f"_json_body returned {type(out).__name__}"


class _Store:
    def __init__(self, meta):
        self.meta = meta

    def get_meta(self, key, default=None):
        return self.meta.get(key, default)

    def set_meta(self, key, value):
        self.meta[key] = value


_STORE = _Store({})
_CID, _TOKEN = clients.pair(_STORE, "fuzz", now=0)


def run_client_token(text):
    """Oracle: verify() accepts exactly the issued token and nothing else."""
    got = clients.verify(_STORE, text)
    assert (got == _CID) == (text == _TOKEN), f"client token verify({text!r}) -> {got!r}"
    clients.looks_like(text)


def run_client_store(text):
    """The meta record is the daemon's own, but it must never crash verify()."""
    clients.verify(_Store({clients.META_KEY: text}), _TOKEN)


TOKEN_VALUE = "a1" * 32


def run_request_token(text):
    """Oracle: with a per-start token in force, a request is accepted only when one
    of its credentials is exactly that token."""
    old = token._TOKEN
    token._TOKEN = TOKEN_VALUE
    try:
        for headers in ({"Cookie": text}, {"Authorization": text}, {token.HEADER: text}):
            ok = token.accepts(_Headers(headers))
            exact = TOKEN_VALUE in token.candidates(_Headers(headers))
            assert ok == exact, f"accepts={ok} for {headers!r}"
    finally:
        token._TOKEN = old


TARGETS = [
    Target("web.json_body", run_json_body, [b'{"a": 1}', b"[1]", b'{"x": [[]]}'], kind="bytes",
           tokens=(b"[", b"{", b'"a":', b"\xff", b"1e400", b"NaN"), max_len=8192),
    Target("web.client_token", run_client_token, [_TOKEN, "jc1_" + "0" * 12 + "_" + "A" * 43, _TOKEN + "\n"],
           tokens=("\n", "jc1_", "_", "\u0663"), max_len=128),
    Target("web.client_store", run_client_store,
           [json.dumps([{"id": _CID, "sha256": "0", "revoked_at": None}]), "[]", "{}"],
           tokens=("[", "{", "null", '"id"', "1"), max_len=8192),
    Target("web.request_token", run_request_token,
           [f"{token.COOKIE}={TOKEN_VALUE}", f"Bearer {TOKEN_VALUE}", TOKEN_VALUE],
           tokens=(";", "=", "Bearer ", TOKEN_VALUE, " ", "\u00e9", "\x00"), max_len=1024),
]

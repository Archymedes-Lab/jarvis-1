"""Signed, bounded HTTPS requests to the relay. Errors never contain secrets."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "https://argus.archymedes.xyz"
TIMEOUT_S = 15
MAX_RESPONSE = 256 * 1024
UA = "notify-client/1"


class RelayError(RuntimeError):
    pass


def base_url(conf):
    url = (conf.get("notify_url") or DEFAULT_URL).strip().rstrip("/")
    # Judge the parsed host, not a prefix: "http://127.0.0.1.example.net" starts
    # with "http://127.0.0.1" and is a plaintext request to someone else's host.
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise RelayError("notify_url is not a URL") from None
    # "localhost" as well: WebAuthn needs a hostname (not an IP) as its relying-party id, so browser tests use it.
    local = parts.scheme == "http" and host in ("127.0.0.1", "localhost")
    if not host or (parts.scheme != "https" and not local) or parts.username or parts.password:
        raise RelayError("notify_url must be https (http only for 127.0.0.1 / localhost tests)")
    return url


def call(conf, ident, method, path, payload=None, now=None, opener=urllib.request.urlopen):
    body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"User-Agent": UA, "Content-Type": "application/json",
               **ident.request_headers(method, path, body, time.time() if now is None else now)}
    req = urllib.request.Request(base_url(conf) + path, data=body if payload is not None else None,
                                 method=method, headers=headers)
    try:
        with opener(req, timeout=TIMEOUT_S) as resp:
            raw = resp.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read(4096) or b"{}").get("error", "")
        except (ValueError, OSError):
            pass
        raise RelayError(f"HTTP {exc.code}" + (f": {str(detail)[:120]}" if detail else "")) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RelayError(type(exc).__name__) from None
    if len(raw) > MAX_RESPONSE:
        raise RelayError("relay response too large")
    try:
        return json.loads(raw or b"null")
    except ValueError:
        raise RelayError("relay response is not JSON") from None

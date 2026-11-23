"""How in-repo programs (the CLI, probes, dev tools) authenticate to the API.

Credential order:
  1. a paired client token file: $JARVIS_CLIENT_TOKEN_FILE, else
     ~/.config/jarvis/client.token (written by `jarvis desktop save`). It must be
     a regular file readable by its owner only, or it is refused;
  2. the daemon's per-start token file, when this account can read it (the
     daemon runs as this same account).

The token is sent as the X-JARVIS-Token header and never placed in a URL,
an argument list or an error message.
"""

import json
import os
import stat
import urllib.error
import urllib.request

from jarvis.web import clients
from jarvis.web import token as api_token

CLIENT_TOKEN_PATH = os.path.expanduser("~/.config/jarvis/client.token")


class Unpaired(RuntimeError):
    """No usable credential: pair with `jarvis desktop pair` first."""


def client_token_path(environ=None):
    env = environ if environ is not None else os.environ
    return env.get("JARVIS_CLIENT_TOKEN_FILE") or CLIENT_TOKEN_PATH


def read_private(path):
    """The token in `path`, or "" when it is missing, not a regular file, not
    ours, open to group/other, or not a client token."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return ""
        if hasattr(os, "geteuid") and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
            return ""
        value = os.read(fd, 512).decode("ascii", "ignore").strip()
    finally:
        os.close(fd)
    return value if clients.looks_like(value) else ""


def save_private(path, value):
    """Write a client token 0600 (exclusive temp file, then rename)."""
    if not clients.looks_like(value):
        raise ValueError("that is not a client token (jc1_...)")
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".client.token.", dir=directory)
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            os.write(fd, value.encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def credential(environ=None):
    """The token to send, or raise Unpaired."""
    value = read_private(client_token_path(environ))
    if value:
        return value
    value = api_token.read()
    if value:
        return value
    raise Unpaired("not paired with the daemon: run `jarvis desktop pair --name cli | "
                   "jarvis desktop save` (under the service account: `sudo jarvis-svc "
                   "desktop pair --name cli | jarvis desktop save`)")


def request(method, path, port=8787, body=None, timeout=10, environ=None):
    """(status, parsed JSON or None) for one authenticated loopback request."""
    headers = {api_token.HEADER: credential(environ)}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{int(port)}{path}", data=data,
                                 method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw, status = resp.read(8 << 20), resp.status
    except urllib.error.HTTPError as exc:
        raw, status = exc.read(1 << 16), exc.code
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None

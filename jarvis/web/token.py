"""Per-start API token, and who may receive it.

`jarvis serve` writes a fresh random token to a 0600 file when it starts. Every
API route except liveness (/api/health, /api/live) requires a credential: this
token as the `X-JARVIS-Token` header, `Authorization: Bearer`, or the
`jarvis_token` cookie; or a paired client token (web/clients.py) the same ways
or as the `jarvis_client` cookie a browser gets from the /pair page.

The dashboard's HTML pages hand the per-start token to whoever loads them, so
that hand-over is gated (QC-ARGUS-1-2026-10-27 blocker 4):

  * Only accounts that can already read the token file receive it: the
    connecting socket's owner is looked up in /proc/net/tcp{,6} and the cookie
    goes only to the daemon's own account and root. Any other account, any peer
    whose owner cannot be determined (a Windows program reaching the daemon
    through WSL networking) and, since 2026-11-08, the owner account of a
    service-account install (formerly JARVIS_OWNER_UID) get no cookie: they pair
    explicitly (`jarvis desktop pair`, then the app's token file or the /pair
    page). The hand-over therefore grants nothing a process did not already have.
  * Only a browser's top-level navigation receives it (fetch metadata:
    Sec-Fetch-Mode navigate, Sec-Fetch-Site none or same-origin). And a
    state-changing request whose only credential is a cookie must carry
    same-origin browser metadata (server.Handler). These are headers a local
    process can forge: they stop tools and confused deputies that fetch a URL
    without choosing its headers, not a process that targets this API.

What remains, stated plainly: a process running as the daemon's own account
can read the token file and send it as a header, so in the default install
(daemon runs as the user) same-user malware can still trigger runs and fixes.
Under the service account, a process running as the owner cannot get the
per-start token from the daemon, but it can still read a paired client token
the owner saved (the desktop app's client.token, a browser profile's cookie
store), drive or inspect the owner's own browser (debugging port, injection),
or replay a stolen cookie with forged fetch metadata. Reads (GET) with a
cookie are not held to the same-origin rule. Only separate accounts (the
service account) and, eventually, per-action owner confirmation close these;
this is a gate, not a wall (docs/guides/SERVICE-ACCOUNT.md).

With no token issued (serve() not started) nothing is accepted: the gate fails
closed.
"""

import os
import secrets
import socket
import tempfile

TOKEN_PATH = os.path.expanduser("~/.jarvis/api.token")
HEADER = "X-JARVIS-Token"
COOKIE = "jarvis_token"
_TOKEN = None


def issue(path=TOKEN_PATH):
    """Write a new token (0600) and keep it in memory for this process.

    The file is created fresh with O_EXCL under a random name (tempfile.mkstemp:
    mode 0600, never through a link, never reusing a file someone left behind
    with a looser mode), flushed, then renamed over the old one. The token is
    therefore never readable by another account, not even for an instant.
    """
    global _TOKEN
    value = secrets.token_hex(32)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".api.token.", dir=directory)
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            data = value.encode()
            while data:
                data = data[os.write(fd, data):]
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
    _TOKEN = value
    return value


def current():
    """The token this process issued, or None (tests, or serve not started)."""
    return _TOKEN


def read(path=TOKEN_PATH):
    """A client's view: the token file, or "" when there is none."""
    try:
        with open(path, encoding="ascii", errors="ignore") as fh:
            return fh.read().strip()[:128]
    except OSError:
        return ""


CLIENT_COOKIE = "jarvis_client"
CLIENT_COOKIE_MAX_AGE = 30 * 86400


def _cookies(headers):
    out = {}
    for part in (headers.get("Cookie") or "").split(";")[:64]:
        name, _, val = part.strip().partition("=")
        if name and name not in out:
            out[name] = val.strip()
    return out


def candidates(headers):
    """Every credential a request carries, in order: the header, a Bearer
    Authorization, the dashboard cookie, the paired-browser cookie."""
    out = []
    value = (headers.get(HEADER) or "").strip()
    if value:
        out.append(value)
    auth = (headers.get("Authorization") or "").strip()
    if auth[:7].lower() == "bearer " and auth[7:].strip():
        out.append(auth[7:].strip())
    cookies = _cookies(headers)
    for name in (COOKIE, CLIENT_COOKIE):
        if cookies.get(name):
            out.append(cookies[name])
    return [v[:256] for v in out]


def header_credentials(headers):
    """The credentials a request carries in headers a browser page cannot set
    for another origin (X-JARVIS-Token, Authorization: Bearer), not cookies."""
    return candidates({HEADER: headers.get(HEADER), "Authorization": headers.get("Authorization")})


def presented(headers):
    """The first credential a request carries, or ""."""
    found = candidates(headers)
    return found[0] if found else ""


def accepts(headers):
    """True only when a token is in force and the request carries exactly it.

    Fails closed: with no token issued nothing is accepted. The comparison is
    constant time over bytes, so a non-ASCII header value is a plain mismatch
    rather than an exception.
    """
    if _TOKEN is None:
        return False
    want = _TOKEN.encode("ascii")
    ok = False
    for value in candidates(headers):
        ok |= secrets.compare_digest(value.encode("utf-8", "replace"), want)
    return ok


def cookie_header():
    """Set-Cookie value for the dashboard page, or None when not serving.

    HttpOnly: no page script reads it (the browser attaches it), so injected
    script cannot copy it out. SameSite=Strict: no cross-site request carries it.
    """
    if _TOKEN is None:
        return None
    return f"{COOKIE}={_TOKEN}; Path=/; HttpOnly; SameSite=Strict"


def client_cookie_header(client_token):
    """Set-Cookie value that keeps a paired browser's client token."""
    return (f"{CLIENT_COOKIE}={client_token}; Path=/; HttpOnly; SameSite=Strict; "
            f"Max-Age={CLIENT_COOKIE_MAX_AGE}")


# ---- who may receive the token with the dashboard page ------------------------

PROC_NET = ("/proc/net/tcp", "/proc/net/tcp6")
_PROC_ROWS_MAX = 65_536          # bounded scan of the socket tables


def _decode(hexaddr):
    """('127.0.0.1', 8787) from a /proc/net/tcp{,6} "ADDR:PORT" field, or None."""
    try:
        addr, port = hexaddr.split(":")
        raw = bytes.fromhex(addr)
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw[::-1]), int(port, 16)
        if len(raw) == 16:
            # Four 32-bit words, each in host (little-endian) order.
            raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            if raw[:12] == b"\0" * 10 + b"\xff\xff":      # v4-mapped
                return socket.inet_ntop(socket.AF_INET, raw[12:]), int(port, 16)
            return socket.inet_ntop(socket.AF_INET6, raw), int(port, 16)
    except (ValueError, OSError):
        pass
    return None


def peer_uid(client, server, tables=PROC_NET):
    """The uid owning the client end of a loopback TCP connection, or None.

    `client` and `server` are (host, port) as the server sees them. The client's
    socket is the row whose local address is `client` and whose remote address
    is `server`. None when no such row exists (Windows peers under WSL mirrored
    networking, non-Linux hosts) or the tables cannot be read.
    """
    want_local = (str(client[0]), int(client[1]))
    want_remote = (str(server[0]), int(server[1]))
    for table in tables:
        try:
            with open(table, encoding="ascii", errors="replace") as fh:
                next(fh, None)                      # header line
                for n, line in enumerate(fh):
                    if n >= _PROC_ROWS_MAX:
                        break
                    fields = line.split()
                    if len(fields) < 8:
                        continue
                    if (_decode(fields[1]) == want_local
                            and _decode(fields[2]) == want_remote):
                        try:
                            return int(fields[7])
                        except ValueError:
                            return None
        except OSError:
            continue
    return None


def may_receive(uid):
    """Whether a peer owned by `uid` may be handed the token with the page.

    Only accounts that can read the 0600 token file anyway: this account and
    root. Every other account, including a service-account install's owner, and
    a peer whose owner cannot be determined (None) pairs explicitly. Fails closed.
    """
    if uid is None:
        return False
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    return uid == 0 or uid == euid


# Fetch metadata of a browser's top-level load of one of our pages: typed,
# bookmarked or opened by the OS (none), or followed from our own pages.
NAV_SITES = ("none", "same-origin")


def is_browser_navigation(headers):
    """True when the request says it is a browser's own top-level (or framed)
    navigation. Forgeable by a local process; see the module docstring."""
    return ((headers.get("Sec-Fetch-Mode") or "").strip().lower() == "navigate"
            and (headers.get("Sec-Fetch-Site") or "").strip().lower() in NAV_SITES)

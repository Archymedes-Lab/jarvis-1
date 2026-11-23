"""Minimal sd_notify client — no dependency on python-systemd.

systemd hands a service a datagram socket in $NOTIFY_SOCKET when the unit sets
`NotifyAccess`. Writing `READY=1` once and `WATCHDOG=1` on an interval lets the
manager tell the difference between "running" and "wedged": a process that has
stopped pinging within `WatchdogSec` is killed and restarted, which is the one
failure the rest of this codebase cannot catch itself — a scheduler thread that
deadlocks keeps the process alive and every snapshot frozen.

All calls are best-effort. If there is no socket (run by hand, not under
systemd) every function is a silent no-op.
"""

import os
import socket

_SOCK = None
_ADDR = None


_CAPTURED = {}
_NOTIFY_VARS = ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID")


def capture():
    """Take the notify settings out of the environment, keeping them here.

    Children inherit the environment; with NOTIFY_SOCKET in it, any child that
    speaks the protocol pings systemd as if it were the service, which
    NotifyAccess=main rejects and logs ("reception only permitted for main
    PID", seen on JARVIS and Argus 2026-10-29). Call once at startup, before
    anything is launched."""
    for name in _NOTIFY_VARS:
        value = os.environ.pop(name, None)
        if value is not None:
            _CAPTURED[name] = value


def _env(name, default=None):
    return _CAPTURED.get(name, os.environ.get(name, default))


def _ensure():
    global _SOCK, _ADDR
    if _SOCK is not None:
        return _SOCK
    addr = _env("NOTIFY_SOCKET")
    if not addr:
        return None
    # Abstract namespace sockets start with '@' -> NUL byte.
    _ADDR = "\0" + addr[1:] if addr.startswith("@") else addr
    try:
        _SOCK = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    except OSError:
        _SOCK = None
    return _SOCK


def _send(msg: str) -> bool:
    sock = _ensure()
    if not sock:
        return False
    try:
        sock.sendto(msg.encode("utf-8"), _ADDR)
        return True
    except OSError:
        return False


def available() -> bool:
    return bool(_env("NOTIFY_SOCKET"))


def ready():
    _send("READY=1")


def watchdog():
    _send("WATCHDOG=1")


def status(text: str):
    _send("STATUS=" + text.replace("\n", " ")[:200])


def watchdog_usec() -> int:
    """WatchdogSec, in microseconds, as systemd exported it — 0 if disabled."""
    try:
        return int(_env("WATCHDOG_USEC", "0"))
    except ValueError:
        return 0

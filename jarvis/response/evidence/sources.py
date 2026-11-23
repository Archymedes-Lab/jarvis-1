"""Reaching files this shell cannot open directly.

Under WSL the Windows drive is mounted per-namespace. A /mnt/c established
with a restrictive uid/gid mapping refuses `winevt\\Logs` with EPERM, while
another running process may hold a mount of the same drive that reads it
fine, and a stale mount fails every path with EIO. Rather than making the
operator diagnose that, collection resolves a readable view of a path and
records which view it used.
"""

import errno
import os

from jarvis.platform import host

_PROC = "/proc"

# The namespace that last worked. Scanning /proc costs a stat per process, so
# the winning pid is reused until it exits or its mount goes stale.
_cached_pid = None


def to_wsl(path):
    """`C:\\Users\\x` as this process names it (`/mnt/c/Users/x` under WSL);
    POSIX paths pass through."""
    p = (path or "").replace("\\", "/")
    if len(p) > 1 and p[1] == ":" and p[0].isalpha():
        return host.local_path(path) or p
    return p


def _ok(path):
    """True when `path` can actually be opened for reading.

    os.access is not enough: a stale DrvFS mount reports the file as present
    and permitted, then fails the read with EIO.
    """
    try:
        if os.path.isdir(path):
            os.listdir(path)
            return True
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def _via(pid, path):
    return os.path.join(_PROC, str(pid), "root", path.lstrip("/"))


def _candidate_pids():
    """Processes whose mount namespace we are allowed to traverse.

    Only our own processes are readable without privilege, so a root-owned
    service is skipped rather than raising.
    """
    try:
        names = os.listdir(_PROC)
    except OSError:
        return                  # no /proc (native Windows): nothing to traverse
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == os.getpid():
            continue
        root = os.path.join(_PROC, name, "root")
        try:
            if os.access(root, os.X_OK):
                yield pid
        except OSError:
            continue


def resolve(path, search=True):
    """Return (readable_path, how) for `path`, or (None, reason).

    `how` is "direct" or "namespace:<pid>", and is recorded in the manifest so
    a later reader knows the copy did not come from this shell's own view.
    """
    global _cached_pid
    path = to_wsl(path)
    if _ok(path):
        return path, "direct"
    if not search:
        return None, "unreadable"

    if _cached_pid is not None:
        alt = _via(_cached_pid, path)
        if _ok(alt):
            return alt, "namespace:%d" % _cached_pid
        _cached_pid = None

    for pid in _candidate_pids():
        alt = _via(pid, path)
        if _ok(alt):
            _cached_pid = pid
            return alt, "namespace:%d" % pid
    return None, "unreadable in any reachable mount namespace"


def diagnose(path):
    """Why a path cannot be read, in the terms the operator has to act on."""
    path = to_wsl(path)
    try:
        os.stat(path)
    except OSError as exc:
        if exc.errno == errno.EIO:
            return ("EIO — the Windows drive mount is stale; restart WSL or "
                    "re-mount /mnt/c")
        if exc.errno == errno.ENOENT:
            return "not present"
        if exc.errno in (errno.EACCES, errno.EPERM):
            return "permission denied in this mount namespace"
        return "%s" % exc.strerror
    return "present" if _ok(path) else "present but unreadable"

"""Windows-drive mount health: one probe, one verdict, shared by every reader.

Under WSL the Windows drive (/mnt/c) can go stale — after sleep/hibernate, a
wedged 9P server, or sheer load — and every path on it then fails with EIO,
including files JARVIS never wrote (another program's own config reads fail
the same way; the mount is a fellow victim, not evidence of tampering).

Without a shared gate, each collector discovers this independently: the native
job throws out of an unguarded directory listing every 60s, the toolchain
walks dead profiles hourly, and the dashboard fills with confusing
"unreadable" noise instead of the one actionable diagnosis. So every
/mnt/c reader consults this module first: when the drive is stale they skip
the traversal and the coverage self-audit reports the single finding with the
fix, instead of N collectors hammering a sick mount with failing syscalls.

One stat per call, cached briefly so a run storm does not become a stat
storm. No writes, no subprocess, no network — safe to call from the daemon.
"""

import errno
import os
import time

from jarvis.platform import host

WINDOWS_DRIVE = host.windows_root()

# How long one verdict is reused. Long enough to calm a run storm, short
# enough that a remount is noticed within a minute.
CACHE_TTL = 60.0

HEALTHY = "healthy"
STALE = "stale"
MISSING = "missing"
RESTRICTED = "restricted"

_cache: dict = {}


def _probe(path):
    """One stat, mapped to a verdict. Never raises."""
    try:
        os.stat(path)
        return HEALTHY
    except OSError as exc:
        if exc.errno in (errno.EIO, errno.ENODEV, errno.ESTALE):
            return STALE
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            return MISSING
        if exc.errno in (errno.EACCES, errno.EPERM):
            return RESTRICTED
        # Unknown failure: treat as stale rather than healthy. A mount that
        # answers with an error we do not recognise is not one to hammer.
        return STALE
    except Exception:
        return STALE


def state(path=WINDOWS_DRIVE, now=None):
    """Verdict for `path`, cached briefly. Never raises."""
    stamp = time.time() if now is None else now
    try:
        hit = _cache.get(path)
        if hit is not None and stamp - hit[0] < CACHE_TTL:
            return hit[1]
    except Exception:
        pass
    verdict = _probe(path)
    try:
        _cache[path] = (stamp, verdict)
    except Exception:
        pass
    return verdict


def windows_drive(now=None):
    """Verdict for the Windows drive mount. Never raises."""
    return state(WINDOWS_DRIVE, now=now)


def reset():
    """Drop cached verdicts. Tests use this; production never needs it."""
    _cache.clear()


def under_windows_drive(path):
    """True when `path` is read through the Windows drive mount."""
    try:
        text = os.fspath(path)
    except TypeError:
        text = str(path)
    return text == WINDOWS_DRIVE or text.startswith(WINDOWS_DRIVE + os.sep)


def diagnose(path=WINDOWS_DRIVE):
    """Why a Windows-drive path cannot be read, in operator-actionable terms."""
    verdict = state(path)
    if verdict == HEALTHY:
        return "readable"
    if verdict == MISSING:
        return f"{path} is not mounted in this WSL session"
    if verdict == RESTRICTED:
        return (f"{path} is mounted but not accessible from this account; "
                "Windows-side elevation is a separate matter")
    return ("EIO — the Windows drive mount is stale. From Windows run "
            "`wsl --shutdown`, then reopen WSL; if it recurs after "
            "sleep/hibernate, that host transition is the trigger, not an "
            "intrusion. JARVIS backs off its Windows-drive reads until the "
            "mount answers again.")


def stale_detail(path=WINDOWS_DRIVE):
    """Finding detail shared by every collector that skips a stale drive.

    The caller has already established staleness (a gate verdict or an EIO
    errno), so this asserts rather than re-probes: re-probing here would let
    a mocked gate in tests — or a flapping mount in production — downgrade a
    known outage back to "readable".
    """
    return ("EIO — the Windows drive mount is stale. From Windows run "
            "`wsl --shutdown`, then reopen WSL; if it recurs after "
            "sleep/hibernate, that host transition is the trigger, not an "
            "intrusion. JARVIS backs off its Windows-drive reads until the "
            "mount answers again.")

"""Independent views of the process list, so one can be lied to and
disagree with the others."""

import errno
import os
import re

from jarvis.platform.linux import signal_zero

# Shared with the osquery cross-view (collectors may not import each other).
from jarvis.platform.procfs import SYS_getdents64, is_thread, view_getdents, view_readdir  # noqa: F401

from .common import DEFAULT_SWEEP, PROC, _read

_SCHED_ROW = re.compile(r"^\s*[RS>]?\s+(\S+)\s+(\d+)\s+\d")




def view_stat_sweep(limit=DEFAULT_SWEEP):
    """A pid whose directory entry is filtered from listings usually still
    resolves when you stat the path directly."""
    found = set()
    for pid in range(1, limit + 1):
        try:
            os.stat(f"{PROC}/{pid}")
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ESRCH, errno.EACCES, errno.EPERM):
                continue
            continue
        found.add(pid)
    return found


def view_kill_probe(limit=DEFAULT_SWEEP):
    """Ask the kernel whether a pid exists by trying to signal it.

    Every view above this one goes through procfs, so a rootkit that filters
    procfs defeats all of them at once. kill(pid, 0) delivers nothing but
    resolves the pid through the kernel's pid hash table instead, which is a
    different structure reached by a different path. ESRCH means no such
    process; success or EPERM both mean it is there.
    """
    found = set()
    for pid in range(1, limit + 1):
        try:
            signal_zero(pid)
        except ProcessLookupError:
            continue
        except PermissionError:
            found.add(pid)          # exists, owned by someone else
            continue
        except OSError:
            continue
        found.add(pid)
    return found


# Linux 5.13 moved /proc/sched_debug here; reading it needs root or
# CAP_DAC_READ_SEARCH (debugfs is 0700).
SCHED_DEBUGFS = "/sys/kernel/debug/sched/debug"
# The kernel's initial pid namespace (PROC_PID_INIT_INO).
INIT_PID_NS = "pid:[4026531836]"


def pid_namespace_nested():
    """True inside a child pid namespace (a container, or a WSL2 distro),
    where the scheduler's global pids cannot be matched to this /proc."""
    try:
        return os.readlink(f"{PROC}/self/ns/pid") != INIT_PID_NS
    except OSError:
        return False


def view_sched_debug():
    """Read pids out of /proc/sched_debug.

    The scheduler prints every task on every runqueue. It is generated from the
    runqueues rather than from the procfs directory tree, so a rootkit that
    hides a /proc/<pid> entry has to remember to scrub this too, and most do
    not. Returns None when the kernel was built without CONFIG_SCHED_DEBUG,
    which is a missing view rather than a clean one.
    """
    if pid_namespace_nested():
        return None     # the scheduler lists global pids; /proc here does not
    text = _read(f"{PROC}/sched_debug") or _read(SCHED_DEBUGFS)
    if not text.strip():
        return None
    pids = set()
    for line in text.splitlines():
        m = _SCHED_ROW.match(line)
        if m:
            try:
                pids.add(int(m.group(2)))
            except ValueError:
                continue
    return pids or None


def pid_max():
    try:
        with open(f"{PROC}/sys/kernel/pid_max", errors="replace") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return DEFAULT_SWEEP


def _describe(pid):
    """Whatever we can learn about a pid the listings did not want to show."""
    info = {"pid": pid, "name": "?", "exe": "", "cmdline": "", "ppid": 0,
            "uid": "?", "tgid": pid}
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Name:"):
                    info["name"] = line.split("\t", 1)[-1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                elif line.startswith("Uid:"):
                    info["uid"] = line.split()[1]
                elif line.startswith("Tgid:"):
                    info["tgid"] = int(line.split()[1])
    except OSError:
        pass
    try:
        info["exe"] = os.readlink(f"{PROC}/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"{PROC}/{pid}/cmdline", "rb") as fh:
            info["cmdline"] = " ".join(
                a.decode("utf-8", "replace") for a in fh.read().split(b"\x00") if a
            )
    except OSError:
        pass
    return info


def _alive(pid):
    try:
        os.stat(f"{PROC}/{pid}")
        return True
    except OSError:
        return False



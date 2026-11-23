"""Bounded evidence that a deleted Linux executable was reinstalled unchanged."""

import hashlib
import os
import stat

# The protected host's Sysmon binary is 31,693,824 bytes. Keep the ceiling
# just above that measured size while rejecting larger, unbounded comparisons.
MAX_COMPARE_BYTES = 32 << 20


def _start_time(pid, proc):
    with open(f"{proc}/{pid}/stat", encoding="utf-8", errors="replace") as fh:
        fields = fh.read().rsplit(") ", 1)[1].split()
    return fields[19]  # Linux /proc stat field 22, after pid and comm.


def _digest(fh):
    digest = hashlib.sha256()
    size = 0
    while block := fh.read(1 << 20):
        size += len(block)
        if size > MAX_COMPARE_BYTES:
            raise OSError("executable exceeds comparison budget")
        digest.update(block)
    return digest.digest()


def _same_file(before, after):
    return (before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns)


def replaced_identically(pid, mapped, proc="/proc"):
    """True only when one PID instance still maps bytes equal to its old path.

    Any unreadable, missing, changed, racing, or oversized file returns False.
    The caller retains the raw deleted-path evidence either way.
    """
    suffix = " (deleted)"
    if not isinstance(pid, int) or pid <= 0 or not mapped.endswith(suffix):
        return False
    original = mapped[:-len(suffix)]
    if not original.startswith("/"):
        return False
    exe_link = f"{proc}/{pid}/exe"
    try:
        started = _start_time(pid, proc)
        if os.readlink(exe_link) != mapped or os.path.islink(original):
            return False
        with open(exe_link, "rb") as running, open(original, "rb") as installed:
            run_stat, disk_stat = os.fstat(running.fileno()), os.fstat(installed.fileno())
            if (not stat.S_ISREG(run_stat.st_mode)
                    or not stat.S_ISREG(disk_stat.st_mode)
                    or run_stat.st_size > MAX_COMPARE_BYTES
                    or disk_stat.st_size > MAX_COMPARE_BYTES):
                return False
            same_bytes = _digest(running) == _digest(installed)
            if (not same_bytes
                    or not _same_file(run_stat, os.fstat(running.fileno()))
                    or not _same_file(disk_stat, os.fstat(installed.fileno()))):
                return False
        return (started == _start_time(pid, proc)
                and os.readlink(exe_link) == mapped
                and _same_file(disk_stat, os.stat(original)))
    except (OSError, ValueError, IndexError, TypeError):
        return False

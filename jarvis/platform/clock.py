"""Paired clock samples and journald's own record of wall-clock steps."""

import re
import subprocess
import time

MAX_WATCH_S = 120
JOURNAL_LINES = 2000


def sample():
    return (time.time(), time.clock_gettime(time.CLOCK_MONOTONIC))


def collect(seconds, *, interval=1.0, clock=sample, sleep=time.sleep):
    """Samples over a bounded window (whole seconds, at most MAX_WATCH_S)."""
    seconds = max(0, min(int(seconds), MAX_WATCH_S))
    out = [clock()]
    for _ in range(int(seconds / interval)):
        sleep(interval)
        out.append(clock())
    return out


def journal_backward_count(since_s=3600, runner=subprocess.run):
    """journald "Time jumped backwards" lines in the last `since_s` seconds.

    None means the journal could not be read; that is unknown, never zero.
    """
    try:
        r = runner(["journalctl", "--no-pager", "-o", "cat", "-g",
                    "Time jumped backwards", "--since", f"-{int(since_s)}s"],
                   capture_output=True, text=True, errors="replace", timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    # journalctl -g exits 1 when nothing matches; that is a real zero.
    if r.returncode not in (0, 1):
        return None
    lines = [ln for ln in r.stdout.splitlines()[:JOURNAL_LINES]
             if re.search(r"Time jumped backwards", ln)]
    return len(lines)

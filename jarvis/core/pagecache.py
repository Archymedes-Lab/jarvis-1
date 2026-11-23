"""Release one-shot reads from the page cache.

Verifying the event history reads every sealed segment once (1.25 GB packed
on 2026-10-25). Those pages are charged to the daemon's memory cgroup, so a
daily verify left about a gigabyte of cache that the kernel then had to reclaim
under MemoryHigh, throttling the daemon (6490 memory.high events in ten minutes,
measured). Dropping a sealed file's pages once it has been read keeps the
cache for what is read repeatedly (the database). Measured on real segments:
+44 MB cached without it, +0 MB with it, no slower.

Best effort: a platform without posix_fadvise, or a file it cannot advise
(network mounts), keeps its pages and nothing fails.
"""

import os


def drop(fileobj):
    """Advise the kernel that this file's cached pages will not be reused."""
    advise = getattr(os, "posix_fadvise", None)
    if advise is None:
        return False
    try:
        advise(fileobj.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        return True
    except (OSError, ValueError, AttributeError):
        return False

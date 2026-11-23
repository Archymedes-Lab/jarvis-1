"""Give freed heap back to the operating system, and keep it from scattering.

The daemon is one long-lived process with a thread per scheduler lane and per
API request. Each job and request opens its own short-lived SQLite connection,
fills a private page cache and frees it on close. glibc keeps such freed
page-sized blocks in per-thread arenas instead of returning them, so resident
memory ratchets up to the sum of past peaks (measured 2026-11-06 on this
host: 595 MB anonymous in the live daemon; a hunt run left 105 MB resident
that malloc_trim brought back to 38 MB).

Two calls fix that without changing what any job does:

  limit_arenas()  at startup, before threads exist: at most ARENA_MAX glibc
                  arenas, so freed memory is not stranded in one per thread.
  trim()          after a job or a request: malloc_trim(0) returns free pages
                  to the kernel. Rate-limited; a few milliseconds when called.

Both are no-ops off glibc (Windows edition, musl, macOS) and never raise:
memory housekeeping must not be able to stop a collector or an API answer.
"""

import ctypes
import sys
import threading
import time

M_ARENA_MAX = -8          # glibc <malloc.h>
ARENA_MAX = 2             # one for the main thread, one shared by the others
MIN_INTERVAL_S = 5.0      # at most one trim this often; the lanes finish jobs in bursts

_lock = threading.Lock()
_last = 0.0
_libc = None              # None: not looked up yet; False: not glibc


def _glibc():
    global _libc
    if _libc is None:
        _libc = False
        if sys.platform.startswith("linux"):
            try:
                libc = ctypes.CDLL("libc.so.6")
                if not hasattr(libc, "gnu_get_libc_version"):   # musl has no such symbol
                    return _libc
                libc.malloc_trim.argtypes = [ctypes.c_size_t]
                libc.malloc_trim.restype = ctypes.c_int
                libc.mallopt.argtypes = [ctypes.c_int, ctypes.c_int]
                libc.mallopt.restype = ctypes.c_int
                _libc = libc
            except (OSError, AttributeError):
                _libc = False
    return _libc


def limit_arenas(arenas=ARENA_MAX):
    """Cap glibc malloc arenas. Call before starting threads. True when applied."""
    libc = _glibc()
    if not libc:
        return False
    try:
        return bool(libc.mallopt(M_ARENA_MAX, int(arenas)))
    except (OSError, ValueError):
        return False


def trim(force=False, clock=time.monotonic):
    """Return free heap pages to the kernel. True when malloc_trim ran."""
    global _last
    libc = _glibc()
    if not libc:
        return False
    now = clock()
    with _lock:
        if not force and now - _last < MIN_INTERVAL_S:
            return False
        _last = now
    try:
        libc.malloc_trim(0)
    except OSError:
        return False
    return True

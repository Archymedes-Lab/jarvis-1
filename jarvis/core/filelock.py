"""One exclusive, non-blocking lock per open file, on every platform.

The event log and the mesh publisher each allow exactly one writer. That rule
was `flock`, which Windows does not have; there the same guarantee comes from a
byte-range lock on the file's first byte. Either way the lock belongs to the
open handle: closing it, or the process dying, releases it, and nothing has to
clean up after a crash.

Windows byte-range locks are mandatory rather than advisory, so the locked file
must be a dedicated lock file that nothing reads or writes.
"""

import os

try:
    import fcntl
except ImportError:          # native Windows
    fcntl = None
    import msvcrt


def acquire(handle):
    """Take the exclusive lock now or raise OSError when another holder has it."""
    fd = handle if isinstance(handle, int) else handle.fileno()
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

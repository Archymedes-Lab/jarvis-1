"""Bounded stable regular-file reads, anchored against ancestor-link traversal.

No interpretation, writes or logging. Callers decide whether missing evidence is
expected or a visibility gap. A replacement or interrupted read yields no data.
"""
import os
import stat

DEFAULT_LIMIT = 2 * 1024 * 1024


def identity(st):
    return [st.st_dev, st.st_ino, st.st_ctime_ns, st.st_mtime_ns, st.st_size]


def open_safe(path, directory=False):
    """Anchor every component to an opened, non-link directory descriptor."""
    parts = os.path.abspath(path).split(os.sep)
    fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(parts):
            if not part:
                continue
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise



def read_start(path, limit=DEFAULT_LIMIT, expected=None):
    """Read a stable regular file without traversing links; races return unknown."""
    try:
        fd = open_safe(path)
    except OSError:
        return None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (expected is not None and identity(before) != expected):
            return None
        chunks, left = [], limit
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        if identity(os.fstat(fd)) != identity(before):
            return None
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)

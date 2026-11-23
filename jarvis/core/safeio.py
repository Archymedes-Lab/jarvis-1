"""Bounded reads of files whose type or target someone else controls.

A collector that reads files in other users' folders (authorized_keys, a
scanned repository) must not trust a type it checked earlier or a size it was
told: between an lstat and an open, a local user can swap in a FIFO (open
blocks forever and the lane stalls), a symlink to /dev/zero (an uncapped read
fills memory) or a symlink to a root-only file. Here the type is judged on the
open descriptor itself, the open never waits for a writer, and the read stops
at the limit whatever the size claimed.
"""

import errno
import os
import stat


class NotRegular(OSError):
    """The path is not a regular file (FIFO, device, socket, directory, or a
    symlink when links are refused)."""


def read_regular(path, limit, follow=True):
    """Up to limit + 1 bytes of a regular file, so a caller can tell "exactly
    limit" from "more". Raises FileNotFoundError, NotRegular or OSError.

    follow=False refuses a symlink at the last path component (ELOOP), for
    walks that already decided not to follow links."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if not follow and exc.errno == errno.ELOOP:
            raise NotRegular(exc.errno, "a symbolic link", path) from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise NotRegular(0, "not a regular file", path)
        chunks, left = [], limit + 1
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_text(path, limit, follow=True, errors="replace"):
    """read_regular decoded as UTF-8 with universal newlines, like open(path)
    in text mode. None when the file holds more than `limit` bytes."""
    data = read_regular(path, limit, follow=follow)
    if len(data) > limit:
        return None
    return data.decode("utf-8", errors).replace("\r\n", "\n").replace("\r", "\n")

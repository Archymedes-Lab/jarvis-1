"""Listing /proc two ways, and telling threads from processes.

Shared by the hidden-process collector and the osquery cross-view: an
LD_PRELOAD hook on readdir filters view_readdir() but not view_getdents(),
which asks the kernel directly.
"""

import ctypes
import ctypes.util
import os
import struct

PROC = "/proc"
SYS_getdents64 = {"x86_64": 217, "aarch64": 61, "armv7l": 217, "i686": 220}
# (openat, read, close) per ABI, for reads an LD_PRELOAD open/fopen hook cannot filter.
SYS_FILE = {"x86_64": (257, 0, 3), "aarch64": (56, 63, 57)}
AT_FDCWD = -100
RAW_MAX = 16 * 1024 * 1024


def view_readdir():
    try:
        return {int(e) for e in os.listdir(PROC) if e.isdigit()}
    except OSError:
        return set()


def view_getdents():
    """List /proc through the syscall directly, so an LD_PRELOAD hook on
    readdir cannot filter the result."""
    nr = SYS_getdents64.get(os.uname().machine)
    if nr is None:
        return None  # unknown ABI; caller treats None as "view unavailable"
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except OSError:
        return None

    fd = os.open(PROC, os.O_RDONLY | os.O_DIRECTORY)
    pids = set()
    buf = ctypes.create_string_buffer(65536)
    try:
        while True:
            n = libc.syscall(nr, ctypes.c_int(fd), buf, ctypes.c_uint(len(buf)))
            if n <= 0:
                break
            off = 0
            raw = buf.raw
            while off < n:
                # struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen;
                #                         u8 d_type; char d_name[]; }
                reclen = struct.unpack_from("H", raw, off + 16)[0]
                if reclen == 0:
                    break
                name = raw[off + 19 : off + reclen].split(b"\x00", 1)[0]
                if name.isdigit():
                    pids.add(int(name))
                off += reclen
    except OSError:
        return None
    finally:
        os.close(fd)
    return pids


def is_thread(pid):
    """/proc/<tid> stats successfully for every thread, but readdir only lists
    thread-group leaders. A thread showing up in the stat sweep and not in the
    listing is how Linux is supposed to work, not something hiding."""
    try:
        with open(f"{PROC}/{pid}/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("Tgid:"):
                    return int(line.split()[1]) != pid
    except OSError:
        pass
    return False


def read_raw(path, limit=RAW_MAX):
    """File bytes read through the kernel directly (openat/read/close syscalls),
    so a preloaded open()/fopen() hook cannot rewrite them; None when the ABI is
    unknown or the read fails. Measured 2026-11-02: a port hidden from Python's
    open() by an /etc/ld.so.preload library stays visible here."""
    nrs = SYS_FILE.get(os.uname().machine)
    if nrs is None:
        return None
    sys_openat, sys_read, sys_close = nrs
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except OSError:
        return None
    libc.syscall.restype = ctypes.c_long
    fd = libc.syscall(sys_openat, ctypes.c_int(AT_FDCWD), ctypes.c_char_p(os.fsencode(path)),
                      ctypes.c_int(os.O_RDONLY | os.O_CLOEXEC))
    if fd < 0:
        return None
    chunks, total = [], 0
    buf = ctypes.create_string_buffer(65536)
    try:
        while total < limit:
            n = libc.syscall(sys_read, ctypes.c_int(fd), buf, ctypes.c_size_t(len(buf)))
            if n < 0:
                return None
            if n == 0:
                break
            chunks.append(buf.raw[:n])
            total += n
    finally:
        libc.syscall(sys_close, ctypes.c_int(fd))
    return b"".join(chunks)

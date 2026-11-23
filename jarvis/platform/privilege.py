"""Least-privilege Linux visibility: the capabilities JARVIS reads with.

The daemon runs as the user. Seeing other accounts' processes needs more than
that, but not root: the systemd drop-in systemd/capabilities.conf grants only

  CAP_SYS_PTRACE       /proc/<pid>/{fd,maps,environ,exe} of other accounts
  CAP_DAC_READ_SEARCH  root-only files such as /sys/kernel/tracing
  CAP_SYSLOG           kernel addresses in /proc/kallsyms and /proc/modules

Listing eBPF objects needs CAP_SYS_ADMIN and reading netfilter rules needs
CAP_NET_ADMIN. Both are close to full root, so they are deliberately not
requested, and coverage reports that as a stated limit.

The grant is only safe for a root-owned install run with `python3 -I`: on a
checkout the service user can write, that user could edit the code, let the
daemon restart and inherit the capabilities (CAP_SYS_PTRACE into a root
process is root). The backdoor audit reports exactly that configuration.

systemd delivers the grant as ambient capabilities, which every exec'd child
would inherit. `drop_ambient()` clears them once, before any thread starts,
so the daemon's own threads keep reading while nothing it launches (model
tooling, tests, PowerShell, sudo) gains a capability from it.
"""

import ctypes
import os

CAPS = {"CAP_DAC_READ_SEARCH": 2, "CAP_SYS_PTRACE": 19, "CAP_SYSLOG": 34}
NOT_REQUESTED = ("CAP_SYS_ADMIN (eBPF enumeration)", "CAP_NET_ADMIN (netfilter rules)")

PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4


def effective(status_path="/proc/thread-self/status"):
    """This thread's effective capability mask, or 0 when unreadable."""
    try:
        with open(status_path, errors="replace") as fh:
            for line in fh:
                if line.startswith("CapEff:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def missing(mask=None):
    """Names of the visibility capabilities this thread does not hold."""
    if not hasattr(os, "geteuid"):
        return list(CAPS)       # native Windows: Linux capabilities do not exist
    if os.geteuid() == 0:
        return []
    mask = effective() if mask is None else mask
    return [name for name, bit in CAPS.items() if not mask >> bit & 1]


def can_read_other_processes(mask=None):
    return "CAP_SYS_PTRACE" not in missing(mask)


def drop_ambient():
    """Stop exec'd children inheriting the grant. True when the ambient set
    is empty afterwards (including when there was nothing to clear)."""
    if os.name == "nt":
        return True             # no capability sets on Windows: nothing to inherit
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    try:
        with open("/proc/thread-self/status", errors="replace") as fh:
            for line in fh:
                if line.startswith("CapAmb:"):
                    return int(line.split()[1], 16) == 0
    except (OSError, ValueError, IndexError):
        pass
    return False


def code_tree_problems(root, limit=5):
    """Why `root` cannot safely run with privilege: a file, directory or
    ancestor that is not owned by root or that group/other can write, or any
    symlink inside it. Empty when the tree is sealed."""
    problems = []
    path = os.path.abspath(root)
    while True:
        try:
            st = os.stat(path)
        except OSError as exc:
            return [f"{path}: {exc.strerror}"]
        if st.st_uid != 0 or st.st_mode & 0o022:
            problems.append(f"{path} is writable by a non-root account")
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError as exc:
                problems.append(f"{full}: {exc.strerror}")
                continue
            if os.path.islink(full):
                problems.append(f"{full} is a symlink")
            elif st.st_uid != 0 or st.st_mode & 0o022:
                problems.append(f"{full} is writable by a non-root account")
            if len(problems) >= limit:
                return problems
    return problems


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def drop_all():
    """Give up every capability of this thread for good (empty permitted
    set). Always allowed; True when the effective set reads empty after."""
    drop_ambient()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        header = _CapHeader(0x20080522, 0)          # _LINUX_CAPABILITY_VERSION_3
        data = (_CapData * 2)()
        libc.capset(ctypes.byref(header), data)
    except (OSError, AttributeError):
        pass
    return effective() == 0

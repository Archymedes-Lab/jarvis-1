"""Entry point of a root-owned JARVIS release (scripts/deploy_root_runtime.py).

systemd runs it as `/usr/bin/python3 -I /opt/jarvis/current/jarvis-release.py`
with a few visibility capabilities. -I keeps the working directory, PYTHON*
variables and user site-packages out of the import path, so the only code
that runs is this release. Before importing anything from the release, the
launcher checks that the whole tree is root-owned and unwritable by anyone
else. If it is not, every capability is dropped first and JARVIS runs
unprivileged, which coverage reports.

The check is deliberately written out here with the standard library alone:
importing JARVIS code to verify JARVIS code would trust what it is checking.
"""

import ctypes
import os
import sys

ROOT = os.path.dirname(os.path.realpath(__file__))


def sealed_problems(root):
    problems = []
    path = root
    while True:
        st = os.stat(path)
        if st.st_uid != 0 or st.st_mode & 0o022:
            problems.append(f"{path} is writable by a non-root account")
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            if os.path.islink(full):
                problems.append(f"{full} is a symlink")
            elif st.st_uid != 0 or st.st_mode & 0o022:
                problems.append(f"{full} is writable by a non-root account")
            if len(problems) >= 5:
                return problems
    return problems


def drop_capabilities():
    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(47, 4, 0, 0, 0)                    # PR_CAP_AMBIENT_CLEAR_ALL
    libc.capset(ctypes.byref(Header(0x20080522, 0)), (Data * 2)())


def main():
    problems = [] if sys.flags.isolated else ["not started with python3 -I"]
    try:
        problems += sealed_problems(ROOT)
    except OSError as exc:
        problems.append(f"release unreadable: {exc}")
    if problems:
        drop_capabilities()
        print("JARVIS release is not sealed; running without capabilities: "
              + "; ".join(problems), file=sys.stderr, flush=True)
    sys.path.insert(0, ROOT)
    from jarvis.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())

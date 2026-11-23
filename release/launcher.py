"""Entry point of the native Argus binary (compiled by release/build_server.py).

The binary replaces `python3 -I argus-release.py` and `python3 -m argus`. It
keeps the launcher's seal check: before any Argus module is imported, the
folder the binary runs from must be root-owned and unwritable by anyone else,
or every capability is dropped first and Argus runs unprivileged (coverage
reports it). The check uses the standard library alone: importing Argus code
to verify Argus code would trust what it is checking.

A native binary cannot run `-m module`. The daemon starts two helpers that
way, and the installer runs the shipped verification (`-m argus.verify`), so
`argus -m <module> ...` dispatches to those three by name and refuses any
other module: the binary never runs arbitrary code by name.
"""

import ctypes
import os
import sys

# The modules run as `-m`: three child processes of the daemon
# (service/scheduler.py _isolated_job, collectors/host/fridaydefender.py, and
# core/rulepack.py's regex timing child) and the installer's self-verification
# (property and model checks).
CHILD_MODULES = ("jarvis.service.collector_worker", "jarvis.collectors.host.fridaydefender",
                 "jarvis.verify", "jarvis.core.rulepack")


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


def run_child(module, args):
    sys.argv = [sys.executable, *args]
    if module == "jarvis.service.collector_worker":
        from jarvis.service import collector_worker
        return collector_worker.main(args)
    if module == "jarvis.verify":
        from jarvis.verify.report import main as verify_main
        return verify_main(args)
    if module == "jarvis.core.rulepack":
        from jarvis.core import rulepack
        return rulepack._main(args)
    from jarvis.collectors.host import fridaydefender
    if len(args) == 4 and args[0] == "review":
        try:
            fridaydefender.review(args[1], args[2], args[3])
        finally:
            try:
                os.remove(fridaydefender.LOCK)
            except OSError:
                pass
        return 0
    return 2


def never_die_on_output():
    """Console output must not be able to stop the program.

    On Windows a redirected stdout (the logon task, the desktop app starting
    the daemon) uses the ANSI code page, and the daemon's startup banner holds
    an arrow: the compiled program exited with UnicodeEncodeError before it
    served anything. Unencodable text is replaced instead. Standard library
    only, like the rest of this file, and the same guard as jarvis/__main__.py,
    which the compiled program does not run.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


def main():
    never_die_on_output()
    root = os.path.dirname(os.path.realpath(sys.executable))
    if sys.platform.startswith("linux"):
        try:
            problems = sealed_problems(root)
        except OSError as exc:
            problems = [f"release unreadable: {exc}"]
        if problems:
            drop_capabilities()
            if not os.environ.get("JARVIS_QUIET_SEAL"):
                print("JARVIS release is not sealed; running without capabilities: "
                      + "; ".join(problems), file=sys.stderr, flush=True)
    args = sys.argv[1:]
    if args[:1] == ["-m"]:
        if len(args) < 2 or args[1] not in CHILD_MODULES:
            print(f"jarvis: -m runs only {', '.join(CHILD_MODULES)}", file=sys.stderr)
            return 2
        return run_child(args[1], args[2:])
    from jarvis.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())

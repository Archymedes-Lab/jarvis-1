"""Every module ARGUS-INSTINCT ships must import on Windows Python.

2026-10-27, measured with a real download: the Windows package failed its own
install check because collectors/host/storage.py used `os.statvfs` as a default
argument. Defaults run at import, Windows Python has no statvfs, and the whole
daemon (scheduler, jobs, web server, verify) could not load. The Linux suite
never noticed. This imports the package in a child interpreter made to look like
Windows: the POSIX-only os functions removed and the POSIX-only modules made
unimportable. A real Windows import (the bundled Python) is run by the Argus
build as well; this keeps the check in every unit-suite run.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Scripts that only ever run inside a Linux guest or on Linux by design.
LINUX_ONLY = ("jarvis.lab.guest.",)

CHILD = r"""
import importlib, json, os, pkgutil, sys, traceback
# The standard library first, as it is on Windows: its own internals are not
# what this checks, and on Linux they need the POSIX names removed below.
for name in ("subprocess", "shutil", "pathlib", "tempfile", "socket", "ssl", "sqlite3",
             "http.server", "urllib.request", "logging", "asyncio", "multiprocessing",
             "getpass", "platform", "signal", "selectors", "threading", "zipfile", "gzip",
             "email", "uuid", "ctypes", "concurrent.futures"):
    importlib.import_module(name)
# Then the APIs Windows Python does not have. Anything ARGUS-INSTINCT itself touches
# at import time (a default argument, a module-level call or import) now fails.
for name in ("statvfs", "fstatvfs", "getuid", "geteuid", "getgid", "getegid", "getpgid",
             "getloadavg", "sched_getaffinity", "killpg", "setpgid", "getpgrp"):
    if hasattr(os, name):
        delattr(os, name)
for name in ("resource", "fcntl", "pwd", "grp", "termios", "pty"):
    sys.modules[name] = None          # `import fcntl` now raises ImportError
# Windows-only standard modules exist there; stand-ins with the same names.
import types
msvcrt = types.ModuleType("msvcrt")
msvcrt.LK_NBLCK, msvcrt.LK_UNLCK, msvcrt.LK_LOCK = 2, 0, 1
msvcrt.locking = lambda fd, mode, nbytes: None
sys.modules["msvcrt"] = msvcrt
winreg = types.ModuleType("winreg")
sys.modules.setdefault("winreg", winreg)
import jarvis
skip = tuple(json.loads(sys.argv[1]))
bad = []
for m in pkgutil.walk_packages(jarvis.__path__, "jarvis."):
    if m.name.startswith(skip) or m.name.endswith("__main__"):
        continue
    try:
        importlib.import_module(m.name)
    except BaseException as exc:
        tb = traceback.extract_tb(exc.__traceback__)[-1]
        bad.append(f"{m.name}: {type(exc).__name__}: {exc} ({tb.filename}:{tb.lineno})")
print(json.dumps(bad))
"""


class WindowsImportTests(unittest.TestCase):
    def test_every_shipped_module_imports_without_posix_only_apis(self):
        out = subprocess.run([sys.executable, "-c", CHILD, json.dumps(LINUX_ONLY)],
                             cwd=ROOT, capture_output=True, text=True, timeout=600)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        bad = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual(bad, [], "\n".join(bad))


if __name__ == "__main__":
    unittest.main()

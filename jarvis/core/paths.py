"""Every on-disk location jarvis ships or reads relative to its own code.

Paths built from a module's `__file__` hard-code how deep that module sits, and
break silently when it moves: splitting inputwatch into a package once pointed
the input hook at a directory that did not exist, and nothing noticed but the
supervisor. Resolving them here, from one fixed anchor, means a module can move
without its data files moving out from under it.
"""

import os
import sys
from pathlib import Path

# abspath, not resolve(): the Windows task check compares against the path the
# repo was installed from, symlinks included.
PACKAGE_DIR = Path(os.path.abspath(__file__)).parent.parent   # jarvis/core/ -> jarvis/
REPO_ROOT = PACKAGE_DIR.parent

# A root-owned release (scripts/deploy_root_runtime.py) carries RELEASE.json
# naming the editable checkout it belongs to. Code runs from the release;
# anything that must act on that checkout (fix drafting, Windows tasks and the
# selfcheck unit installed from it) uses SOURCE_ROOT.
#
# "checkout" is preferred over "source": a narrow release is built from a
# temporary clone, and treating that clone as the checkout made JARVIS's own
# watchdog tasks (installed with -RepoRoot <checkout>) fail verification and
# read as critical persistence (2026-09-24, /tmp/jarvis-netwatch-narrow-*).
RELEASE_MANIFEST = REPO_ROOT / "RELEASE.json"


def _source_root():
    try:
        import json
        with open(RELEASE_MANIFEST, encoding="utf-8", errors="replace") as fh:
            manifest = json.load(fh)
        for key in ("checkout", "source"):
            value = manifest.get(key)
            if isinstance(value, str) and os.path.isabs(value):
                return Path(value)
    except (OSError, ValueError, AttributeError):
        pass
    return REPO_ROOT


SOURCE_ROOT = _source_root()

# PowerShell payloads run through the Windows bridge.
WIN_SCRIPTS_DIR = PACKAGE_DIR / "platform" / "win"
# The dashboard page and its assets.
STATIC_DIR = PACKAGE_DIR / "web" / "static"
# The owner's settings file. response/alert.py reads it for delivery; lower
# layers that need one setting read it here instead of importing upward.
CONFIG_PATH = os.path.expanduser("~/.jarvis/config.json")


# The compiled Windows edition ships no .ps1 file: release/build_windows.py
# generates jarvis/core/_payloads.py (SCRIPTS: {name: bytes}, DIGEST: sha256 of
# the whole set) and Nuitka compiles it into the program. The compiled copy
# always wins over a file of the same name, so a script planted beside the
# program cannot replace a payload. Payloads that something runs as a file
# (scheduled tasks, the broker, the input hook) are written, byte for byte, into
# a per-user folder named by DIGEST, so two releases never mix their scripts.
PAYLOAD_MODULE = "jarvis.core._payloads"


def _embedded():
    """(SCRIPTS, DIGEST) of a compiled edition, or (None, None) in a source tree."""
    try:
        import importlib
        mod = importlib.import_module(PAYLOAD_MODULE)
    except ImportError:
        return None, None
    return mod.SCRIPTS, mod.DIGEST


def payload_root(digest, env=None):
    """Per-user folder the compiled payloads of one release are written to."""
    env = os.environ if env is None else env
    base = env.get("LOCALAPPDATA") if os.name == "nt" else None
    if not base:
        base = os.path.join(os.path.expanduser("~"), ".jarvis")
    return Path(base) / "Jarvis" / "Payload" / digest[:16]


def materialize(name, data, root):
    """Write `data` to root/name unless it already holds exactly those bytes; the
    write goes through a temporary file and a rename, so a reader never sees half
    a script. Returns the path."""
    path = Path(root) / name
    try:
        with open(path, "rb") as fh:
            if fh.read() == data:
                return path
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    return path


def _compiled():
    """True inside a Nuitka-compiled edition (Nuitka defines __compiled__ in every module)."""
    return "__compiled__" in globals()


def self_executable(compiled=None, argv0=None, executable=None, listdir=os.listdir, module_path=None):
    """The program file to start when Argus runs a copy of itself (`-m module`).

    `sys.executable` is wrong in a compiled Windows build: Nuitka's standalone
    mode reports a python.exe in the install folder that does not exist, so
    every collector worker failed with FileNotFoundError (found 2026-11-03 on
    the compiled program and on the clean-machine CI run 41646681752). In
    order: an existing sys.executable; on Windows the running program's own
    path from GetModuleFileNameW; argv[0]; the one other program in its folder.
    """
    compiled = _compiled() if compiled is None else compiled
    executable = sys.executable if executable is None else executable
    if not compiled or (executable and os.path.exists(executable)):
        return executable
    found = (module_path or _module_path)()
    if found and os.path.exists(found):
        return found
    argv0 = (sys.argv[0] if sys.argv else "") if argv0 is None else argv0
    candidates = [os.path.abspath(argv0)] if argv0 else []
    candidates += [c + ".exe" for c in candidates if not c.lower().endswith(".exe")]
    for c in candidates:
        if os.path.isfile(c):
            return c
    folder = os.path.dirname(os.path.abspath(executable))
    try:
        others = [n for n in listdir(folder) if n.lower().endswith(".exe") and n.lower() != "python.exe"]
    except OSError:
        others = []
    if len(others) == 1:
        return os.path.join(folder, others[0])
    return executable


def _module_path():
    """The running program's path as Windows knows it, or None elsewhere."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(32768)
        if ctypes.windll.kernel32.GetModuleFileNameW(None, buf, len(buf)):
            return buf.value
    except (AttributeError, OSError):
        pass
    return None


# The name the native service commands use.
program = self_executable


def win_script(name):
    """Path of a bundled PowerShell payload (written out first in a compiled edition)."""
    scripts, digest = _embedded()
    if scripts is not None and name in scripts:
        root = payload_root(digest)
        try:
            return materialize(name, scripts[name], root)
        except OSError:
            # Called at import time by some collectors: an unwritable profile
            # must not stop the daemon. Whatever runs this path then fails and
            # reports itself unavailable.
            return root / name
    return WIN_SCRIPTS_DIR / name


def shipped_script(rel, code_root):
    """Path of a script the release ships at `rel` (relative to `code_root`): the
    compiled copy, written out, when this edition carries one by that name, else
    the file in the tree. The control audit fingerprints what this returns."""
    scripts, _ = _embedded()
    name = os.path.basename(str(rel))
    if scripts is not None and name in scripts:
        return win_script(name)
    return Path(code_root) / rel


def load_win_script(name):
    """Text of a bundled PowerShell payload, byte for byte.

    newline="" disables newline translation, so the script reaches PowerShell
    (and any str.replace templating) exactly as it is stored. Payloads load at
    import time, so a damaged byte is replaced rather than raised: one broken
    script then shows up as that collector's "unavailable" finding instead of
    stopping the daemon and every other collector with it.
    """
    scripts, _ = _embedded()
    if scripts is not None:
        if name in scripts:
            return scripts[name].decode("utf-8", errors="replace")
        return f'throw "{name} is not part of this edition"\n'
    try:
        with open(WIN_SCRIPTS_DIR / name, encoding="utf-8", errors="replace", newline="") as fh:
            return fh.read()
    except FileNotFoundError:
        # The Linux server edition ships no Windows payloads. A payload that
        # throws keeps the absence explicit: a collector that ever ran it would
        # report itself unavailable, never an empty clean result.
        return f'throw "{name} is not part of this edition"\n'


def repo_file(name):
    """Path of an operator script shipped at the repository level."""
    return REPO_ROOT / name

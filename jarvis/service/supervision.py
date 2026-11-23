"""Starting the daemon safely when something else is also trying to: the Task Scheduler
watchdog, the desktop app, and a person at a terminal.

`serve --supervised` is what the logon task and the desktop app run. Before the
daemon does any work it passes this gate, in this order:

1. **One instance.** A machine-wide lock named for the port. A second start that
   finds it held exits 0, silently and without counting as a start, so the
   watchdog firing every few minutes while the daemon runs costs nothing and can
   never create a second daemon.
2. **Stopped on purpose.** `argus stop` leaves a marker. While it is there a
   supervised start exits 0 and does nothing: someone chose to stop monitoring,
   and neither the watchdog nor the app may undo that. `argus start` clears it.
3. **No restart loop.** At most LIMIT supervised starts in WINDOW seconds. A
   daemon that dies the moment it starts is tried a few times, then left alone
   and the reason is written where the desktop app shows it, instead of a
   machine that restarts it forever.

A start from a terminal without `--supervised` skips the gate: a person who
types `argus serve` gets what they asked for.

Everything here is standard library; state is three small files in the state
folder (the daemon's own, not the program's folder).
"""

import json
import os
import sys
import time

STATE_DIR = os.path.expanduser("~/.jarvis")
STOP_MARKER = "stopped-on-purpose"
STARTS_FILE = "supervised-starts.json"
REFUSED_NOTE = "start-refused.txt"

LIMIT = 5                 # supervised starts allowed ...
WINDOW = 3600             # ... in this many seconds
EXIT_REFUSED = 75         # EX_TEMPFAIL: not started, by design, try again later

_HELD = []                # keeps the lock handle alive for the life of the process


def limit():
    try:
        return max(1, int(os.environ.get("JARVIS_RESTART_LIMIT", LIMIT)))
    except ValueError:
        return LIMIT


def _path(name, state_dir=None):
    return os.path.join(state_dir or STATE_DIR, name)


# ---- 1. one instance ---------------------------------------------------------

def take_instance_lock(port):
    """True when this process now owns the daemon lock for `port`; False when
    another process already does. Windows: a named mutex, visible to every
    session of the machine. Elsewhere there is no lock (systemd supervises)."""
    if not sys.platform.startswith("win"):
        return True
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    name = "Global" + chr(92) + f"ArgusDaemon-{int(port)}"
    handle = kernel32.CreateMutexW(None, False, name)
    err = ctypes.get_last_error()
    if not handle:
        return False          # e.g. access denied: another account's daemon holds it
    if err == 183:            # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return False
    _HELD.append(handle)
    return True


# ---- 2. stopped on purpose ---------------------------------------------------

def stopped_on_purpose(state_dir=None):
    return os.path.exists(_path(STOP_MARKER, state_dir))


def mark_stopped(state_dir=None, now=None):
    os.makedirs(state_dir or STATE_DIR, exist_ok=True)
    with open(_path(STOP_MARKER, state_dir), "w", encoding="utf-8") as fh:
        fh.write(f"stopped on purpose at {int(now if now is not None else time.time())}\n")


def clear_stopped(state_dir=None):
    try:
        os.remove(_path(STOP_MARKER, state_dir))
        return True
    except FileNotFoundError:
        return False


# ---- 3. no restart loop ------------------------------------------------------

def _read_starts(state_dir):
    try:
        with open(_path(STARTS_FILE, state_dir), encoding="utf-8", errors="replace") as fh:
            value = json.load(fh)
        return [float(t) for t in value] if isinstance(value, list) else []
    except (OSError, ValueError, TypeError):
        return []


def _write_atomic(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def record_start(state_dir=None, now=None, max_starts=None, window=WINDOW):
    """(allowed, starts_in_window). Records the start only when it is allowed."""
    now = time.time() if now is None else now
    max_starts = limit() if max_starts is None else max_starts
    recent = [t for t in _read_starts(state_dir) if 0 <= now - t < window]
    if len(recent) >= max_starts:
        return False, len(recent)
    recent.append(now)
    _write_atomic(_path(STARTS_FILE, state_dir), json.dumps(recent))
    return True, len(recent)


def refusal_text(starts, window=WINDOW, max_starts=None):
    max_starts = limit() if max_starts is None else max_starts
    return (f"Argus was started {starts} times in the last {window // 60} minutes and did not stay up, "
            f"so it will not be started again automatically (limit {max_starts} per hour) until that "
            "hour has passed. Start it by hand with `argus serve` or `argus start` to see why it stops.")


def read_refusal(state_dir=None, now=None, max_age=900):
    """The latest refusal reason if it is recent, else ''. The desktop app shows it."""
    path = _path(REFUSED_NOTE, state_dir)
    try:
        if (time.time() if now is None else now) - os.path.getmtime(path) > max_age:
            return ""
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(600).strip()
    except OSError:
        return ""


# ---- the gate ----------------------------------------------------------------

def gate(port, state_dir=None, now=None, lock=take_instance_lock, out=None):
    """None to go on and start the daemon, or the exit code to stop with."""
    out = out or sys.stderr
    if not lock(port):
        print(f"Argus is already running on port {port}.", file=out)
        return 0
    if stopped_on_purpose(state_dir):
        print("Argus was stopped on purpose (`argus stop`); not starting. Use `argus start`.", file=out)
        return 0
    allowed, starts = record_start(state_dir, now)
    if not allowed:
        text = refusal_text(starts)
        _write_atomic(_path(REFUSED_NOTE, state_dir), text + "\n")
        print(text, file=out)
        return EXIT_REFUSED
    try:
        os.remove(_path(REFUSED_NOTE, state_dir))
    except OSError:
        pass
    return None

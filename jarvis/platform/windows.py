"""Collect Windows processes and TCP connections through PowerShell.

From the WSL guest powershell.exe is reached through interop; on native Windows
it is started directly (platform/host.py says which). Everything happens in one
powershell.exe invocation because starting it costs ~1s either way; doing it
per-process would make scanning unusable. The payload comes back base64-encoded
so console codepage quirks can't corrupt it.
"""

import base64
import collections
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import threading
import time

from jarvis.core import collection
from jarvis.core.paths import load_win_script
from jarvis.core.util import fingerprint
from jarvis.platform import host, interop_gate

HOST = "win"

PS_SCRIPT = load_win_script("process_snapshot.ps1")

# Hosts that run someone else's code; the argument is the real identity.
SCRIPT_HOSTS = re.compile(
    r"^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|python[\d.]*|node|"
    r"ruby|perl|php|java|javaw|wsl|bash)\.exe$",
    re.I,
)
SCRIPT_EXT = re.compile(r"\.(ps1|psm1|bat|cmd|vbs|js|jse|wsf|py|rb|pl|php|jar|hta)\b", re.I)

_PS = None


def ensure_interop() -> bool:
    """Make sure WSL_INTEROP points at a live socket.

    Launching a Windows binary from WSL goes through a per-session Unix socket
    named in $WSL_INTEROP. A systemd *user service* inherits no such variable —
    and a value inherited from a login shell goes stale the moment that session
    ends. Either way the daemon silently loses every Windows collector while
    looking perfectly healthy, so we resolve a working socket ourselves instead
    of trusting the environment.
    """
    if host.native_windows():
        return True     # no interop boundary: powershell.exe is a local program
    if not host.on_wsl():
        return False
    current = os.environ.get("WSL_INTEROP")
    if current and os.path.exists(current):
        return True

    try:
        candidates = [
            os.path.join("/run/WSL", n)
            for n in os.listdir("/run/WSL")
            if n.endswith("_interop")
        ]
    except OSError:
        return False

    # Newest socket first: it belongs to the most recent session, which is the
    # one most likely to still be attached to a running Windows side.
    for path in sorted(candidates, key=lambda p: os.stat(p).st_mtime, reverse=True):
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                os.environ["WSL_INTEROP"] = path
                return True
        except OSError:
            continue
    return False


# How the kernel starts a Windows executable from WSL: a binfmt_misc entry
# that names /init as the interpreter. The table is shared by everything on
# the VM, and a privileged container running its own systemd flushes it on
# boot or shutdown (two such containers on 2026-10-22 17:24 took every
# PowerShell collector down while the daemon reported the bridge up). The
# registration cannot be restored without root, but the interpreter can be
# named explicitly: /init <exe> ... starts the program exactly as the entry
# would. The launcher is consulted on every spawn, so a flush between two
# collections costs one failed attempt, not an outage.
BINFMT_DIR = "/proc/sys/fs/binfmt_misc"
INTEROP_INIT = "/init"


def interop_binfmt_registered() -> bool:
    """True while a WSLInterop binfmt entry exists and is enabled."""
    if not host.on_wsl():
        return True
    try:
        names = os.listdir(BINFMT_DIR)
    except OSError:
        return False
    for name in names:
        if not name.startswith("WSLInterop"):
            continue
        try:
            with open(os.path.join(BINFMT_DIR, name), encoding="ascii", errors="replace") as fh:
                if fh.readline().strip() == "enabled":
                    return True
        except OSError:
            continue
    return False


def interop_launcher() -> list:
    """argv prefix that starts a Windows program when binfmt cannot."""
    if not host.on_wsl() or interop_binfmt_registered():
        return []
    if os.access(INTEROP_INIT, os.X_OK):
        return [INTEROP_INIT]
    return []


def interop_mode() -> str:
    """'direct' (kernel binfmt), 'init' (explicit interpreter) or 'broken'."""
    if not host.on_wsl() or interop_binfmt_registered():
        return "direct"
    return "init" if os.access(INTEROP_INIT, os.X_OK) else "broken"


def spawn(args, *, gated=True, expect_output=False, **kwargs):
    """subprocess.run for a Windows program, through whichever interop path
    works right now. A binfmt flush between the launcher check and the exec
    surfaces as ENOEXEC; that one case is retried through /init.

    Over WSL interop the launch passes the admission gate (interop_gate.py):
    a bounded number at once, and none while the relay is backing off, which
    raises interop_gate.Refused (an OSError). `gated=False` is for launches
    that restore protection or wait on the owner. With `expect_output`, an
    empty stdout counts as a failed launch (the relay's "no payload" mode)."""
    if not gated or not host.on_wsl():
        return _spawn(args, **kwargs)
    timeout = kwargs.get("timeout") or interop_gate.WAIT_MAX
    interop_gate.GATE.acquire(wait=timeout)
    ok = False
    try:
        result = _spawn(args, **kwargs)
        out = getattr(result, "stdout", None)
        ok = not expect_output or bool(out and out.strip())
        return result
    finally:
        # A timeout or launch error leaves ok False: a transport failure.
        interop_gate.GATE.release(ok)


def _spawn(args, **kwargs):
    prefix = interop_launcher()
    try:
        return subprocess.run([*prefix, *args], **kwargs)
    except OSError as exc:
        if (exc.errno == errno.ENOEXEC and not prefix and host.on_wsl()
                and os.access(INTEROP_INIT, os.X_OK)):
            return subprocess.run([INTEROP_INIT, *args], **kwargs)
        raise


# Where powershell.exe lives when PATH cannot help. A login shell gets the
# Windows directories appended to PATH by WSL; a systemd service does not, so
# shutil.which() finds nothing there and every Windows collector goes quiet.
# On native Windows PATH is not consulted at all: the search order there would
# let a powershell.exe planted in a writable PATH directory run as JARVIS.
FALLBACK_PS = host.powershell_candidates()


def find_powershell() -> str:
    if not host.has_windows():
        return ""
    found = "" if host.native_windows() else (
        shutil.which("powershell.exe") or shutil.which("pwsh.exe"))
    if found:
        return found
    for path in FALLBACK_PS:
        if os.path.exists(path):
            return path
    return ""


def available() -> bool | None:
    """True when the Windows side is reachable from here.
    
    Returns:
        True when Windows is reachable and PowerShell is available.
        False when PowerShell is missing (cannot be found).
        None when PowerShell is found but interop is unavailable.
    """
    global _PS
    if not _PS:
        _PS = find_powershell()
    # A cached binary path and a surviving socket do not prove the Windows
    # filesystem survived a suspend. Recheck before declaring the bridge up.
    if not _PS:
        return False
    if not os.path.isfile(_PS):
        return False
    if not ensure_interop():
        return None
    return True


# The reason recorded when PowerShell cannot be reached at all.
UNREACHABLE = "interop unavailable" if not host.native_windows() else "PowerShell unavailable"

# Human-readable descriptions for each failure mode.
UNREACHABLE_REASON = {
    "interop unavailable": "PowerShell transport unavailable (no WSL interop socket)",
    "PowerShell unavailable": "PowerShell not found or not executable",
}

_SESSION_PROBE = ("\"$((Get-Process -Id $PID).SessionId):"
                  "$((Get-Process explorer -EA SilentlyContinue | Select-Object -First 1).SessionId)\"")


def interop_sockets():
    """Live interop sockets, newest first. Each reaches its own Windows session."""
    if not host.on_wsl():
        return []
    try:
        paths = [os.path.join("/run/WSL", n) for n in os.listdir("/run/WSL")
                 if n.endswith("_interop")]
        live = [p for p in paths
                if not os.path.islink(p) and stat.S_ISSOCK(os.stat(p).st_mode)]
        return sorted(live, key=os.path.getmtime, reverse=True)
    except OSError:
        return []


def _run_via(sock, script, timeout):
    env = {**os.environ, "WSL_INTEROP": sock} if sock else None
    note_own_script(script)
    try:
        return spawn([_PS or find_powershell(), "-NoProfile", "-NonInteractive",
                      "-Command", script], gated=False,
                              capture_output=True, text=True, errors="replace",
                              timeout=timeout, cwd=host.subprocess_cwd(), env=env,
                              **host.spawn_options())
    except (OSError, subprocess.SubprocessError):
        return None


def desktop_interop() -> str:
    """An interop socket whose Windows processes land on the user's desktop.

    Each socket belongs to the wsl.exe that created it, and a Windows process
    launched through it inherits that launcher's session. When WSL was started
    by a background task, its sockets reach session 0, which has no desktop or
    keyboard. Anything that has to see the user's input or windows — a
    low-level keyboard hook above all — is blind there while looking perfectly
    alive. So each socket is asked where it lands, and only one reaching the
    session Explorer runs in is returned. "" when none does (no WSL terminal is
    open on the desktop).

    Native Windows has no sockets to choose between: see on_desktop().
    """
    if not (_PS or find_powershell()):
        return ""
    for sock in interop_sockets():
        r = _run_via(sock, _SESSION_PROBE, 30)
        own, _, desktop = (r.stdout.strip() if r else "").partition(":")
        if own.isdigit() and own == desktop and own != "0":
            return sock
    return ""


def on_desktop() -> bool:
    """True when a program started from here lands in the user's desktop session.

    The native-Windows form of desktop_interop(): JARVIS itself runs in some
    session, and only when that is the one Explorer runs in can it see input
    and windows. A daemon started by a boot task runs in session 0 and answers
    False; an unanswered probe is False too, never assumed.
    """
    if host.on_wsl():
        return bool(desktop_interop())
    if not (host.native_windows() and (_PS or find_powershell())):
        return False
    r = _run_via("", _SESSION_PROBE, 30)
    own, _, desktop = (r.stdout.strip() if r else "").partition(":")
    return own.isdigit() and own == desktop and own != "0"


def run_in_every_session(script, timeout=60):
    """Run an idempotent PowerShell command once through every interop socket.

    Windows refuses to terminate a process in another logon session: a stop
    issued from the desktop is denied for a session-0 helper and succeeds from
    session 0. Cleanup that must reach every session therefore runs from each.
    Returns how many runs completed.
    """
    if not (_PS or find_powershell()):
        return 0
    if host.native_windows():
        # One process, one session: other sessions' helpers are out of reach
        # from here, which the caller sees as a count of one, not of "all".
        return 1 if _run_via("", script, timeout) else 0
    return sum(1 for sock in interop_sockets() if _run_via(sock, script, timeout))


def _split_args(cmd: str):
    """Tokenize a Windows command line, honoring double quotes."""
    return [t.strip('"') for t in re.findall(r'"[^"]*"|\S+', cmd or "")]


def _script_target(cmd: str, exe_base: str) -> str:
    if not SCRIPT_HOSTS.match(exe_base):
        return ""
    for arg in _split_args(cmd)[1:]:
        if arg.startswith(("-", "/")):
            continue
        if SCRIPT_EXT.search(arg):
            return arg
    return ""


def collect(timeout: int = 45):
    """Return a list of process records for the Windows side (empty if unreachable)."""
    if not host.has_windows():
        return []           # no Windows domain here: not applicable, not a failure
    if (reachable := available()) is None:
        collection.failed('windows-processes', UNREACHABLE)
        return []
    if reachable is False:
        collection.failed('windows-processes', UNREACHABLE)
        return []
    note_own_script(PS_SCRIPT)
    try:
        res = spawn(
            [str(_PS), "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT],
            expect_output=True, capture_output=True,
            timeout=timeout,
            cwd=host.subprocess_cwd(), **host.spawn_options(),
        )
    except interop_gate.Refused as exc:
        collection.failed('windows-processes', str(exc))
        return []
    except (subprocess.TimeoutExpired, OSError):
        collection.failed('windows-processes', 'query failed or timed out')
        return []

    raw = res.stdout
    text = raw.decode("ascii", "ignore") if isinstance(raw, bytes) else str(raw or "")
    blob = text.strip().replace("\r", "").replace("\n", "")
    if not blob:
        collection.failed('windows-processes', 'query returned no payload')
        return []
    try:
        data = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
    except Exception:
        collection.failed('windows-processes', 'invalid payload')
        return []

    if not isinstance(data, dict) or not data.get('procs'):
        collection.failed('windows-processes', 'no process observations')
        return []
    collection.succeeded('windows-processes')

    by_pid: dict = {}
    for c in data.get("conns") or []:
        # Windows reports pid 0 for connections it declines to attribute; that
        # is not the System Idle Process actually talking to the internet.
        pid = c.get("pid")
        by_pid.setdefault(0 if pid in (0, None) else pid, []).append({
            "proto": c.get("proto", "tcp"),
            "local_ip": c.get("lip", ""),
            "local_port": c.get("lport", 0),
            "remote_ip": c.get("rip", ""),
            "remote_port": c.get("rport", 0),
            "state": c.get("state", ""),
        })

    procs = []
    for p in data.get("procs") or []:
        pid = p.get("pid")
        exe = p.get("exe") or ""
        name = p.get("name") or ""
        cmd = p.get("cmd") or name
        if pid == 0:
            name = "(unattributed)"
        exe_base = os.path.basename(exe.replace("\\", "/")) or name
        script = _script_target(cmd, exe_base)
        ident_exe = script if script else exe

        procs.append({
            "host": HOST,
            "pid": pid,
            "ppid": p.get("ppid", 0),
            "name": name,
            "exe": exe,
            "script": script,
            "cmdline": cmd,
            "started": p.get("started") or "",
            "observed_at": data.get("process_observed_at") or "",
            "user": "",  # per-process owner lookup is too slow to do on every scan
            "rss_bytes": int(p.get("rss") or 0),
            "cpu_seconds": float(p.get("cpu") or 0),
            "logical_cpus": int(data.get("logical_cpus") or 0),
            "conns": by_pid.get(pid, []),
            "fp": fingerprint(HOST, ident_exe or name, cmd, ""),
        })

    return procs


def stdin_text(var):
    """PowerShell that reads the whole stdin as UTF-8 into `$<var>`.

    Pair with ps_json(..., payload=...). Data that used to travel as an inline
    base64 literal decoded by FromBase64String put model prompts and finding
    paths into every process listing and Sysmon Event 1, and made JARVIS's own
    helper match the encoded-command rule it enforces (measured 2026-09-24:
    ~140 critical/high scan events in two days). Raw bytes are read so the
    console input codepage cannot corrupt non-ASCII text.
    """
    if not re.fullmatch(r"[A-Za-z]\w*", var or ""):
        raise ValueError("invalid PowerShell variable name")
    return ("$jarvisIn=New-Object IO.MemoryStream;"
            "[Console]::OpenStandardInput().CopyTo($jarvisIn);"
            f"${var}=[Text.Encoding]::UTF8.GetString($jarvisIn.ToArray());")


# Scripts this process launched itself, by SHA-256 of the exact text handed to
# PowerShell. Windows records that same text when script-block logging is on
# (measured 2026-11-10: identical hash), so the script-block reader can leave the
# monitor's own scripts out exactly, not by name. In memory only and bounded; a
# script launched by another process (a CLI command, a Windows task) is not here
# and is judged like anyone else's.
OWN_SCRIPTS_MAX = 4000
_OWN_SCRIPTS = collections.OrderedDict()
_OWN_LOCK = threading.Lock()


def note_own_script(script):
    digest = hashlib.sha256((script or "").encode("utf-8", "surrogatepass")).hexdigest()
    with _OWN_LOCK:
        _OWN_SCRIPTS.pop(digest, None)
        _OWN_SCRIPTS[digest] = time.time()
        while len(_OWN_SCRIPTS) > OWN_SCRIPTS_MAX:
            _OWN_SCRIPTS.popitem(last=False)
    return digest


def own_scripts():
    """{sha256 hex: last launch time} of scripts this process launched."""
    with _OWN_LOCK:
        return dict(_OWN_SCRIPTS)


def ps_json(script, timeout=120, payload=None):
    """Run a PowerShell script and decode its base64 JSON payload.

    `payload` (str or bytes) is written to the script's stdin; read it with
    stdin_text(). Nothing from it reaches the command line.

    Retries once after forcing interop re-resolution: the socket named in
    WSL_INTEROP can go stale between calls when the session that created it
    ends, and the only symptom is empty output.
    """
    if not host.has_windows():
        return None         # no Windows domain here: not applicable, not a failure
    if (reachable := available()) is None:
        collection.failed('windows', UNREACHABLE)
        return None
    if reachable is False:
        collection.failed('windows', UNREACHABLE)
        return None
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    stdin = {} if payload is None else {"input": payload}
    note_own_script(script)

    for attempt in (1, 2):
        try:
            r = spawn(
                [_PS, "-NoProfile", "-NonInteractive",
                 "-Command", script],
                expect_output=True, capture_output=True, timeout=timeout,
                cwd=host.subprocess_cwd(), **stdin, **host.spawn_options(),
            )
        except interop_gate.Refused as exc:
            collection.failed('windows', str(exc))
            return None
        except (OSError, subprocess.TimeoutExpired):
            collection.failed('windows', 'PowerShell failed or timed out')
            return None

        blob = (r.stdout.decode("ascii", "ignore")
                .strip().replace("\r", "").replace("\n", ""))
        if blob:
            try:
                value = json.loads(base64.b64decode(blob).decode("utf-8", "replace"))
                if value is None:
                    collection.failed('windows', 'PowerShell returned null')
                else:
                    collection.succeeded('windows')
                return value
            except Exception:
                collection.failed('windows', 'invalid PowerShell payload')
                return None

        if attempt == 1:
            if interop_gate.GATE.degraded():
                break           # a retry storm is what wedges a slow relay
            # No output at all: most likely a dead interop socket. Drop the
            # cached value so ensure_interop() picks a fresh one, and retry.
            # Natively there is no socket; the retry is one plain second try.
            os.environ.pop("WSL_INTEROP", None)
            if not ensure_interop():
                collection.failed('windows', 'interop retry unavailable')
                return None
    collection.failed('windows', 'PowerShell returned no payload'
                      + ('; interop degraded, not retried' if interop_gate.GATE.degraded() else ''))
    return None


def aslist(v):
    """PowerShell collapses single-element arrays; normalize back to a list."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]

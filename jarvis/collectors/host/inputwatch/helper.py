"""Staging, starting and stopping the Windows input helper, and the
paths and pids that describe it."""

import os
import re
import subprocess

from jarvis.core.util import now
from jarvis.platform import host
from jarvis.platform import windows as collect_windows
from jarvis.platform.windows import ps_json

from .common import HOOK_PS1

_PATHS_CACHE = None

# Windows keeps the hook in the desktop session for us: a task that runs only
# while its user is logged on always starts there, whoever triggers it, and
# Windows restarts it on failure and refuses a second instance. Launching
# through WSL interop cannot promise any of that — the socket JARVIS happens
# to hold may reach session 0, where a keyboard hook sees nothing.
TASK_NAME = "JARVIS input hook"


def _paths():
    """Where the helper writes, in both Windows and WSL spelling.

    `$env:LOCALAPPDATA` is fixed for the life of the machine, so the resolved
    answer is cached: the short-interval watchdog calls this every pass and a
    powershell.exe round trip each time would defeat the point of a local-only
    health check. A run that only reaches the fallback is not cached, so a
    transient interop failure does not pin us to C:\\Windows\\Temp.
    """
    global _PATHS_CACHE
    if _PATHS_CACHE:
        return _PATHS_CACHE
    out = ps_json(
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{t=$env:LOCALAPPDATA})))", timeout=60)
    base = (out or {}).get("t")
    resolved = bool(base)
    base = base or r"C:\Windows\Temp"
    p = base.replace("\\", "/")
    wsl = host.local_path(base) if len(p) > 2 and p[1] == ":" else "/tmp"
    wsl_dir = os.path.join(wsl, "Jarvis")
    try:
        os.makedirs(wsl_dir, exist_ok=True)
    except OSError:
        pass
    pair = (base + r"\Jarvis\input.jsonl", os.path.join(wsl_dir, "input.jsonl"))
    if resolved:
        _PATHS_CACHE = pair
    return pair


OWNER_FILE = "input-hook-owner.txt"   # in %LOCALAPPDATA%, shared by every install on the machine


def _owner_marker():
    """WSL path of the per-user marker naming the install that owns the hook."""
    _win_out, wsl_out = _paths()
    return os.path.join(os.path.dirname(os.path.dirname(wsl_out)), OWNER_FILE)


def owner():
    """The owning install's output file (Windows path) from the marker, or "".

    Data, not code: the Argus build rewrites product names in its copy of this
    module, so a literal "defer to JARVIS" would name itself there. Only a path
    under the same %LOCALAPPDATA% ending in \\input.jsonl is accepted.
    """
    win_out, _wsl_out = _paths()
    base = win_out.rsplit("\\", 2)[0]
    try:
        with open(_owner_marker(), encoding="utf-8", errors="replace") as fh:
            value = fh.read(400).strip()
    except OSError:
        return ""
    parts = value.rsplit("\\", 2)
    # One plain folder directly under %LOCALAPPDATA%: no "..", no separators.
    if len(parts) != 3 or parts[0].lower() != base.lower() or parts[2].lower() != "input.jsonl" \
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _-]{0,63}", parts[1]):
        return ""
    return value


def claim_owner():
    """Make this install the owner of the machine's input hook. Returns its path."""
    win_out, _wsl_out = _paths()
    tmp = _owner_marker() + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(win_out)
    os.replace(tmp, _owner_marker())
    return win_out


def _owner_file(owner_win, name):
    win_out, wsl_out = _paths()
    base_win = win_out.rsplit("\\", 2)[0]
    if not owner_win.lower().startswith(base_win.lower()):
        return None
    return os.path.join(os.path.dirname(os.path.dirname(wsl_out)), owner_win.rsplit("\\", 2)[1], name)


def owner_output_size(owner_win):
    """Size of the owning install's output file; its consumer truncates it after each read."""
    path = _owner_file(owner_win, "input.jsonl")
    try:
        return os.path.getsize(path) if path else None
    except OSError:
        return None


def owner_hook_verified(owner_win):
    """True when the pid in the owner's pulse file is a live powershell.exe whose
    command line runs inputhook.ps1 with that -OutFile. A touched file alone
    must not make every install stand down. None when it cannot be asked."""
    path = _owner_file(owner_win, "input.alive")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            pid = int(fh.read(40).split(":", 1)[0])
    except (OSError, ValueError, TypeError):
        return False
    out = owner_win.replace("'", "''")
    d = ps_json(
        "$ok = 0; $p = Get-CimInstance Win32_Process -Filter \"ProcessId=%d\" -EA SilentlyContinue;"
        "if ($p -and $p.Name -eq 'powershell.exe' -and $p.CommandLine -like '*inputhook.ps1*' -and "
        "$p.CommandLine.IndexOf('%s', [StringComparison]::OrdinalIgnoreCase) -ge 0) { $ok = 1 };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json @{ok=$ok})))"
        % (pid, out), timeout=30)
    if not d:
        return None
    return bool(d.get("ok"))


def owner_pulse_mtime(owner_win):
    """mtime of the owning install's .alive pulse, or None if absent."""
    win_out, wsl_out = _paths()
    base_win = win_out.rsplit("\\", 2)[0]
    base_wsl = os.path.dirname(os.path.dirname(wsl_out))
    folder = owner_win.rsplit("\\", 2)[1]
    try:
        return os.path.getmtime(os.path.join(base_wsl, folder, "input.alive")) \
            if owner_win.lower().startswith(base_win.lower()) else None
    except OSError:
        return None


def _stage_helper():
    """Copy the hook script somewhere powershell.exe can actually reach."""
    win_out, wsl_out = _paths()
    wsl_dir = os.path.dirname(wsl_out)
    dest = os.path.join(wsl_dir, "inputhook.ps1")
    try:
        with open(HOOK_PS1, encoding="utf-8", errors="replace") as src, \
                open(dest, "w", encoding="utf-8-sig") as dst:
            dst.write(src.read())
    except OSError as exc:
        return None, None, f"could not stage the hook helper: {exc}"
    return win_out.rsplit("\\", 1)[0] + r"\inputhook.ps1", win_out, ""


def _pid_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".pid"


def running():
    """PIDs of the helper on the Windows side, if it is alive.

    Reads a pid file the helper writes rather than searching command lines.
    Searching was subtly wrong: the query's own command line contains the
    script name, so the querying shell matched itself, `running()` was always
    true, and `start()` short-circuited on "already running" without ever
    launching anything.
    """
    try:
        with open(_pid_path(), errors="replace") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return []
    d = ps_json(
        "$ok = 0; try { $p = Get-Process -Id %d -ErrorAction Stop; "
        "if ($p.ProcessName -eq 'powershell') { $ok = 1 } } catch { };"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{ok=$ok})))" % pid, timeout=90)
    return [pid] if (d or {}).get("ok") else []


def _own_helper_clause():
    """PowerShell condition for "this install's hook helper": a powershell.exe
    whose command line names our own output file.

    Matching only `inputhook.ps1` counted every product's hook as ours. With
    the installed Argus app supervising its own hook (AppData\\Local\\Argus)
    beside this daemon's (AppData\\Local\\Jarvis), each supervisor took the
    other's helper for a duplicate and stopped both, and `start()` refused to
    launch while the other's ran (measured 2026-10-31 20:13-20:26). The
    duplicate rule exists to stop two hooks writing one file, so the output
    file is the identity.
    """
    win_out = _paths()[0].replace("'", "''")
    return ("$_.CommandLine -and $_.CommandLine -like '*inputhook.ps1*' -and "
            f"$_.CommandLine.IndexOf('{win_out}', [StringComparison]::OrdinalIgnoreCase) -ge 0")


def helper_count():
    """How many hook helpers are running on Windows right now; -1 if unknown.

    Asked of the process table itself, not the pid file: the helper writes that
    only once its hook is installed, and every "is it up?" decision taken in
    that gap launched a duplicate. Excludes this query's own shell, whose
    command line names the script too.
    """
    d = ps_json(
        "$n = @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\""
        " | Where-Object { (" + _own_helper_clause() + ") -and "
        "$_.ProcessId -ne $PID }).Count;"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(ConvertTo-Json @{n=$n})))", timeout=60)
    try:
        return int((d or {}).get("n"))
    except (TypeError, ValueError):
        return -1


def task_arguments(script_win, win_out):
    """The PowerShell arguments the task runs, and the only ones trusted_tasks
    accepts for it."""
    return ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass '
            f'-File "{script_win}" -OutFile "{win_out}"')


def _ensure_task_script(script_win, win_out):
    """PowerShell that registers the task when missing or changed, then runs it."""
    inner = task_arguments(script_win, win_out).replace("'", "''")
    return (
        "$ErrorActionPreference='Stop';"
        f"$name='{TASK_NAME}';"
        "$conhost=\"$env:SystemRoot\\System32\\conhost.exe\";"
        "$ps=\"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\";"
        f"$arg='--headless \"' + $ps + '\" ' + '{inner}';"
        "$o=@{registered=$false;started=$false;error=''};"
        "try{"
        "  $me=\"$env:USERDOMAIN\\$env:USERNAME\";"
        "  $t=Get-ScheduledTask -TaskName $name -EA SilentlyContinue;"
        "  if(-not $t -or @($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -ne $conhost"
        "     -or $t.Actions[0].Arguments -ne $arg){"
        "    $action=New-ScheduledTaskAction -Execute $conhost -Argument $arg;"
        "    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $me;"
        "    $principal=New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive"
        "       -RunLevel Limited;"
        "    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries"
        "       -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew"
        "       -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3"
        "       -RestartInterval (New-TimeSpan -Minutes 1);"
        "    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger"
        "       -Principal $principal -Settings $settings -Force | Out-Null;"
        "    $o.registered=$true};"
        "  Start-ScheduledTask -TaskName $name;"
        "  $o.started=$true"
        "}catch{$o.error=[string]$_.Exception.Message};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Compress)))")


def _lock_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".starting"


def start():
    """Launch the hook helper, hidden and detached. Returns "" on success.

    Refuses while any helper exists (or the count cannot be taken): the pid
    file appears only once a hook is installed, and deciding from it launched
    duplicates. The short-lived lock file covers the moment between counting
    and the new process appearing, when two callers could both count zero.
    """
    count = helper_count()
    if count > 0:
        return "already running"
    if count < 0:
        return "could not count running helpers; not starting a possible duplicate"
    try:
        age = now() - os.path.getmtime(_lock_path())
        if age < 45:
            return "a start is already in progress"
    except OSError:
        pass
    if not collect_windows.available():
        return "the Windows interop bridge is not available"
    script_win, win_out, err = _stage_helper()
    if err:
        return err
    try:
        with open(_lock_path(), "w") as fh:
            fh.write(str(now()))
    except OSError:
        pass

    task = ps_json(_ensure_task_script(script_win, win_out), timeout=90) or {}
    if task.get("started"):
        return ""
    task_error = str(task.get("error") or "the scheduled task did not start")

    # Fallback while the task cannot run (not yet registrable, or Task
    # Scheduler refused): launch it directly, but only through a socket that
    # reaches the desktop — a hook in session 0 heartbeats and sees nothing.
    if host.native_windows():
        desktop = ""
        if not collect_windows.on_desktop():
            return (f"{task_error}; and JARVIS is not running in the Windows desktop "
                    f"session, so the hook cannot be started where it can see input")
    else:
        desktop = collect_windows.desktop_interop()
        if not desktop:
            return (f"{task_error}; and no WSL connection reaches the Windows desktop "
                    f"session, so the hook cannot be started where it can see input")
    cmd = ("Start-Process powershell.exe -WindowStyle Hidden -ArgumentList "
           "'-NoProfile','-NonInteractive','-WindowStyle','Hidden',"
           "'-ExecutionPolicy','Bypass','-File','"
           + script_win + "','-OutFile','" + win_out + "'")
    try:
        subprocess.run([*collect_windows.interop_launcher(), collect_windows._PS,
                        "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, timeout=90,
                       cwd=host.subprocess_cwd(), **host.spawn_options(),
                       env={**os.environ, "WSL_INTEROP": desktop} if desktop else None)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"{task_error}; direct start failed too: {exc}"
    return ""


def ensure():
    """Best-effort "make sure it is up" for callers without a Store handle."""
    pids = running()
    if pids:
        return pids
    start()
    return running()


def stop():
    pids = running()
    if not pids:
        return "not running"
    ps_json("Stop-Process -Id " + ",".join(str(p) for p in pids)
             + " -Force; [Convert]::ToBase64String([Text.Encoding]::UTF8"
               ".GetBytes((ConvertTo-Json @{ok=1})))", timeout=90)
    for p in (_pid_path(), _alive_path()):
        try:
            os.remove(p)
        except OSError:
            pass
    return ""  # note: under the daemon, the watchdog will start it again


def _stop_all(pids=()):
    """Kill every hook helper, not just the one in the pid file.

    Helpers are found by command line and, because that is not always
    readable, also by `pids` — the processes seen writing heartbeats. A helper
    launched into session 0 returned a null command line, survived every
    stop-all, and kept writing zero heartbeats beside the real hook, so each
    reconciliation killed the working helper instead. Explicit pids are only
    stopped if they are PowerShell processes, and the stop runs from every
    session, because Windows denies terminating another session's process.
    The caller starts exactly one.
    """
    explicit = ",".join(str(int(p)) for p in pids if str(p).strip().isdigit()) or "0"
    collect_windows.run_in_every_session(
        f"Stop-ScheduledTask -TaskName '{TASK_NAME}' -EA SilentlyContinue;"
        "$targets = @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        "Where-Object { (" + _own_helper_clause() + ") -and $_.ProcessId -ne $PID } | "
        "ForEach-Object { $_.ProcessId });"
        f"$targets += @({explicit}) | Where-Object {{ $_ -gt 0 -and $_ -ne $PID -and "
        "(Get-Process -Id $_ -EA SilentlyContinue).ProcessName -eq 'powershell' };"
        "$targets | Sort-Object -Unique | ForEach-Object { Stop-Process -Id $_ -Force "
        "-EA SilentlyContinue; Wait-Process -Id $_ -Timeout 5 -EA SilentlyContinue }",
        timeout=90)
    for p in (_pid_path(), _alive_path(), _lock_path()):
        try:
            os.remove(p)
        except OSError:
            pass


def _staged_matches_source():
    """True if the copy powershell.exe will read is identical (BOM aside) to
    the in-repo helper — a staged file rewritten under us aborts the restart."""
    _win, wsl_out = _paths()
    staged = os.path.join(os.path.dirname(wsl_out), "inputhook.ps1")
    try:
        with open(HOOK_PS1, "rb") as a, open(staged, "rb") as b:
            return a.read().decode("utf-8-sig") == b.read().decode("utf-8-sig")
    except (OSError, UnicodeError):
        return False


def _alive_path():
    _win, wsl_out = _paths()
    return os.path.splitext(wsl_out)[0] + ".alive"


def _alive_mtime():
    try:
        return os.path.getmtime(_alive_path())
    except OSError:
        return None


def _pidfile_pid():
    try:
        return int(open(_pid_path(), errors="replace").read().strip())
    except (OSError, ValueError):
        return None

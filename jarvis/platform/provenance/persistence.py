"""Declarations of the persistence JARVIS itself installs.

Each scheduled task JARVIS (or its reviewed IDE keepalive) registers on
Windows is declared once here: action, exact arguments, principal run
level, logon type, and where its script fingerprint comes from. The
control audit reconstructs the live task independently, and
`verify_task` compares it with the declaration field by field:

    declaration + live state match exactly  -> known managed persistence (low)
    anything else about a declared name     -> critical, with the mismatch named
    an undeclared task                      -> the ordinary audit decides

The declaration is data inside the sealed release, so changing it is a
reviewed release like any other code. Names, paths and the "jarvis" prefix
buy nothing by themselves (EVIDENCE-FABRIC.md, P1).

Script fingerprints come from the sealed release (`code_root`), never from
the user-editable checkout: the tasks re-copy their scripts from the
checkout, so trusting the checkout would accept any edit made there.
Arguments name the checkout (`checkout_root`), because the tasks were
installed from it.
"""

import hashlib
import re
from dataclasses import dataclass, replace

from jarvis.core import paths

POWERSHELL_PREFIX = ("-NoProfile -NonInteractive -WindowStyle Hidden "
                     "-ExecutionPolicy Bypass ")
WSL_START_ARGS = "-d Ubuntu --exec /bin/true"


@dataclass(frozen=True)
class ManagedTask:
    name: str                # scheduled task name, compared case-insensitively
    script: str              # staged script file name, for display
    args: str                # exact PowerShell arguments; {local} and {checkout} are filled in
    logon: str               # expected logon type
    run_level: str = "limited"
    release_script: str = ""  # script path inside the sealed release, fingerprinted live
    fixed_hash: str = ""      # reviewed fingerprint for scripts JARVIS does not ship
    kind: str = "powershell"  # "powershell" or "wsl_start"
    principal: str = "user"   # "user": the current Windows user; "system": LocalSystem


MANAGED_TASKS = (
    ManagedTask(
        name="jarviscursorspeed", script="cursor-speed.ps1",
        release_script="windows-sensor/cursor-speed.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\CursorSpeed\cursor-speed.ps1"'),
    ManagedTask(
        name="jarvis connectivity guard", script="jarvis-connectivity-guard.ps1",
        release_script="jarvis-connectivity-guard.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\Connectivity\jarvis-connectivity-guard.ps1" '
                                 r'-StateRoot "{local}\Jarvis\Connectivity"'),
    ManagedTask(
        name="jarvis independent health monitor", script="jarvis-health-monitor.ps1",
        release_script="jarvis-health-monitor.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\HealthMonitor\jarvis-health-monitor.ps1"'),
    ManagedTask(
        # Registered by inputwatch.helper so the keystroke monitor keeps
        # running in the desktop session.
        name="jarvis input hook", script="inputhook.ps1",
        release_script="jarvis/platform/win/inputhook.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\inputhook.ps1" '
                                 r'-OutFile "{local}\Jarvis\input.jsonl"'),
    ManagedTask(
        # The one task that runs elevated, by design, and only from the
        # administrator-only ProgramData folder, never LocalAppData.
        name="jarvis elevated broker", script="jarvis-elevated-broker.ps1",
        # Runs as SYSTEM: a task holding the user's elevated token also gets
        # the user's environment (HKCU\\Environment), which the user can write.
        release_script="jarvis-elevated-broker.ps1", logon="serviceaccount", run_level="highest",
        principal="system",
        args=POWERSHELL_PREFIX + r'-File "C:\ProgramData\Jarvis\Broker\jarvis-elevated-broker.ps1" -Run'),
    ManagedTask(
        # The few-second revival loop, staged by its own -Install.
        name="jarvis reviver", script="jarvis-reviver.ps1",
        release_script="jarvis-reviver.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\Reviver\jarvis-reviver.ps1" '
                                 r'-Distro "Ubuntu" -RepoRoot "{checkout}"'),
    ManagedTask(
        # A machine without WSL: this loop is what starts the daemon and
        # restarts it, in place of systemd and the reviver. Python's path and
        # the port live in its own service.json, so the arguments stay exact.
        name="jarvis native service", script="jarvis-native-service.ps1",
        release_script="jarvis-native-service.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\Jarvis\NativeService\jarvis-native-service.ps1" '
                                 r'-RepoRoot "{checkout}"'),
    ManagedTask(
        name="jarvis wake watchdog", script="jarvis-wake-watchdog.ps1",
        release_script="jarvis-wake-watchdog.ps1", logon="interactive",
        args=POWERSHELL_PREFIX + r'-File "{local}\WSLKeepalive\jarvis-wake-watchdog.ps1" '
                                 r'-Distro "Ubuntu" -RepoRoot "{checkout}" -RecoverInterop true'),
    ManagedTask(
        # Reviewed 2026-10-27 against the pre-edit copy (.bak-2026-10-11, which
        # matched the old pin 45c0e95c): the 2026-10-11 edit only adds bounded
        # exponential back-off on fast failures and log summarising; the wsl.exe
        # command, distro and keepalive target are unchanged.
        name="wsl ide keepalive", script="wsl-ide-keepalive-supervisor.ps1", logon="s4u",
        fixed_hash="08a7fbaf6c40cc947fe60286a2de1251ec7709072a3fd3f6951073303ddfb1ec",
        args=POWERSHELL_PREFIX + r'-File "{local}\WSLKeepalive\wsl-ide-keepalive-supervisor.ps1"'),
    ManagedTask(
        name="wsl ide keepalive watchdog", script="wsl-ide-keepalive-watchdog.ps1", logon="s4u",
        fixed_hash="1e69a376ceec44355343684861239f55e2f3b3955ed684a51ef2cf3929ab6207",
        args=POWERSHELL_PREFIX + r'-File "{local}\WSLKeepalive\wsl-ide-keepalive-watchdog.ps1"'),
    ManagedTask(
        # install.sh: start the distro at logon so systemd brings jarvis.service
        # up. It runs no user-editable script (/bin/true inside WSL is
        # root-owned), so the exact definition is the whole verification.
        name="wsl jarvis 24x7", script="", kind="wsl_start", logon="interactive",
        args=WSL_START_ARGS),
)

BY_NAME = {t.name: t for t in MANAGED_TASKS}

# The layouts installed before the scripts were renamed to match their tasks
# (2026-09-28). A live task still registered this way is accepted only with
# the exact old arguments AND the exact fingerprint of the old script as it
# shipped in the sealed release that installed it -- the same pinned-review
# rule as `fixed_hash`. Any edit to an old copy therefore still fails. What
# this does admit is a re-registration back to the exact old reviewed script,
# so the table is transitional: delete each entry once the live task has been
# re-registered and read back on the new layout
# (docs/guides/WINDOWS-SUPERVISOR-NAMES.md).
#
# name -> (old script file, exact old arguments, pinned old fingerprint)
LEGACY_LAYOUTS = {
    "jarvis connectivity guard": (
        "connectivity-jarvis.ps1",
        POWERSHELL_PREFIX + r'-File "{local}\Jarvis\Connectivity\connectivity-jarvis.ps1" '
                            r'-StateRoot "{local}\Jarvis\Connectivity"',
        "a60f5813703b5768e2ce16a05f8177209fc66974c1c9cffd2ce8941021fdd862"),
    "jarvis independent health monitor": (
        "deadman-jarvis.ps1",
        POWERSHELL_PREFIX + r'-File "{local}\Jarvis\Deadman\deadman-jarvis.ps1"',
        "c9cae3d0006aed24596a74ab3dddb1b4dbf4b65ea689fe3f6896bba74ac4ad8a"),
    "jarvis elevated broker": (
        "broker-jarvis.ps1",
        POWERSHELL_PREFIX + r'-File "C:\ProgramData\Jarvis\Broker\broker-jarvis.ps1" -Run',
        "e99aa1e764279b44bd8af0fea5bb1a971a800d18bf03c099ab510214fb2fe48d"),
    "jarvis reviver": (
        "revive-jarvis.ps1",
        POWERSHELL_PREFIX + r'-File "{local}\Jarvis\Reviver\revive-jarvis.ps1" '
                            r'-Distro "Ubuntu" -RepoRoot "{checkout}"',
        "dc66b9d9b538c5a6800faabfbd6b227ff82ee9de7b003a1098ece912341c98fc"),
    "jarvis wake watchdog": (
        "wake-jarvis.ps1",
        POWERSHELL_PREFIX + r'-File "{local}\WSLKeepalive\wake-jarvis.ps1" '
                            r'-Distro "Ubuntu" -RepoRoot "{checkout}" -RecoverInterop true',
        "9e3d7c9a487dfb8fc779616bafa57af9fc0cdcd0a3d3f588775729888925f20a"),
}


def legacy_layout(task):
    """The pre-rename declaration of `task`, pinned to its old fingerprint, or None."""
    old = LEGACY_LAYOUTS.get(task.name)
    if old is None:
        return None
    script, args, fingerprint = old
    return replace(task, script=script, args=args, fixed_hash=fingerprint,
                   release_script="")
# Declared names whose verification failure is a critical finding: a task
# impersonating or modifying JARVIS's own persistence.
CRITICAL_ON_MISMATCH = frozenset(t.name for t in MANAGED_TASKS if t.kind == "powershell")


def normalized_text_hash(path):
    """Hash reviewed script text independent of Windows newline/EOF style."""
    try:
        with open(path, encoding="utf-8-sig", errors="strict", newline="") as fh:
            text = fh.read().replace("\r\n", "\n").rstrip()
    except (OSError, UnicodeError):
        return ""
    return hashlib.sha256(text.encode()).hexdigest()


def expected_hash(task, code_root):
    if task.fixed_hash:
        return task.fixed_hash
    return normalized_text_hash(str(paths.shipped_script(task.release_script, code_root)))


def expected_arguments(task, local, checkout_root):
    return task.args.format(local=local, checkout=str(checkout_root))


def _one_action(live):
    actions = live.get("actions")
    actions = actions if isinstance(actions, list) else [actions] if actions else []
    if len(actions) != 1 or not isinstance(actions[0], dict):
        return None
    return actions[0]


def _principal_problem(task, live, data):
    if (live.get("runLevel") or "").casefold() != task.run_level:
        return f"principal run level is not {task.run_level}"
    actual_user = (live.get("user") or "").casefold().rsplit("\\", 1)[-1]
    if task.principal == "system":
        if actual_user not in ("system", "s-1-5-18"):
            return "principal is not SYSTEM"
        return ""
    current_user = (data.get("currentUser") or "").casefold().rsplit("\\", 1)[-1]
    if not actual_user or actual_user != current_user:
        return "principal is not the current Windows user"
    return ""


def _verify_wsl_start(task, live, data):
    action = _one_action(live)
    if action is None:
        return False, "expected exactly one action"
    execute = (action.get("execute") or "").replace("/", "\\").casefold()
    if not re.fullmatch(r"(?:(?:%systemroot%|c:\\windows)\\system32\\)?wsl\.exe", execute):
        return False, "action is not the Windows wsl.exe"
    if (action.get("arguments") or "").strip() != task.args:
        return False, "arguments differ from the reviewed definition"
    problem = _principal_problem(task, live, data)
    if problem:
        return False, problem
    if (live.get("logonType") or "").casefold() != task.logon:
        return False, f"logon type is not {task.logon}"
    return True, "exact task definition verified (starts WSL, no script)"


def verify_task(live, data, code_root, checkout_root):
    """(verified, reason) for one live scheduled task against its declaration."""
    task = BY_NAME.get((live.get("name") or "").casefold())
    if task is None:
        return False, "not a known maintenance task"
    if task.kind == "wsl_start":
        return _verify_wsl_start(task, live, data)

    action = _one_action(live)
    if action is None:
        return False, "expected exactly one action"
    execute = (action.get("execute") or "").replace("/", "\\").casefold()
    arguments = action.get("arguments") or ""
    if re.fullmatch(r"(?:%systemroot%|c:\\windows)\\system32\\conhost\.exe", execute):
        # conhost --headless is the only launch path that never shows a
        # window; accepted solely as a wrapper around System32 Windows PowerShell.
        wrapped = re.match(
            r"--headless\s+\"?(?:%SystemRoot%|C:\\Windows)\\System32\\WindowsPowerShell"
            r"\\v1\.0\\powershell\.exe\"?\s+(.*)$", arguments, re.I | re.S)
        if not wrapped:
            return False, "headless console host does not wrap Windows PowerShell"
        arguments = wrapped.group(1)
    elif execute.rsplit("\\", 1)[-1] not in ("powershell.exe", "powershell"):
        return False, "action is not Windows PowerShell"
    problem = _principal_problem(task, live, data)
    if problem:
        return False, problem
    if (live.get("logonType") or "").casefold() != task.logon:
        return False, f"logon type is not {task.logon}"
    local = (data.get("localAppData") or "").rstrip("\\/")
    target = (action.get("targetHash") or "").casefold()
    verified, reason = _match_layout(task, arguments, target, local, code_root, checkout_root)
    if verified:
        return True, reason
    legacy = legacy_layout(task)
    if legacy is None:
        return False, reason
    old_ok, old_reason = _match_layout(legacy, arguments, target, local,
                                       code_root, checkout_root)
    if old_ok:
        return True, ("exact pre-rename task definition and pinned script "
                      "fingerprint verified; re-register it on the new layout")
    # Old arguments with the wrong script: name the fingerprint, not the
    # arguments, so the report points at the file that changed.
    return False, reason if old_reason.startswith("arguments") else "pre-rename " + old_reason


def _match_layout(task, arguments, target, local, code_root, checkout_root):
    if arguments.casefold() != expected_arguments(task, local, checkout_root).casefold():
        return False, "arguments differ from the reviewed definition"
    wanted = expected_hash(task, code_root)
    if not wanted or target != wanted:
        return False, "script fingerprint differs from the reviewed version"
    return True, "exact task definition and script fingerprint verified"


def manifest(local, code_root, checkout_root):
    """The expected state of every managed task, for review and export."""
    out = []
    for task in MANAGED_TASKS:
        out.append({"name": task.name, "kind": task.kind, "run_level": task.run_level,
                    "logon": task.logon,
                    "arguments": expected_arguments(task, local, checkout_root)
                    if task.kind == "powershell" else task.args,
                    "script": task.script, "fingerprint": expected_hash(task, code_root)
                    if task.kind == "powershell" else None,
                    "fingerprint_source": "fixed review" if task.fixed_hash else
                    ("sealed release: " + task.release_script) if task.release_script else None})
    return out

"""Do the Windows supervisors still check on us?

JARVIS is supervised from outside WSL by Windows scheduled tasks: the
independent health monitor (`jarvis-health-monitor.ps1`), the instant reviver
(`jarvis-reviver.ps1`) and the elevated collector broker
(`jarvis-elevated-broker.ps1`). This module reads what each one last wrote.

The health monitor is the only layer that can tell you JARVIS is gone when WSL
itself is down — nothing inside a stopped distro can send that mail. That
makes its own silence the most dangerous silence available: a task stuck in
`Running` refuses every later trigger under MultipleInstances=IgnoreNew, and
Task Scheduler still shows the task as present and Ready afterwards.

So the supervision runs both ways. The Windows task verifies that JARVIS's
scheduler is progressing; this checks that the Windows task is still writing
its state file. Each side is the only thing positioned to notice the other's
failure.
"""

import calendar
import json
import os
import re
import time

from jarvis.platform import host

_LOCAL = host.local_appdata().replace("\\", "/")

# Written by the monitor on every run, via write-then-rename.
STATE = _LOCAL + "/Jarvis/HealthMonitor/state.json"
# Where monitors installed before the rename still write. Read only while the
# new location has no state yet, so a monitor that has not been re-registered
# keeps its liveness visible instead of reading as "never run". Remove with
# persistence.LEGACY_LAYOUTS once the live task is measured on the new layout.
LEGACY_STATE = _LOCAL + "/Jarvis/Deadman/state.json"

# The task repeats every minute. Three missed runs is a real stall rather than
# one slow probe on a loaded machine.
STALE_AFTER = 300


def health_monitor_state_path(path=None, legacy=None):
    """The state file the installed monitor actually writes.

    The new location wins as soon as it exists, even if stale: once the task
    is re-registered, a stale new file is a real stall and must not be masked
    by an old file from the legacy location.
    """
    path = STATE if path is None else path
    legacy = LEGACY_STATE if legacy is None else legacy
    if os.path.exists(path) or not os.path.exists(legacy):
        return path
    return legacy


def _finding(severity, title, detail, where=STATE):
    return {"category": "daemon", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": "win"}


def read_state(path=STATE, retries=2, delay=0.25, sleep=time.sleep):
    """A supervisor's state file, or None when it cannot be read.

    The Windows loops rewrite these every few seconds and the WSL view of the
    drive can catch a write half done (seen 2026-11-02: the reviver's file
    read as unparsable, valid 2 s later). A failed parse is retried briefly
    before it counts as unreadable, so a torn read is not reported as a
    broken supervisor."""
    for attempt in range(retries + 1):
        try:
            # errors="replace": a truncated or partially written state file must
            # degrade to "unreadable", never take the collector down with it.
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            if attempt < retries:
                sleep(delay)
    return None


_PAUSED = re.compile(r"^mail\.json\.paused-(\d{8}T\d{6}Z)\.bak$")


PAUSE_GRACE_DAYS = 7


def pause_age_days(stamp, now):
    """Whole days since a pause stamp like 20260929T131238Z, or None."""
    try:
        when = calendar.timegm(time.strptime(stamp, "%Y%m%dT%H%M%SZ"))
    except (ValueError, OverflowError):
        return None
    return max(0, int(now - when) // 86400)


def mail_paused_since(folder):
    """The stamp of a deliberate mail pause, or "" when mail.json is in place."""
    try:
        if os.path.exists(os.path.join(folder, "mail.json")):
            return ""
        stamps = sorted(m.group(1) for name in os.listdir(folder)
                        if (m := _PAUSED.match(name)))
    except OSError:
        return ""
    return stamps[-1] if stamps else ""


def audit_health_monitor(path=None, now=None):
    """Findings about the Windows-side health monitor's own liveness."""
    now = int(time.time() if now is None else now)
    path = health_monitor_state_path() if path is None else path
    if not os.path.exists(path):
        return [_finding(
            "medium", "the independent Windows monitor has never run",
            "no state file at %s. Install it with "
            "`powershell.exe -File jarvis-health-monitor.ps1 -Install` — without it, "
            "nothing reports an outage while WSL is stopped." % path, path)]

    state = read_state(path)
    if state is None:
        detail = ("%s exists but could not be parsed; its liveness cannot be "
                  "confirmed" % path)
        try:
            from jarvis.platform import mounts as _mounts
            if _mounts.under_windows_drive(path) \
                    and _mounts.windows_drive() == _mounts.STALE:
                detail = ("%s cannot be read because %s; the monitor itself "
                          "may be fine — the drive is the patient"
                          % (path, _mounts.stale_detail()))
        except Exception:
            pass
        return [_finding(
            "medium", "the independent Windows monitor's state is unreadable",
            detail, path)]

    checked = int(state.get("checkedAt") or 0)
    age = now - checked
    if not checked:
        return [_finding(
            "medium", "the independent Windows monitor has not recorded a check",
            "its state file carries no check timestamp", path)]

    if age > STALE_AFTER:
        return [_finding(
            "high", "the independent Windows monitor has stopped checking",
            "its last check was %dm ago (stale after %dm). A scheduled task "
            "stuck in 'Running' refuses every later trigger and still reports "
            "Ready, so this is the failure that hides itself. Clear it with "
            "`Stop-ScheduledTask -TaskName 'JARVIS independent health monitor'`."
            % (age // 60, STALE_AFTER // 60), path)]

    out = []
    if not state.get("healthy", True):
        out.append(_finding(
            "medium", "the independent Windows monitor reports JARVIS unhealthy",
            "%s (as of %dm ago)" % (state.get("reason") or "no reason recorded",
                                    age // 60), path))
    for field, label in (("mailError", "email"), ("toastError", "toast")):
        if not state.get(field):
            continue
        paused = mail_paused_since(os.path.dirname(path)) if field == "mailError" else ""
        if paused:
            # mail.json was deliberately set aside (renamed with a stamp), so the
            # send fails on a missing file by design: a pause, not a fault. A
            # pause is an owner decision, so it reads low at first; one left in
            # place for longer than PAUSE_GRACE is a notification gap again.
            days = pause_age_days(paused, now)
            long = days is None or days > PAUSE_GRACE_DAYS
            out.append(_finding(
                "medium" if long else "low",
                "outage email has been paused for %d days" % days if long and days is not None
                else "outage email is paused",
                "mail.json was paused on %s and no outage email can be sent until "
                "it is restored; the monitor still checks and toasts. Restore the "
                "file to resume." % paused, path))
            continue
        out.append(_finding(
            "medium", "the Windows monitor's %s path is failing" % label,
            "%s. Outage notification would not reach you by %s."
            % (state[field], label), path))
    if not out:
        out.append(_finding(
            "ok", "the independent Windows monitor is checking on JARVIS",
            "last check %ds ago; it verified %s"
            % (age, state.get("reason") or "JARVIS health"), path))
    return out


# ── the instant reviver ─────────────────────────────────────────────────────
#
# `jarvis-reviver.ps1` is the Windows loop that re-runs a stale protection
# source or restarts a dead daemon within seconds. Like the monitor above, its
# own silence hides itself, so this reads its state file the same way.

REVIVER_STATE = _LOCAL + "/Jarvis/Reviver/state.json"

# It writes every five seconds; a minute of silence is a dead loop. The task's
# five-minute trigger restarts it, so this only fires when that failed too.
REVIVER_STALE_AFTER = 60


def audit_reviver(path=REVIVER_STATE, now=None):
    """Findings about the instant reviver's own liveness and posture."""
    now = int(time.time() if now is None else now)
    if not os.path.exists(path):
        return [_finding(
            "medium", "the instant reviver is not installed",
            "nothing revives JARVIS within seconds; an outage waits for the "
            "five-minute wake task. Install with `powershell.exe -File "
            "jarvis-reviver.ps1 -Install`.", path)]
    state = read_state(path)
    if state is None:
        detail = "%s could not be parsed" % path
        try:
            from jarvis.platform import mounts as _mounts
            if _mounts.under_windows_drive(path) \
                    and _mounts.windows_drive() == _mounts.STALE:
                detail = ("%s cannot be read because %s"
                          % (path, _mounts.stale_detail()))
        except Exception:
            pass
        return [_finding("medium", "the instant reviver's state is unreadable",
                         detail, path)]
    # max(0, …): the Windows and WSL clocks drift a few seconds apart.
    age = max(0, now - int(state.get("checkedAt") or 0))
    if age > REVIVER_STALE_AFTER:
        return [_finding(
            "high", "the instant reviver has stopped",
            "its last check was %ds ago. Its task restarts it within five "
            "minutes; if this persists, run `Start-ScheduledTask -TaskName "
            "'jarvis reviver'` in PowerShell." % age, path)]
    if state.get("gaveUp"):
        return [_finding(
            "high", "the instant reviver has used its restart budget",
            "it restarted JARVIS repeatedly without recovery and has stopped "
            "restarting. Last action: %s." % (state.get("lastAction") or "none"), path)]
    if state.get("paused"):
        return [_finding(
            "medium", "the instant reviver is paused for maintenance",
            "it checks but repairs nothing while the pause file exists "
            "(%s)." % os.path.join(os.path.dirname(path), "pause"), path)]
    detail = "checking every few seconds; last check %ds ago" % age
    if state.get("lastResult"):
        detail += "; last recovery: %s" % state["lastResult"]
    return [_finding("ok", "the instant reviver is watching JARVIS", detail, path)]


# ── the native service ──────────────────────────────────────────────────────
#
# On a Windows machine without WSL, `jarvis-native-service.ps1` is the loop
# that starts this daemon and restarts it: systemd and the reviver in one. The
# supervision still runs both ways - it watches the daemon's health endpoint,
# and this reads the state file it writes on every pass.

NATIVE_STATE = _LOCAL + "/Jarvis/NativeService/state.json"
NATIVE_STALE_AFTER = 60


def audit_native_service(path=NATIVE_STATE, now=None, pid=None):
    """Findings about the native service loop's liveness and posture."""
    now = int(time.time() if now is None else now)
    pid = os.getpid() if pid is None else pid
    if not os.path.exists(path):
        return [_finding(
            "high", "the native service is not installed",
            "nothing outside this process restarts it if it dies, and a dead "
            "daemon cannot report its own death. Install with `powershell.exe "
            "-File jarvis-native-service.ps1 -Install`.", path)]
    state = read_state(path)
    if state is None:
        return [_finding("medium", "the native service's state is unreadable",
                         "%s could not be parsed" % path, path)]
    age = max(0, now - int(state.get("checkedAt") or 0))
    if age > NATIVE_STALE_AFTER:
        return [_finding(
            "high", "the native service has stopped",
            "its last check was %ds ago, so nothing would restart this daemon. "
            "Its task restarts it within five minutes; if this persists, run "
            "`Start-ScheduledTask -TaskName 'jarvis native service'` in "
            "PowerShell." % age, path)]
    if state.get("gaveUp"):
        return [_finding(
            "high", "the native service has used its restart budget",
            "it restarted JARVIS repeatedly without recovery and has stopped "
            "restarting. Last action: %s." % (state.get("lastAction") or "none"), path)]
    if state.get("paused"):
        return [_finding(
            "medium", "the native service is paused for maintenance",
            "it checks but starts and stops nothing while the pause file exists "
            "(%s)." % os.path.join(os.path.dirname(path), "pause"), path)]
    if state.get("pid") != pid:
        # It is alive, but it is watching some other process: this daemon was
        # started by hand, so nothing restarts it.
        return [_finding(
            "medium", "this daemon was not started by the native service",
            "the service supervises pid %s; this daemon is pid %d and would "
            "not be restarted if it died." % (state.get("pid") or "none", pid), path)]
    return [_finding("ok", "the native service supervises this daemon",
                     "checking every few seconds; last check %ds ago" % age, path)]


# ── the elevated broker ─────────────────────────────────────────────────────

def audit_broker(now=None):
    """Is the elevated collector broker installed, current and running?"""
    from jarvis.platform import broker
    now = int(time.time() if now is None else now)
    where = broker.ROOT
    if not broker.installed():
        return [_finding(
            "medium", "the elevated collector broker is not installed",
            "posture, memscan, the firewall traffic log and Sysmon policy "
            "inspection run unelevated or remain unreadable and "
            "report what administrator would see as unreadable. Install with "
            "`jarvis broker install` (one UAC prompt).", where)]
    drift = broker.drifted()
    if drift:
        return [_finding(
            "medium", "the elevated broker's scripts differ from this checkout",
            "staged copies of %s are not the reviewed versions, so their results "
            "are not used. Re-run `jarvis broker install` to restage them."
            % ", ".join(drift), where)]
    st = broker.status() or {}
    age = now - int(st.get("finished") or 0)
    if age > broker.MAX_AGE:
        return [_finding(
            "high", "the elevated broker has stopped running",
            "its last completed run was %dm ago; collectors have fallen back to "
            "unelevated results" % (age // 60), where)]
    failed = {k: v.get("error") for k, v in (st.get("jobs") or {}).items() if not v.get("ok")}
    if failed:
        return [_finding("medium", "an elevated broker job is failing",
                         "; ".join(f"{k}: {v}" for k, v in failed.items()), where)]
    if not st.get("admin"):
        return [_finding("high", "the elevated broker is running without administrator",
                         "its task is not using an elevated token, so its results "
                         "are no better than the unelevated collectors'", where)]
    return [_finding("ok", "the elevated broker is feeding privileged read-only evidence",
                     "last run %dm ago, all jobs succeeded" % (age // 60), where)]

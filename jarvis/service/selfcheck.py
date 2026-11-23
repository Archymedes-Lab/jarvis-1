"""The watchdog outside the daemon.

Everything else that reports an outage runs *inside* `jarvis serve`. That
covers a collector going quiet, the Windows bridge dropping, the input hook
dying — but not the one failure that silences all of them at once: the daemon
itself being gone. A dead process cannot mail you about being dead.

So this module is deliberately small, has no state of its own beyond a few meta
keys, and is meant to be run from a systemd timer that is independent of
jarvis.service:

    jarvis selfcheck            report only  (safe, unprivileged)
    jarvis selfcheck --restart  also restart the unit if it is not running
    jarvis selfcheck --quiet    exit status only, for the timer

Health is judged on evidence, not on systemd's opinion alone:

  * the unit is active, AND
  * the newest snapshot in the database is fresher than STALE_AFTER.

The second clause is the important one. `systemctl is-active` reports "active"
for a process that is running and doing nothing at all, which is exactly the
wedged-scheduler case. A snapshot timestamp only advances when a job actually
completed and wrote a result.

Mail goes out through the same Resend transport as everything else, with its
finite age escalation so a timer running every few minutes cannot flood an
inbox during a persistent outage.
"""

import os
import subprocess
import time

from jarvis.core.store import DEFAULT_DB, Store
from jarvis.core.util import iso, now
from jarvis.response import alert

UNIT = "jarvis.service"

# What the outage and recovery messages say first, in everyday words
# (response/plainalert.py); the exact facts follow under "Details:".
SUBJECT_DOWN = "[ARGUS-INSTINCT] Stopped watching this computer"
PLAIN_DOWN = ("ARGUS-INSTINCT has stopped watching this computer. Until it is running again, "
              "nothing new is being checked or recorded.")
PLAIN_DOWN_NEXT = ("What to do: open ARGUS-INSTINCT on this computer to see why it stopped and "
                   "the steps to start it again. If this keeps happening, keep this message: the "
                   "details below show what was wrong.")
SUBJECT_UP = "[ARGUS-INSTINCT] Watching this computer again"
PLAIN_UP = ("ARGUS-INSTINCT is running again and has started checking this computer again. "
            "Anything that happened while it was stopped may not have been recorded.")

# The scheduler runs jobs one at a time and the longest measured job is ~106s,
# so a gap of a couple of minutes is normal. Five is not.
STALE_AFTER = 300

# Never declare the daemon dead on one reading. A check can lose a race with a
# restart, a systemctl call can time out under load, sqlite can be locked mid
# write. Re-check this many times, spaced RECHECK_DELAY apart, and only call it
# down if every single attempt agrees.
ATTEMPTS = 4
RECHECK_DELAY = 6

# How many times to try bringing the unit back before giving up on this pass.
RESTART_ATTEMPTS = 3
RESTART_SETTLE = 8

_M_LAST_ALERT = "selfcheck_last_alert"
_M_LAST_STATE = "selfcheck_last_state"


def _user_env():
    """Environment that lets `systemctl --user` find the user manager.

    jarvis.service runs under the *system* manager (as chris, but system
    scope), and a system service inherits no XDG_RUNTIME_DIR or session bus.
    Without them `systemctl --user` fails with "Failed to connect to bus: No
    medium found", which reads identically to "the timer is not installed" --
    so the daemon would report its own watchdog missing and try to reinstall
    something that was there all along.
    """
    env = dict(os.environ)
    runtime = env.get("XDG_RUNTIME_DIR")
    if not runtime or not os.path.isdir(runtime):
        candidate = f"/run/user/{os.getuid()}"
        if os.path.isdir(candidate):
            env["XDG_RUNTIME_DIR"] = candidate
    return env


def _run(cmd, env=None):
    # Notification authority belongs to the daemon's main PID. systemctl is
    # linked to libsystemd and may use an inherited NOTIFY_SOCKET, which makes
    # the manager log "reception only permitted for main PID" for every call
    # (and risks a child notification being mistaken for the daemon's own).
    # Same strip as coverage._cmd; the sudo path below inherits too.
    base = dict(os.environ) if env is None else dict(env)
    for key in ("NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID"):
        base.pop(key, None)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=30,
                           env=base)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def _systemctl(*args, user=False, privileged=False):
    """Run systemctl, escalating to a passwordless sudo only when required.

    Reads never need privilege. A restart of a *system* unit does, and this
    runs unprivileged from a user timer on purpose — a monitor should not need
    to be root to keep itself alive. install.sh drops a sudoers rule that
    permits exactly two verbs on exactly this unit and nothing else; without
    it the read path still works and the restart simply reports that it could
    not act, which is itself worth mailing about.
    """
    base = ["systemctl"] + (["--user"] if user else []) + list(args)
    rc, out, err = _run(base, env=_user_env() if user else None)
    if rc == 0 or user or not privileged:
        return rc, out, err
    blocked = ("access denied" in err.lower() or "authentication" in err.lower()
               or "interactive authentication required" in err.lower())
    if not blocked:
        return rc, out, err
    return _run(["sudo", "-n"] + base)


def unit_state():
    """(scope, ActiveState) for whichever manager owns the unit, or ("", "")."""
    for scope, user in (("system", False), ("user", True)):
        rc, out, _ = _systemctl("show", UNIT, "-p", "ActiveState",
                                "--value", user=user)
        if rc == 0 and out:
            return scope, out
    return "", ""


def uptime_s():
    """Seconds the unit has been active, or None if that cannot be read.

    Snapshots are legitimately stale for the first few seconds after a start,
    so "how long has it been up" is the difference between a daemon that is
    booting and one that is wedged.
    """
    scope, _ = unit_state()
    if not scope:
        return None
    rc, out, _ = _systemctl("show", UNIT, "-p", "ActiveEnterTimestampMonotonic",
                            "--value", user=(scope == "user"))
    try:
        started_us = int(out)
        if started_us <= 0:
            return None
        with open("/proc/uptime", errors="replace") as fh:
            boot_s = float(fh.read().split()[0])
        return max(0.0, boot_s - started_us / 1_000_000)
    except (ValueError, OSError, IndexError):
        return None


def newest_snapshot(db_path=DEFAULT_DB):
    """(kind, ts) of the most recently written snapshot, or ("", 0)."""
    store = Store(db_path)
    try:
        row = store.db.execute(
            "SELECT kind, ts FROM snapshots ORDER BY ts DESC LIMIT 1").fetchone()
        return (row["kind"], int(row["ts"])) if row else ("", 0)
    except Exception:
        return "", 0
    finally:
        store.close()


def check(db_path=DEFAULT_DB):
    """Return a verdict dict. Never raises."""
    scope, state = unit_state()
    kind, ts = newest_snapshot(db_path)
    age = now() - ts if ts else None

    up = uptime_s() if state == "active" else None
    starting = up is not None and up < STALE_AFTER

    problems = []
    if not scope:
        problems.append(f"{UNIT} is not installed under either systemd manager")
    elif state != "active":
        problems.append(f"{UNIT} is {state or 'unknown'} ({scope} manager)")

    # Only judge snapshot freshness once the daemon has been up long enough to
    # have produced one. Otherwise every restart would immediately re-page.
    if not starting:
        if ts == 0:
            problems.append("the database holds no collector snapshots at all")
        elif age is not None and age > STALE_AFTER:
            problems.append(
                f"the newest snapshot is {age}s old ({kind}, written "
                f"{iso(ts)}) — the scheduler has written nothing for over "
                f"{STALE_AFTER}s, so it is wedged or dead even though the "
                f"process is up")

    return {
        "healthy": not problems,
        "scope": scope,
        "active_state": state,
        "uptime": int(up) if up is not None else None,
        "starting": starting,
        "newest_kind": kind,
        "newest_ts": ts,
        "age": age,
        "problems": problems,
    }


TIMER = "jarvis-selfcheck.timer"


def timer_state():
    """(ActiveState, UnitFileState) of the out-of-daemon watchdog timer."""
    rc, out, _ = _systemctl("show", TIMER, "-p", "ActiveState",
                            "-p", "UnitFileState", user=True)
    if rc != 0:
        return "", ""
    vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return vals.get("ActiveState", ""), vals.get("UnitFileState", "")


def systemd_supervision():
    """(watchdog seconds, Restart=) of this daemon's own system unit. A unit with
    a watchdog and Restart=always is an out-of-process supervisor: systemd kills
    and restarts the daemon when the scheduler stops reporting progress. (0, "")
    when unreadable."""
    rc, out, _ = _systemctl("show", UNIT, "-p", "WatchdogUSec", "-p", "Restart")
    if rc != 0:
        return 0, ""
    vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    raw = vals.get("WatchdogUSec", "0")
    seconds = 0
    try:
        seconds = int(raw) // 1_000_000 if raw.isdigit() else _span_seconds(raw)
    except ValueError:
        seconds = 0
    return seconds, vals.get("Restart", "")


def _span_seconds(text):
    """'15min' / '1h 30s' / 'infinity' -> seconds (0 when unset or infinite)."""
    if not text or text in ("0", "infinity"):
        return 0
    units = {"h": 3600, "min": 60, "s": 1, "ms": 0.001, "us": 0.000001}
    total = 0.0
    for part in text.split():
        num = "".join(ch for ch in part if ch.isdigit() or ch == ".")
        unit = part[len(num):]
        total += float(num) * units.get(unit, 0)
    return int(total)


def timer_will_fire():
    """True only if the timer has a next elapse scheduled.

    "active" is not the same as "will fire". A timer built on OnUnitInactiveSec
    whose chain was broken -- by a disable/enable cycle, a failed run, a manual
    stop -- sits at ActiveState=active with NextElapse=infinity: armed,
    enabled, and never going to run again, reporting healthy to every status
    command there is. That is the worst failure a watchdog can have, so it is
    checked explicitly rather than inferred from ActiveState.
    """
    rc, out, _ = _systemctl("show", TIMER, "-p", "NextElapseUSecRealtime",
                            "-p", "NextElapseUSecMonotonic", user=True)
    if rc != 0:
        return False
    for line in out.splitlines():
        _, _, val = line.partition("=")
        val = val.strip()
        if val and val not in ("infinity", "0", "n/a"):
            return True
    return False


def ensure_timer():
    """Re-arm the watchdog timer if it has stopped. Returns "" when healthy.

    This is the other half of a mutual supervision loop: the timer restarts the
    daemon when the daemon dies, and the daemon re-arms the timer when the
    timer stops. Neither can be the single thing whose failure ends monitoring,
    which is the whole point — a watchdog nothing watches is just a process.

    Only meaningful when the timer is installed at all; an uninstalled timer is
    a reporting matter for coverage, not something to conjure from here.
    """
    active, enabled_state = timer_state()
    if not active:
        return "not installed"
    if active == "active" and enabled_state == "enabled" and timer_will_fire():
        return ""
    # A restart re-evaluates the schedule from scratch, which is what recovers
    # an armed-but-never-firing timer; enable makes it survive the next login.
    _systemctl("enable", TIMER, user=True)
    _systemctl("restart", TIMER, user=True)
    active2, enabled2 = timer_state()
    if active2 == "active" and timer_will_fire():
        return ""
    if active2 == "active":
        return (f"{TIMER} is active but has no next elapse — it will never "
                f"fire again (unit file schedule is broken)")
    return f"could not re-arm {TIMER} (state={active2 or 'unknown'}/{enabled2})"


def confirm_unhealthy(db_path=DEFAULT_DB, attempts=ATTEMPTS):
    """Check repeatedly; return the verdict only once every attempt agrees.

    A single reading is not evidence. The daemon may be mid-restart, systemctl
    may have timed out behind a loaded bus, the database may have been locked
    for the instant we looked. Any single healthy reading wins immediately —
    we are trying to avoid crying wolf, not to build a case for the prosecution.
    """
    verdict = check(db_path)
    for _ in range(max(1, attempts) - 1):
        if verdict["healthy"]:
            return verdict
        time.sleep(RECHECK_DELAY)
        verdict = check(db_path)
    return verdict


# The root-owned restart gate (scripts/repair/jarvis-restart-gate): when it is
# installed a system-unit restart goes through it, so the fault is re-checked
# as root and the warrant recorded before the monitor is stopped. A refusal
# (exit 3) or the rate limit (exit 4) is final: never fall back around it.
RESTART_GATE = "/usr/local/sbin/jarvis-restart-gate"
GATE_REFUSED, GATE_RATE_LIMITED = 3, 4


def _gate_restart(db_path):
    """(rc, error) from one restart through the gate."""
    reason = "unit-down" if check(db_path).get("active_state") != "active" else "health-silent"
    rc, out, err = _run(["sudo", "-n", RESTART_GATE, "--actor", "selfcheck", "--reason", reason])
    if rc in (GATE_REFUSED, GATE_RATE_LIMITED):
        return rc, f"the restart gate declined: {(out or err).strip()[-200:]}"
    return rc, (err or out or f"the restart gate returned {rc}") if rc else ""


def restart(attempts=RESTART_ATTEMPTS, db_path=DEFAULT_DB):
    """Bring the unit back, trying more than once. Returns "" on success.

    `systemctl restart` can fail transiently — the bus is busy, a previous stop
    is still settling, the start limit was hit. Each of those is worth another
    go, and a `reset-failed` in between clears the one case systemd will
    otherwise refuse to retry on its own.
    """
    scope, _ = unit_state()
    if not scope:
        return f"{UNIT} is not installed under either systemd manager"
    user = (scope == "user")
    gate = not user and os.access(RESTART_GATE, os.X_OK)
    last = ""
    for i in range(max(1, attempts)):
        if i:
            # Clears start-limit-hit, which makes systemd refuse to start a
            # unit that has restarted too often — exactly the state that must
            # never leave this machine unmonitored.
            _systemctl("reset-failed", UNIT, user=user, privileged=True)
            time.sleep(RESTART_SETTLE)
        if gate:
            rc, err = _gate_restart(db_path)
            if rc in (GATE_REFUSED, GATE_RATE_LIMITED):
                return err
        else:
            rc, _, err = _systemctl("restart", UNIT, user=user, privileged=True)
        if rc == 0:
            time.sleep(RESTART_SETTLE)
            if check(db_path)["active_state"] == "active":
                return ""
            last = "restart reported success but the unit is not active"
        else:
            last = err or f"systemctl restart returned {rc}"
    return f"{last} (after {attempts} attempts)"


def _notify(db_path, verdict, restart_err=None, restarted=False):
    """Mail once initially and at the 1h, 6h, and 24h outage thresholds.

    A recovery is always mailed once, so "jarvis is back" is never inferred
    from silence — the same rule the in-daemon alerts follow.
    """
    conf = alert.load_conf()
    if not alert.enabled(conf):
        return "alerts are not configured"

    store = Store(db_path)
    try:
        last_state = store.get_meta(_M_LAST_STATE, "") or ""
        state = "healthy" if verdict["healthy"] else "down"

        if verdict["healthy"]:
            # A new outage must start a fresh clock even if no outage mail
            # was delivered, or recovery delivery is still pending.
            store.set_meta('selfcheck_first_down', 0)
            store.set_meta('selfcheck_escalation', -1)
            if last_state != "down":
                store.set_meta(_M_LAST_STATE, state)
                store.set_meta("selfcheck_retry_at", 0)
                return ""
            if now() < int(store.get_meta('selfcheck_retry_at', 0) or 0):
                return ""
            body = (f"{PLAIN_UP}\n\nDetails:\n"
                    f"newest snapshot: {verdict['newest_kind']} "
                    f"{iso(verdict['newest_ts'])} ({verdict['age']}s ago)\n"
                    f"unit: {UNIT} {verdict['active_state']} "
                    f"({verdict['scope']} manager)\n")
            err = alert.deliver(conf, SUBJECT_UP, body, category="system", severity="high")
            if not err:
                alert.record_send(store)
                store.set_meta(_M_LAST_STATE, state)
                store.set_meta(_M_LAST_ALERT, 0)
                store.set_meta('selfcheck_first_down',0)
                store.set_meta('selfcheck_escalation',-1)
                store.set_meta('selfcheck_retry_at',0)
            else:
                store.set_meta('selfcheck_retry_at',now()+300)
            return err

        first_down = int(store.get_meta('selfcheck_first_down',0) or 0)
        if not first_down:
            first_down = now()
            store.set_meta('selfcheck_first_down',first_down)
        level = sum(now()-first_down >= t for t in (3600,21600,86400))
        delivered = int(store.get_meta('selfcheck_escalation',-1))
        if last_state == 'down' and level <= delivered:
            return ''
        retry = int(store.get_meta('selfcheck_retry_at',0) or 0)
        if now() < retry:
            return ''

        lines = [PLAIN_DOWN, ""]
        if restarted:
            lines += ["It tried to restart itself automatically; the restart reported success."
                      if not restart_err else
                      "It tried to restart itself automatically, and that did not work.", ""]
        lines += [PLAIN_DOWN_NEXT, "", "Details:", "JARVIS is NOT monitoring this machine."]
        lines += [f"  - {p}" for p in verdict["problems"]]
        lines += ["", f"unit:  {UNIT} {verdict['active_state'] or '?'} "
                      f"({verdict['scope'] or 'not installed'})"]
        if verdict["newest_ts"]:
            lines.append(f"last snapshot: {verdict['newest_kind']} at "
                         f"{iso(verdict['newest_ts'])}")
        if restarted:
            lines += ["", "A restart was attempted automatically."
                          if not restart_err
                          else f"Automatic restart FAILED: {restart_err}"]
        lines += ["", "This message comes from a separate safety check (jarvis selfcheck) "
                      "that runs on its own, so it can reach you even when the main part "
                      "has stopped."]
        err = alert.deliver(conf, SUBJECT_DOWN, "\n".join(lines) + "\n",
                            category="system", severity="critical")
        if not err:
            alert.record_send(store)
            store.set_meta(_M_LAST_STATE, state)
            store.set_meta(_M_LAST_ALERT, now())
            store.set_meta('selfcheck_escalation',level)
            store.set_meta('selfcheck_retry_at',0)
        else:
            store.set_meta('selfcheck_retry_at',now()+300)
        return err
    except Exception as exc:
        return str(exc)
    finally:
        store.close()


def run(db_path=DEFAULT_DB, do_restart=False, notify=True, attempts=ATTEMPTS):
    """One full pass: confirm, optionally restart, optionally mail.

    Order matters. We confirm before acting so a restart is never triggered by
    a single bad reading, and we mail *after* the restart attempt so the alert
    can say whether recovery worked — an alert that says "down, and I could not
    bring it back" needs a human; one that says "down, restarted, healthy" does
    not.
    """
    verdict = confirm_unhealthy(db_path, attempts)
    restarted, restart_err = False, ""

    if not verdict["healthy"] and do_restart:
        restarted = True
        restart_err = restart(db_path=db_path)
        after = check(db_path)
        verdict["after_restart"] = after
        if after["healthy"]:
            # It is back. Say so rather than paging as if it were still down.
            verdict = dict(after, recovered_by_restart=True)

    mail_err = ""
    if notify:
        mail_err = _notify(db_path, verdict, restart_err, restarted) or ""

    verdict["restarted"] = restarted
    verdict["restart_error"] = restart_err
    verdict["mail_error"] = mail_err
    return verdict

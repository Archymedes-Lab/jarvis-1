"""Is the helper alive, unmodified and actually producing data?"""

import json
import os

from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now
from jarvis.platform import windows as collect_windows

from .analysis import _latency_findings, _typing_findings, sort_findings
from .common import (
    _M_DUPES,
    _M_OVERSIZE,
    _M_SESSION,
    HOOK_PS1,
    HOST_META,
    READ_CAP,
    STATES_META,
    _mget_int,
    _sha256,
)
from .helper import (
    _alive_mtime,
    _alive_path,
    _paths,
    _pid_path,
    _pidfile_pid,
    _staged_matches_source,
    _stop_all,
    helper_count,
    owner,
    owner_hook_verified,
    owner_output_size,
    owner_pulse_mtime,
    running,
    start,
    stop,
)
from .ingest import ingest

MISS_LIMIT = 2         # watchdog passes with nothing moving before "down"

START_GRACE = 120      # a fresh helper's pulse may not have propagated yet

BACKOFF_BASE = 20

BACKOFF_CAP = 600

FLAP_WINDOW = 6 * 3600

FLAP_N = 4

GIVEUP_FAILS = 8

_M_FAILS = "input_hook_fails"          # consecutive failed supervise cycles

_M_LASTTRY = "input_hook_last_try"     # ts of the last (re)start attempt

_M_RESTARTS = "input_hook_restarts"    # json list of recent restart ts

_M_OKSINCE = "input_hook_ok_since"     # ts we last became healthy

_M_SRCSHA = "input_hook_src_sha256"    # content pin of the trusted helper

_M_PROBE = "input_hook_probe"          # json snapshot for change-based liveness


def _newest_beat(store):
    row = store.db.execute("SELECT MAX(ts) t FROM input_beats").fetchone()
    return int(row["t"]) if row and row["t"] else 0


def _restart_log(store):
    try:
        return [int(x) for x in json.loads(store.get_meta(_M_RESTARTS, "[]")
                                           or "[]")]
    except (ValueError, TypeError):
        return []


def liveness(store):
    """Is the helper alive — decided by *change*, not by any absolute clock.

    Every timestamp available from WSL (a heartbeat's embedded ts, a DrvFs
    file mtime) rides the Windows clock, so a skew there defeats any "is this
    recent?" test. What cannot be faked by a skew is motion: between two
    watchdog passes a live helper always advances its 10 s `.alive` pulse, its
    output file, or its newest heartbeat. Nothing advancing across N passes is
    death.

    Returns (state, misses) where state is "fresh", "stale" or "new" (first
    observation — no prior snapshot to compare against).
    """
    snap = {"alive": _alive_mtime(),
            "size": _jsonl_size(store),
            "beat": _newest_beat(store)}
    try:
        prev = json.loads(store.get_meta(_M_PROBE, "") or "{}")
    except ValueError:
        prev = {}
    if not prev:
        snap["misses"] = 0
        store.set_meta(_M_PROBE, json.dumps(snap))
        return "new", 0
    moved = (snap["alive"] != prev.get("alive")
             or (snap["size"] >= 0 and snap["size"] != prev.get("size"))
             or snap["beat"] != prev.get("beat"))
    misses = 0 if moved else int(prev.get("misses", 0)) + 1
    snap["misses"] = misses
    store.set_meta(_M_PROBE, json.dumps(snap))
    return ("fresh" if moved else "stale"), misses


def _verify_pin(store):
    """Surface a change to the trusted helper source.

    Not a verdict — a legitimate `git pull` and tampering look identical from
    here — but the code that gets launched changing without notice is worth
    seeing, and an unreadable source means we cannot restart from known-good.
    """
    cur = _sha256(HOOK_PS1)
    if not cur:
        return [_finding(
            "input", "high",
            "the input-hook helper script is missing or unreadable",
            f"{HOOK_PS1} could not be hashed — the monitor cannot be restarted "
            f"from a known-good copy", HOOK_PS1)]
    old = store.get_meta(_M_SRCSHA, "")
    if old != cur:
        store.set_meta(_M_SRCSHA, cur)
    if old and old != cur:
        return [_finding(
            "input", "medium",
            "the input-hook helper script changed on disk",
            f"sha256 {old[:12]} → {cur[:12]}. If you did not just update "
            f"JARVIS, treat an unannounced change to a security monitor as "
            f"tampering", HOOK_PS1)]
    return []


def _jsonl_size(store):
    try:
        _w, wsl_out = _paths()
        return os.path.getsize(wsl_out)
    except OSError:
        return -1


def _dupes(store):
    """(age_seconds, "pid,pid") if ingest saw >1 helper recently, else None."""
    v = store.get_meta(_M_DUPES, "")
    if not v or ":" not in v:
        return None
    ts, pids = v.split(":", 1)
    try:
        age = now() - int(ts)
    except ValueError:
        return None
    return (age, pids) if age < 180 else None


def _outside_desktop(store):
    """(helper session, desktop session) when the newest beat shows the hook
    running somewhere it cannot see the user's input, else None."""
    own, _, desktop = (store.get_meta(_M_SESSION, "") or "").partition(":")
    if own.lstrip("-").isdigit() and desktop.lstrip("-").isdigit() \
            and int(desktop) >= 0 and own != desktop:
        return int(own), int(desktop)
    return None


def _flap_finding(store):
    recent = [t for t in _restart_log(store) if now() - t < FLAP_WINDOW]
    if len(recent) < FLAP_N:
        return []
    hrs = max(1, (now() - min(recent)) // 3600)
    return [_finding(
        "input", "high",
        f"the injected-input monitor has restarted {len(recent)} times in {hrs}h",
        "a security monitor that keeps dying is itself the finding — something "
        "may be calling Stop-Process on it, or it is crashing on this host. "
        "Note what holds focus when it dies", "input_beats")]


STATE_WINDOW = 24 * 3600

OWNER_STALE_S = 180    # the owner's pulse frozen this long: run our own hook

OWNER_UNREAD_S = 900   # the owner's output not drained this long: nobody reads it, run ours

OWNER_VERIFY_S = 300   # how often the owner's pulse pid is checked to be a real hook

_M_OWNER = "input_hook_owner_probe"    # {"mtime": owner pulse mtime, "seen": local ts it last moved}


def deferral(store):
    """(owner path, seconds its pulse has been frozen) when another install owns
    the machine's hook, else None. Decided by motion, not by comparing a
    Windows file time with this clock (the two have disagreed by an hour)."""
    other = owner()
    win_out = _paths()[0]
    if not other or other.lower() == win_out.lower():
        return None
    mtime = owner_pulse_mtime(other)
    try:
        prev = json.loads(store.get_meta(_M_OWNER, "") or "{}")
    except ValueError:
        prev = {}
    t = now()
    seen = t if (mtime is not None and mtime != prev.get("mtime")) or not prev else int(prev.get("seen") or t)
    # Drained: the owner's consumer truncates the file after each read, so a
    # size that only grows means its hook runs and nothing reads it (the WSL
    # daemon down while Windows is up).
    size = owner_output_size(other)
    drained = t if (size is not None and (size == 0 or size < int(prev.get("size") or 0))) or not prev \
        else int(prev.get("drained") or t)
    verified, checked = prev.get("verified"), int(prev.get("checked") or 0)
    if mtime is not None and t - checked >= OWNER_VERIFY_S:
        result = owner_hook_verified(other)
        if result is not None:
            verified, checked = result, t
    store.set_meta(_M_OWNER, json.dumps({"mtime": mtime, "seen": seen, "size": size,
                                         "drained": drained, "verified": verified, "checked": checked}))
    frozen = t - seen if mtime is not None else OWNER_STALE_S + 1
    if verified is False:
        frozen = max(frozen, OWNER_STALE_S + 1)
    elif t - drained > OWNER_UNREAD_S:
        frozen = max(frozen, OWNER_STALE_S + 1)
    return other, frozen, verified is False, t - drained


def host_findings(store, clock=None):
    """What the resident host says about itself (2026-10-31): hooks Windows
    dropped and the watchdog reinstalled, deafness a reinstall did not cure,
    output lines dropped at the queue cap, and tasks that threw."""
    t = clock if clock is not None else now()
    out = []
    try:
        states = [s for s in json.loads(store.get_meta(STATES_META, "[]") or "[]")
                  if isinstance(s, list) and len(s) >= 4 and t - int(s[0]) < STATE_WINDOW]
    except (ValueError, TypeError):
        states = []
    drops = [s for s in states if s[1] == "reinstalling"]
    deaf = [s for s in states if s[1] == "still-deaf"]
    # Unconfirmed until soaked (2026-11-01): on this machine the watchdog fired
    # about every 7 minutes at ~3 s gaps while the owner typed, with no
    # confirmed drop. Low and medium until the kb/mouse split explains it.
    def _which(s):
        if len(s) >= 6 and s[4] >= 0 and s[5] >= 0:
            return f"; keyboard hook quiet {s[4] // 1000} s, mouse hook quiet {s[5] // 1000} s"
        return ""
    if drops:
        last = drops[-1]
        out.append(_finding(
            "input", "low",
            f"input reached the desktop {len(drops)} time(s) in 24 h without a hook callback; reinstalled",
            f"{int(last[2]) // 1000} s of input with no callback (last at {iso(int(last[0]))}, "
            f"foreground {last[3] or '?'}{_which(last)}). Unconfirmed: Windows dropping the "
            f"hook, a hook installed after this one swallowing input, or touch/pen input the "
            f"hooks never see all look like this. The hook was reinstalled either way",
            "inputwatch"))
    if deaf:
        out.append(_finding(
            "input", "medium", "input kept arriving without a hook callback after a reinstall",
            f"{len(deaf)} time(s) in 24 h (last at {iso(int(deaf[-1][0]))}{_which(deaf[-1])}). "
            f"A hook that cannot be re-established cannot see injection; until the keyboard/"
            f"mouse split shows which input is missed this is not a verdict",
            "inputwatch"))
    try:
        host = json.loads(store.get_meta(HOST_META, "") or "{}")
    except ValueError:
        host = {}
    if isinstance(host, dict) and host:
        dropped = int(host.get("out_dropped") or 0)
        if dropped:
            out.append(_finding(
                "input", "medium", f"the input hook dropped {dropped} output line(s)",
                "its output queue reached its cap; the counters still count every event, "
                "but the dropped lines' detail is lost", "inputwatch"))
        faults = int(host.get("task_faults") or 0)
        if faults:
            out.append(_finding(
                "input", "low", f"{faults} input-hook task fault(s) since it started",
                f"a periodic task (audio, brightness, sound, heartbeat, watchdog) threw and "
                f"was skipped; the hook itself keeps running. Last: "
                f"{str(host.get('last_fault') or '?')[:160]}", "inputwatch"))
    return out


def supervise(store, deep=False):
    """Keep the hook alive; make repeated failure loud. Returns (pids, findings).

    Healthy path is cheap: drain the helper's output, see a fresh heartbeat,
    return — no powershell.exe. Only a stale or absent heartbeat escalates to
    the interop-crossing probe and a backed-off restart.

    `deep` adds the one health check that does cross the interop boundary on a
    healthy host — the LowLevelHooksTimeout registry read — so the frequent
    watchdog can leave it to the slower full audit.
    """
    out = _verify_pin(store)
    ingest(store)
    if store.get_meta(_M_OVERSIZE):
        store.set_meta(_M_OVERSIZE, "")
        out.append(_finding(
            "input", "high",
            "the input hook's output file blew past its size cap",
            f"over {READ_CAP // (1024 * 1024)} MiB of helper output in one "
            f"interval — it is writing without bound, and the overflow was "
            f"dropped rather than loaded", "input.jsonl"))

    last_try = _mget_int(store, _M_LASTTRY)
    fails = _mget_int(store, _M_FAILS)

    # One hook per machine (owner decision 2026-10-31): when the marker names
    # another install, defer to it while its pulse moves, and take over only
    # when it has been frozen for OWNER_STALE_S, so a stale or forged marker
    # can never leave the machine with no hook.
    deferred = deferral(store)
    if deferred:
        other, frozen, fake, unread = deferred
        where = other.rsplit("\\", 2)[1]
        if frozen <= OWNER_STALE_S:
            if os.path.exists(_pid_path()) or os.path.exists(_alive_path()):
                _stop_all()
                out.append(_finding(
                    "input", "low", f"stopped this install's input hook: {where} owns it",
                    "the owner's hook is back (pulse moving); ours was stopped so one "
                    "hook runs, as the owner marker in %LOCALAPPDATA% says", "inputwatch"))
            # Low, not ok: standing down is a state worth seeing, because a
            # forged marker is how a same-user program would ask for it.
            out.append(_finding(
                "input", "low", f"the input hook is provided by the {where} install",
                f"this machine's owner marker names {other}; its pulse moved "
                f"{frozen}s ago. If it freezes for {OWNER_STALE_S // 60} min, this "
                f"install runs its own", "inputwatch"))
            return [], sort_findings(out)
        why = ("its pulse file names a process that is not that install's hook; a touched "
               "file must not make every install stand down" if fake else
               f"its output has not been read for {unread}s, so its hook runs and nothing "
               f"consumes it" if unread > OWNER_UNREAD_S else
               f"its pulse has not moved for {frozen}s")
        out.append(_finding(
            "input", "high" if fake else "medium",
            f"the {where} install's input hook is not usable; running ours",
            f"the owner marker names {other}, but {why}. This install supervises its "
            f"own hook until the owner's is back", "inputwatch"))

    # Two helpers writing the same file. Reconcile before anything else: stop
    # every hook, start exactly one.
    dup = _dupes(store)
    if dup:
        store.set_meta(_M_DUPES, "")
        _stop_all(pids=dup[1].split(","))
        store.set_meta(_M_LASTTRY, now())
        store.set_meta(_M_PROBE, "")
        err = start()
        store.set_meta(_M_FAILS, 0 if not err else fails + 1)
        out.append(_finding(
            "input", "high" if err else "medium",
            "duplicate input-hook helpers were running",
            f"heartbeats from pids {dup[1]} in one interval — they double-count "
            f"and corrupt the totals. Stopped all and started one"
            + (f"; restart failed: {err}" if err else ""), "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    state, misses = liveness(store)

    # "new" means no prior snapshot to diff against. Normally that earns one
    # grace pass — but if nothing is even on disk (no pid file, no pulse file,
    # empty output) there is nothing to wait for, so treat it as down.
    present = (os.path.exists(_pid_path()) or os.path.exists(_alive_path())
               or _jsonl_size(store) > 0)
    if state == "new" and not present:
        state, misses = "stale", MISS_LIMIT

    outside = _outside_desktop(store) if state in ("fresh", "new") else None
    if outside:
        # Alive, heartbeating, and deaf: a hook in another session never sees
        # this desktop's keyboard. Observed 2026-09-15 after WSL was restarted
        # by a background task — 85 minutes of zero keys reported as healthy.
        store.set_meta(_M_SESSION, "")
        _stop_all()
        store.set_meta(_M_LASTTRY, now())
        store.set_meta(_M_PROBE, "")
        err = start()
        store.set_meta(_M_FAILS, 0 if not err else fails + 1)
        out.append(_finding(
            "input", "high",
            "the input hook was running outside the desktop session",
            f"helper in Windows session {outside[0]}, desktop in session {outside[1]} — it "
            f"saw no keyboard or mouse input at all. Stopped it"
            + (f"; restart failed: {err}" if err else " and restarted it on the desktop"),
            "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    if state in ("fresh", "new"):
        # Alive. Reset the failure counter and re-emit any flap finding.
        if fails:
            store.set_meta(_M_FAILS, 0)
        if not _mget_int(store, _M_OKSINCE):
            store.set_meta(_M_OKSINCE, now())
        out += _flap_finding(store)
        latest = store.db.execute(
            "SELECT * FROM input_beats ORDER BY ts DESC LIMIT 1").fetchone()
        out += _latency_findings(store, latest, probe_registry=deep)
        out += host_findings(store)
        out += _typing_findings(store, latest)
        pid = _pidfile_pid()
        embedded = _newest_beat(store)
        seen = f", last heartbeat stamped {iso(embedded)}" if embedded else ""
        out.append(_finding(
            "input", "ok", "the injected-input monitor is healthy",
            f"pid {pid or '?'} — pulse, output file or heartbeat advanced since "
            f"the last check{seen}", "inputwatch"))
        return ([pid] if pid else []), sort_findings(out)

    if last_try and now() - last_try < START_GRACE:
        out.append(_finding(
            "input", "low", "the injected-input monitor is starting",
            f"launched {now() - last_try}s ago; waiting for its first pulse",
            "inputwatch"))
        return [], sort_findings(out)

    if misses < MISS_LIMIT:
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor has gone quiet",
            f"nothing has advanced for {misses} watchdog pass(es) — pulse, "
            f"output file and heartbeat all frozen. One more and it is cycled",
            "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    # Frozen for MISS_LIMIT passes. Confirm across the interop boundary.
    alive = bool(running())
    pid = _pidfile_pid()
    helpers = helper_count()
    if helpers > 1:
        _stop_all()
        alive = False
        out.append(_finding(
            "input", "medium", f"{helpers} input-hook helpers were running",
            "more than one hook writing the same file — stopped all, starting "
            "one", "inputwatch"))
    elif alive:
        # Process up but everything frozen — the hook was removed or the loop
        # is wedged. Same remedy either way.
        out.append(_finding(
            "input", "high",
            "the input hook is running but has stopped watching",
            f"pid {pid} is alive, yet its pulse, output file and heartbeat have "
            f"all been frozen for {misses} passes — the low-level hook was "
            f"removed or the message loop is stuck. Cycling it", "inputwatch"))
        _stop_all()
        alive = False

    if not collect_windows.available():
        out.append(_finding(
            "input", "medium",
            "the injected-input monitor is down and cannot be restarted",
            "the Windows interop bridge is unavailable — environmental, not "
            "necessarily tampering; will retry", "inputwatch"))
        return [], sort_findings(out)

    delay = min(BACKOFF_BASE * (2 ** fails), BACKOFF_CAP)
    if last_try and now() - last_try < delay:
        out.append(_finding(
            "input", "high" if fails >= FLAP_N else "medium",
            "the injected-input monitor is down",
            f"restart backed off — {fails} consecutive failures, next attempt "
            f"in {delay - (now() - last_try)}s", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    store.set_meta(_M_LASTTRY, now())
    store.set_meta(_M_PROBE, "")          # next liveness() starts a clean baseline
    err = start()
    if not err and not _staged_matches_source():
        stop()
        err = "the staged helper does not match its trusted source"

    if err:
        n = fails + 1
        store.set_meta(_M_FAILS, n)
        sev = ("critical" if n >= GIVEUP_FAILS else
               "high" if n >= FLAP_N else "medium")
        out.append(_finding(
            "input", sev, "could not restart the injected-input monitor",
            f"{err} — {n} consecutive failures", "inputwatch"))
        return [], sort_findings(out + _flap_finding(store))

    log = [t for t in _restart_log(store) if now() - t < 86400] + [now()]
    store.set_meta(_M_RESTARTS, json.dumps(log[-64:]))
    store.set_meta(_M_FAILS, 0)
    store.set_meta(_M_OKSINCE, 0)
    out.append(_finding(
        "input", "medium",
        "the injected-input monitor was down and has been restarted",
        "synthetic-input recording had stopped; a fresh hook is starting up",
        "inputwatch"))
    return [], sort_findings(out + _flap_finding(store))

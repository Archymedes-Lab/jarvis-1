"""Positive control for the Linux process sensor: prove it still sees, end to end.

Collector receipts prove a job ran, not that it would have seen anything: a
blinded or starved sensor looks healthy to them. Every run this job starts one
harmless, labelled process and looks for its ProcessCreate event in Sysmon for
Linux's journal, through the same parser the sysmon_linux collector uses. A
probe that never comes back is a finding; one that does is a measured round trip
(latency) kept as evidence.

Invariants (tests/test_sensorprobe.py):

* Harmless and bounded: at most one child per run, a fixed root-owned
  program (true(1)) given only the label, no shell, empty environment, 5 s
  timeout. Nothing is contained, changed or deleted.
* No false sighting: the label is random per run and never placed on any other
  command line (the journal is filtered in Python), and a sighting needs event
  id 1, the probe program's resolved image and the label as its own argument,
  read only from records journald attributes to the sysmon unit running as
  root (`journal.TRUSTED_MATCH`); `logger -t sysmon` lines from other accounts
  are not evidence (measured forgeable 2026-11-01).
* Honest outcome: seen, late (seen on the next run), missed or skipped. Never
  "ok" without a sighting; a stopped sensor is reported as skipped, not healthy.
* Bounded: waits use the monotonic clock; a late check reads at most LATE_S of
  journal; the kept history is HISTORY entries.
* Pipeline: once a probe is seen in the journal, a later run checks that the
  sysmon_linux collector's own cursor passed it and that its start history
  recorded the probe image at or after the probe time. Cursor past, nothing
  recorded: the collector's window lost an event the sensor wrote (high).

Not covered (assurance.py `sensor_positive_control`): a later start of the same
image can stand in for a lost probe in the pipeline check; selective blinding
(a Sysmon configuration that excludes an intruder's images but not true(1));
the Windows sensors; and an intruder who runs as root (it can forge the
sensor's own records).
"""

import json
import os
import secrets
import sqlite3
import stat
import subprocess
import time

from jarvis.core.finding import finding

from .sysmon_linux import journal

META = "sensorprobe_state"
PREFIX = "argus-probe-"
PROGRAMS = ("/usr/bin/true", "/bin/true")
SPAWN_TIMEOUT_S = 5
WAIT_S = 5.0
POLL_S = 0.25
SKEW_S = 2
LATE_S = 300
BLIND_AFTER = 2
HISTORY = 96
CURSOR_KEY = "sysmon_linux_last"   # the sysmon_linux collector's incremental cursor
PIPELINE_MAX_WAITS = 4             # runs to wait for that cursor to pass a seen probe
WHERE = "Sysmon for Linux (process starts)"


def _f(severity, title, detail):
    return finding("integrity", severity, title, detail, where=WHERE)


def program(paths=PROGRAMS, lstat=os.stat):
    """The first probe program that is a regular file owned by root and not
    writable by group or others, or None. A writable true(1) is not run."""
    for path in paths:
        try:
            st = lstat(path)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022:
            return path
    return None


def spawn(path, label):
    """Start the probe once. '' on success, else the error type."""
    try:
        subprocess.run([path, label], env={}, cwd="/", stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=SPAWN_TIMEOUT_S, close_fds=True, check=False)
        return ""
    except (OSError, subprocess.SubprocessError) as exc:
        return type(exc).__name__


def read(since, until=None):
    """Trusted Sysmon journal text in [since, until]; '' when unreadable."""
    return journal.trusted_text(since, until)


def sighted(text, label, image):
    """True when a ProcessCreate of `image` carries `label` as an argument."""
    for ev in journal._parse(text):
        if ev.get("id") != 1:
            continue
        if os.path.realpath(ev.get("Image", "")) != image:
            continue
        if label in (ev.get("CommandLine") or "").split():
            return True
    return False


def _load(store):
    try:
        state = json.loads(store.get_meta(META, "{}") or "{}")
    except (TypeError, ValueError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    if not isinstance(state.get("history"), list):
        state["history"] = []
    return state


def _record(state, at, outcome, latency_ms=None):
    state["history"] = (state["history"] + [{"t": int(at), "outcome": outcome,
                                             "latency_ms": latency_ms}])[-HISTORY:]


def _summary(state):
    seen = sorted(h["latency_ms"] for h in state["history"]
                  if h.get("outcome") == "seen" and isinstance(h.get("latency_ms"), int))
    if not seen:
        return "no measured round trip kept yet"
    return (f"{len(seen)} of the last {len(state['history'])} probes seen in time; "
            f"median {seen[len(seen) // 2]} ms, slowest {seen[-1]} ms")


def _check_pending(state, reader):
    """Resolve the previous run's unseen probe: late or missed. Returns a finding or None."""
    pending = state.pop("pending", None)
    if not isinstance(pending, dict) or not pending.get("label"):
        return None
    t = float(pending.get("t", 0))
    text = reader(int(t) - SKEW_S, int(t) + LATE_S)
    if sighted(text, pending["label"], pending.get("image", "")):
        _record(state, t, "late")
        state["misses"] = 0
        return _f("low", "Sysmon for Linux answered its positive control late",
                  f"The probe started at {time.strftime('%H:%M:%S', time.gmtime(t))} UTC was "
                  f"not in the journal within {WAIT_S:g} s but arrived before the next run. "
                  "Sysmon may be draining a backlog; events are delayed, not lost.")
    _record(state, t, "missed")
    state["misses"] = int(state.get("misses", 0)) + 1
    return None


def pipeline(store, image, t):
    """Did the sysmon_linux pass ingest a start of `image` at or after `t`?

    'ingested', 'lost' (cursor past t, no such start recorded), 'pending'
    (cursor not yet past t) or 'unknown' (no cursor or no start history)."""
    try:
        cursor = int(store.get_meta(CURSOR_KEY, 0) or 0)
    except (TypeError, ValueError):
        cursor = 0
    if not cursor:
        return "unknown"
    if cursor <= t:
        return "pending"
    try:
        row = store.db.execute("SELECT max(last_seen) FROM start_images WHERE image = ?",
                               (image,)).fetchone()
    except (sqlite3.Error, AttributeError):
        return "unknown"
    last = row[0] if row else None
    return "ingested" if last is not None and int(last) >= int(t) else "lost"


def _check_pipeline(state, store):
    check = state.get("pipeline")
    if not isinstance(check, dict) or "t" not in check:
        return None
    result = pipeline(store, check.get("image", ""), int(check["t"]))
    if result == "pending" and int(check.get("waits", 0)) + 1 < PIPELINE_MAX_WAITS:
        check["waits"] = int(check.get("waits", 0)) + 1
        return None
    state.pop("pipeline", None)
    state["pipeline_last"] = result
    if result == "lost":
        return _f("high", "Sysmon recorded the probe but the sysmon_linux collector never ingested it",
                  "The sensor wrote the probe's ProcessCreate event and the collector's cursor has "
                  "moved past it, yet its start history holds no start of that program since then. "
                  "Events in that window were seen by the sensor and dropped by the collector.")
    if result == "pending":
        return _f("low", "sysmon_linux has not read past the last seen probe",
                  f"The collector's cursor stayed behind a probe for {PIPELINE_MAX_WAITS} runs; "
                  "check that the sysmon_linux job is running.")
    return None


def run(store, now=None, active=journal.active, find_program=program, start=spawn,
        reader=read, clock=time.monotonic, sleep=time.sleep):
    state = _load(store)
    findings = []
    for check in (_check_pending(state, reader), _check_pipeline(state, store)):
        if check:
            findings.append(check)

    def done(extra):
        store.set_meta(META, json.dumps(state, sort_keys=True))
        return findings + extra

    misses = int(state.get("misses", 0))
    if misses >= BLIND_AFTER:
        findings.append(_f(
            "high", "Sysmon for Linux did not see its positive-control probes: the process "
                    "sensor may be blind",
            f"{misses} harmless labelled process starts in a row never reached the journal as "
            "Sysmon ProcessCreate events, even late. Process-start detections on this host are "
            "not working while this holds. Check `systemctl status sysmon`, its configuration "
            "(`sysmon -c`) and journald rate limits. " + _summary(state)))

    if not active():
        state["skipped"] = int(state.get("skipped", 0)) + 1
        return done([_f("low", "sensor positive control skipped: Sysmon for Linux is not running",
                        "No probe was started, so nothing is proved about the process sensor. The "
                        "sysmon_linux collector reports why the sensor is down.")])
    path = find_program()
    if path is None:
        return done([_f("low", "sensor positive control has no safe probe program",
                        "Neither /usr/bin/true nor /bin/true is a root-owned file that only root "
                        "can write, so no probe was started.")])
    image = os.path.realpath(path)
    label = PREFIX + secrets.token_hex(8)
    wall = time.time() if now is None else now
    t0 = clock()
    error = start(path, label)
    if error:
        return done([_f("low", "sensor positive control could not start its probe",
                        f"Starting {path} failed ({error}); nothing was proved this run.")])
    while True:
        if sighted(reader(int(wall) - SKEW_S), label, image):
            latency = int((clock() - t0) * 1000)
            _record(state, wall, "seen", latency)
            state["misses"] = 0
            state["last_seen"] = int(wall)
            # Keep the oldest unverified probe: replacing it every run would reset
            # its wait count and hide a cursor that never moves.
            state.setdefault("pipeline", {"t": int(wall), "image": image})
            if misses >= BLIND_AFTER:
                findings.pop()  # the sensor sees again; the blind finding no longer holds
                findings.append(_f("medium", "Sysmon for Linux sees again after missed probes",
                                   f"{misses} probes in a row were missed before this one. Events "
                                   "from that period were not recorded."))
            return done([_f("ok", "Sysmon for Linux answered its positive control",
                            f"A labelled probe process was seen as a ProcessCreate event "
                            f"{latency} ms after it started. " + _summary(state))])
        if clock() - t0 >= WAIT_S:
            break
        sleep(POLL_S)
    state["pending"] = {"label": label, "t": int(wall), "image": image}
    severity = "medium" if misses + 1 >= BLIND_AFTER else "low"
    return done([_f(severity, "Sysmon for Linux has not yet seen its positive-control probe",
                    f"A labelled probe process was not in the journal within {WAIT_S:g} s. The next "
                    f"run checks again; {BLIND_AFTER} misses in a row are reported as a blind "
                    "sensor. " + _summary(state))])

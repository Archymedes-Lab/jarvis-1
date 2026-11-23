"""Restart autopsy: every stop of jarvis.service gets a named cause, or an alarm.

Stopping the monitor is the cheapest way to blind it, so a stop is security
evidence, not housekeeping. On 2026-11-04 the owner's Windows wake watchdog
read wsl.exe's own error text as the unit state and restarted a healthy
daemon (64 times since 2026-10-19), through a passwordless sudoers rule that
lets any process of the desktop user do the same. Nothing reported it.

For every stop the journal records, three independent witnesses are
cross-examined:

    systemd   what happened to the unit: a stop/restart job (and of what
              kind), a crash with its exit status, a watchdog timeout, or an
              exit with no stop request (a signal)
    Sysmon    which process issued it: the systemctl (or kill) that ran just
              before, its lineage, and where that lineage came from (the
              Windows interop bridge when it has no Linux parent; a sudo
              child is joined to the sudo that spawned it)
    claims    what a known restarter says it did and why: the wake watchdog's
              and the reviver's logs on Windows

Verdicts:

    explained    a known actor's signature in the lineage AND (for the Windows
                 restarters) a matching claim; its reason is not contradicted
    unjustified  explained, but its stated reason is contradicted by systemd
                 (it claimed the unit was down; systemd stopped a running
                 unit): medium, the restarter is faulty
    crashed      the daemon died (exit status, or systemd's watchdog): medium
    unexplained  anything else, including missing evidence: high

Invariants (tests/test_restarts.py holds each):
    I1  no stop is silently accepted: every stop of the unit receives exactly
        one verdict, and only `explained` produces no finding
    I2  missing evidence is unknown, never benign: an unreadable journal is a
        visibility finding; Sysmon not caught up past the stop is retried
        MAX_TRIES times, then the stop is `unexplained`
    I3  no self-exoneration: a restarter's claim alone never explains a stop;
        the issuing lineage must carry that restarter's signature
    I4  bounded: journal lines, Sysmon window, stops per run, kept verdicts,
        listed lineage and stored text all have ceilings
    I5  privacy: only the issuing command (when it is a restart/stop/kill of
        the unit) is kept, truncated; the rest of the lineage is image names
"""

import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone

from jarvis.core.finding import finding as _finding
from jarvis.platform import host
from jarvis.platform.sysmon_records import TRUSTED_MATCH
from jarvis.platform.sysmon_records import parse as _parse

UNIT = "jarvis.service"
STATE_META = "restart_autopsy_v1"   # {"cursor", "pending": {inv: tries}, "verdicts": [...]}

# systemd catalogue message ids (systemd/src/systemd/sd-messages.h)
MSG_STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"   # unit stopping (a stop/restart job runs)
MSG_STOPPED = "9d1aaa27d60140bd96365438aad20286"    # job done; JOB_TYPE says stop or restart
MSG_EXITED = "98e322203f7a4ed290d09fe03c09fe15"     # main process exited, EXIT_CODE/EXIT_STATUS
MSG_DEACTIVATED = "7ad2d189f7e94e70a38c781354912448"
MSG_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"     # failed with result X
MSG_STARTED = "39f53479d3a045ac8e11786248231fbf"

SETTLE_S = 20          # leave a stop alone this long so Sysmon can drain its queue
LOOKBACK_S = 90        # Sysmon window before a stop in which its issuer must appear
AFTER_S = 2            # ... and after it, by process start time
# Sysmon writes to the journal behind its own queue: on 2026-11-03 15:26 the
# issuer's record reached the journal ~80 s after the stop. Read this far past
# the stop by journal time, then order by the process start time (UtcTime).
INGEST_LAG_S = 300
MAX_TRIES = 6          # runs that wait for Sysmon to pass a stop before it is unexplained
MAX_STOPS_PER_RUN = 3     # about 4 s of Sysmon reading each; the frequent lane caps a job at 60 s
MAX_LINES = 20000
MAX_VERDICTS = 200
MAX_CHAIN = 8
MAX_CMD = 200
KEEP_S = 7 * 24 * 3600
FIRST_RUN_S = 2 * 24 * 3600   # how far back the first run looks
CLAIM_WINDOW_S = 20 * 60      # Windows and WSL clocks were measured 9 min 47.7 s apart
MAX_CLAIM_BYTES = 2 * 1024 * 1024

# A systemctl/kill aimed at this unit. Shell control operators end a command.
ISSUE_RE = re.compile(r"\bsystemctl\b[^|;&]*\b(restart|stop|kill|try-restart|reload-or-restart|"
                      r"condrestart|isolate)\b[^|;&]*\bjarvis(?:\.service)?\b")
SYSTEMCTL_STATES = ("active", "reloading", "inactive", "failed", "activating", "deactivating",
                    "maintenance", "refreshing")

# The exact command the Windows wake watchdog, the reviver and quickstart send
# through wsl.exe. Its presence proves only "one of those scripts, or anyone
# imitating them": a matching claim in that script's own log is required too.
WINDOWS_RESTART_CMD = ("bash -lc systemctl restart jarvis.service 2>/dev/null "
                       "|| sudo -n systemctl restart jarvis.service")
# 2026-11-04 on: the same restarters try the gate first and name themselves;
# this form reaches systemctl only when the gate is not installed.
WINDOWS_GATED_RE = re.compile(
    r"^bash -lc if \[ -x /usr/local/sbin/jarvis-restart-gate \]; then exec sudo -n "
    r"/usr/local/sbin/jarvis-restart-gate --actor (reviver|wake-watchdog|quickstart) "
    r"--reason [a-z-]+; fi; " + re.escape(WINDOWS_RESTART_CMD[len("bash -lc "):]) + "$")
# The root-owned restart gate (scripts/repair/jarvis-restart-gate) records each
# decision with the InvocationID it stops, before acting. Only root can write
# its log, so a gate record is the one claim the desktop user cannot forge.
GATE = "/usr/local/sbin/jarvis-restart-gate"
# The gate's own process (or the sudo that runs it), by its exact root-owned
# path, not a shell line that merely mentions it.
GATE_PROC_RE = re.compile(r"^(?:\S*/?python3(?:\.\d+)?\s+(?:-I\s+)?|sudo\s+-n\s+)?"
                          + re.escape(GATE) + r"\s+--actor\s")
GATE_LOG = "/var/log/jarvis-restart-gate.jsonl"
MAX_GATE_LINES = 2000
# (actor, argv fragment found in the issuing lineage)
LINUX_ACTORS = (
    ("selfcheck", "-m jarvis selfcheck"),
    ("deploy", "deploy_root_runtime.py"),
)
# Windows restarters: (actor, log path under the Windows user's LOCALAPPDATA, claim regex)
CLAIM_SOURCES = (
    ("wake-watchdog", ("WSLKeepalive", "jarvis-wake.log"),
     re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) jarvis\.service is '(.*)' -- restarting\s*$")),
    ("reviver", ("Jarvis", "Reviver", "revive.log"),
     re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) restarting jarvis\.service: (.*)$")),
)


def _run(argv, timeout=40):
    """(returncode, stdout) or (None, reason)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, check=False)
    except FileNotFoundError:
        return None, f"{argv[0]} is not installed"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{argv[0]} failed: {type(exc).__name__}"
    if argv[0] == "journalctl" and "insufficient permissions" in (r.stderr or ""):
        return None, "the system journal is not readable by this account"
    return r.returncode, r.stdout


# ── witness 1: systemd ──────────────────────────────────────────────────

def read_stops(since, run=_run):
    """([stop, ...], problem). One stop per ended invocation of the unit, oldest first."""
    code, out = run(["journalctl", "-u", UNIT, "-o", "json", "--no-pager",
                     "--since", f"@{int(since)}", "-n", str(MAX_LINES)])
    if code is None:
        return [], out
    if code != 0:
        return [], f"journalctl -u {UNIT} exited {code}"
    inv = {}
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        # systemd's own records carry INVOCATION_ID; the daemon's output lines
        # carry the trusted _SYSTEMD_INVOCATION_ID (and its main pid as _PID).
        iid = d.get("INVOCATION_ID") or d.get("_SYSTEMD_INVOCATION_ID") or ""
        if not iid:
            continue
        try:
            ts = int(d.get("__REALTIME_TIMESTAMP") or 0) / 1e6
        except ValueError:
            continue
        rec = inv.setdefault(iid, {"invocation": iid, "boot": d.get("_BOOT_ID", ""), "pids": {}})
        if d.get("_PID") != "1":   # the daemon's own lines: its main pid
            rec["pids"][d.get("_PID")] = rec["pids"].get(d.get("_PID"), 0) + 1
            continue
        mid, msg = d.get("MESSAGE_ID", ""), str(d.get("MESSAGE", ""))
        if mid == MSG_STOPPING:
            rec.setdefault("t", ts)
            rec["requested"] = True
        elif mid == MSG_STOPPED:
            rec["job"] = d.get("JOB_TYPE") or ""
            rec.setdefault("t", ts)
        elif mid == MSG_EXITED:
            rec.setdefault("t", ts)
            rec["exit"] = f"{d.get('EXIT_CODE', '')}/{d.get('EXIT_STATUS', '')}"
        elif mid == MSG_DEACTIVATED:
            rec.setdefault("t", ts)
            rec["ended"] = True
        elif mid == MSG_FAILED or "Watchdog timeout" in msg:
            rec.setdefault("t", ts)
            if "watchdog" in msg.lower():
                rec["watchdog"] = True
    stops = []
    for rec in inv.values():
        if "t" not in rec:
            continue   # still running
        pids = rec.pop("pids")
        rec["main_pid"] = max(pids, key=pids.get) if pids else ""
        ex = rec.get("exit", "")
        # dumped (a core) or a non-zero exit is the daemon dying; killed/<sig>
        # or a clean exit with no stop job needs a sender, like any stop.
        rec["kind"] = ("watchdog" if rec.get("watchdog")
                       else "requested" if rec.get("requested")
                       else "crash" if ex.startswith("dumped/") or (ex.startswith("exited/") and ex != "exited/0")
                       else "signal")
        stops.append(rec)
    return sorted(stops, key=lambda r: r["t"]), ""


def main_pid_of(invocation, run=_run):
    """The daemon's main pid in one invocation, from its own first output
    lines (it writes few, mostly at start), or ""."""
    if not re.fullmatch(r"[0-9a-f]{32}", invocation or ""):
        return ""
    code, out = run(["journalctl", f"_SYSTEMD_INVOCATION_ID={invocation}", "-o", "json",
                     "--no-pager", "-n", "20"], timeout=20)
    if code != 0:
        return ""
    for line in (out or "").splitlines():
        try:
            pid = json.loads(line).get("_PID")
        except ValueError:
            continue
        if pid and pid != "1":
            return pid
    return ""


# ── witness 2: Sysmon lineage ───────────────────────────────────────────

def started_at(e):
    """Sysmon's own event time (UtcTime): when the process started, not when
    the journal received the record."""
    value = (e.get("UtcTime") or "").strip()
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None


def read_sysmon(t, run=_run):
    """(process-create events started in [t-LOOKBACK_S, t+AFTER_S], newest
    Sysmon event time read, problem)."""
    # Only records journald attributes to the root sysmon unit (FZ-04, platform/sysmon_records.TRUSTED_MATCH):
    # a `logger -t sysmon` line from any account could otherwise name a known
    # restarter as the issuer and explain a stop away. Forged lines are counted
    # and reported by the sensor probe (collectors/telemetry/sensorprobe.py).
    code, out = run(["journalctl", *TRUSTED_MATCH, "-o", "cat", "--no-pager",
                     "--since", f"@{int(t - LOOKBACK_S)}", "--until", f"@{int(t + INGEST_LAG_S) + 1}"],
                    timeout=60)
    if code is None:
        return [], None, out
    events = _parse(out)
    times = [x for x in (started_at(e) for e in events) if x]
    keep = [e for e in events if e.get("id") == 1
            and t - LOOKBACK_S <= (started_at(e) or 0) <= t + AFTER_S]
    return keep, (max(times) if times else None), ""


def _clean(v):
    v = (v or "").strip()
    return "" if v in ("-", "<unknown process>", "<unknown>") else v


def _key(e, field):
    return _clean(e.get(field + "Guid")) or _clean(e.get(field + "Id"))


def lineage(events, t, main_pid=""):
    """The issuer of a stop at `t` and its lineage, or None.

    Issuer: the newest systemctl aimed at the unit started no later than the
    stop (or a kill naming the daemon's main pid). Lineage follows parent ids
    inside the window. A root process with no recorded parent that follows a
    `sudo ... <same command>` by the same user within 5 s is that sudo's
    child: Sysmon records exec, not the fork sudo makes first.
    """
    def at(e):
        return started_at(e) or 0.0

    before = [e for e in events if at(e) <= t + 0.5]
    issued = [e for e in before if os.path.basename(_clean(e.get("Image"))) == "systemctl"
              and ISSUE_RE.search(e.get("CommandLine", ""))]
    if not issued and main_pid:
        kill = re.compile(rf"\bkill\b.*(?<!\d){re.escape(str(main_pid))}(?!\d)")
        issued = [e for e in before if kill.search(e.get("CommandLine", ""))]
    if not issued:
        return None
    issuer = max(issued, key=at)
    by_key = {}
    for e in events:
        for field in ("ProcessGuid", "ProcessId"):
            if _clean(e.get(field)):
                by_key.setdefault(_clean(e.get(field)), e)
    chain, cur, seen = [issuer], issuer, {id(issuer)}
    while len(chain) < MAX_CHAIN:
        parent = by_key.get(_key(cur, "ParentProcess"))
        if parent is None and _clean(cur.get("User")) == "root":
            cmd = cur.get("CommandLine", "")
            parent = next((s for s in sorted(before, key=at, reverse=True)
                           if os.path.basename(_clean(s.get("Image"))) == "sudo"
                           and cmd and cmd in s.get("CommandLine", "")
                           and 0 <= at(cur) - at(s) <= 5
                           and _clean(s.get("CurrentDirectory")) == _clean(cur.get("CurrentDirectory"))),
                          None)
        if parent is None or id(parent) in seen:
            break
        chain.append(parent)
        seen.add(id(parent))
        cur = parent
    # Sysmon records an exec as a new start in the same pid (bash -lc "a || b"
    # execs b): the earlier images of a chain pid carry the command that ran.
    execs = [e for c in chain for e in events
             if e is not c and _clean(e.get("ProcessId")) == _clean(c.get("ProcessId"))
             and 0 <= at(c) - at(e) <= 5]
    top = chain[-1]
    # A chain whose top has no Linux parent and runs in a Windows folder came
    # in through wsl.exe (the /init interop bridge).
    from_windows = (not _clean(top.get("ParentImage"))
                    and _clean(top.get("CurrentDirectory")).startswith("/mnt/"))
    return {"issuer": issuer, "chain": chain, "execs": execs, "from_windows": from_windows,
            "at": at(issuer)}


def actor_of(found):
    """(actor, evidence needed) from the issuing lineage's signature:
    "" none, "claim" a restarter's own log, "gate" the root-owned gate log."""
    cmds = [re.sub(r"\s+", " ", e.get("CommandLine", "")).strip()
            for e in found["chain"] + found.get("execs", [])]
    if any(GATE_PROC_RE.match(c) for c in cmds):
        return "gate", "gate"
    for actor, fragment in LINUX_ACTORS:
        if any(fragment in c for c in cmds):
            return actor, ""
    if found["from_windows"]:
        if WINDOWS_RESTART_CMD in cmds:
            return "windows", "claim"
        named = next((m.group(1) for m in map(WINDOWS_GATED_RE.match, cmds) if m), "")
        if named:
            return named, "claim"
    return "", ""


def gate_record(invocation, path=GATE_LOG, stat=os.stat):
    """(the gate's "allowed" record for this InvocationID or None, problem).

    The log counts only while root owns it and nobody else can write it."""
    try:
        st = stat(path)
    except FileNotFoundError:
        return None, "the restart gate log does not exist"
    except OSError as exc:
        return None, f"the restart gate log is unreadable: {type(exc).__name__}"
    if st.st_uid != 0 or st.st_mode & 0o022:
        return None, "the restart gate log is not root-owned and protected: its records cannot be trusted"
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-MAX_GATE_LINES:]
    except OSError as exc:
        return None, f"the restart gate log is unreadable: {type(exc).__name__}"
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("decision") == "allowed" and rec.get("invocation") == invocation:
            return rec, ""
    return None, ""


# ── witness 3: the restarters' own claims ───────────────────────────────

def read_claims(root=None):
    """([(actor, unix time, reason)], problem) from the Windows restarters'
    logs, bounded. A log that exists but cannot be read is a problem (the
    claim is unknown), not an empty log."""
    if root is None:
        try:
            root = host.local_appdata()
        except Exception:   # noqa: BLE001 - no Windows side: nothing to read
            root = ""
    claims, problems = [], []
    if not root:
        return claims, ""
    for actor, parts, rx in CLAIM_SOURCES:
        path = os.path.join(root, *parts)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as fh:
                fh.seek(max(0, os.path.getsize(path) - MAX_CLAIM_BYTES))
                text = fh.read().replace(b"\0", b"").decode("utf-8", "replace")
        except OSError as exc:
            problems.append(f"{actor} log unreadable: {type(exc).__name__}")
            continue
        for line in text.splitlines():
            m = rx.match(line.strip())
            if m:
                try:
                    when = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp()
                except ValueError:
                    continue
                claims.append((actor, when, re.sub(r"\s+", " ", m.group(2)).strip()[:MAX_CMD]))
    return claims, "; ".join(problems)


def match_claim(claims, t, used=()):
    """The closest unused claim within CLAIM_WINDOW_S of `t`, or None."""
    near = [c for c in claims if abs(c[1] - t) <= CLAIM_WINDOW_S and c not in used]
    return min(near, key=lambda c: abs(c[1] - t)) if near else None


SILENT_RE = re.compile(r"silent for (\d+)\s*s")
# The daemon's own command line, as Sysmon records it for each child it starts
# (the daemon writes little to the journal, so its pid is not always known).
DAEMON_RE = re.compile(r"(?:jarvis-release\.py|-m jarvis)\s+serve\b")


def daemon_children(events, main_pid=""):
    return [e for e in events
            if DAEMON_RE.search(e.get("ParentCommandLine") or "")
            or (main_pid and _clean(e.get("ParentProcessId")) == str(main_pid))]


def contradiction(actor, reason, stop, events=()):
    """Why an independent witness contradicts the actor's stated reason, or "".

    wake-watchdog says the unit was not active: systemd's own record of a
    stop job on a running unit contradicts it.
    reviver says the daemon was silent (its HTTP health did not answer):
    Sysmon contradicts it when the daemon's main process was still starting
    its collectors during that silence, i.e. it was slow, not dead.
    """
    if actor == "reviver":
        m = SILENT_RE.search(reason)
        if m:
            span = min(int(m.group(1)), LOOKBACK_S)
            kids = [e for e in daemon_children(events, stop.get("main_pid", ""))
                    if stop["t"] - span <= (started_at(e) or 0) <= stop["t"] - 1]
            if kids:
                return (f"it said the daemon was silent for {m.group(1)} s, but the daemon started "
                        f"{len(kids)} collector process(es) in the last {span} s before the restart: "
                        "it was slow (load), not dead")
    if actor == "wake-watchdog" and stop.get("requested"):
        word = reason.strip().lower()
        if word not in SYSTEMCTL_STATES:
            return (f"it read the unit state as '{reason[:60]}', which is not a systemctl state "
                    "(wsl.exe's own error text), while systemd stopped a running unit")
        if word in ("active", "activating", "reloading"):
            return f"it restarted on the healthy state '{word}'"
        return f"it claimed the unit was '{word}', but systemd stopped a running unit"
    return ""


# ── the autopsy ─────────────────────────────────────────────────────────

def _brief(e):
    cmd = re.sub(r"\s+", " ", e.get("CommandLine", "")).strip()
    return cmd[:MAX_CMD] if ISSUE_RE.search(cmd) or "kill" in cmd.split()[:1] else ""


def examine(stop, run=_run, claims=(), used=(), claims_problem=""):
    """One verdict for one stop, or None to retry later (Sysmon not caught up)."""
    v = {"t": stop["t"], "invocation": stop["invocation"], "kind": stop["kind"],
         "job": stop.get("job", ""), "exit": stop.get("exit", "")}
    if stop["kind"] == "watchdog":
        return {**v, "verdict": "crashed", "actor": "systemd watchdog",
                "reason": "the daemon stopped answering its systemd watchdog and was killed"}
    if stop["kind"] == "crash":
        return {**v, "verdict": "crashed", "actor": "the daemon itself",
                "reason": f"the main process died ({stop.get('exit')})"}
    if not stop.get("main_pid"):
        stop = {**stop, "main_pid": main_pid_of(stop["invocation"], run)}
    events, newest, problem = read_sysmon(stop["t"], run)
    if problem:
        return {**v, "verdict": "unexplained", "actor": "", "reason": "",
                "evidence": f"Sysmon could not be read: {problem}"}
    if newest is None or newest < stop["t"] + AFTER_S:
        return None   # Sysmon has not yet recorded past the stop: its lineage may be partial
    found = lineage(events, stop["t"], stop.get("main_pid", ""))
    if found is None:
        return {**v, "verdict": "unexplained", "actor": "", "reason": "",
                "evidence": ("no systemctl or kill aimed at the unit in the "
                             f"{LOOKBACK_S} s of Sysmon process records before it")}
    v["issuer"] = _brief(found["issuer"])
    v["issuer_user"] = _clean(found["issuer"].get("User"))
    v["lineage"] = [os.path.basename(_clean(e.get("Image"))) or "?" for e in found["chain"]]
    v["origin"] = ("Windows, through wsl.exe (no Linux parent)" if found["from_windows"]
                   else "a Linux process" if _clean(found["chain"][-1].get("ParentImage"))
                   else "unknown (parent not recorded)")
    actor, needs = actor_of(found)
    if needs == "gate":
        rec, why = gate_record(stop["invocation"])
        if rec is None:
            return {**v, "verdict": "unexplained", "actor": "", "reason": "",
                    "evidence": why or "the restart came through the gate's path, but the gate "
                                       "recorded no allowed restart of this instance"}
        return {**v, "verdict": "explained", "actor": f"{str(rec.get('actor'))[:24]} via restart gate",
                "reason": f"{str(rec.get('reason'))[:24]}: {str(rec.get('why'))[:MAX_CMD]}",
                "contradiction": ""}
    if not actor:
        return {**v, "verdict": "unexplained", "actor": "", "reason": "",
                "evidence": "the issuing lineage matches no known restarter"}
    if needs == "claim":
        named = "" if actor == "windows" else actor
        claim = match_claim([c for c in claims if not named or c[0] == named], stop["t"], used)
        if claim is None and claims_problem:
            return None   # the claim is unknown, not absent: retry
        if claim is None:
            return {**v, "verdict": "unexplained", "actor": "",
                    "reason": "", "evidence": ("the command matches the Windows restarters' but none "
                                               "of their logs records a restart at that time")}
        actor, when, reason = claim
        v["claim_offset_s"] = round(when - stop["t"], 1)
        v["claim"] = claim
    else:
        reason = {"selfcheck": "jarvis selfcheck found the unit down or hung",
                  "deploy": "a release switch (deploy_root_runtime.py)"}[actor]
    why_not = contradiction(actor, reason, stop, events)
    return {**v, "verdict": "unjustified" if why_not else "explained", "actor": actor,
            "reason": reason, "contradiction": why_not}


def _verdict_finding(v):
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(v["t"]))
    where = f"jarvis.service stop {v['invocation'][:12]}"
    trail = "; ".join(x for x in (
        f"issued by {v['issuer']!r} as {v.get('issuer_user') or '?'}" if v.get("issuer") else "",
        "lineage " + " < ".join(v["lineage"]) if v.get("lineage") else "",
        f"from {v['origin']}" if v.get("origin") else "",
        v.get("evidence", "")) if x)
    if v["verdict"] == "unexplained":
        return _finding("tamper", "high", "JARVIS was stopped by an unidentified process",
                        f"at {when} ({v['kind']} stop, job {v.get('job') or 'none'}): {trail}. "
                        "Stopping the monitor blinds it; if you did not do this, treat it as an "
                        "attack. Read `journalctl -u jarvis.service` and Linux Sysmon around that time.",
                        where)
    if v["verdict"] == "unjustified":
        return _finding("tamper", "medium", f"JARVIS was restarted without a real fault by the {v['actor']}",
                        f"at {when}: {v['contradiction']}. {trail}. The restart blinded every "
                        "collector for its duration; fix the restarter.", where)
    if v["verdict"] == "crashed":
        return _finding("tamper", "medium", "JARVIS stopped unexpectedly",
                        f"at {when}: {v['reason']}; systemd restarted it", where)
    return None


def audit(store, hosts=None, now=None, run=_run, claims_reader=read_claims):
    now = time.time() if now is None else now
    out, problems = [], []
    try:
        state = json.loads(store.get_meta(STATE_META, "") or "{}")
        if not isinstance(state, dict):
            raise ValueError
    except (ValueError, TypeError):
        state = {}
        problems.append("stored restart verdicts could not be read; starting again")
    cursor = float(state.get("cursor") or now - FIRST_RUN_S)
    pending = dict(state.get("pending") or {})
    verdicts = [x for x in state.get("verdicts") or [] if isinstance(x, dict)
                and now - x.get("t", 0) <= KEEP_S]
    judged = {x["invocation"] for x in verdicts}

    stops, problem = read_stops(cursor - LOOKBACK_S, run)
    if problem:
        problems.append(problem)
    todo = [s for s in stops if s["invocation"] not in judged]
    ready = [s for s in todo if now - s["t"] >= SETTLE_S][:MAX_STOPS_PER_RUN]
    claims, claims_problem = (claims_reader() if any(s["kind"] in ("requested", "signal") for s in ready)
                              else ([], ""))
    used = [x["claim"] for x in verdicts if x.get("claim")]
    used = [tuple(c) for c in used]
    for s in ready:
        v = examine(s, run, claims, used, claims_problem)
        key = s["invocation"]
        if v is None:
            pending[key] = pending.get(key, 0) + 1
            if pending[key] < MAX_TRIES:
                continue
            v = {"t": s["t"], "invocation": key, "kind": s["kind"], "job": s.get("job", ""),
                 "verdict": "unexplained", "actor": "", "reason": "",
                 "evidence": (f"the evidence stayed unreadable for {MAX_TRIES} runs: "
                              + (claims_problem or "Linux Sysmon never recorded past the stop"))}
        pending.pop(key, None)
        if v.get("claim"):
            used.append(tuple(v["claim"]))
            v["claim"] = list(v["claim"])
        verdicts.append(v)
    waiting = [s["t"] for s in todo if s["invocation"] not in {x["invocation"] for x in verdicts}]
    new_cursor = min(waiting) if waiting else max([cursor] + [s["t"] for s in stops])
    store.set_meta(STATE_META, json.dumps({"cursor": new_cursor, "pending": pending,
                                           "verdicts": verdicts[-MAX_VERDICTS:]}))
    for v in verdicts[-MAX_VERDICTS:]:
        f = _verdict_finding(v)
        if f:
            out.append(f)
    if problems:
        out.append(_finding("visibility", "medium", "JARVIS stops not fully attributed",
                            "; ".join(problems)[:1500], "restart autopsy"))
    return out


def ledger(store):
    """Every judged stop in the last KEEP_S, newest first (for the CLI and API)."""
    try:
        state = json.loads(store.get_meta(STATE_META, "") or "{}")
    except (ValueError, TypeError):
        return []
    return sorted(state.get("verdicts") or [], key=lambda v: -v.get("t", 0))

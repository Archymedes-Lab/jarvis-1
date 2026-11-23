"""Event history retention: everything for 30 days, then only what is suspicious.

Owner decision 2026-11-04: the forensic event log had filled its budget (2 GiB at
~84 MiB/day) and was refusing new process and sensor history. Keep every event
for KEEP_DAYS, then rewrite each older segment to keep only its suspicious
events (core/eventlog.py `compact`); a segment with none is removed whole. Both
are recorded, so the loss is explicit and the chain still verifies.

What counts as suspicious is decided here, late, with what is known when the
segment ages out, not when the event arrived: threat data downloaded since and
rules added since still catch an old event. Deterministic, no model. In doubt,
keep: an event is dropped only when no rule below matches.

Kept, whatever else:
  * any event inside an active hold (incident evidence, an owner hold);
  * any event a current finding cites by sequence number;
  * ARGUS's own outage records and Defender protection events (not routine health);
  * persistence and tampering: registry writes under auto-start keys, scheduled
    task registration or change, alternate data streams, remote threads,
    process access, driver loads;
  * a process start or image load whose hash, or a connection or DNS query whose
    address or name, is a known indicator;
  * a process start a detection rule matches (collectors/telemetry/techniques.py),
    or one run from a folder malware favours (temp, AppData, ProgramData, /tmp).

Bounded: at most MAX_SEGMENTS segments and TIME_BUDGET_S per run, bulk lane, the
writer lock taken without waiting (a busy writer means: try next run).
"""

import datetime
import re
import time

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.core.finding import win_finding as _finding

KEEP_DAYS = 30
MAX_SEGMENTS = 40
TIME_BUDGET_S = 120.0
REASON = f"retention: older than {KEEP_DAYS} days, events with no sign of anything suspicious"
STATE_META = "eventlog_retention"

ALWAYS_SOURCES = {"jarvis-outage-record"}
PERSISTENCE_ACTIONS = {"stream_create", "remote_thread", "process_access", "driver_load",
                       "raw_access_read", "tamper"}
TASK_ACTIONS = {"registered", "updated", "deleted", "event_106", "event_140", "event_141"}
# Registry locations that make something start or run on its own (the usual
# autostart extensibility points). Matched case-insensitively anywhere in the key.
AUTOSTART_KEYS = re.compile(
    r"\\(run|runonce|runonceex|runservices|runservicesonce)(\\|$)"
    r"|\\currentcontrolset\\services\\"
    r"|\\winlogon\\(shell|userinit|notify)"
    r"|\\image file execution options\\"
    r"|\\appinit_dlls|\\appcertdlls"
    r"|\\policies\\explorer\\run"
    r"|\\schedule\\taskcache\\"
    r"|\\shell folders\\startup|\\user shell folders\\startup"
    r"|\\silentprocessexit\\"
    r"|\\control\\session manager\\(bootexecute|knowndlls)"
    r"|\\lsa\\(security packages|authentication packages|notification packages)"
    r"|\\print\\monitors\\"
    r"|\\netsh\\"
    r"|\\wmi\\autologger",
    re.I)
STAGING = re.compile(r"\\(users\\[^\\]+\\appdata|windows\\temp|programdata|users\\public)\\"
                     r"|^/tmp/|^/dev/shm/|^/var/tmp/", re.I)
SHA256 = re.compile(r"SHA256=([0-9A-Fa-f]{64})|^([0-9A-Fa-f]{64})$")


def _sha(value):
    m = SHA256.search(str(value or ""))
    return (m.group(1) or m.group(2)).lower() if m else ""


def _target(ev):
    t = ev.get("target")
    return t if isinstance(t, dict) else {}


def lookups(ev):
    """(kind, normalized value) pairs of this event to check against threat data."""
    p, t = ev.get("process") or {}, _target(ev)
    for h in (_sha(p.get("hashes")), _sha(p.get("sha256")), _sha(t.get("hashes")), _sha(t.get("sha256"))):
        if h:
            yield "sha256", h
    if t.get("ip"):
        yield "ipv4", str(t["ip"]).strip()
    q = str(t.get("query") or "").strip().lower().rstrip(".")
    if q:
        yield "domain", q


def keep_reason(ev, known=frozenset(), cited=frozenset(), match=None):
    """Why this event is kept, or None when nothing marks it as suspicious.

    `known` holds the (kind, value) pairs of this batch that are indicators;
    `cited` the sequence numbers current findings point at; `match(image,
    cmdline, platform, parent)` the detection rules (techniques.match)."""
    src, cat, act = ev.get("source"), ev.get("category"), ev.get("action")
    if ev.get("seq") in cited:
        return "cited by a finding"
    if src in ALWAYS_SOURCES:
        return "ARGUS outage record"
    if src == "defender" and act != "health":
        return "Defender protection event"
    if act in PERSISTENCE_ACTIONS:
        return f"tampering or persistence ({act})"
    if src == "taskscheduler" and act in TASK_ACTIONS:
        return f"scheduled task {act}"
    if cat == "registry":
        t = _target(ev)
        key = " ".join(str(t.get(k) or "") for k in ("name", "key", "path", "object")) or str(ev.get("attrs") or "")
        if AUTOSTART_KEYS.search(key):
            return "autostart registry change"
    for pair in lookups(ev):
        if pair in known:
            return f"known indicator ({pair[0]})"
    p = ev.get("process") or {}
    if cat == "process" and act == "start" and p.get("image"):
        if match is not None:
            platform = "linux" if ev.get("host") == "wsl" else "windows"
            try:
                if match(p.get("image") or "", p.get("cmdline") or "", platform,
                         (ev.get("parent") or {}).get("image") or ""):
                    return "detection rule"
            except Exception:
                return "detection rule check failed (kept)"
        if STAGING.search(p.get("image") or ""):
            return "program run from a staging folder"
    if act == "image_load":
        t = _target(ev)
        if str(t.get("signed")).lower() == "false" and STAGING.search(str(t.get("path") or "")):
            return "unsigned module from a staging folder"
    return None


def lineage(events, kept_seqs):
    """Sequence numbers to keep so each kept event's process can be traced: the
    start events, in this segment, of the processes (and their parents) that
    have a kept event. Across segments the index keeps every parent link."""
    guids = set()
    for ev in events:
        if ev.get("seq") in kept_seqs:
            for side in ("process", "parent"):
                g = (ev.get(side) or {}).get("guid")
                if g:
                    guids.add(g)
    return {ev["seq"] for ev in events
            if ev.get("category") == "process" and ev.get("action") == "start"
            and (ev.get("process") or {}).get("guid") in guids}


SUMMARY_TOP = 25


def summarize(events):
    """A bounded picture of the events a compaction dropped: what kind, where to,
    which programs. Enough to ask "was there traffic to X?" later; not the events."""
    import collections
    kinds, dests, programs = collections.Counter(), collections.Counter(), collections.Counter()
    tmin = tmax = None
    for ev in events:
        kinds[f"{ev.get('category')}/{ev.get('action')}"] += 1
        t = _target(ev)
        d = t.get("query") or t.get("ip")
        if d:
            dests[str(d)[:120]] += 1
        img = (ev.get("process") or {}).get("image")
        if img:
            programs[str(img)[:200]] += 1
        tt = ev.get("time")
        if tt:
            tmin = tt if tmin is None or tt < tmin else tmin
            tmax = tt if tmax is None or tt > tmax else tmax
    return {"events": len(events), "time_min": tmin, "time_max": tmax,
            "kinds": dict(kinds.most_common(SUMMARY_TOP)),
            "destinations": dict(dests.most_common(SUMMARY_TOP)), "destination_count": len(dests),
            "programs": dict(programs.most_common(SUMMARY_TOP)), "program_count": len(programs)}


def known_indicators(store, pairs):
    """The subset of (kind, value) pairs that are active indicators, by batched lookups."""
    found, by_kind = set(), {}
    for kind, value in pairs:
        by_kind.setdefault(kind, set()).add(value)
    for kind, values in by_kind.items():
        values = list(values)
        for i in range(0, len(values), 500):
            chunk = values[i:i + 500]
            rows = store.db.execute(
                f"SELECT norm FROM indicators WHERE kind=? AND (status IS NULL OR status='active') "
                f"AND norm IN ({','.join('?' * len(chunk))})", (kind, *chunk)).fetchall()
            found.update((kind, r[0]) for r in rows)
    return found


def cited_sequences(store):
    """Sequence numbers that current findings point at (Sysmon findings carry `seq`)."""
    out = set()
    try:
        snaps = store.get_snapshots()
    except Exception:
        return out
    for snap in (snaps or {}).values():
        for f in (snap or {}).get("findings") or ():
            if isinstance(f, dict):
                for k in ("seq", "event_seq"):
                    if isinstance(f.get(k), int):
                        out.add(f[k])
    return out


def _cutoff(now):
    return (datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
            - datetime.timedelta(days=KEEP_DAYS)).isoformat()


def candidates(log, now):
    """Older sealed segments not yet reduced, oldest first; never the newest."""
    cutoff = _cutoff(now)
    done = log._pruned() | set(log._compacted())
    newest = log.chain[-1]["segment"] if log.chain else 0
    held = [(a, b) for a, b, _r in log.holds()]
    # A segment entirely inside an active hold would only be read and kept whole:
    # skip it until the hold is released (each pass used to re-read the same 40).
    return [h for h in log.chain
            if h["segment"] < newest and h["segment"] not in done
            and h.get("time_max") and str(h["time_max"]) < cutoff
            and not any(a <= h["first_seq"] and h["last_seq"] <= b for a, b in held)]


def run(store, log, now=None, max_segments=MAX_SEGMENTS, budget_s=TIME_BUDGET_S, match=None,
        clock=time.monotonic):
    """One bounded pass. Returns a summary dict."""
    now = time.time() if now is None else now
    todo = candidates(log, now)
    cited = cited_sequences(store)
    start = clock()
    summary = {"candidates": len(todo), "segments": 0, "kept": 0, "dropped": 0, "freed": 0,
               "removed": 0, "errors": [], "reasons": {}}
    for header in todo[:max_segments]:
        if clock() - start > budget_s:
            break
        events = list(log.iter_events(after=header["first_seq"] - 1, until=header["last_seq"]))
        pairs = {pair for ev in events for pair in lookups(ev)}
        known = known_indicators(store, pairs) if pairs else set()
        reasons = summary["reasons"]
        kept_seqs = set()
        for ev in events:
            why = keep_reason(ev, known, cited, match)
            if why:
                reasons[why] = reasons.get(why, 0) + 1
                kept_seqs.add(ev["seq"])
        extra = lineage(events, kept_seqs) - kept_seqs
        if extra:
            reasons["process lineage of a kept event"] = reasons.get("process lineage of a kept event", 0) + len(extra)
            kept_seqs |= extra
        try:
            r = log.compact(header["segment"], lambda ev, keep=kept_seqs: ev.get("seq") in keep, REASON,
                            summary=summarize)
        except (LogError, OSError, ValueError) as exc:
            summary["errors"].append(f"segment {header['segment']}: {exc}"[:200])
            continue
        summary["segments"] += 1
        summary["kept"] += r["kept"]
        summary["dropped"] += r["dropped"]
        summary["freed"] += r["freed"]
        summary["removed"] += r["action"] == "removed"
    return summary


def retention(store, hosts=("win",), root=None, match=None):
    """The `retention` job: bulk lane, bounded; reports what it reduced.

    `match` is the detection-rule matcher (techniques.match), handed in by the job
    runner so this bulk-lane module imports nothing that reaches Windows."""
    import json
    root = root or DEFAULT_ROOT
    try:
        log = EventLog(root, writer=True)
    except LogError as exc:
        return [_finding("visibility", "ok", "Event history retention waited for the writer",
                         f"{exc}; it runs again next time.", str(root))]
    try:
        s = run(store, log, match=match)
        stats = log.stats()
    finally:
        log.close()
    store.set_meta(STATE_META, json.dumps({"at": time.time(), **{k: s[k] for k in
                   ("candidates", "segments", "kept", "dropped", "freed", "removed")}}))
    store.commit()
    out = [_finding(
        "visibility", "ok",
        f"Event history: kept the suspicious events of {s['segments']} older segment(s)",
        f"Older than {KEEP_DAYS} days: {s['kept']} events kept, {s['dropped']} normal events "
        f"removed ({s['freed'] // 1024 // 1024} MiB freed, {s['removed']} empty segments removed); "
        f"{max(0, s['candidates'] - s['segments'])} older segments still to check. "
        f"Kept because: {', '.join(f'{k} {v}' for k, v in sorted(s['reasons'].items(), key=lambda kv: -kv[1])[:6]) or 'nothing'}. "
        f"History now {stats['sealed_bytes'] // 1024 // 1024} MiB of a "
        f"{stats['payload_budget_bytes'] // 1024 // 1024} MiB cap.", str(root))]
    if s["errors"]:
        out.append(_finding("visibility", "medium", "Some older history could not be reduced",
                            "; ".join(s["errors"][:3]), str(root)))
    return out

"""The data behind the /coverage view: what JARVIS defends, and how it is running.

One read-only summary joining three things that already exist: the ATT&CK
coverage map (attackmap, measured by probes), the collectors with their real
freshness and open findings, and what the scheduler is running right now.

Nothing here is computed to look better than the sources. A technique's level
is attackmap's, a collector's state is the score's own freshness rule, and a
collector with no stored snapshot is "missing", never quiet.

The map is measured every few hours, but a collector can die in between. A
technique whose probe fired is therefore shown as validated only while a
collector that feeds it is current *now*; otherwise it is claimed, with the
reason. The probe result itself is never re-derived here, only its liveness.

Uptime is read from the collector receipts (defender_runs). A collector is up
while its newest complete receipt is no older than the score's own staleness
limit; partial and unavailable runs do not keep it up. Time before a collector's
first receipt is unknown and left out, never counted as up or down.

The page does not poll that whole summary to stay live. `live()` is a compact
state (which collector ran when, what is running, whether any tile changed
level) cheap enough to rebuild twice a second, pushed to the page as it
changes; the page fetches the full summary again only when `levels` moves.
"""
import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path

from jarvis.core.store import Store
from jarvis.response import alert
from jarvis.response.reporting import score
from jarvis.response.reporting.commands import JOB_COMMANDS
from jarvis.service import attackmap
from jarvis.service.schedule import JOBS

SEVERITIES = ("critical", "high", "medium", "low")
BUCKETS, BUCKET_S, WEEK_S, CACHE_S = 24, 3600, 7 * 86400, 30
_uptime_cache = {}
# attackmap's free-text source names that are not job or command names.
ALIASES = {"detect": ("scan",), "monitor": ("internet",), "peers": ("scan",),
           "startup": ("boot",), "sysmon_linux": ("sysmon_linux",)}


def _jobs_for(word):
    """Jobs behind one source word of a COVERAGE entry ('hidden', 'asep', ...)."""
    word = word.strip().lower().replace("-", "_")
    if word in JOBS:
        return (word,)
    if word in ALIASES:
        return ALIASES[word]
    return tuple(sorted(job for job, command in JOB_COMMANDS.items()
                        if command.split()[0].replace("-", "_") == word and job in JOBS))


def sources(tid, evidence):
    """Collectors that feed a technique: the probe's jobs, else the mapped ones."""
    if tid in attackmap.PROBES:
        return [j for j in attackmap.PROBES[tid][1] if j in JOBS]
    head = re.split(r"\s[—-]\s", evidence or "", maxsplit=1)[0]
    found = []
    for word in head.split("/"):
        for job in _jobs_for(word):
            if job not in found:
                found.append(job)
    return found


def _grace(interval):
    """How long a complete receipt keeps a collector up: score.freshness's limit."""
    return max(interval * 2, interval + 300)


def _overlap(segments, lo, hi):
    return sum(max(0.0, min(b, hi) - max(a, lo)) for a, b in segments)


def _fresh_segments(times, grace, now):
    """Spans a collector had fresh evidence: each receipt holds until the next one."""
    out = []
    for i, t in enumerate(times):
        end = times[i + 1] if i + 1 < len(times) else now
        out.append((t, min(t + grace, end, now)))
    return out


def _longest_gap(segments, lo, hi):
    gap, cursor = 0.0, lo
    for a, b in segments:
        if b <= lo or a >= hi:
            continue
        gap = max(gap, max(a, lo) - cursor)
        cursor = max(cursor, min(b, hi))
    return max(gap, hi - cursor)


def _collector_uptime(times, first, grace, now, runs):
    day = now - BUCKETS * BUCKET_S
    segs = _fresh_segments(times, grace, now)
    known24 = max(0.0, now - max(day, first))
    known7 = max(0.0, now - max(now - WEEK_S, first))
    if not known24:
        return None
    buckets = []
    for k in range(BUCKETS):
        lo = day + k * BUCKET_S
        hi = lo + BUCKET_S
        known = max(0.0, hi - max(lo, first))
        buckets.append(round(_overlap(segs, lo, hi) / known, 4) if known else None)
    fresh24 = _overlap(segs, day, now)
    return {"pct24": round(fresh24 / known24, 4),
            "pct7d": round(_overlap(segs, now - WEEK_S, now) / known7, 4) if known7 else None,
            "buckets": buckets, "observed_s": int(known24), "fresh_s": int(fresh24),
            "longest_gap_s": int(_longest_gap(segs, max(day, first), now)),
            "runs24": runs}


def _technique_uptime(jobs, segs, now):
    """Share of the last 24 h in which at least one feeding collector had fresh evidence."""
    have = [segs[j] for j in jobs if j in segs]
    if not have:
        return None
    day = now - BUCKETS * BUCKET_S
    known = now - max(day, min(first for _s, first in have))
    if known <= 0:
        return None
    spans = sorted((max(a, day), min(b, now)) for s, _f in have for a, b in s if b > day and a < now)
    fresh, edge = 0.0, day
    for a, b in spans:
        a = max(a, edge)
        if b > a:
            fresh += b - a
            edge = b
    return round(min(1.0, fresh / known), 4)


def uptime(store, now):
    """Per-collector and fleet uptime from the stored receipts."""
    per, fleet, _segs = _collect(store, now)
    return per, fleet


def _collect(store, now):
    """Receipts to uptime: per collector, fleet, and the fresh spans themselves."""
    start = now - WEEK_S - max(_grace(i) for i, _ in JOBS.values())
    firsts = dict(store.db.execute("SELECT job, MIN(observed_at) FROM defender_runs GROUP BY job"))
    times = {}
    for job, ts in store.db.execute(
            "SELECT job, observed_at FROM defender_runs WHERE coverage='complete' "
            "AND observed_at>=? ORDER BY job, observed_at", (start,)):
        times.setdefault(job, []).append(ts)
    runs = {}
    for job, coverage, n in store.db.execute(
            "SELECT job, coverage, COUNT(*) FROM defender_runs WHERE observed_at>=? GROUP BY job, coverage",
            (now - BUCKETS * BUCKET_S,)):
        runs.setdefault(job, dict.fromkeys(("complete", "partial", "unavailable"), 0))[coverage] = n
    per, segs = {}, {}
    for job, (interval, _label) in JOBS.items():
        if job in firsts:
            segs[job] = (_fresh_segments(times.get(job, []), _grace(interval), now), firsts[job])
            per[job] = _collector_uptime(times.get(job, []), firsts[job], _grace(interval), now,
                                         runs.get(job, dict.fromkeys(("complete", "partial", "unavailable"), 0)))
    tracked = [u for u in per.values() if u]
    fleet = None
    if tracked:
        fleet_buckets = []
        for k in range(BUCKETS):
            known = [u["buckets"][k] for u in tracked if u["buckets"][k] is not None]
            fleet_buckets.append(round(sum(known) / len(known), 4) if known else None)
        observed = sum(u["observed_s"] for u in tracked)
        fleet = {"pct24": round(sum(u["fresh_s"] for u in tracked) / observed, 4),
                 "buckets": fleet_buckets, "tracked": len(tracked), "of": len(JOBS),
                 "partial_history": sum(1 for u in tracked if u["observed_s"] < BUCKETS * BUCKET_S - 60)}
    return per, fleet, segs


def live_level(row, jobs, snaps, now):
    """(level, evidence) for a technique right now.

    Only a row whose probe fired can move, and only between validated and
    claimed. Regressed, blind, mapped-without-a-probe and burst-only rows keep
    the level the map gave them, as do rows from a map stored before probe
    results were recorded.
    """
    level, evidence = row["level"], row.get("evidence") or ""
    if (not row.get("fired") or level not in ("validated", "claimed")
            or row["tid"] in attackmap.CONTEXT_ONLY):
        return level, evidence
    live = [j for j in jobs if score.freshness(snaps.get(j), JOBS[j][0], now) == "current"]
    what = row.get("what") or evidence
    if live:
        return "validated", f"{what}; live via {', '.join(live)}"
    return "claimed", (f"{what} fires, but {', '.join(jobs) or 'no collector here'} "
                       f"{'is' if len(jobs) == 1 else 'are'} not reporting now")


def _tally(techniques, tactic_names):
    """Totals and per-tactic counts for the levels actually shown."""
    blank = lambda: dict.fromkeys(("validated", "claimed", "blind", "regressed", "total"), 0)  # noqa: E731
    totals, tactics = blank(), {name: blank() for name in tactic_names}
    for tech in techniques:
        totals[tech["level"]] += 1
        totals["total"] += 1
        for name in tech["tactics"]:
            if name in tactics:
                tactics[name][tech["level"]] += 1
                tactics[name]["total"] += 1
    return totals, tactics


def intel_gaps(snaps, now):
    """Argus's detection gaps against current intel, from the `gaps` job.

    These are statements about the tool ("nothing here checks T1001"), so they
    live here, in the coverage view, rather than among the machine's findings
    (ALERT-QUALITY-2026-11-08). Every gap is listed; `priority` is the gaps
    job's own ranking by how many intel documents raised the technique."""
    snap = snaps.get("gaps") or {}
    items = []
    for f in snap.get("findings") or ():
        if not alert.is_coverage_gap(f):
            continue
        title = str(f.get("title") or "")
        tid, _, name = title.partition(" ")
        items.append({"tid": tid, "name": name, "kind": f.get("category"),
                      "priority": f.get("severity"), "detail": f.get("detail", "")})
    order = {"high": 0, "medium": 1, "low": 2}
    items.sort(key=lambda g: (order.get(g["priority"], 9), g["tid"]))
    by_kind = {}
    for g in items:
        by_kind.setdefault(g["kind"], {}).setdefault(g["priority"], 0)
        by_kind[g["kind"]][g["priority"]] += 1
    interval = (JOBS.get("gaps") or (21600, ""))[0]
    ts = snap.get("ts")
    return {"state": score.freshness(snap or None, interval, now),
            "ts": int(ts) if ts else None, "total": len(items),
            "by_kind": by_kind, "items": items}


def build(db_path, scheduler=None, now=None):
    now = time.time() if now is None else now
    store = Store(db_path)
    try:
        snaps = store.get_snapshots()
        attack = attackmap.latest(store)
        verified = score.last_verified(store)
        cached = _uptime_cache.get(db_path)
        if cached and abs(now - cached[0]) < CACHE_S:
            per_uptime, fleet, segs = cached[1]
        else:
            per_uptime, fleet, segs = _collect(store, now)
            _uptime_cache[db_path] = (now, (per_uptime, fleet, segs))
    finally:
        store.close()
    running = []
    if scheduler is not None:
        try:
            running = list(scheduler.wake_phase().get("current") or [])
        except Exception:
            running = []

    techniques, feeds = [], {}
    for row in (attack or {}).get("techniques", []):
        jobs = [] if row["level"] == "blind" else sources(row["tid"], row.get("evidence"))
        for job in jobs:
            feeds.setdefault(job, []).append(row["tid"])
        level, evidence = live_level(row, jobs, snaps, now)
        techniques.append({"tid": row["tid"], "name": row["name"], "tactics": row["tactics"],
                           "level": level, "evidence": evidence, "ways": row.get("ways"),
                           "sources": jobs, "uptime": _technique_uptime(jobs, segs, now)})
    totals, tactics = _tally(techniques, (attack or {}).get("tactics") or {})

    collectors = []
    for job, (interval, label) in JOBS.items():
        snap = snaps.get(job)
        counts = dict.fromkeys(SEVERITIES, 0)
        for finding in (snap or {}).get("findings") or []:
            if isinstance(finding, dict) and finding.get("severity") in counts:
                counts[finding["severity"]] += 1
        ts = (snap or {}).get("ts")
        collectors.append({
            "job": job, "label": label, "interval": interval,
            "area": score.AREA_OF.get(job, "Unscored"),
            "state": score.freshness(snap, interval, now),
            "ts": int(ts) if ts else None,
            "findings": counts, "running": job in running, "uptime": per_uptime.get(job),
            "techniques": sorted(feeds.get(job, []))})
    return {
        "at": int(now),
        "map_at": (attack or {}).get("at"),
        "totals": totals if attack else {},
        "tactics": tactics,
        "techniques": techniques,
        "collectors": collectors,
        "running": running,
        "uptime": fleet,
        "intel_gaps": intel_gaps(snaps, now),
        "score": ({"score": verified.get("score"), "grade": verified.get("grade"),
                   "at": verified.get("at")} if verified else None),
    }


# ── the live feed ───────────────────────────────────────────────────────────
LIVE_PERIOD_S = 0.5         # the shared live state is rebuilt at most this often
LIVE_STREAMS = 4            # open /api/coverage/stream connections at once
LIVE_BEAT_S = 5             # a visible heartbeat this often while nothing changes
_INGESTED = re.compile(r"(\d+) events? committed")
_live_cache = {}            # db_path -> {"map": (raw, rows), "open": {job: (ts, n)}}


def _open_serious(conn, job, run, cache):
    """Open critical and high findings in a snapshot, read once per run.

    `run` identifies the run: its second and its measured duration, so two runs
    stamped in the same second are still told apart."""
    known = cache.get(job)
    if known and known[0] == run:
        return known[1]
    row = conn.execute("SELECT payload FROM snapshots WHERE kind=?", (job,)).fetchone()
    try:
        findings = json.loads(row[0]) if row else []
    except (TypeError, ValueError):
        findings = []
    n = sum(1 for f in findings if isinstance(f, dict)
            and f.get("severity") in ("critical", "high"))
    cache[job] = (run, n)
    return n


def _map_rows(raw, cache):
    """The stored map's technique rows with their feeding jobs, parsed once per map."""
    known = cache.get("map")
    if known and known[0] == raw:
        return known[1], known[2]
    try:
        attack = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        attack = None
    rows = [(row, [] if row["level"] == "blind" else sources(row["tid"], row.get("evidence")))
            for row in (attack or {}).get("techniques", [])]
    cache["map"] = (raw, rows, (attack or {}).get("at"))
    return rows, (attack or {}).get("at")


def live(db_path, scheduler=None, now=None):
    """What changed since the page last looked. Never raises: a failure is a
    state with `ok: false`, which the page shows as "not live", never as calm.

    Read-only, through a read-only connection of its own: it runs twice a
    second while a page is open and must not take the store's write path.
    """
    now = time.time() if now is None else now
    cache = _live_cache.setdefault(db_path, {"open": {}})
    try:
        # as_uri(): a Windows path or one with spaces is a valid URI this way.
        conn = sqlite3.connect(Path(db_path).absolute().as_uri() + "?mode=ro", uri=True, timeout=2)
        try:
            snaps = {kind: {"ts": ts, "error": error, "duration": duration}
                     for kind, ts, error, duration in
                     conn.execute("SELECT kind, ts, error, duration FROM snapshots")}
            meta = dict(conn.execute("SELECT k, v FROM meta WHERE k IN (?, ?)",
                                     (attackmap.META, "native_delivery")))
            collectors = {}
            for job, (interval, _label) in JOBS.items():
                snap = snaps.get(job)
                ts = int(snap["ts"]) if snap and snap.get("ts") else 0
                collectors[job] = [ts, score.freshness(snap, interval, now),
                                   _open_serious(conn, job, (ts, snap.get("duration")),
                                                 cache["open"]) if ts else 0]
        finally:
            conn.close()
    except (sqlite3.Error, OSError) as exc:
        return _versioned({"ok": False, "error": type(exc).__name__, "at": int(now)})

    rows, map_at = _map_rows(meta.get(attackmap.META), cache)
    levels = hashlib.sha256("".join(
        f"{row['tid']}:{live_level(row, jobs, snaps, now)[0]};"
        for row, jobs in rows).encode()).hexdigest()[:16]

    running = []
    if scheduler is not None:
        try:
            running = list(scheduler.wake_phase().get("current") or [])
        except Exception:
            running = []

    ingest = None
    try:
        delivery = json.loads(meta.get("native_delivery") or "null")
        found = _INGESTED.search(delivery["stages"]["ingested"]["detail"])
        if found:
            # Events the native sensor's last pass committed to the history.
            ingest = {"events": int(found.group(1)), "at": int(delivery["at"])}
    except (TypeError, ValueError, KeyError):
        ingest = None

    return _versioned({"ok": True, "at": int(now), "map_at": map_at, "levels": levels,
                       "running": running, "c": collectors, "ingest": ingest})


def _versioned(state):
    """Add `version`: a digest of everything but the clock, so the stream can
    tell a real change from a re-send."""
    body = {k: v for k, v in state.items() if k != "at"}
    state["version"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return state

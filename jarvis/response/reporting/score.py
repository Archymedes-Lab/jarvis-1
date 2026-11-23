"""How safe is this machine right now, as one number and a bar to fill.

The findings list answers "what is wrong". This answers "how far is this system
from secure", so progress is visible: fixing a high finding moves the bar, and
so does getting a blind collector reporting again.

Three rules keep the number honest:

  * It is built from what the collectors last observed, grouped into
    protection areas by the job that observed it. Nothing is guessed.
  * Blindness is not safety. An area whose collectors are failing, stale or
    have never run is shown as unverified and does not count as healthy, and
    the overall score is pulled down in proportion to how much of the machine
    is currently unobserved.
  * Inventory is not risk. Low-severity findings (every scheduled task, every
    installed extension) do not lower the score, per-process and per-peer
    churn is left out exactly as alerting leaves it out, and medium findings
    from one collector stop counting past a small cap, so a noisy rule cannot
    bury everything else.

An owner-accepted finding is charged as low (owner decision 2026-09-25,
reversing the "accepted findings keep their debt" rule). The acceptance stays
visible: it is pinned to the finding's identity and severity, carries a
reason and an expiry, is tallied as `acknowledged`, and the full weight
returns the moment the finding changes, worsens or the acceptance expires.
"""

import json
import time

from jarvis.core import mechanisms
from jarvis.response import acknowledge, alert

# Protection areas, in display order, and the jobs whose findings describe them.
# A job outside every area does not describe the machine's safety and is not
# scored; its Collector declaration says why. Declared per collector in core/mechanisms.py, with the reason each unscored
# job is unscored; order inside an area is precedence (see Collector).
AREAS = mechanisms.score_areas()
UNSCORED = mechanisms.names(area=None)
AREA_OF = {job: area for area, jobs in AREAS for job in jobs}

WEIGHT = {"critical": 20, "high": 8, "medium": 2, "low": 0, "ok": 0}
MEDIUM_CAP = 5     # mediums counted per job
K = 16             # penalty at which an area reads 50%: two highs, or 8 mediums

HISTORY_META = "security_score_history"
HISTORY_KEEP = 400
SUSTAINED_META = "security_sustained_history_v1"
SUSTAINED_KEEP = 2016
SUSTAINED_MIN_S = 15 * 60
SUSTAINED_MAX_GAP_S = 10 * 60

GRADES = ((90, "secure"), (75, "good"), (50, "needs work"), (0, "at risk"))

# Re-verification after a gap (sleep, reboot, daemon down): see stable().
WARMUP_GAP_S = 15 * 60
WARMUP_MAX_S = 30 * 60
# A collector whose first run after a wake fails is shown as retrying, not
# news, for this long only: the Windows bridge needed 134-160 s to recover
# after standby (reviver log, 2026-09-24). Longer would let a collector
# disabled right after wake hide behind the held score.
WAKE_RETRY_GRACE_S = 5 * 60
WARMUP_META = "security_score_warmup_since"
VERIFIED_META = "security_score_verified"


def grade(score):
    for floor, label in GRADES:
        if score >= floor:
            return label
    return GRADES[-1][1]


def freshness(snap, interval, now):
    if not snap or not snap.get("ts"):
        return "missing"
    if snap.get("error"):
        return "failing"
    if now - int(snap["ts"]) > max(interval * 2, interval + 300):
        return "stale"
    return "current"


def _scored(findings, job="", acks=None, now=None):
    """Findings that describe risk. Per-process and per-peer churn (and meta
    categories) are the same ones alerting never pages on: they change by the
    minute and would make the bar jitter rather than track progress.

    `acks`, when given, also drops acknowledged findings. compute()
    deliberately does not pass it: it keeps an accepted finding in view and
    charges it as low instead."""
    return [f for f in findings or () if isinstance(f, dict)
            and f.get("category") not in alert.NOPAGE_CATEGORIES
            and not (acks and acknowledge.is_acknowledged(acks, f, job, now))]


def _superseded(f, verdict_ts, snapshots, jobs, now):
    """A coverage verdict about a collector that has since produced a newer,
    clean, in-window result.

    Coverage judges other collectors from their snapshots at the moment it
    runs; its snapshot then keeps that verdict until its own next run. Under
    host load that can be many minutes: on 2026-09-24 a verdict taken at
    07:56 mid catch-up kept 21 recovered collectors "stale" and Monitoring at
    0 for 20+ minutes. The scorer already charges genuine blindness from each
    collector's own freshness, so dropping only verdicts that newer evidence
    has contradicted hides nothing: a still-stale or failing collector stays
    blind here and keeps its area at 0."""
    target = f.get("about_collector")
    if not target or target not in jobs or verdict_ts is None:
        return False
    snap = snapshots.get(target)
    if not snap or not snap.get("ts") or float(snap["ts"]) <= float(verdict_ts):
        return False
    return freshness(snap, jobs[target][0], now) == "current"


def _job_penalty(findings):
    counts = {}
    for f in findings:
        sev = f.get("severity")
        counts[sev] = counts.get(sev, 0) + 1
    return (WEIGHT["critical"] * counts.get("critical", 0)
            + WEIGHT["high"] * counts.get("high", 0)
            + WEIGHT["medium"] * min(counts.get("medium", 0), MEDIUM_CAP)), counts


def _area_score(penalty):
    return round(100 * K / (K + penalty))


def compute(snapshots, jobs, now=None, acks=None):
    """Score from stored snapshots. `jobs` is the schedule: name -> (interval, label).
    `acks` is acknowledge.load(store): findings you confirmed as expected."""
    now = int(time.time() if now is None else now)
    areas, next_steps = [], []
    observed_jobs = scored_jobs = acknowledged = 0
    for area, members in AREAS:
        penalty, counts, blind = 0, {}, []
        seen = set()     # one observed fact counts once per area
        present = [j for j in members if j in jobs]
        for job in present:
            snap = snapshots.get(job)
            state = freshness(snap, jobs[job][0], now)
            scored_jobs += 1
            if state != "current":
                blind.append({"job": job, "state": state})
                continue
            observed_jobs += 1
            kept = []
            # deep_hidden repeats hidden's audit with deeper sweeps: the same
            # orphan socket reported by both is one fact, not two.
            for f in _scored(snap.get("findings"), job):
                if job == "coverage" and _superseded(f, snap.get("ts"), snapshots, jobs, now):
                    continue
                key = (f.get("host"), alert.finding_key(f), str(f.get("detail") or ""))
                if key in seen:
                    continue
                seen.add(key)
                kept.append(f)
            accepted = [acknowledge.is_acknowledged(acks or {}, f, job, now) for f in kept]
            acknowledged += sum(accepted)
            charged = [dict(f, severity="low") if a else f for f, a in zip(kept, accepted)]
            p, c = _job_penalty(charged)
            penalty += p
            for sev, n in c.items():
                if sev in WEIGHT and sev != "ok":
                    counts[sev] = counts.get(sev, 0) + n
            for f in charged:
                w = WEIGHT.get(f.get("severity"), 0)
                if w:
                    next_steps.append({"area": area, "job": job, "weight": w,
                                       "severity": f.get("severity"),
                                       "title": f.get("title", ""),
                                       "where": f.get("where", "")})
        observed = len(present) - len(blind)
        areas.append({
            "name": area,
            "score": (0 if blind else _area_score(penalty)) if observed else None,
            "open": counts,
            "jobs": len(present),
            "observed": observed,
            "blind": blind,
        })
    scored = [a["score"] or 0 for a in areas if a["jobs"]]
    coverage = observed_jobs / scored_jobs if scored_jobs else 0.0
    base = sum(scored) / len(scored) if scored else 0.0
    # A machine that is half unobserved cannot score better than half-way
    # between its observed score and zero.
    score = round(base * (0.5 + 0.5 * coverage)) if scored else 0
    next_steps.sort(key=lambda s: (-s["weight"], s["area"], s["title"]))
    return {
        "score": score,
        "grade": grade(score),
        "coverage": round(coverage * 100),
        "areas": areas,
        "next_steps": next_steps[:8],
        "acknowledged": acknowledged,
        "at": now,
    }


def bar(score, width=20):
    """[##########----------] as text, for email bodies and terminals."""
    score = max(0, min(100, int(score)))
    filled = round(width * score / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def _warmup_since(store, now):
    """Start of the current re-verification window, or None.

    A window opens when the report job records after a gap longer than
    WARMUP_GAP_S (sleep, reboot, daemon down): every collector's evidence is
    then older than the gap and the area scores read blind until each one has
    run again. It closes after WARMUP_MAX_S, or earlier once nothing is blind.
    """
    try:
        since = float(store.get_meta(WARMUP_META, "0") or 0)
    except (TypeError, ValueError):
        since = 0.0
    if since and 0 <= now - since <= WARMUP_MAX_S:
        return since
    return None


def last_verified(store):
    """The last recorded result that observed every scored collector."""
    try:
        value = json.loads(store.get_meta(VERIFIED_META, "") or "null")
        return value if isinstance(value, dict) and "score" in value else None
    except (TypeError, ValueError):
        return None


def open_wake_window(store, now=None):
    """Start a re-verification window now: the scheduler calls this when it
    wakes from a suspend or starts cold, so the dashboard shows JARVIS
    re-checking instead of a partial live score collapsing mid-sweep."""
    now_i = int(time.time() if now is None else now)
    since = _warmup_since(store, now_i)
    if since is None:
        store.set_meta(WARMUP_META, str(now_i))
        store.commit()
        return now_i
    return since


def stable(store, jobs, now=None, acks=None, live=None, snapshots=None, phase=None):
    """The score to show: live, or during a re-verification window the last
    fully verified result, marked as such, with progress beside it.

    Nothing new is claimed: the held number carries when it was verified, and
    the live progress stays visible. The hold is bounded (WARMUP_MAX_S) and
    narrow. A collector that was already failing before the window opened is
    news and ends it at once. A collector whose first run after a wake fails
    (the Windows bridge often needs a retry after standby) is shown as
    retrying instead, for WAKE_RETRY_GRACE_S only; still failing after that,
    it ends the hold and the live score applies. `phase` is the scheduler's view: {"holding": [...],
    "current": [...], "resumed_at": ts}."""
    now = int(time.time() if now is None else now)
    snapshots = store.get_snapshots() if snapshots is None else snapshots
    live = live or compute(snapshots, jobs, now,
                           acknowledge.load(store) if acks is None else acks)
    blind = [b for a in live["areas"] for b in a["blind"]]
    since = _warmup_since(store, now)
    verified = last_verified(store)

    def failure_is_news(b):
        ts = (snapshots.get(b["job"]) or {}).get("ts")
        return (not ts or since is None or float(ts) < since
                or now - since > WAKE_RETRY_GRACE_S)
    if (not blind or since is None or verified is None
            or any(b["state"] == "failing" and failure_is_news(b) for b in blind)):
        return {**live, "state": "current"}
    observed = sum(a["observed"] for a in live["areas"])
    total = sum(a["jobs"] for a in live["areas"])
    phase = phase or {}
    resumed = phase.get("resumed_at")
    return {**verified, "state": "verifying",
            "phase": "waking" if resumed and float(resumed) >= since else "verifying",
            "verified_at": verified.get("at"), "warmup_since": since,
            "warmup_ends": since + WARMUP_MAX_S,
            "progress": {"checked": observed, "total": total,
                         "pending": sorted(b["job"] for b in blind if b["state"] != "failing"),
                         "retrying": sorted(b["job"] for b in blind if b["state"] == "failing"),
                         "running": list(phase.get("current") or [])},
            "live": {"score": live["score"],
            "coverage": live["coverage"], "observed": observed, "jobs": total,
            "areas": live["areas"], "next_steps": live["next_steps"]},
            "at": now}


def record(store, jobs, now=None):
    """Compute, and append to the stored history (one point per call).

    Points taken while re-verifying after a gap are not appended: they
    measure how far the sweep has got, not the machine."""
    now_i = int(time.time() if now is None else now)
    history = history_of(store)
    try:
        opened = float(store.get_meta(WARMUP_META, "0") or 0)
    except (TypeError, ValueError):
        opened = 0.0
    # One window per gap: warm-up points are not appended, so the gap stays
    # open in the history until the window ends and must not reopen it.
    if history and now_i - history[-1][0] > WARMUP_GAP_S and history[-1][0] >= opened:
        store.set_meta(WARMUP_META, str(now_i))
    result = compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    if not any(a["blind"] for a in result["areas"]):
        store.set_meta(VERIFIED_META, json.dumps(result))
    elif stable(store, jobs, now_i, live=result)["state"] == "verifying":
        store.set_meta("security_score_live", json.dumps(result))
        return result
    history.append([result["at"], result["score"]])
    store.set_meta(HISTORY_META, json.dumps(history[-HISTORY_KEEP:]))
    sustained = sustained_history_of(store)
    sustained.append({
        "at": result["at"], "score": result["score"],
        "coverage": result["coverage"],
        "verified": (result["score"] == 100 and result["coverage"] == 100
                     and all(not area["blind"] for area in result["areas"])),
    })
    store.set_meta(SUSTAINED_META, json.dumps(sustained[-SUSTAINED_KEEP:]))
    store.set_meta("security_score_latest", json.dumps(result))
    return result


def history_of(store):
    try:
        value = json.loads(store.get_meta(HISTORY_META, "[]") or "[]")
        return [p for p in value if isinstance(p, list) and len(p) == 2]
    except (TypeError, ValueError):
        return []


def sustained_history_of(store):
    """Validated health samples only; malformed persisted state fails closed."""
    try:
        value = json.loads(store.get_meta(SUSTAINED_META, "[]") or "[]")
        return [row for row in value if isinstance(row, dict)
                and isinstance(row.get("at"), (int, float))
                and isinstance(row.get("score"), int)
                and isinstance(row.get("coverage"), int)
                and isinstance(row.get("verified"), bool)]
    except (TypeError, ValueError):
        return []


def sustained_health(samples, now=None, min_seconds=SUSTAINED_MIN_S,
                     max_gap_seconds=SUSTAINED_MAX_GAP_S):
    """Describe the latest uninterrupted run of recorded perfect health."""
    now = int(time.time() if now is None else now)
    rows = sorted((row for row in samples if row["at"] <= now),
                  key=lambda row: row["at"])
    base = {"status": "unverified", "since": None, "duration_s": 0,
            "samples": 0, "latest_at": rows[-1]["at"] if rows else None,
            "required_s": int(min_seconds), "max_gap_s": int(max_gap_seconds)}
    if not rows or now - rows[-1]["at"] > max_gap_seconds:
        return base
    if not rows[-1]["verified"]:
        return {**base, "status": "broken"}
    run = [rows[-1]]
    for row in reversed(rows[:-1]):
        if not row["verified"] or run[0]["at"] - row["at"] > max_gap_seconds:
            break
        run.insert(0, row)
    duration = int(run[-1]["at"] - run[0]["at"])
    return {**base,
            "status": "verified" if duration >= min_seconds else "collecting",
            "since": run[0]["at"], "duration_s": duration,
            "samples": len(run), "latest_at": run[-1]["at"]}


def change_within(store, seconds, now=None):
    """Score change across the recorded points of the last `seconds`, oldest to
    newest. This is what the dashboard's sparkline shows, so speech and screen
    agree; None with fewer than two points."""
    now = int(time.time() if now is None else now)
    recent = [p for p in history_of(store) if p[0] >= now - seconds]
    return recent[-1][1] - recent[0][1] if len(recent) > 1 else None


def latest(store):
    """The last recorded score, or None if the report job has not run yet."""
    try:
        value = json.loads(store.get_meta("security_score_latest", "") or "null")
        return value if isinstance(value, dict) and "score" in value else None
    except (TypeError, ValueError):
        return None


def change_since(store, seconds, now=None):
    """Score change against the recorded point closest to `seconds` ago."""
    now = int(time.time() if now is None else now)
    history = history_of(store)
    if len(history) < 2:
        return None
    target = now - seconds
    past = min(history[:-1], key=lambda p: abs(p[0] - target))
    if abs(past[0] - target) > 3 * 3600:
        return None     # no point near enough to that moment to compare with
    return history[-1][1] - past[1]



def summary_lines(result, delta=None):
    """Plain-text block for emails: the overall bar, then one bar per area."""
    trend = "" if delta is None else (
        f"  ({'+' if delta > 0 else ''}{delta} in 24h)" if delta else "  (no change in 24h)")
    lines = [f"SECURITY HEALTH {bar(result['score'])} {result['score']}% — "
             f"{result['grade']}{trend}",
             f"  monitoring coverage {result['coverage']}%"]
    for a in result["areas"]:
        if a["score"] is None:
            lines.append(f"  {a['name']:<22} unverified — no current data")
        else:
            opened = ", ".join(f"{n} {s}" for s, n in sorted(
                a["open"].items(), key=lambda kv: WEIGHT.get(kv[0], 0), reverse=True)
                if WEIGHT.get(s, 0))
            note = f"  {opened}" if opened else ""
            blind = f"  ({len(a['blind'])} check(s) not reporting)" if a["blind"] else ""
            lines.append(f"  {a['name']:<22} {bar(a['score'], 10)} {a['score']:>3}%{note}{blind}")
    if result["next_steps"]:
        lines.append("  biggest gains:")
        for s in result["next_steps"][:3]:
            lines.append(f"    fix {s['severity']}: {s['title']} ({s['job']})")
    return lines

"""Durable collector receipts and conservative incident lifecycle accounting.

No OS access, notifications, model calls, or response authority belong here.
The caller owns the transaction. Replaying a retained run ID is idempotent;
reusing it for different evidence is an error. This is finding history, not a
replacement for raw sensor events or an independently protected audit log.
"""

import hashlib
import json
import math

SEVERITIES = {"critical": 0, "high": 1, "medium": 2, "low": 3}
COVERAGE = {"complete", "partial", "unavailable"}
# The error the scheduler stores when a run returned evidence but its coverage
# was not complete and no collector error explains why (a visibility finding).
COVERAGE_INCOMPLETE = "collector coverage incomplete"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False, default=str)


def coverage_status(findings, error="", reported="complete"):
    """A returned list is not complete if it contains an explicit blind spot.

    Legacy collectors do not all instrument successful source reads; complete
    therefore means collector-reported completeness, not universal coverage.
    """
    if reported not in COVERAGE:
        raise ValueError("invalid collection coverage")
    # A finding about another collector (the coverage audit reporting that
    # `hidden` failed) is complete evidence about that collector; it counts
    # against that collector's area, not as a blind spot in the reporter's.
    failed = error or any(
        f.get("coverage_status") in ("partial", "unavailable") or
        (f.get("category") in ("visibility", "collectors") and f.get("severity") != "ok"
         and not f.get("about_collector"))
        for f in findings)
    if reported == "unavailable":
        return reported
    if failed:
        return "partial" if findings else "unavailable"
    return reported


def identity(job, finding):
    """Separate hosts and sources; do not infer relationships from nearby times.

    New detectors may supply rule_id and subject_id. Legacy findings retain
    their category/title/location identity, with a process fingerprint if one
    is provided. A bare PID is deliberately not a stable entity identity.
    """
    parts = ["incident-v1", job, finding.get("host", ""),
             finding.get("rule_id") or finding.get("category", ""),
             "" if finding.get("rule_id") else finding.get("title", ""),
             finding.get("subject_id") or finding.get("fp") or finding.get("where", "")]
    return hashlib.sha256(encode(parts).encode()).hexdigest()


def record(db, job, findings, *, run_id, observed_at, coverage="complete", error=""):
    """Write one receipt plus incident projection, within the caller's transaction."""
    if not isinstance(job, str) or not job or len(job) > 128:
        raise ValueError("invalid observation job")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise ValueError("invalid observation run ID")
    if (type(observed_at) not in (int, float) or not math.isfinite(observed_at)
            or observed_at < 0):
        raise ValueError("invalid observation time")
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        raise ValueError("observation findings must be a list of objects")
    if not isinstance(error, str):
        raise ValueError("observation error must be text")
    coverage = coverage_status(findings, error, coverage)
    digest = hashlib.sha256(encode([job, observed_at, coverage, error, findings]).encode()).hexdigest()
    prior = db.execute("SELECT * FROM defender_runs WHERE run_id=?", (run_id,)).fetchone()
    if prior:
        if prior["digest"] != digest:
            raise ValueError("run ID already belongs to different evidence")
        return {**dict(prior), "duplicate": True}
    latest = db.execute(
        "SELECT observed_at FROM defender_runs WHERE job=? ORDER BY sequence DESC LIMIT 1",
        (job,)).fetchone()
    if latest and observed_at < latest["observed_at"]:
        raise ValueError("out-of-order observation; historical evidence needs a replay path")

    # A duplicated detector result in one pass is one sighting, with the most
    # serious severity. Never lower confidence because of list ordering.
    seen = {}
    for finding in findings:
        if finding.get("severity") not in SEVERITIES:
            continue
        key = identity(job, finding)
        old = seen.get(key)
        if old is None or SEVERITIES[finding["severity"]] < SEVERITIES[old["severity"]]:
            seen[key] = finding
    db.execute(
        "INSERT INTO defender_runs(run_id,job,observed_at,coverage,error,digest,finding_count) "
        "VALUES(?,?,?,?,?,?,?)",
        (run_id, job, observed_at, coverage, error[:800], digest, len(seen)))
    existing = {r["id"]: dict(r) for r in db.execute(
        "SELECT * FROM defender_incidents WHERE job=?", (job,))}
    for key, finding in seen.items():
        old = existing.get(key)
        severity = finding["severity"]
        evidence = encode(finding)
        previous = old["state"] if old else ""
        worst = min((old["worst_severity"], severity), key=SEVERITIES.get) if old else severity
        # Losing telemetry and regaining it is not a proven threat recurrence.
        recurrence = int(bool(old and previous == "not_observed"))
        db.execute(
            "INSERT INTO defender_incidents(id,job,host,category,title,locus,severity,"
            "worst_severity,state,first_seen,last_seen,updated_at,seen_count,recurrences,"
            "last_run_id,evidence) VALUES(?,?,?,?,?,?,?,?,'active',?,?,?,1,0,?,?) "
            "ON CONFLICT(id) DO UPDATE SET title=excluded.title,locus=excluded.locus,"
            "severity=excluded.severity,worst_severity=excluded.worst_severity,state='active',"
            "last_seen=excluded.last_seen,updated_at=excluded.updated_at,"
            "seen_count=defender_incidents.seen_count+1,"
            "recurrences=defender_incidents.recurrences+?,last_run_id=excluded.last_run_id,"
            "evidence=excluded.evidence",
            (key, job, str(finding.get("host", "")), str(finding.get("category", "")),
             str(finding.get("title", "")), str(finding.get("where", "")), severity, worst,
             observed_at, observed_at, observed_at, run_id, evidence, recurrence))
        if not old or previous != "active" or old["severity"] != severity:
            reason = "first observation" if not old else (
                "observed again" if previous != "active" else "severity changed")
            _transition(db, key, run_id, observed_at, previous, "active", reason, evidence)

    # Missing evidence is never evidence of remediation. Preserve the finding
    # and last_seen even when a collector returns nothing or stops working.
    state = "not_observed" if coverage == "complete" else "unobserved"
    reason = ("absent from a complete collector result; resolution unverified"
              if coverage == "complete" else "collector coverage incomplete; condition unknown")
    for key, old in existing.items():
        if key in seen:
            continue
        # A later blind pass does not invalidate an earlier complete pass that
        # established this incident was absent. Current source coverage lives
        # on defender_runs/overview.sources. Rewriting every dormant incident
        # to unobserved and back on a bridge wobble is both semantically noisy
        # and O(total historical incidents) write amplification.
        if coverage != "complete" and old["state"] == "not_observed":
            continue
        db.execute(
            "UPDATE defender_incidents SET state=?,updated_at=?,last_run_id=? WHERE id=?",
            (state, observed_at, run_id, key))
        if old["state"] != state:
            _transition(db, key, run_id, observed_at, old["state"], state, reason, old["evidence"])
    receipt = db.execute("SELECT * FROM defender_runs WHERE run_id=?", (run_id,)).fetchone()
    return {**dict(receipt), "duplicate": False}


def _transition(db, key, run_id, stamp, previous, state, reason, evidence):
    db.execute(
        "INSERT INTO defender_transitions(incident_id,run_id,observed_at,previous_state,"
        "state,reason,evidence) VALUES(?,?,?,?,?,?,?)",
        (key, run_id, stamp, previous, state, reason, evidence))


def overview(db, limit=100):
    """Bounded local read model. None of these states means verified resolution."""
    limit = max(1, min(500, int(limit)))
    counts = {state: 0 for state in ("active", "unobserved", "not_observed")}
    counts.update({r["state"]: r["n"] for r in db.execute(
        "SELECT state,COUNT(*) n FROM defender_incidents GROUP BY state")})
    rows = [dict(r) for r in db.execute(
        "SELECT id,job,host,category,title,locus,severity,worst_severity,state,first_seen,"
        "last_seen,updated_at,seen_count,recurrences,last_run_id FROM defender_incidents "
        "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END,updated_at DESC,id LIMIT ?", (limit,))]
    sources = [dict(r) for r in db.execute(
        "SELECT * FROM defender_runs WHERE sequence IN "
        "(SELECT MAX(sequence) FROM defender_runs GROUP BY job) ORDER BY job")]
    return {"schema_version": 1, "counts": counts, "total": sum(counts.values()),
            "incidents": rows, "sources": sources, "truncated": sum(counts.values()) > len(rows)}


def detail(db, incident_id, limit=100):
    row = db.execute("SELECT * FROM defender_incidents WHERE id=?", (incident_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["evidence"] = json.loads(result["evidence"])
    limit = max(1, min(500, int(limit)))
    result["transitions"] = []
    for item in db.execute(
            "SELECT * FROM defender_transitions WHERE incident_id=? ORDER BY sequence DESC LIMIT ?",
            (incident_id, limit)):
        item = dict(item)
        item["evidence"] = json.loads(item["evidence"])
        result["transitions"].append(item)
    result["transitions_total"] = db.execute(
        "SELECT COUNT(*) FROM defender_transitions WHERE incident_id=?", (incident_id,)).fetchone()[0]
    result["transitions_truncated"] = result["transitions_total"] > len(result["transitions"])
    return result

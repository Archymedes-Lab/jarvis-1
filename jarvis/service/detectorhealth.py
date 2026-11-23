"""Detector health: what each detector is doing, why, and what it means for coverage.

A read-only layer over the reliability plane (freshness, leases, retries) and
the stored snapshots. It adds the part those do not say: *why* a detector is
not producing evidence, in terms a person can act on, and how much of the
machine ARGUS can honestly claim to be watching because of it.

Invariants:
  * Health is derived from stored evidence (snapshot time, error, shape) and
    the schedule, never from a detector's own claim of being fine.
  * A detector is `healthy` only if its latest result is fresh, error-free and
    well-formed. "No findings" is healthy; "no result" never is.
  * Missing optional software, a permission limit, or an unsupported platform
    is reported as such. None of them is a compromise verdict.
  * Recovery is `confirmed` only when a result newer than the last failure is
    valid. A restart, a queued rerun or a recovery state alone does not count.
  * Coverage can only fall when evidence is lost and rise when fresh valid
    evidence returns; nothing here raises a score.
"""

from __future__ import annotations

import json
import time

from jarvis.core import mechanisms
from jarvis.service import reliability

HEALTHY, LATE, STALE = "healthy", "late", "stale"
FAILING, NEVER_RAN, MALFORMED = "failing", "never_ran", "malformed"
RESTRICTED, MISSING_DEP, UNSUPPORTED = "permission_restricted", "missing_dependency", "unsupported"
NOT_APPLICABLE = "not_applicable"

# Coverage classes. "claimed" would be a detector that says it is fine while
# its evidence is old; this layer never grants it, it only reports verified,
# partial, or blind.
VERIFIED, PARTIAL, BLIND, NA = "verified", "partial", "blind", "not_applicable"

REPEATED_FAILURES = 3

# How much the overall status leans on a check, from the reliability plane's own criticality rating.
_AFFECTS = {
    "critical": "Yes. The overall status is not reliable while this check is down.",
    "high": "Yes. The overall status is not reliable while this check is down.",
    "medium": "Partly. The overall status is less complete without it.",
    "low": "Slightly. The overall status is mostly unaffected.",
}
HISTORY_KEY, HISTORY_MAX = "detector_health_history", 200

_EXPLAIN = {
    HEALTHY: ("Working normally.", "None.", ""),
    LATE: ("Running a little behind schedule.", "Its coverage is slightly delayed.",
           "No action needed unless this continues."),
    STALE: ("Has not reported fresh results for too long.",
            "ARGUS may be missing activity in this area.",
            "Re-run it from the dashboard; if it stays stale, check the ARGUS service."),
    FAILING: ("Its last run failed.", "ARGUS may be missing activity in this area.",
              "Re-run it; if it fails again, read the recorded error."),
    NEVER_RAN: ("Has not produced a result on this computer yet.",
                "This area has not been observed.",
                "Wait for its first scheduled run, or re-run it from the dashboard."),
    MALFORMED: ("Returned a result ARGUS could not read.",
                "Its output is not trusted, so this area is treated as unobserved.",
                "Re-run it. If it repeats, the detector needs a fix."),
    RESTRICTED: ("It is not allowed to read something it needs.",
                 "This area is only partly observed.",
                 "Run ARGUS with the access this detector needs, or accept the gap."),
    MISSING_DEP: ("A program or file it depends on is missing on this computer.",
                  "This area is not observed. It does not mean anything is wrong.",
                  "Install the missing component, or accept the gap if you don't use it."),
    UNSUPPORTED: ("It is not supported on this computer.",
                  "This area cannot be observed here.",
                  "Nothing to fix; there is no alternative on this platform."),
    NOT_APPLICABLE: ("Does not apply to this computer.", "None; it is not expected here.", ""),
}
_COVERAGE = {HEALTHY: VERIFIED, LATE: PARTIAL, RESTRICTED: PARTIAL, NOT_APPLICABLE: NA}


def classify_error(error: str) -> str | None:
    """Map a recorded error string to a cause state, or None if unrecognised."""
    e = (error or "").lower()
    if any(k in e for k in ("permission", "access is denied", "access denied", "not permitted",
                            "eperm", "eacces", "requires administrator", "elevat")):
        return RESTRICTED
    if any(k in e for k in ("not supported", "unsupported", "not available on this platform")):
        return UNSUPPORTED
    # Only phrases that name a missing program, module or install count as a
    # missing dependency. A bare "not found" or "no such file" is ambiguous (a
    # data file, a process, an HTTP 404), and calling a genuine failure a
    # harmless missing component would under-warn, so it stays "failing" with
    # its recorded error on display.
    if any(k in e for k in ("command not found", "is not recognized as", "no module named",
                            "not installed", "executable file not found",
                            "is not recognized as the name of a cmdlet")):
        return MISSING_DEP
    return None


def _well_formed(snap: dict) -> bool:
    findings = snap.get("findings")
    return isinstance(findings, list) and all(isinstance(f, dict) for f in findings)


def assess(name: str, snap: dict | None, interval: int, status: dict | None = None,
           now: float | None = None) -> dict:
    """One detector's health from its stored snapshot. Pure; never raises."""
    now = time.time() if now is None else now
    status = status or {}
    ts = (snap or {}).get("ts")
    error = str((snap or {}).get("error") or "")
    age = (now - int(ts)) if ts else None
    level = reliability.classify(age, interval)
    failures = int(status.get("failure_count") or 0)

    if not snap or not ts:
        state = NEVER_RAN
    elif error:
        state = classify_error(error) or FAILING
    elif not _well_formed(snap):
        state = MALFORMED
    elif level == "STALE":
        state = STALE
    elif level in ("LATE", "DEGRADED"):
        state = LATE
    else:
        state = HEALTHY

    why, impact, action = _EXPLAIN[state]
    if state in (FAILING, STALE) and failures >= REPEATED_FAILURES:
        why = f"It has failed {failures} times in a row."
        action = "Automatic retries are paused; check the recorded error before re-running."
    last_failure = status.get("last_failure")
    confirmed = bool(state == HEALTHY and ts and (not last_failure or int(ts) > int(last_failure)))
    return {
        "id": name, "state": state,
        "coverage": _COVERAGE.get(state, BLIND),
        "reason": why, "impact": impact, "next_action": action,
        "last_success": int(ts) if ts and not error else None,
        "last_result": int(ts) if ts else None,
        "age_s": int(age) if age is not None else None,
        "expected_interval": interval,
        "error": " ".join(error.split())[:200],
        "failure_count": failures,
        "recovery_state": status.get("recovery_state") or "idle",
        "recovery_confirmed": confirmed,
        "findings": len((snap or {}).get("findings") or []) if state == HEALTHY else None,
    }


def report(jobs: dict, snapshots: dict, statuses: dict | None = None,
           not_applicable: dict | None = None, now: float | None = None) -> dict:
    """Every scheduled detector plus the ones that do not apply here."""
    now = time.time() if now is None else now
    statuses = statuses or {}
    detectors = []
    specs = reliability.build_specs(jobs)
    declared = {c.name: c for c in mechanisms.COLLECTORS}
    for name, entry in jobs.items():
        if name in reliability.NON_EVIDENCE_JOBS:
            continue
        item = assess(name, (snapshots or {}).get(name), int(entry[0]), statuses.get(name), now)
        item["label"] = entry[1] if len(entry) > 1 else name
        spec, decl = specs.get(name), declared.get(name)
        item["what"] = item["label"]
        item["criticality"] = spec.criticality if spec else "medium"
        item["affects_status"] = _AFFECTS.get(item["criticality"], _AFFECTS["medium"])
        item["command"] = (decl.command if decl and decl.command else "")
        detectors.append(item)
    for name, why in (not_applicable or {}).items():
        label = name
        detectors.append({"id": name, "label": label, "state": NOT_APPLICABLE, "coverage": NA,
                          "reason": why, "impact": _EXPLAIN[NOT_APPLICABLE][1], "next_action": "",
                          "last_success": None, "last_result": None, "age_s": None,
                          "expected_interval": None, "error": "", "failure_count": 0,
                          "recovery_state": "idle", "recovery_confirmed": False, "findings": None,
                          "what": label, "criticality": "low", "affects_status": "", "command": ""})
    scored = [d for d in detectors if d["coverage"] != NA]
    counts = {c: sum(1 for d in scored if d["coverage"] == c) for c in (VERIFIED, PARTIAL, BLIND)}
    problems = sorted((d for d in scored if d["state"] != HEALTHY),
                      key=lambda d: (d["coverage"] != BLIND, d["id"]))
    return {"detectors": detectors, "counts": counts, "total": len(scored),
            "attention": [d["id"] for d in problems],
            "summary": _summary(counts, len(scored), problems)}


def _summary(counts: dict, total: int, problems: list) -> str:
    if not total:
        return "No detectors are scheduled on this computer."
    if not problems:
        return f"All {total} detectors are reporting fresh, valid results."
    blind = counts[BLIND]
    return (f"{counts[VERIFIED]} of {total} detectors are verified and reporting. "
            f"{blind} {'is' if blind == 1 else 'are'} not producing usable results and "
            f"{counts[PARTIAL]} {'is' if counts[PARTIAL] == 1 else 'are'} partly covered. "
            "A gap in coverage is not evidence of an attack.")


def record_transitions(store, current: dict, now: float | None = None) -> list:
    """Append state changes to a bounded history; -> the new entries.

    Keeps timestamps and error text so a later investigation can see when a
    detector went blind and when fresh evidence confirmed it back. Writes only
    on change, so polling the dashboard does not grow the record."""
    now = int(time.time() if now is None else now)
    try:
        history = json.loads(store.get_meta(HISTORY_KEY, "[]") or "[]")
        history = history if isinstance(history, list) else []
    except ValueError:
        history = []
    latest = {}
    for entry in history:
        latest[entry.get("id")] = entry.get("state")
    new = []
    for d in current["detectors"]:
        if d["state"] == NOT_APPLICABLE:
            continue
        previous = latest.get(d["id"])
        if previous == d["state"] or (previous is None and d["state"] == HEALTHY):
            continue
        entry = {"ts": now, "id": d["id"], "state": d["state"], "from": previous,
                 "error": d["error"], "recovery_confirmed": d["recovery_confirmed"]}
        history.append(entry)
        new.append(entry)
    if new:
        store.set_meta(HISTORY_KEY, json.dumps(history[-HISTORY_MAX:]))
    return new


def history(store, detector: str | None = None) -> list:
    try:
        data = json.loads(store.get_meta(HISTORY_KEY, "[]") or "[]")
    except ValueError:
        return []
    return [e for e in data if detector is None or e.get("id") == detector]

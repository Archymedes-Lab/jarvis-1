"""Read-only posture and conditional projections from existing snapshots.

Debt counts are observations, never invented additive score deductions.
Each projection reruns the production score formula; gains overlap and must
not be added. Missing evidence cannot be projected away.
"""

from jarvis.core import posture
from jarvis.response import acknowledge, alert, protocols
from jarvis.response.reporting import score


def build(snapshots, jobs, *, acks=None, now=None, sustained_samples=None,
          repair_state=None):
    acks = acks or {}
    current = score.compute(snapshots, jobs, now, acks)
    debt = []
    for job, (interval, _) in jobs.items():
        if job not in score.AREA_OF:
            continue
        snap = snapshots.get(job) or {}
        fresh = score.freshness(snap, interval, current["at"])
        if fresh != "current":
            debt.append({"id": "coverage:" + job, "kind": posture.COVERAGE,
                         "job": job, "title": job + " evidence is " + fresh,
                         "severity": "unknown", "state": fresh})
        # Retain last observations even when collection fails.
        for finding in snap.get("findings") or []:
            if not isinstance(finding, dict) or finding.get("category") in alert.NOPAGE_CATEGORIES:
                continue
            if not score.WEIGHT.get(finding.get("severity"), 0):
                continue
            fid = acknowledge.finding_id(finding, job)
            accepted = acknowledge.is_acknowledged(acks, finding, job, current["at"])
            debt.append({"id": job + ":" + fid, "kind": posture.category(finding, accepted),
                         "job": job, "title": finding.get("title", ""),
                         "severity": finding.get("severity"), "state": fresh,
                         "expires_at": (acks.get(fid) or {}).get("expires") if accepted else None})
    candidates = []
    matched = set()
    for protocol in protocols.PROTOCOLS:
        targets = {(job, acknowledge.finding_id(f, job))
                   for job, snap in snapshots.items()
                   if job in jobs and score.freshness(snap, jobs[job][0], current["at"]) == "current"
                   for f in snap.get("findings") or []
                   if isinstance(f, dict) and score.WEIGHT.get(f.get("severity"), 0)
                   and posture.category(f) != posture.COVERAGE
                   and protocol.fixes(job, f)}
        if not targets:
            continue
        matched.update(targets)
        projected = _project(snapshots, jobs, targets, current["at"])
        severity = min((alert.SEV_RANK.get(row["severity"], 9) for row in debt
                        if any(row["id"] == job + ":" + fid for job, fid in targets)), default=9)
        candidates.append({"id": protocol.id, "title": protocol.title,
                           "projected_recovery": max(0, projected - current["score"]),
                           "priority": severity, "human_authorization": True,
                           "verification_jobs": list(protocol.jobs),
                           "prerequisites": list(protocol.requires), "status": "proposed"})
    candidates.sort(key=lambda row: (row["priority"], -row["projected_recovery"], row["id"]))
    repair = repair_state or {"status": "unverified", "actions": [], "verified": 0,
                              "failed": 0, "blocked": 0}
    sustained = score.sustained_health(sustained_samples or [], current["at"])
    gates = {
        "host_score_100": current["score"] == 100,
        "collector_coverage_100": current["coverage"] == 100 and bool(jobs),
        "no_weighted_findings": not any(row["kind"] != posture.COVERAGE for row in debt),
        "automatic_remediation_ledger_clear": (
            repair.get("status") == "active" and repair.get("failed") == 0
            and repair.get("blocked") == 0
            and all(action.get("status") == "verified"
                    for action in repair.get("actions", []))),
        "sustained_health_100_15m": sustained["status"] == "verified",
    }
    return {"score": current["score"], "coverage_pct": current["coverage"],
            "debt": debt, "debt_counts": {kind: sum(row["kind"] == kind for row in debt)
                                           for kind in posture.DEBT_KINDS},
            "candidates": candidates, "projection_is_verified": False,
            "projected_after_verified_remediation": _project(snapshots, jobs, matched, current["at"]),
            "projection_note": "Conditional on fresh successful verification; individual gains overlap.",
            "readiness": ("unknown" if not jobs else
                          "candidate" if all(gates.values()) else "blocked"),
            "readiness_scope": "host evidence gates only; JARVIS assurance is separate",
            "readiness_gates": gates,
            "automatic_remediation": repair,
            "sustained_health": sustained,
            "at": current["at"]}


def _project(snapshots, jobs, targets, now):
    copies = {job: {**snap, "findings": [f for f in snap.get("findings") or []
               if not isinstance(f, dict) or (job, acknowledge.finding_id(f, job)) not in targets]}
              for job, snap in snapshots.items()}
    return score.compute(copies, jobs, now)["score"]

"""Collector Reliability Plane: freshness budgets, leases and supervised recovery.

The failure this exists to prevent is not "collector down" but "no trustworthy
recent evidence while everything looks up": the daemon runs, the dashboard is
online, and several collectors have quietly aged out. A collector becomes stale
only after JARVIS has already noticed it going late and attempted recovery.

This module is pure policy plus small in-memory state. It does not run
collectors itself; the scheduler owns execution, and the watchdog loop in
``scheduler.py`` owns recovery attempts. Keeping the math here means it can be
unit-tested without threads, subprocesses or a database.

Contracts (per proposal):

    collector: persistence
    expected_interval: 300s
    soft_deadline: 390s (130%)
    hard_deadline: 600s (200%)
    execution_timeout: 45s
    retries: 3
    criticality: high

Freshness budgets, as a fraction of the expected interval:

    0-100%    FRESH
    100-130%  LATE        -> prioritize rerun immediately
    130-200%  DEGRADED    -> coverage reduced, watchdog escalation
    >200%     STALE       -> coverage lost, paging via coverage.py

Last-known-good semantics: a failed rerun never rewrites the last successful
snapshot as unsafe. ``collector_status`` keeps ``last_verified`` apart from
``current_coverage`` so the UI can say "CLEAN as of 21:00, verification
overdue by 5 min" instead of flipping between clean and unsafe.

Freshness invariant (testable):

    for every mandatory collector c:
        now - c.last_success <= c.hard_deadline
        OR c.recovery_state in {queued, retrying, restarting_dependency,
                                fallback_active}

There must never be STALE + "nothing trying to recover it".
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from jarvis.core import mechanisms

# Freshness budget boundaries, as multiples of the expected interval.
LATE_AFTER = 1.0
DEGRADED_AFTER = 1.3
STALE_AFTER = 2.0

# Recovery states that satisfy the freshness invariant while a collector is
# stale: something is actively trying to bring it back.
ACTIVE_RECOVERY = frozenset({
    "queued",
    "retrying",
    "restarting_dependency",
    "fallback_active",
})

# Bounded exponential retry: transient failure waits 2s, 5s, 15s, then stops
# hammering the machine and escalates instead.
RETRY_DELAYS = (2.0, 5.0, 15.0)

CRITICALITY_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0}

# Jobs that never describe evidence freshness. They are excluded from the
# mandatory set and from the invariant.
NON_EVIDENCE_JOBS = frozenset(mechanisms.names(evidence=False))

# Dependency roots: when one of these dies, every dependent collector fails
# for the same reason. Reporting the root once beats paging five times.
DEPENDENCIES: dict[str, tuple[str, ...]] = mechanisms.dependencies()


@dataclass(frozen=True)
class CollectorSpec:
    """Explicit contract for one scored collector."""
    name: str
    expected_interval: int
    execution_timeout: float = 45.0
    retries: int = 3
    criticality: str = "medium"
    tier: int = 2
    fallback: str | None = None
    dependencies: tuple[str, ...] = ()

    @property
    def soft_deadline(self) -> float:
        return self.expected_interval * DEGRADED_AFTER

    @property
    def hard_deadline(self) -> float:
        return self.expected_interval * STALE_AFTER


@dataclass
class CollectorLease:
    """A worker's claim on one collector run. Expiry without completion
    means the job did not complete -- no waiting minutes to infer failure."""
    collector: str
    lease_id: str
    worker_id: str
    started: float
    expires: float

    def expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires


@dataclass
class CollectorHealth:
    """Latest known reliability state for one collector."""
    name: str
    last_start: float | None = None
    last_success: float | None = None
    last_failure: float | None = None
    last_duration_ms: float = 0.0
    consecutive_failures: int = 0
    active_lease: CollectorLease | None = None
    worker_id: str = ""
    last_error: str = ""
    recovery_state: str = "idle"  # idle | queued | retrying |
    # restarting_dependency | fallback_active | escalated
    next_retry_at: float = 0.0


def classify(age_s: float, interval_s: float) -> str:
    """Freshness level for evidence ``age_s`` old against an expected
    interval. Unknown age (None/negative) is STALE: no result is no result."""
    if interval_s <= 0:
        return "STALE"
    if age_s is None or age_s < 0:
        return "STALE"
    ratio = age_s / interval_s
    if ratio <= LATE_AFTER:
        return "FRESH"
    if ratio <= DEGRADED_AFTER:
        return "LATE"
    if ratio <= STALE_AFTER:
        return "DEGRADED"
    return "STALE"


def freshness_pressure(age_s: float | None, interval_s: float) -> float:
    """Share of the promised cadence consumed. >1 means overdue."""
    if age_s is None or age_s < 0 or interval_s <= 0:
        return 99.0
    return age_s / interval_s


def priority(spec: CollectorSpec, age_s: float | None,
             consecutive_failures: int = 0) -> float:
    """Scheduler priority: criticality x freshness pressure x failure pressure.

    Something approaching stale naturally rises to the top, and a repeatedly
    failing collector gets a bounded boost so it is retried rather than
    starved -- without permanently eclipsing everything else.
    """
    weight = CRITICALITY_WEIGHT.get(spec.criticality, 1.0)
    fresh = max(0.0, freshness_pressure(age_s, spec.expected_interval))
    failure = 1.0 + min(3, max(0, consecutive_failures)) * 0.25
    return weight * (1.0 + fresh) * failure


def retry_delay(attempt: int) -> float | None:
    """Seconds to wait before retry ``attempt`` (0-based), or None when the
    bounded retry budget is spent and the plane must escalate instead."""
    if attempt < 0 or attempt >= len(RETRY_DELAYS):
        return None
    return RETRY_DELAYS[attempt]


def _tier_and_criticality(name: str, interval: int) -> tuple[int, str]:
    """Tier assignment keeps expensive collectors from starving fast ones.

    Tier 0 continuous: native event streams. Tier 1 (1-2 min): liveness
    reconciliation. Tier 2 (~5 min): persistence/firewall/hidden. Tier 3
    (15+ min): secrets/posture/toolchain/deep checks. Tier 4 (daily/event):
    expensive hunts. Declared collectors carry theirs in core/mechanisms.py;
    a name outside the registry (synthetic tables in tests) is placed by
    interval alone.
    """
    declared = mechanisms.BY_NAME.get(name)
    if declared is not None:
        return declared.tier, declared.criticality
    if interval <= 300:
        return 2, "medium"
    if interval <= 7200:
        return 3, "medium"
    return 4, "low"


def _execution_timeout(name: str, interval: int) -> float:
    """Bounded run budget per collector. Fast-lane watchdogs must stay under
    a few seconds; slow audits get room without holding the plane hostage."""
    declared = mechanisms.BY_NAME.get(name)
    if declared is not None:
        return declared.timeout
    # A PowerShell audit costs 15-90s; cap well below the shortest hard
    # deadline so a hang is detected before dependents go stale.
    return min(300.0, max(60.0, interval / 10.0))


def build_specs(jobs: dict[str, tuple]) -> dict[str, CollectorSpec]:
    """Derive an explicit contract for every scheduled job from the single
    schedule table, so the scheduler, coverage and dashboard read one truth."""
    specs: dict[str, CollectorSpec] = {}
    for name, entry in jobs.items():
        interval = int(entry[0]) if entry else 0
        tier, criticality = _tier_and_criticality(name, interval)
        deps: tuple[str, ...] = ()
        for root, members in DEPENDENCIES.items():
            if name in members:
                deps = deps + (root,)
        specs[name] = CollectorSpec(
            name=name,
            expected_interval=interval,
            execution_timeout=_execution_timeout(name, interval),
            retries=3,
            criticality=criticality,
            tier=tier,
            dependencies=deps,
        )
    return specs


def acquire_lease(health: CollectorHealth, worker_id: str,
                  timeout_s: float, now: float | None = None) -> CollectorLease:
    """Claim a collector run. The lease expires even if the worker dies."""
    stamp = time.time() if now is None else now
    lease = CollectorLease(
        collector=health.name,
        lease_id=uuid.uuid4().hex[:12],
        worker_id=worker_id,
        started=stamp,
        expires=stamp + max(1.0, timeout_s),
    )
    health.active_lease = lease
    health.worker_id = worker_id
    health.last_start = stamp
    return lease


def release_lease(health: CollectorHealth, lease: CollectorLease,
                  success: bool, error: str = "",
                  duration_ms: float = 0.0,
                  now: float | None = None) -> None:
    """Close a lease. Only the holder's lease may close it, so a late orphan
    thread can never overwrite a newer run's verdict."""
    if health.active_lease is not lease:
        return
    stamp = time.time() if now is None else now
    health.active_lease = None
    health.last_duration_ms = max(0.0, duration_ms)
    if success:
        health.last_success = stamp
        health.consecutive_failures = 0
        health.last_error = ""
        health.recovery_state = "idle"
    else:
        health.last_failure = stamp
        health.consecutive_failures += 1
        health.last_error = (error or "collector failed")[:500]


def expired_leases(states: dict[str, CollectorHealth],
                   now: float | None = None) -> list[str]:
    """Collectors whose worker died without reporting completion."""
    stamp = time.time() if now is None else now
    return sorted(name for name, health in states.items()
                  if health.active_lease is not None
                  and health.active_lease.expired(stamp))


class ReliabilityState:
    """In-memory health receipts for the reliability plane."""

    def __init__(self, specs: dict[str, CollectorSpec]):
        self.specs = specs
        self.health: dict[str, CollectorHealth] = {
            name: CollectorHealth(name=name) for name in specs
        }

    def status(self, name: str, snapshot_ts: float | None,
               snapshot_error: str = "",
               now: float | None = None) -> dict:
        """One collector's contract state: LAST START/SUCCESS/FAILURE, NEXT
        DEADLINE, EXPECTED CADENCE, RUNTIME, FAILURE COUNT, CURRENT WORKER,
        FRESH/LATE/DEGRADED/STALE. Never claims clean on missing evidence:
        unknown last success is STALE with last_verified None."""
        stamp = time.time() if now is None else now
        spec = self.specs[name]
        health = self.health[name]
        age = (stamp - snapshot_ts) if snapshot_ts else None
        level = classify(age if age is not None else -1, spec.expected_interval)
        current_coverage = "complete"
        if snapshot_error:
            current_coverage = "unavailable"
        elif level in ("DEGRADED", "STALE"):
            current_coverage = "degraded"
        elif level == "LATE":
            current_coverage = "late"
        return {
            "collector": name,
            "expected_interval": spec.expected_interval,
            "soft_deadline": spec.soft_deadline,
            "hard_deadline": spec.hard_deadline,
            "execution_timeout": spec.execution_timeout,
            "criticality": spec.criticality,
            "tier": spec.tier,
            "freshness": level,
            "age_s": age,
            "last_start": health.last_start,
            "last_success": snapshot_ts,
            "last_failure": health.last_failure,
            "next_deadline": (snapshot_ts + spec.expected_interval)
            if snapshot_ts else stamp,
            "expected_cadence": spec.expected_interval,
            "runtime_ms": health.last_duration_ms,
            "failure_count": health.consecutive_failures,
            "current_worker": (health.active_lease.worker_id
                               if health.active_lease else health.worker_id),
            "lease_expires": (health.active_lease.expires
                              if health.active_lease else None),
            "last_error": snapshot_error or health.last_error,
            # Last-known-good: the verified state survives a failed rerun.
            "last_verified": snapshot_ts,
            "current_coverage": current_coverage,
            "recovery_state": health.recovery_state,
        }

    def all_statuses(self, snapshots: dict,
                     now: float | None = None) -> dict[str, dict]:
        stamp = time.time() if now is None else now
        out: dict[str, dict] = {}
        for name in self.specs:
            snap = (snapshots or {}).get(name) or {}
            out[name] = self.status(name, snap.get("ts"),
                                    snap.get("error", ""), now=stamp)
        return out

    def invariant_violations(self, snapshots: dict,
                             now: float | None = None) -> list[dict]:
        """Collectors that are STALE with nothing actively recovering them.

        This is the bug class to eliminate: silent staleness. A stale
        collector with queued/retrying/restart/fallback state is degraded but
        supervised, not a violation.
        """
        stamp = time.time() if now is None else now
        violations = []
        for name, spec in self.specs.items():
            if name in NON_EVIDENCE_JOBS:
                continue
            snap = (snapshots or {}).get(name) or {}
            ts = snap.get("ts")
            age = (stamp - ts) if ts else None
            if classify(age if age is not None else -1,
                        spec.expected_interval) != "STALE":
                continue
            state = self.health[name].recovery_state
            forced = snap.get("_forced", False)
            if state in ACTIVE_RECOVERY or forced:
                continue
            violations.append({
                "collector": name,
                "age_s": age,
                "hard_deadline": spec.hard_deadline,
                "recovery_state": state,
            })
        return violations

    def pick_next(self, candidates: list[str], snapshots: dict,
                  now: float | None = None) -> str | None:
        """Highest-priority due collector: criticality x freshness pressure
        x failure pressure. Candidates must already be due."""
        stamp = time.time() if now is None else now
        best, best_score = None, None
        for name in candidates:
            spec = self.specs.get(name)
            if spec is None:
                continue
            snap = (snapshots or {}).get(name) or {}
            ts = snap.get("ts")
            age = (stamp - ts) if ts else None
            score = priority(spec, age,
                             self.health[name].consecutive_failures)
            if best_score is None or score > best_score:
                best, best_score = name, score
        return best

    def dependency_root_cause(self, failing: list[str]) -> dict:
        """Collapse many dependent failures into one root dependency."""
        counts: dict[str, list[str]] = {}
        for dep, members in DEPENDENCIES.items():
            affected = [name for name in failing if name in members]
            if affected:
                counts[dep] = affected
        if not counts:
            return {}
        root = max(counts, key=lambda dep: len(counts[dep]))
        return {"root": root, "affected": sorted(counts[root])}

    def summary(self, snapshots: dict, now: float | None = None) -> dict:
        statuses = self.all_statuses(snapshots, now=now)
        levels = {"FRESH": 0, "LATE": 0, "DEGRADED": 0, "STALE": 0}
        for entry in statuses.values():
            levels[entry["freshness"]] = levels.get(entry["freshness"], 0) + 1
        stale = sorted(name for name, entry in statuses.items()
                       if entry["freshness"] == "STALE"
                       and name not in NON_EVIDENCE_JOBS)
        recovering = sorted(name for name in stale
                            if self.health[name].recovery_state
                            in ACTIVE_RECOVERY)
        return {
            "levels": levels,
            "stale_collectors": stale,
            "recovering": recovering,
            "violations": [v["collector"] for v in
                           self.invariant_violations(snapshots, now=now)],
            "expired_leases": expired_leases(self.health, now=now),
        }

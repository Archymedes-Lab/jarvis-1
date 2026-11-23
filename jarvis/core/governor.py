"""Resource governor: JARVIS controls its own footprint.

Phase 5 groundwork (advisory, not yet enforcing): observe CPU, RAM, disk
pressure, battery/AC, user activity, queue depth and telemetry backlog, and
decide which noncritical work must pause. The scheduler and dashboard read
this decision; nothing here kills processes or changes collection.

Tiers (Phase 20):
  Tier 0  OS protection, native telemetry, firewall, event storage, response
          — ALWAYS LOCAL, never paused by the governor.
  Tier 1  local models, local intelligence — optional, pausable.
  Tier 2  cloud intelligence, satellite, Exa, updates — enrichment, pausable.

A pressured host pauses Tier 1/2 maintenance; an idle host on AC resumes it.
"""

from jarvis.core import mechanisms

TIER_0 = ("native telemetry", "critical detection", "event persistence",
          "firewall", "response")
TIER_1 = ("local model narration", "threat-intel refresh")
TIER_2 = ("deep threat hunt", "large secret scan", "database compaction",
          "satellite refresh", "intelligence update")

NONCRITICAL = TIER_1 + TIER_2

# Scheduler job names the governor may defer under pressure. Tier 0 jobs
# (scan, bridge, native, firewall-adjacent coverage) are never in this set:
# protection, ingestion and freshness supervision always run.
# Declared per collector in core/mechanisms.py (conformance forbids tier 0
# and fast-lane collectors from being governed).
GOVERNED_JOBS = frozenset(mechanisms.names(governed=True))

CPU_PRESSURE_PCT = 75.0
QUEUE_PRESSURE = 50
BACKLOG_PRESSURE = 20


def decide(*, cpu_pct=None, memory_pressure=False, disk_pressure=False,
           battery_saver=False, user_active_compiling=False,
           queue_depth=0, telemetry_backlog=0, on_ac=True):
    """Pure advisory decision. Returns {"pause": [...], "keep": [...], "reason"}."""
    pressured = (
        (cpu_pct is not None and cpu_pct >= CPU_PRESSURE_PCT)
        or bool(memory_pressure)
        or bool(disk_pressure)
        or bool(battery_saver)
        or bool(user_active_compiling)
        or queue_depth >= QUEUE_PRESSURE
        or telemetry_backlog >= BACKLOG_PRESSURE
    )
    if pressured:
        causes = []
        if cpu_pct is not None and cpu_pct >= CPU_PRESSURE_PCT:
            causes.append(f"CPU {cpu_pct:.0f}%")
        if memory_pressure:
            causes.append("memory pressure")
        if disk_pressure:
            causes.append("disk pressure")
        if battery_saver:
            causes.append("battery saver")
        if user_active_compiling:
            causes.append("user compiling")
        if queue_depth >= QUEUE_PRESSURE:
            causes.append(f"queue {queue_depth}")
        if telemetry_backlog >= BACKLOG_PRESSURE:
            causes.append(f"telemetry backlog {telemetry_backlog}")
        return {"pause": list(NONCRITICAL), "keep": list(TIER_0),
                "pressured": True,
                "reason": "host pressured (" + ", ".join(causes) + "); "
                          "Tier 0 only, resume deferred maintenance when idle"}
    if on_ac and queue_depth == 0 and telemetry_backlog == 0:
        return {"pause": [], "keep": list(TIER_0 + NONCRITICAL),
                "pressured": False,
                "reason": "machine idle on AC; deferred maintenance may resume"}
    return {"pause": [], "keep": list(TIER_0 + NONCRITICAL),
            "pressured": False, "reason": "nominal load; all tiers permitted"}


def attribution(owner_cpu, owner_rss):
    """JARVIS self-cost breakdown: which part of JARVIS costs what.

    Inputs are {owner: cpu_pct} and {owner: rss_bytes} mappings (see
    resourcewatch owners). Returns shares that always sum to ~1 so the
    dashboard can render "what part of JARVIS is slowing JARVIS down"
    without inventing precision the counters do not have. Tier 0 work is
    never deferrable; deferral applies only to GOVERNED_JOBS.
    """
    owners = set(owner_cpu) | set(owner_rss)
    total_cpu = sum(max(0.0, owner_cpu.get(o, 0.0)) for o in owners) or 1.0
    total_rss = sum(max(0, owner_rss.get(o, 0)) for o in owners) or 1
    out = {}
    for owner in sorted(owners):
        out[owner] = {
            "cpu_share": round(max(0.0, owner_cpu.get(owner, 0.0)) / total_cpu, 4),
            "rss_share": round(max(0, owner_rss.get(owner, 0)) / total_rss, 4),
        }
    return out


def should_defer(job_name, pressured):
    """Whether the scheduler may defer one job under governor pressure.

    Pure. Tier 0 protection/ingestion jobs never defer; only GOVERNED_JOBS
    yield. Deferral is a delay, not a drop: the job stays due and runs when
    pressure clears, so staleness accounting keeps working.
    """
    return bool(pressured) and job_name in GOVERNED_JOBS


def live_pressure(queue_depth=0, telemetry_backlog=0):
    """Cheap host-pressure probe for the scheduling hot path. Never raises.

    Reads 1-minute load average vs CPU count and available-memory share;
    no subprocesses, no Windows interop. Returns (pressured, detail).
    """
    try:
        import os
        cpu_count = max(1, os.cpu_count() or 1)
        try:
            with open("/proc/loadavg", errors="replace") as fh:
                load1 = float(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            load1 = 0.0
        cpu_pct = load1 / cpu_count * 100.0
        memory_pressure = False
        try:
            values = {}
            with open("/proc/meminfo", errors="replace") as fh:
                for line in fh:
                    name, value = line.split(":", 1)
                    values[name] = int(value.split()[0])
            total = values.get("MemTotal", 0)
            avail = values.get("MemAvailable", total)
            memory_pressure = bool(total) and (avail / total * 100.0) < 10.0
        except (OSError, ValueError, KeyError, IndexError):
            pass
        decision = decide(cpu_pct=cpu_pct, memory_pressure=memory_pressure,
                          queue_depth=queue_depth,
                          telemetry_backlog=telemetry_backlog)
        return decision["pressured"], decision["reason"]
    except Exception:
        return False, "pressure probe unavailable; all tiers permitted"

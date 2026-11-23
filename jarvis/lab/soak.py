"""Soak analysis: prove JARVIS stays flat over days, not minutes.

Phase 24. A soak run samples the daemon (RSS, FDs, threads, database and
spool bytes, event lag, CPU average) over 24h/72h/7d; this module judges
the samples. Pure: no clocks, no IO. The load-bearing metric is RAM after
warmup — essentially flat, or there is a leak or an unbounded cache.

Sample shape: {"at": epoch, "rss_mb": f, "fds": i, "threads": i,
"db_mb": f, "spool_mb": f, "event_lag_s": f, "cpu_pct": f}.
Warmup (first WARMUP_S seconds) is excluded from growth fits so allocator
settling never reads as a leak.

Usage: collect samples (e.g. every 60 s from /proc/self/statm, /proc/self/fd,
`du` on the database and spool, scheduler heartbeats), then analyse().
"""

WARMUP_S = 3600.0

# Per-day growth budgets. RAM is the strictest: after warmup it must be
# flat within measurement noise, or the soak fails.
BUDGETS = {
    "rss_mb": 5.0,       # MB/day: flat after warmup
    "fds": 2.0,          # descriptors/day
    "threads": 1.0,      # threads/day
    "db_mb": 50.0,       # MB/day: event volume, bounded by retention budget
    "spool_mb": 20.0,    # MB/day: un-ingested backlog must not grow
    "event_lag_s": 1.0,  # seconds/day: ingestion keeps up
}


def linear_slope(xs, ys):
    """Least-squares slope of y on x; 0.0 when undefined. Pure."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    denom = sum((x - mean_x) ** 2 for x in xs)
    if not denom:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys)) / denom


def analyze(samples, budgets=None, warmup=WARMUP_S):
    """Judge soak samples against per-day growth budgets.

    Returns {"ok": bool, "metrics": {name: {slope_per_day, ...}},
    "problems": [...], "samples": n}. Empty or warmup-only input is not a
    pass: it is reported as insufficient evidence.
    """
    budgets = dict(BUDGETS if budgets is None else budgets)
    samples = sorted(samples, key=lambda s: s.get("at", 0))
    if not samples:
        return {"ok": False, "metrics": {}, "problems": ["no samples"],
                "samples": 0}
    start = samples[0].get("at", 0)
    settled = [s for s in samples if s.get("at", 0) - start >= warmup]
    if len(settled) < 2:
        return {"ok": False, "metrics": {},
                "problems": ["insufficient post-warmup evidence"],
                "samples": len(samples)}
    problems, metrics = [], {}
    for name, budget in budgets.items():
        xs = [s["at"] for s in settled if isinstance(s.get(name), (int, float))]
        ys = [float(s[name]) for s in settled if isinstance(s.get(name), (int, float))]
        if len(xs) < 2:
            continue
        slope_day = linear_slope(xs, ys) * 86400.0
        metrics[name] = {"slope_per_day": round(slope_day, 3),
                         "first": ys[0], "last": ys[-1]}
        if slope_day > budget:
            problems.append(
                f"{name} grows {slope_day:.1f}/day, budget {budget}/day")
    # Absolute guards: descriptors and lag have ceilings regardless of slope.
    last = settled[-1]
    if isinstance(last.get("fds"), (int, float)) and last["fds"] > 500:
        problems.append(f"fd count {last['fds']}: ceiling 500")
    if isinstance(last.get("event_lag_s"), (int, float)) and last["event_lag_s"] > 60:
        problems.append(f"event lag {last['event_lag_s']}s: ceiling 60s")
    return {"ok": not problems, "metrics": metrics, "problems": problems,
            "samples": len(samples)}

"""Sampled execution + heatmaps: where CPU really goes. Pure, bounded.

Normal operation stores low-rate samples (instruction pointer, stack,
thread, process, module), never every instruction. Aggregation yields
per-module and per-function heatmaps; a process whose CPU shifts from
signed modules into unknown private regions becomes visible as a
deviation, not a verdict. No IO, no clocks.
"""


def heatmap(samples, limit=500):
    """Aggregate samples into {module: share} and {function: share}."""
    samples = list(samples or [])[:max(0, int(limit))]
    mod, func, total = {}, {}, 0
    for s in samples:
        total += 1
        mod[s.get("module") or "unknown"] = \
            mod.get(s.get("module") or "unknown", 0) + 1
        if s.get("function"):
            func[s.get("function")] = func.get(s.get("function"), 0) + 1
    if not total:
        return {"modules": {}, "functions": {}, "samples": 0}
    return {"modules": {k: round(v / total, 4) for k, v in
                        sorted(mod.items(), key=lambda kv: -kv[1])},
            "functions": {k: round(v / total, 4) for k, v in
                          sorted(func.items(), key=lambda kv: -kv[1])[:20]},
            "samples": total}


def deviation(baseline_heatmap, current_heatmap, *, threshold=0.15):
    """Unknown-region share shift beyond threshold. Returns dict or None."""
    base = (baseline_heatmap or {}).get("modules", {})
    cur = (current_heatmap or {}).get("modules", {})
    shift = (cur.get("unknown", 0.0) or 0.0) - (base.get("unknown", 0.0) or 0.0)
    if shift >= threshold:
        return {"detector": "execution-shift", "severity": "medium",
                "unknown_shift": round(shift, 4),
                "detail": (f"CPU in unknown regions rose {shift:.0%} vs "
                           "baseline: subtle change worth correlation")}
    return None

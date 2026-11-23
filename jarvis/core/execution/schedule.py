"""Sampling schedule: every signal gets its own timescale. Pure.

Event-driven (process/thread/module/network/file/registry/service/
driver) is always on. Interval signals back off by cost: sub-second CPU
and responsiveness, 1s RAM/disk/throughput/GPU, 5-30s thermal/power,
minutes for full reconciliation and baseline comparison. Suspicious
entities (L2/L3) boost one step; governor pressure drops noncritical
sampling entirely. Constants are reviewable; no IO, no clocks.
"""

EVENT_DRIVEN = ("process", "thread", "module", "network", "file",
                "registry", "service", "driver")

INTERVALS_S = {
    "cpu": 0.25,
    "responsiveness": 0.5,
    "ram": 1.0,
    "disk": 1.0,
    "net_throughput": 1.0,
    "gpu": 1.0,
    "temperature": 15.0,
    "power": 15.0,
    "reconciliation": 300.0,
    "baseline_compare": 600.0,
}

BOOSTED = {"L2": 0.5, "L3": 0.25}


def interval(signal, *, level="L1", pressured=False):
    """Seconds between samples for one signal. Pure."""
    if signal in EVENT_DRIVEN:
        return 0.0
    base = INTERVALS_S.get(signal)
    if base is None:
        raise ValueError(f"unknown signal {signal!r}")
    if pressured and signal in ("reconciliation", "baseline_compare",
                                "temperature", "power", "gpu"):
        return base * 4
    return base * BOOSTED.get(level, 1.0)

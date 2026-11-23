"""Resource deltas: checkpoints, not repeated steady state. Pure.

Instead of persisting temperature=57 forever, keep a checkpoint and
record 57->63 deltas beyond a per-signal threshold. Same for process
counts: store create/exit transitions, not repeated full listings.
Thresholds are parameters. No IO, no clocks.
"""

DEFAULT_THRESHOLDS = {
    "temperature": 2.0,
    "cpu": 5.0,
    "memory_pressure": 5.0,
    "disk_latency_ms": 20.0,
    "responsiveness": 5.0,
}


def delta(checkpoint, current, *, thresholds=None):
    """Return {signal: (old, new)} for moves beyond threshold. Pure."""
    thresholds = thresholds or DEFAULT_THRESHOLDS
    out = {}
    for signal, new in (current or {}).items():
        old = (checkpoint or {}).get(signal)
        if old is None or new is None:
            continue
        try:
            if abs(float(new) - float(old)) >= float(
                    thresholds.get(signal, 0)):
                out[signal] = (old, new)
        except (TypeError, ValueError):
            if old != new:
                out[signal] = (old, new)
    return out

"""JARVIS monitors JARVIS: sensor self-watch and suppression tripwires.

Signals: sensor exit/stop, log cleared, bookmark reset, sequence gaps,
spool stall, event-rate collapse while the machine stays active
(telemetry contradiction), and envelope breaches (surge/drop vs learned
min/max). A suddenly quiet system is evidence, not health. Pure.
"""


def contradiction(*, events_per_min=0, baseline_min=100,
                  cpu_active=False, snapshot_changing=False):
    """Silent stream while activity continues. Returns dict or None."""
    if events_per_min == 0 and (cpu_active or snapshot_changing):
        return {"detector": "telemetry-contradiction", "severity": "high",
                "detail": ("event stream silent while CPU/snapshot activity "
                           "continues: possible blind-spot creation")}
    if events_per_min < baseline_min * 0.1 \
            and (cpu_active or snapshot_changing):
        return {"detector": "telemetry-suppression", "severity": "medium",
                "detail": (f"{events_per_min} events/min vs baseline "
                           f"{baseline_min}: investigate, do not assume quiet")}
    return None


def envelope(value, *, lo=0.0, hi=1.0, name="rate"):
    """Surge/drop vs learned envelope. Returns dict or None."""
    if value < lo or value > hi:
        return {"detector": "envelope-breach", "severity": "low",
                "detail": f"{name}={value} outside [{lo}, {hi}]: signal"}
    return None


def sensor_liveness(*, exited=False, gap=False, spool_stalled=False,
                    log_cleared=False):
    """Sensor-health transitions that are themselves security events."""
    out = []
    if exited:
        out.append({"detector": "sensor-exit", "severity": "high",
                    "detail": "native sensor exited: coverage at risk"})
    if log_cleared:
        out.append({"detector": "log-cleared", "severity": "high",
                    "detail": "event log cleared: generation boundary + gap"})
    if gap:
        out.append({"detector": "sequence-gap", "severity": "medium",
                    "detail": "sequence gap: continuity broken"})
    if spool_stalled:
        out.append({"detector": "spool-stall", "severity": "medium",
                    "detail": "spool stopped moving: ingestion at risk"})
    return out

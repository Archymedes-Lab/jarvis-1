"""What to say when the administrator sensor is not installed.

The Windows release without the elevated parts (the Sysmon-fed native sensor
and the read-only broker) runs everything that needs no administrator rights.
It must not read as full coverage: each collector that uses the broker's
results (`broker.result`) or the native sensor's spool is declared on the
registry with `admin_sensor="unavailable"` or `"limited"` (core/mechanisms.py).
Without the sensor those jobs are reported as blind with one reason, in the
same words everywhere.

Adding the elevated components in a later native release needs no change
here: once `broker.installed()` is true, `absent()` is false and nothing is
reported.
"""

import sys

from jarvis.core.mechanisms import NEEDS_ADMIN_SENSOR, admin_sensor_jobs

__all__ = ["NEEDS_ADMIN_SENSOR", "absent", "merge_blind"]


def absent():
    """True on Windows when the elevated broker is not installed."""
    if not sys.platform.startswith("win"):
        return False
    from jarvis.platform import broker
    try:
        return not broker.installed()
    except OSError:
        return True


def merge_blind(blind, labels, is_absent=None):
    """Add the missing sensor's reason to the pulse's `blind` list, in place.

    A job that needs the sensor is reported with the one reason whether or not
    it is also stale or erroring for a generic reason: without the sensor that
    is the cause, and "stale" would hide it. A job already listed keeps its
    freshness and error fields and gains `reason` and `level`; a job not yet
    listed (it ran, unprivileged, and found what it could) is added as limited.
    `labels` maps job -> display label.
    """
    if not (absent() if is_absent is None else is_absent):
        return blind
    listed = {b.get("job"): b for b in blind}
    for job, level in admin_sensor_jobs().items():
        if job not in labels:
            continue
        entry = listed.get(job)
        if entry is None:
            blind.append({"job": job, "label": labels[job], "reason": NEEDS_ADMIN_SENSOR, "level": level,
                          "freshness": "UNAVAILABLE", "error": False})
        else:
            entry["reason"], entry["level"] = NEEDS_ADMIN_SENSOR, level
    return blind

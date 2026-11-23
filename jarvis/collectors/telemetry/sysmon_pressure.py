"""Bounded, aggregate Sysmon boot-pressure evidence from the elevated broker."""

from jarvis.platform import broker


def audit(now=None):
    """Return health-safe loss and retained-volume measurements; never raises."""
    try:
        data, why = broker.result("sysmon_pressure", now=now)
        if data is None:
            return {"status": "unknown", "detail": why}
        if data.get("ok") is not True or data.get("error"):
            return {"status": "unknown",
                    "detail": str(data.get("error") or "probe failed")[:200]}
        drops = []
        for item in (data.get("drops") or [])[:20]:
            counts = item.get("counts") if isinstance(item, dict) else None
            if not isinstance(counts, dict):
                continue
            drops.append({
                "at": item.get("at"),
                "counts": {str(k)[:40]: int(v) for k, v in counts.items()
                           if type(v) is int and v >= 0},
                "driver_queue_size": item.get("driver_queue_size"),
            })
        return {
            "status": "observed",
            "boot": data.get("boot"),
            "retained_registry_events": int(
                data.get("retained_registry_events") or 0),
            "by_rule": _ranked(data.get("by_rule")),
            "by_image": _ranked(data.get("by_image")),
            "drops": drops,
            "truncated": data.get("truncated") is True,
            "source": "elevated_broker",
        }
    except (KeyError, TypeError, ValueError):
        return {"status": "unknown", "detail": "malformed broker evidence"}


def _ranked(rows):
    out = []
    for row in (rows or [])[:20]:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "(unknown)")[:120]
        count = row.get("count")
        if type(count) is int and count >= 0:
            out.append({"name": name, "count": count})
    return out

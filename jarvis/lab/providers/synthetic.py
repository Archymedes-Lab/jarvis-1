"""Generate a scenario's telemetry as canonical events — executing nothing.

The scenario's `spec.events` is a list of `{id, data}` in a channel's own
vocabulary (Sysmon event IDs and their EventData names). Each becomes a real
source record, is normalized exactly as the sensor's output would be, and is
appended to the event log under test. This is how the Arena exercises detection
of dangerous behavior — LSASS access, injection, recovery destruction — on any
machine, without the behavior ever happening.
"""

from datetime import datetime, timezone

from jarvis.platform.native import normalize

CHANNELS = {"sysmon": normalize.SYSMON, "defender": normalize.DEFENDER,
            "tasks": normalize.TASKS}


def _xml(channel, eid, data):
    provider = {"sysmon": "Microsoft-Windows-Sysmon",
                "defender": "Microsoft-Windows-Windows Defender",
                "tasks": "Microsoft-Windows-TaskScheduler"}[channel]
    fields = "".join(
        f"<Data Name='{k}'>{_escape(v)}</Data>" for k, v in (data or {}).items())
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System><Provider Name='{provider}'/><EventID>{eid}</EventID></System>"
            f"<EventData>{fields}</EventData></Event>")


def _escape(v):
    return (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def produce(scenario, log):
    spec = scenario.spec or {}
    channel_key = spec.get("channel", "sysmon")
    channel = CHANNELS.get(channel_key, normalize.SYSMON)
    events_spec = spec.get("events") or []
    if not events_spec:
        raise ValueError(f"{scenario.id}: synthetic scenario has no spec.events")
    now = datetime.now(timezone.utc)
    batch = {"schema": 2, "sensor_id": "arena", "device_id": "arena", "boot_id": "arena",
             "host_id": "ARENA", "channel": channel, "generation": f"arena-{scenario.id}",
             "sequence": 1, "previous_sequence": 0, "created_at": now.isoformat(),
             "bookmark": "", "status": "complete", "gap": None, "events": []}
    events = []
    for i, item in enumerate(events_spec, start=1):
        stamp = now.replace(microsecond=min(999999, i * 1000)).isoformat()
        data = dict(item.get("data") or {})
        # Let a scenario omit UtcTime; give each event a distinct, ordered one.
        if channel is normalize.SYSMON:
            data.setdefault("UtcTime", stamp.replace("+00:00", "").replace("T", " ")[:23])
        record = {"record_id": i, "event_id": int(item["id"]), "time": stamp,
                  "mono_ms": i, "xml": _xml(channel_key, int(item["id"]), data)}
        events.append(normalize.normalize(record, batch))
    return log.append(events, {"sensor": "arena", "channel": channel,
                               "sequence": 1, "generation": batch["generation"]})

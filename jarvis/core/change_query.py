"""Bounded, read-only change summaries over the committed canonical event log.

The source timestamp is a wall-clock observation, not an ingest timestamp.
This query never labels a quiet window clean or complete: source policy,
clock shifts, stale cursors and bounded replay all limit its meaning.
"""

from collections import Counter
from datetime import datetime, timezone

MAX_SCAN_EVENTS = 20_000
MAX_WINDOW_SECONDS = 3600
CURSOR_FRESH_SECONDS = 180
FUTURE_SKEW_SECONDS = 5


def _stamp(value):
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError):
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo is not None else None


def summarize(log, *, now=None, seconds=10, scan_limit=5000):
    """Count source-timed transitions in a recent bounded sequence window.

    ``log`` is a read-only EventLog. No raw event fields are returned. A
    source's ``time`` is used because old installed sensors do not record
    read-time separately; the result names that limitation explicitly.
    """
    seconds = int(seconds)
    scan_limit = int(scan_limit)
    if not 1 <= seconds <= MAX_WINDOW_SECONDS:
        raise ValueError("seconds must be between 1 and 3600")
    if not 1 <= scan_limit <= MAX_SCAN_EVENTS:
        raise ValueError("scan_limit must be between 1 and 20000")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    cutoff = now.timestamp() - seconds
    after = max(0, log.last_seq - scan_limit)
    counts = Counter()
    matched = []
    scanned = 0
    invalid_times = future_times = 0
    sensor_read_receipts = read_before_source = 0
    max_sensor_read_delay = None
    first_scanned = None
    for ev in log.iter_events(after=after, until=log.last_seq):
        scanned += 1
        seq = ev.get("seq")
        if first_scanned is None:
            first_scanned = seq
        stamp = _stamp(ev.get("time"))
        if stamp is None:
            invalid_times += 1
            continue
        when = stamp.timestamp()
        if when > now.timestamp() + FUTURE_SKEW_SECONDS:
            future_times += 1
            continue
        if cutoff <= when <= now.timestamp() + FUTURE_SKEW_SECONDS:
            counts[f"{ev.get('category', 'unknown')}:{ev.get('action', '?')}"] += 1
            matched.append(seq)
            if (ev.get("attrs") or {}).get("_received_basis") == "sensor_read":
                read = _stamp(ev.get("received"))
                if read is not None:
                    sensor_read_receipts += 1
                    lag = round(read.timestamp() - when, 3)
                    if lag < 0:
                        read_before_source += 1
                    else:
                        max_sensor_read_delay = max(max_sensor_read_delay or 0, lag)

    missing = [list(pair) for pair in log.missing()
               if pair[1] > after and pair[0] <= log.last_seq]
    # An absent sequence in the requested range can also mean an interrupted
    # write or removed segment. Neither is silently interpreted as quiet.
    if first_scanned is not None and first_scanned > after + 1:
        candidate = [after + 1, first_scanned - 1]
        if candidate not in missing:
            missing.append(candidate)
    cursors = []
    for cursor in log.cursors.values():
        age = None
        if isinstance(cursor.get("at"), (int, float)):
            age = round(now.timestamp() - cursor["at"])
        status = str(cursor.get("status") or "unknown")
        cursors.append({"channel": cursor.get("channel"),
                        "status": status, "age_seconds": age,
                        "gap": bool(cursor.get("gap")),
                        "recent_commit": age is not None
                        and -60 <= age <= CURSOR_FRESH_SECONDS
                        and status == "complete" and not cursor.get("gap")})
    cursors.sort(key=lambda c: str(c["channel"]))
    limits = []
    if log.last_seq > scan_limit:
        limits.append("bounded scan may omit events in the requested time window")
    if missing:
        limits.append("one or more requested sequence ranges are missing")
    if invalid_times or future_times:
        limits.append("some source timestamps are invalid or ahead of local time")
    if read_before_source:
        limits.append("sensor read time precedes source time; check clock or provider ordering")
    if not cursors or any(not c["recent_commit"] for c in cursors):
        limits.append("one or more source cursors are absent, stale or degraded")
    limits.append("sensor heartbeat and event-log integrity are not verified by this query")
    limits.append("source policy and uninstrumented transitions limit coverage")
    return {
        "window_seconds": seconds,
        "time_basis": "source event wall clock; sensor read time is not separately recorded",
        "observed_changes": dict(sorted(counts.items())),
        "observed_total": sum(counts.values()),
        "first_matched_seq": min(matched) if matched else None,
        "last_matched_seq": max(matched) if matched else None,
        "last_committed_seq": log.last_seq,
        "events_scanned": scanned,
        "scan_limit": scan_limit,
        "missing_sequences": missing[:20],
        "invalid_timestamps": invalid_times,
        "future_timestamps": future_times,
        "sensor_read_receipts": sensor_read_receipts,
        "max_sensor_read_delay_seconds": max_sensor_read_delay,
        "read_before_source_count": read_before_source,
        "cursors": cursors,
        "coverage": "partial",
        "limitations": limits,
    }

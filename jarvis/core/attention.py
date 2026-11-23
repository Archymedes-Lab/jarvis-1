"""Bounded, read-only attention and activity projections.

Outputs are requests to observe and pointers to evidence, never threat verdicts
or response authorization. No pixels, free text, or raw source records enter an
episode. The canonical event log remains authoritative.
"""

from datetime import datetime

MAX_INPUT = 5000
MAX_EPISODES = 500
MAX_GAP_SECONDS = 600
APPLICATIONS = frozenset({"browser", "editor", "terminal", "file_manager",
                          "installer", "other", "unknown"})
ACTIVITIES = frozenset({"browsing", "development", "download", "installation",
                        "communication", "other", "unknown"})

# A wake means inspect promptly, not that the event is malicious. Unknown events
# are retained by the canonical log and receive no invented risk classification.
IMMEDIATE = frozenset({
    ("malware", "detected"), ("malware", "action_failed"),
    ("protection", "disabled"), ("protection", "error"),
    ("file", "block_executable"), ("file", "block_shredding"),
    ("process", "tamper"), ("process", "remote_thread"),
    ("sensor", "error"),
})
PROMPT = frozenset({
    ("file", "executable_detected"), ("task", "registered"),
    ("task", "updated"), ("driver", "load"),
    ("process", "access"), ("registry", "value_set"),
})


def event_attention(event):
    """Return an advisory inspection priority and evidence pointer."""
    seq = event.get("seq")
    if type(seq) is not int or seq < 1:
        raise ValueError("canonical event needs a positive sequence")
    pair = (event.get("category"), event.get("action"))
    priority = "immediate" if pair in IMMEDIATE else "prompt" if pair in PROMPT else "routine"
    return {"seq": seq, "category": pair[0], "action": pair[1],
            "priority": priority, "authority": "observe_only"}


def event_milestones(events, *, limit=MAX_INPUT):
    """Replay a bounded committed sequence; report gaps and overflow explicitly."""
    if not 1 <= limit <= MAX_INPUT:
        raise ValueError("invalid replay limit")
    milestones = []
    gaps = []
    previous = None
    consumed = 0
    iterator = iter(events)
    for event in iterator:
        if consumed == limit:
            return {"milestones": milestones, "gaps": gaps,
                    "consumed": consumed, "truncated": True}
        item = event_attention(event)
        seq = item["seq"]
        if previous is not None:
            if seq <= previous:
                raise ValueError("event sequence is not increasing")
            if seq > previous + 1:
                gaps.append({"after_seq": previous, "before_seq": seq})
        if item["priority"] != "routine":
            milestones.append(item)
        previous = seq
        consumed += 1
    return {"milestones": milestones, "gaps": gaps,
            "consumed": consumed, "truncated": False}


def _observation(row):
    """Validate an already sanitized local observation; discard extra fields."""
    if not isinstance(row, dict):
        raise ValueError("observation must be a mapping")
    seq = row.get("source_seq")
    if type(seq) is not int or seq < 1:
        raise ValueError("observation needs a canonical source sequence")
    stamp = row.get("observed_at")
    if not isinstance(stamp, str):
        raise ValueError("observation needs a timestamp")
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid observation timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("observation timestamp needs timezone")
    application = row.get("application")
    activity = row.get("activity")
    if application not in APPLICATIONS or activity not in ACTIVITIES:
        raise ValueError("observation labels must be approved categories")
    if type(row.get("active")) is not bool:
        raise ValueError("active must be a boolean")
    return {"source_seq": seq, "observed_at": stamp,
            "_time": parsed, "application": application,
            "activity": activity, "active": row["active"]}


def activity_episodes(observations, *, limit=MAX_INPUT):
    """Compress consecutive routine observations without claiming user intent.

    A sequence gap or a long time gap ends an episode. The caller must source
    observations from committed records; this function never accepts raw images.
    """
    if not 1 <= limit <= MAX_INPUT:
        raise ValueError("invalid replay limit")
    episodes = []
    gaps = []
    current = None
    previous = None
    count = 0
    for raw in observations:
        if count == limit or len(episodes) >= MAX_EPISODES:
            if current is not None and len(episodes) < MAX_EPISODES:
                episodes.append(current)
            return {"episodes": episodes, "gaps": gaps,
                    "consumed": count, "truncated": True}
        row = _observation(raw)
        count += 1
        seq = row["source_seq"]
        if previous is not None:
            if seq <= previous["source_seq"] or row["_time"] < previous["_time"]:
                raise ValueError("observation order is not increasing")
            if seq > previous["source_seq"] + 1:
                gaps.append({"after_seq": previous["source_seq"], "before_seq": seq})
        discontinuity = (previous is not None and
                         (seq != previous["source_seq"] + 1 or
                          (row["_time"] - previous["_time"]).total_seconds() > MAX_GAP_SECONDS))
        same = (current is not None and not discontinuity and
                current["application"] == row["application"] and
                current["activity"] == row["activity"] and
                current["active"] == row["active"])
        if same:
            current["end_at"] = row["observed_at"]
            current["last_seq"] = seq
            current["observations"] += 1
        else:
            if current is not None:
                episodes.append(current)
                if len(episodes) >= MAX_EPISODES:
                    return {"episodes": episodes, "gaps": gaps,
                            "consumed": count - 1, "truncated": True}
            current = {"start_at": row["observed_at"], "end_at": row["observed_at"],
                       "first_seq": seq, "last_seq": seq, "observations": 1,
                       "application": row["application"], "activity": row["activity"],
                       "active": row["active"]}
        previous = row
    if current is not None:
        episodes.append(current)
    return {"episodes": episodes, "gaps": gaps,
            "consumed": count, "truncated": False}

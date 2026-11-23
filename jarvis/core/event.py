"""The canonical JARVIS event: one observed change, in JARVIS's own vocabulary.

Sensors speak their own dialects: Sysmon event 10, Defender 1116, a Task
Scheduler 106. Detectors that reason in those numbers are welded to one
provider, and anything no detector understands today gets thrown away. So every
source record becomes one of these first, and the event log keeps it whether or
not anything currently cares: a rule written in three months can then be
replayed against what already happened.

Normalization is additive. The source identity (channel, log generation, record
ID, provider event ID) and the raw record travel with the event, so a mistaken
mapping can be corrected by replaying the raw evidence, never by guessing.

Two identities for a process, answering different questions:

  process guid   which exact execution this was. Sysmon's ProcessGuid on
                 Windows; a bare PID is never an identity, because PIDs are
                 reused within a boot and restart across boots.
  sha256 / image what kind of program it was — the question the process
                 baseline (`procs.fp`) already answers.

Everything in an event other than `seq`, `received` and `id` came from an
attacker-reachable source: command lines, file names and query names are data,
never instructions.
"""

import hashlib

SCHEMA_VERSION = 1

# category -> actions a normalizer may emit. `unknown` keeps records no mapping
# covers yet: unknown to JARVIS today is not the same as not worth recording.
CATEGORIES = {
    "process": {"start", "exit", "access", "remote_thread", "tamper", "image_load",
                "image_unload", "clipboard"},
    "thread": {"start", "exit"},
    "network": {"connect", "end", "dns_query"},
    "file": {"create", "write", "rename", "delete", "time_change", "stream_create",
             "raw_read", "block_executable", "block_shredding",
             "executable_detected"},
    "registry": {"key_create", "key_delete", "value_set", "rename", "change"},
    "driver": {"load"},
    "service": {"created", "changed", "started", "stopped"},
    "account": {"changed"},
    "device": {"connected", "removed"},
    "memory": {"protection_changed"},
    "ipc": {"pipe_create", "pipe_connect"},
    "wmi": {"filter", "consumer", "binding"},
    "malware": {"detected", "action", "action_failed", "scan", "history_deleted"},
    "protection": {"disabled", "enabled", "config_change", "update", "error", "block",
                   "audit", "health"},
    "task": {"registered", "updated", "deleted", "started", "finished",
             "action_started", "action_finished", "process_created", "failed"},
    "sensor": {"state", "config_change", "error"},
    "unknown": set(),
}


def event_id(host, channel, generation, record):
    """Stable identity of one source record.

    The log generation is part of it: when a log is cleared its record IDs
    restart, and record 12 before the clear is not record 12 after it.
    """
    raw = "\x1f".join(str(x) for x in (host, channel, generation, record))
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def make(*, host, sensor, channel, generation, record, source, source_event,
         time, category, action, device=None, boot=None, mono=None, batch=None,
         process=None, parent=None, target=None, attrs=None, raw=None,
         received=None):
    """Build one event. `seq` is assigned by the event log, never by a source."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown category {category!r}")
    return {
        "v": SCHEMA_VERSION,
        "id": event_id(host, channel, generation, record),
        "device": device or host,
        "sensor": sensor,
        "host": host,
        "boot": boot,
        "time": time,              # when the source says it happened
        "received": received,      # when the sensor read it
        "mono": mono,              # sensor's monotonic clock at read, ms since boot
        "source": source,
        "channel": channel,
        "generation": generation,
        "record": record,
        "source_event": source_event,
        "batch": batch,
        "category": category,
        "action": action,
        "process": process or None,
        "parent": parent or None,
        "target": target or None,
        "attrs": attrs or {},
        "raw": raw,
    }


def validate(event):
    """Reject an event the log must not accept; return it unchanged otherwise."""
    if not isinstance(event, dict) or event.get("v") != SCHEMA_VERSION:
        raise ValueError("unsupported event schema")
    for key in ("id", "host", "sensor", "channel", "generation", "time", "source",
                "category", "action"):
        if not isinstance(event.get(key), str) or not event[key]:
            raise ValueError(f"event field {key} missing")
    if event["category"] not in CATEGORIES:
        raise ValueError("unknown event category")
    if type(event.get("record")) is not int:
        raise ValueError("event record ID missing")
    for key in ("process", "parent", "target"):
        if event.get(key) is not None and not isinstance(event[key], dict):
            raise ValueError(f"event {key} must be an object")
    return event

"""Temporal nervous system: one ordered event feed, many consumers.

Phase 2/4: stop thinking `run collector, receive findings` and think
`something happened`. Every relevant machine transition is already a
canonical event (see jarvis/core/event.py); this module reduces an ordered
event sequence into current-state projections that many consumers share
without rescanning the machine:

  SENSORS -> CANONICAL EVENTS -> TEMPORAL EVENT LOG -> reducer -> state
                                                            +-> detectors

Pure, bounded, replayable. No IO, no clocks, no model calls. Unknown
actions pass through untouched; missing evidence stays unknown.
"""

from collections import defaultdict

# Canonical (category, action) pairs the reducer understands. Everything
# else is retained in the log but does not move the projection.
PROCESS_START = ("process", "start")
PROCESS_EXIT = ("process", "exit")
THREAD_START = ("thread", "start")
THREAD_EXIT = ("thread", "exit")
IMAGE_UNLOAD = ("process", "image_unload")
MEM_PROT = ("memory", "protection_changed")
NET_END = ("network", "end")
PROCESS_SIGNALS = {
    ("process", "access"), ("process", "remote_thread"),
    ("process", "tamper"), ("process", "image_load"),
    ("process", "clipboard"),
}
NET_CONNECT = ("network", "connect")
DNS_QUERY = ("network", "dns_query")
FILE_SIGNALS = {
    ("file", "create"), ("file", "write"), ("file", "rename"),
    ("file", "delete"), ("file", "time_change"),
    ("file", "stream_create"), ("file", "raw_read"),
    ("file", "block_executable"), ("file", "block_shredding"),
    ("file", "executable_detected"),
}
REGISTRY_SIGNALS = {
    ("registry", "key_create"), ("registry", "key_delete"),
    ("registry", "value_set"), ("registry", "rename"),
    ("registry", "change"),
}
DRIVER_LOAD = ("driver", "load")
IPC_SIGNALS = {("ipc", "pipe_create"), ("ipc", "pipe_connect")}
WMI_SIGNALS = {("wmi", "filter"), ("wmi", "consumer"), ("wmi", "binding")}
MALWARE_SIGNALS = {
    ("malware", "detected"), ("malware", "action"),
    ("malware", "action_failed"), ("malware", "scan"),
    ("malware", "history_deleted"),
}
PROTECTION_SIGNALS = {
    ("protection", "disabled"), ("protection", "enabled"),
    ("protection", "config_change"), ("protection", "update"),
    ("protection", "error"), ("protection", "block"),
    ("protection", "audit"), ("protection", "health"),
}
TASK_SIGNALS = {
    ("task", "registered"), ("task", "updated"), ("task", "deleted"),
    ("task", "started"), ("task", "finished"),
    ("task", "action_started"), ("task", "action_finished"),
    ("task", "process_created"), ("task", "failed"),
}
SERVICE_SIGNALS = {
    ("service", "created"), ("service", "changed"),
    ("service", "started"), ("service", "stopped"),
}
SENSOR_SIGNALS = {
    ("sensor", "state"), ("sensor", "config_change"), ("sensor", "error"),
}
TASK_REGISTERED = ("task", "registered")
TASK_DELETED = ("task", "deleted")


def _proc_key(ev):
    proc = ev.get("process") or {}
    guid = proc.get("guid")
    if guid:
        return f"guid:{guid}"
    return f"pid:{ev.get('host')}:{proc.get('pid')}"


def reduce(events, limit=5000):
    """Fold ordered canonical events into a shared state projection.

    `events` must already be in global sequence order. Returns a dict with
    alive processes, observed peers, DNS names, created files, tasks and
    per-category counts. Bounded: at most `limit` events are folded; the
    remainder is reported as truncated rather than silently dropped.

    One ordered feed serves many consumers: the same projection answers
    process, network, file, registry, driver, WMI, malware, protection,
    task and sensor questions without rescanning the machine. Unknown
    actions are counted but never move state; missing evidence stays
    unknown.
    """
    events = list(events)
    truncated = len(events) > limit
    if truncated:
        events = events[-limit:]
    alive = {}
    peers = defaultdict(int)
    dns = defaultdict(int)
    files = {}
    file_deletes = {}
    registry = {}
    drivers = {}
    pipes = {}
    wmi = {"filter": 0, "consumer": 0, "binding": 0}
    malware = defaultdict(int)
    protection = {"disabled": 0, "enabled": 0, "block": 0, "error": 0,
                  "last_disabled": None, "last_block": None}
    tasks = {}
    task_activity = defaultdict(int)
    sensors = {"error": 0, "config_change": 0, "state": 0, "last_error": None}
    proc_signals = defaultdict(int)
    # Change-level projections (additive): threads, services, connection
    # ends, memory-protection changes. Snapshots remain consistency checks
    # against this event-derived state.
    threads_alive = {}
    services = {}
    service_activity = defaultdict(int)
    connections_ended = 0
    mem_protection_changes = 0
    image_unloads = 0
    counts = defaultdict(int)
    first_seq = events[0].get("seq") if events else None
    last_seq = events[-1].get("seq") if events else None
    for ev in events:
        key = (ev.get("category"), ev.get("action"))
        counts[f"{key[0]}:{key[1]}"] += 1
        if key == PROCESS_START:
            alive[_proc_key(ev)] = {
                "image": (ev.get("process") or {}).get("image"),
                "pid": (ev.get("process") or {}).get("pid"),
                "host": ev.get("host"),
                "started": ev.get("time"),
                "seq": ev.get("seq"),
            }
        elif key == PROCESS_EXIT:
            alive.pop(_proc_key(ev), None)
            # Threads die with their process instance: drop its threads so
            # a pid-reusing successor never inherits stale thread state.
            threads_alive = {k: v for k, v in threads_alive.items()
                             if v.get("proc") != _proc_key(ev)}
        elif key == THREAD_START:
            tid = (ev.get("target") or {}).get("tid",
                                               (ev.get("process") or {}).get("tid"))
            threads_alive[f"{_proc_key(ev)}:tid:{tid}"] = {
                "proc": _proc_key(ev), "tid": tid, "started": ev.get("time"),
                "seq": ev.get("seq"),
            }
        elif key == THREAD_EXIT:
            tid = (ev.get("target") or {}).get("tid",
                                               (ev.get("process") or {}).get("tid"))
            threads_alive.pop(f"{_proc_key(ev)}:tid:{tid}", None)
        elif key == IMAGE_UNLOAD:
            image_unloads += 1
        elif key == MEM_PROT:
            mem_protection_changes += 1
        elif key == NET_END:
            connections_ended += 1
        elif key in SERVICE_SIGNALS:
            target = ev.get("target") or {}
            name = str(target.get("name") or target.get("path") or "")
            service_activity[key[1]] += 1
            if name:
                if key[1] == "stopped":
                    services.pop(name, None)
                else:
                    services[name[:256]] = key[1]
        elif key in PROCESS_SIGNALS:
            proc_signals[f"{key[0]}:{key[1]}"] += 1
        elif key == NET_CONNECT:
            target = ev.get("target") or {}
            if target.get("ip"):
                peers[f"{target.get('ip')}:{target.get('port')}"] += 1
        elif key == DNS_QUERY:
            target = ev.get("target") or {}
            if target.get("query"):
                dns[str(target["query"]).lower().rstrip(".")] += 1
        elif key in FILE_SIGNALS:
            target = ev.get("target") or {}
            path = str(target.get("path") or "")
            if path:
                if key[1] == "delete":
                    file_deletes[path] = ev.get("time")
                    files.pop(path, None)
                else:
                    files[path] = ev.get("time")
        elif key in REGISTRY_SIGNALS:
            target = ev.get("target") or {}
            rkey = str(target.get("key") or target.get("path") or "")
            if rkey:
                registry[rkey[:512]] = {"action": key[1], "time": ev.get("time"),
                                        "seq": ev.get("seq")}
        elif key == DRIVER_LOAD:
            target = ev.get("target") or {}
            path = str(target.get("path") or (ev.get("process") or {}).get("image") or "")
            if path:
                drivers[path[:512]] = ev.get("time")
        elif key in IPC_SIGNALS:
            target = ev.get("target") or {}
            name = str(target.get("name") or "")
            if name:
                pipes[name[:256]] = ev.get("time")
        elif key in WMI_SIGNALS:
            wmi[key[1]] += 1
        elif key in MALWARE_SIGNALS:
            malware[key[1]] += 1
        elif key in PROTECTION_SIGNALS:
            protection[key[1]] = protection.get(key[1], 0) + 1
            if key[1] == "disabled":
                protection["last_disabled"] = ev.get("time")
            if key[1] == "block":
                protection["last_block"] = ev.get("time")
        elif key in TASK_SIGNALS:
            target = ev.get("target") or {}
            name = str(target.get("name") or "")
            task_activity[key[1]] += 1
            if name:
                if key[1] == "deleted":
                    tasks.pop(name, None)
                else:
                    tasks[name] = key[1]
        elif key in SENSOR_SIGNALS:
            sensors[key[1]] = sensors.get(key[1], 0) + 1
            if key[1] == "error":
                sensors["last_error"] = ev.get("time")
    return {
        "alive": alive,
        "peers": dict(sorted(peers.items(), key=lambda kv: -kv[1])[:200]),
        "dns": dict(sorted(dns.items(), key=lambda kv: -kv[1])[:200]),
        "files": dict(list(files.items())[-200:]),
        "file_deletes": dict(list(file_deletes.items())[-200:]),
        "registry": dict(list(registry.items())[-200:]),
        "drivers": dict(list(drivers.items())[-200:]),
        "pipes": dict(list(pipes.items())[-200:]),
        "wmi": dict(wmi),
        "malware": dict(malware),
        "protection": dict(protection),
        "tasks": tasks,
        "task_activity": dict(task_activity),
        "services": services,
        "service_activity": dict(service_activity),
        "threads_alive": threads_alive,
        "connections_ended": connections_ended,
        "mem_protection_changes": mem_protection_changes,
        "image_unloads": image_unloads,
        "sensors": dict(sensors),
        "proc_signals": dict(proc_signals),
        "counts": dict(counts),
        "events_folded": len(events),
        "truncated": truncated,
        "first_seq": first_seq,
        "last_seq": last_seq,
    }


def changes(before, after):
    """Diff two projections into a human-readable transition list."""
    out = []
    for key, proc in after.get("alive", {}).items():
        if key not in before.get("alive", {}):
            out.append(f"process start: {proc.get('image') or key}")
    for key in before.get("alive", {}):
        if key not in after.get("alive", {}):
            out.append(f"process exit: {key}")
    for peer in after.get("peers", {}):
        if peer not in before.get("peers", {}):
            out.append(f"new peer: {peer}")
    for name, state in after.get("tasks", {}).items():
        if before.get("tasks", {}).get(name) != state:
            out.append(f"task {state}: {name}")
    for path in after.get("files", {}):
        if path not in before.get("files", {}):
            out.append(f"file created: {path}")
    for path in after.get("file_deletes", {}):
        if path not in before.get("file_deletes", {}):
            out.append(f"file deleted: {path}")
    for key in after.get("registry", {}):
        if key not in before.get("registry", {}):
            out.append(f"registry change: {key}")
    for path in after.get("drivers", {}):
        if path not in before.get("drivers", {}):
            out.append(f"driver loaded: {path}")
    prot_b, prot_a = before.get("protection", {}), after.get("protection", {})
    if (prot_a.get("disabled", 0) or 0) > (prot_b.get("disabled", 0) or 0):
        out.append("protection disabled")
    if (prot_a.get("block", 0) or 0) > (prot_b.get("block", 0) or 0):
        out.append("protection blocked a threat")
    mal_b = sum((before.get("malware") or {}).values())
    mal_a = sum((after.get("malware") or {}).values())
    if mal_a > mal_b:
        out.append("malware telemetry increased")
    for key in after.get("threads_alive", {}):
        if key not in before.get("threads_alive", {}):
            out.append(f"thread start: {key}")
    for name, state in after.get("services", {}).items():
        if before.get("services", {}).get(name) != state:
            out.append(f"service {state}: {name}")
    if (after.get("connections_ended", 0) or 0) > \
            (before.get("connections_ended", 0) or 0):
        out.append("connection ended")
    if (after.get("mem_protection_changes", 0) or 0) > \
            (before.get("mem_protection_changes", 0) or 0):
        out.append("memory protection changed")
    return out


def project(events, limit=5000):
    """Reduce events that are already in global sequence order.

    Thin alias that makes the contract explicit: callers must pass
    sequence-ordered events (EventLog.iter_events order). Out-of-order
    input is still folded but the projection is only meaningful when the
    caller preserves ingest order.
    """
    ordered = sorted(list(events), key=lambda e: (e.get("seq") or 0))
    return reduce(ordered, limit=limit)


def detectors(events, projection=None, window=900.0):
    """Many cheap consumers over one ordered event feed. Pure, bounded.

    No rescans, no model calls, no causality invention: each detector
    names the sequence numbers that triggered it so a later rule can
    replay the same window. Returns a list of {detector, severity,
    detail, seqs}.
    """
    events = sorted(list(events), key=lambda e: (e.get("seq") or 0))
    if projection is None:
        projection = reduce(events)
    out = []
    prot = projection.get("protection") or {}
    if (prot.get("disabled", 0) or 0) > 0:
        out.append({"detector": "protection-disabled", "severity": "high",
                    "detail": "protection disable telemetry present; verify "
                              "fresh posture independently",
                    "seqs": [e.get("seq") for e in events
                             if (e.get("category"), e.get("action")) ==
                             ("protection", "disabled")][:10]})
    mal = projection.get("malware") or {}
    if (mal.get("detected", 0) or 0) > 0:
        out.append({"detector": "malware-detected", "severity": "high",
                    "detail": "Defender/malware detection telemetry present",
                    "seqs": [e.get("seq") for e in events
                             if e.get("category") == "malware"][:10]})
    sensors = projection.get("sensors") or {}
    if (sensors.get("error", 0) or 0) > 0:
        out.append({"detector": "sensor-error", "severity": "medium",
                    "detail": "sensor error telemetry present; coverage may "
                              "have gaps",
                    "seqs": [e.get("seq") for e in events
                             if (e.get("category"), e.get("action")) ==
                             ("sensor", "error")][:10]})
    # Persistence-chain shape: process start, file creation in a startup
    # location or executable signal, and task registration nearby in time.
    # Grouping only; each member is cited, no causal claim is made.
    starts = [e for e in events if (e.get("category"), e.get("action")) ==
              ("process", "start")]
    task_regs = [e for e in events if (e.get("category"), e.get("action")) in
                 {("task", "registered"), ("task", "updated"),
                  ("task", "process_created")}]
    file_persist = []
    for e in events:
        if (e.get("category"), e.get("action")) not in FILE_SIGNALS:
            continue
        path = str(((e.get("target") or {}).get("path")) or "").lower()
        if any(s in path for s in ("startup", "run\\", "run/", "tasks",
                                   "system32", ".lnk", ".ps1", ".vbs", ".js")):
            file_persist.append(e)
    if starts and task_regs and file_persist:
        try:
            t0 = min(float(e.get("seq") or 0) for e in starts)
            t1 = max(float(e.get("seq") or 0) for e in task_regs)
            span_ok = abs(t1 - t0) <= max(50.0, window)
        except (TypeError, ValueError):
            span_ok = True
        if span_ok:
            seqs = sorted({e.get("seq") for e in (starts[:5] + file_persist[:5] +
                                                  task_regs[:5]) if e.get("seq")})
            out.append({"detector": "persistence-chain-shape",
                        "severity": "high",
                        "detail": "process start, startup-location file "
                                  "signal and task registration co-occur; "
                                  "grouped for review, not proven causal",
                        "seqs": seqs[:15]})
    wmi = projection.get("wmi") or {}
    if sum(wmi.values()) >= 3:
        out.append({"detector": "wmi-persistence-shape", "severity": "medium",
                    "detail": "WMI filter/consumer/binding triple present; "
                              "possible persistence shape",
                    "seqs": [e.get("seq") for e in events
                             if e.get("category") == "wmi"][:10]})
    return out

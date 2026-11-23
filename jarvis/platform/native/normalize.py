"""Windows Event Log records -> canonical JARVIS events (`jarvis.core.event`).

Every record the sensor delivers becomes an event, including the ones no
mapping below understands: those are kept as category `unknown` with all of
their fields, because a record nothing understands today can still be replayed
through a rule written next month.

Field names come from the provider schemas and are matched exactly as Windows
writes them, with one known trap: Sysmon's ProcessAccess (10) spells
`SourceProcessGUID` where every other event says `ProcessGuid`. Lookups here
are case-insensitive for that reason.
"""

import xml.etree.ElementTree as ET

from jarvis.core import event as event_mod

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

SYSMON = "Microsoft-Windows-Sysmon/Operational"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
TASKS = "Microsoft-Windows-TaskScheduler/Operational"
SOURCES = {SYSMON: "sysmon", DEFENDER: "defender", TASKS: "taskscheduler"}

# Sysmon event ID -> (category, action). The full schema through v15, so a
# policy change that turns on a new event type needs no code change to be kept.
SYSMON_EVENTS = {
    1: ("process", "start"),
    2: ("file", "time_change"),
    3: ("network", "connect"),
    4: ("sensor", "state"),
    5: ("process", "exit"),
    6: ("driver", "load"),
    7: ("process", "image_load"),
    8: ("process", "remote_thread"),
    9: ("file", "raw_read"),
    10: ("process", "access"),
    11: ("file", "create"),
    12: ("registry", "change"),          # refined from EventType below
    13: ("registry", "value_set"),
    14: ("registry", "rename"),
    15: ("file", "stream_create"),
    16: ("sensor", "config_change"),
    17: ("ipc", "pipe_create"),
    18: ("ipc", "pipe_connect"),
    19: ("wmi", "filter"),
    20: ("wmi", "consumer"),
    21: ("wmi", "binding"),
    22: ("network", "dns_query"),
    23: ("file", "delete"),
    24: ("process", "clipboard"),
    25: ("process", "tamper"),
    26: ("file", "delete"),
    27: ("file", "block_executable"),
    28: ("file", "block_shredding"),
    29: ("file", "executable_detected"),
    255: ("sensor", "error"),
}

DEFENDER_EVENTS = {
    1000: ("malware", "scan"), 1001: ("malware", "scan"), 1002: ("malware", "scan"),
    1005: ("malware", "scan"),
    1006: ("malware", "detected"), 1015: ("malware", "detected"),
    1116: ("malware", "detected"), 1117: ("malware", "action"),
    1007: ("malware", "action"), 1008: ("malware", "action_failed"),
    1118: ("malware", "action_failed"), 1119: ("malware", "action_failed"),
    1013: ("malware", "history_deleted"),
    # Attack surface reduction (1121/1122), controlled folder access
    # (1123/1124) and network protection (1125/1126): block, then audit.
    1121: ("protection", "block"), 1122: ("protection", "audit"),
    1123: ("protection", "block"), 1124: ("protection", "audit"),
    1125: ("protection", "audit"), 1126: ("protection", "block"),
    1150: ("protection", "health"), 1151: ("protection", "health"),
    2000: ("protection", "update"), 2001: ("protection", "error"),
    2002: ("protection", "update"), 2004: ("protection", "error"),
    2010: ("protection", "update"), 2014: ("protection", "update"),
    3002: ("protection", "error"),
    5000: ("protection", "enabled"), 5001: ("protection", "disabled"),
    5004: ("protection", "config_change"), 5007: ("protection", "config_change"),
    5008: ("protection", "error"), 5010: ("protection", "disabled"),
    5012: ("protection", "disabled"), 5013: ("protection", "config_change"),
}

TASK_EVENTS = {
    106: ("task", "registered"), 140: ("task", "updated"), 141: ("task", "deleted"),
    100: ("task", "started"), 102: ("task", "finished"), 101: ("task", "failed"),
    103: ("task", "failed"), 129: ("task", "process_created"),
    200: ("task", "action_started"), 201: ("task", "action_finished"),
    203: ("task", "failed"),
}

MAPS = {SYSMON: SYSMON_EVENTS, DEFENDER: DEFENDER_EVENTS, TASKS: TASK_EVENTS}


class NormalizeError(ValueError):
    pass


def parse(xml):
    """-> (system dict, data dict) from one rendered EventRecord."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise NormalizeError(f"unparseable event XML: {exc}") from None
    system = {}
    sys_el = root.find(NS + "System")
    if sys_el is not None:
        for child in sys_el:
            tag = child.tag.replace(NS, "")
            system[tag] = child.text if child.text is not None else dict(child.attrib)
    data = {}
    for container in ("EventData", "UserData"):
        el = root.find(NS + container)
        if el is None:
            continue
        if container == "EventData":
            for i, d in enumerate(el.findall(NS + "Data")):
                data[d.get("Name") or f"Data{i}"] = d.text or ""
        else:
            # UserData is provider-shaped XML: flatten one level of leaves.
            for node in el.iter():
                if len(node) == 0 and node.text and node.text.strip():
                    data[node.tag.split("}")[-1]] = node.text.strip()
    return system, data


def _get(data, *names):
    lower = {k.lower(): v for k, v in data.items()}
    for n in names:
        v = lower.get(n.lower())
        if v not in (None, "", "-"):
            return v
    return None


NULL_GUID = "{00000000-0000-0000-0000-000000000000}"


def _guid(value):
    """Sysmon writes the all-zero GUID for "no process" (the System parent)."""
    return None if value is None or value == NULL_GUID else value


def _pid(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sha256(hashes):
    """Sysmon packs hashes as 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..'."""
    for part in (hashes or "").split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256" and v.strip():
            return v.strip().lower()
    return None


def _prune(d):
    return {k: v for k, v in d.items() if v not in (None, "")} or None


def _sysmon_time(data, fallback):
    """Sysmon's UtcTime ('2026-09-18 13:03:05.312') is when the kernel saw it."""
    t = _get(data, "UtcTime")
    if t and len(t) >= 19:
        return t.replace(" ", "T", 1) + "Z"
    return fallback


def _sysmon_shape(eid, data):
    """-> (action override, process, parent, target) for one Sysmon record."""
    action = None
    process = _prune({
        "guid": _guid(_get(data, "ProcessGuid", "SourceProcessGuid")),
        "pid": _pid(_get(data, "ProcessId", "SourceProcessId")),
        "image": _get(data, "Image", "SourceImage"),
        "user": _get(data, "User", "SourceUser"),
    })
    parent = target = None
    if eid == 1:
        process = _prune(dict(
            process or {},
            cmdline=_get(data, "CommandLine"), cwd=_get(data, "CurrentDirectory"),
            sha256=_sha256(_get(data, "Hashes")), hashes=_get(data, "Hashes"),
            integrity=_get(data, "IntegrityLevel"), logon=_get(data, "LogonGuid"),
            original_name=_get(data, "OriginalFileName"),
            company=_get(data, "Company"), product=_get(data, "Product")))
        parent = _prune({
            "guid": _guid(_get(data, "ParentProcessGuid")),
            "pid": _pid(_get(data, "ParentProcessId")),
            "image": _get(data, "ParentImage"), "cmdline": _get(data, "ParentCommandLine"),
            "user": _get(data, "ParentUser")})
    elif eid in (8, 10):
        target = _prune({
            "type": "process",
            "guid": _guid(_get(data, "TargetProcessGuid")),
            "pid": _pid(_get(data, "TargetProcessId")),
            "image": _get(data, "TargetImage"), "user": _get(data, "TargetUser"),
            "access": _get(data, "GrantedAccess"), "call_trace": _get(data, "CallTrace"),
            "start_module": _get(data, "StartModule"),
            "start_function": _get(data, "StartFunction"),
            "start_address": _get(data, "StartAddress")})
    elif eid in (6, 7):
        target = _prune({
            "type": "image", "path": _get(data, "ImageLoaded"),
            "sha256": _sha256(_get(data, "Hashes")), "hashes": _get(data, "Hashes"),
            "signed": _get(data, "Signed"), "signature": _get(data, "Signature"),
            "signature_status": _get(data, "SignatureStatus"),
            "original_name": _get(data, "OriginalFileName")})
    elif eid == 3:
        target = _prune({
            "type": "endpoint", "ip": _get(data, "DestinationIp"),
            "port": _pid(_get(data, "DestinationPort")),
            "host": _get(data, "DestinationHostname"), "protocol": _get(data, "Protocol"),
            "initiated": _get(data, "Initiated"), "source_ip": _get(data, "SourceIp"),
            "source_port": _pid(_get(data, "SourcePort"))})
    elif eid == 22:
        target = _prune({"type": "dns", "query": _get(data, "QueryName"),
                         "status": _get(data, "QueryStatus"),
                         "results": _get(data, "QueryResults")})
    elif eid in (2, 11, 15, 23, 26, 27, 28, 29):
        target = _prune({"type": "file", "path": _get(data, "TargetFilename"),
                         "sha256": _sha256(_get(data, "Hashes")),
                         "hashes": _get(data, "Hashes")})
    elif eid in (12, 13, 14):
        kind = (_get(data, "EventType") or "").lower()
        if eid == 12:
            action = {"createkey": "key_create", "deletekey": "key_delete",
                      "createvalue": "value_set", "deletevalue": "key_delete"}.get(kind, "change")
        target = _prune({"type": "registry", "key": _get(data, "TargetObject"),
                         "details": _get(data, "Details"), "new_name": _get(data, "NewName"),
                         "operation": _get(data, "EventType")})
    elif eid in (17, 18):
        target = _prune({"type": "pipe", "name": _get(data, "PipeName")})
    elif eid == 25:
        target = _prune({"type": "process", "tamper": _get(data, "Type")})
    elif eid == 9:
        target = _prune({"type": "device", "path": _get(data, "Device")})
    return action, process, parent, target


def normalize(record, batch):
    """One sensor record + its batch -> a canonical event.

    `record` is the sensor's {record_id, event_id, time, xml[, mono_ms]};
    `batch` is the validated batch dict it arrived in.
    """
    channel = batch["channel"]
    eid = int(record["event_id"])
    xml = record["xml"]
    system, data = parse(xml)
    received = record.get("read_time") or record["time"]
    received_basis = "sensor_read" if record.get("read_time") else "event_time_fallback"
    source = SOURCES.get(channel, "windows-eventlog")
    category, action = MAPS.get(channel, {}).get(eid, ("unknown", f"event_{eid}"))
    process = parent = target = None
    when = received
    if channel == SYSMON:
        when = _sysmon_time(data, received)
        override, process, parent, target = _sysmon_shape(eid, data)
        action = override or action
    elif channel == DEFENDER and 1121 <= eid <= 1126:
        target = _prune({"type": "rule", "rule": _get(data, "ID"), "path": _get(data, "Path")})
        process = _prune({"image": _get(data, "Process Name"), "user": _get(data, "User")})
    elif channel == DEFENDER:
        target = _prune({"type": "threat", "name": _get(data, "Threat Name"),
                         "severity": _get(data, "Severity Name"),
                         "path": _get(data, "Path"), "action": _get(data, "Action Name")})
        process = _prune({"image": _get(data, "Process Name"), "user": _get(data, "Detection User")})
    elif channel == TASKS:
        target = _prune({"type": "task", "name": _get(data, "TaskName", "Name"),
                         "action": _get(data, "ActionName", "Path")})
        process = _prune({"pid": _pid(_get(data, "ProcessID"))})
    return event_mod.make(
        host=batch["host_id"], sensor=batch["sensor_id"], device=batch.get("device_id"),
        boot=batch.get("boot_id"), channel=channel, generation=batch["generation"],
        record=record["record_id"], source=source, source_event=eid, time=when,
        received=received, mono=record.get("mono_ms"), batch=batch["sequence"],
        category=category, action=action, process=process, parent=parent, target=target,
        attrs=dict(data, _provider=(system.get("Provider") or {}).get("Name")
                   if isinstance(system.get("Provider"), dict) else None,
                   _received_basis=received_basis),
        raw=xml)

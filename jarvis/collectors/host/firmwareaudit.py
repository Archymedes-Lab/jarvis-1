"""HP firmware (Sure Start) security audit log, read through the elevated broker.

The firmware of HP business machines journals its own security events — BIOS
corruption and recovery, runtime intrusion detection in SMM, Secure Boot key
repair, Intel ME/CSME recovery, DMA protection, Tamper Lock, Sure Admin — from
the embedded controller and the BIOS. Windows keeps no copy. The broker runs
hp_firmware_audit.ps1 elevated, which loads HP's signed CMSL module only after
checking its files, and this collector turns the records into findings.

Every warning or critical record is reported, grouped by event, on every pass:
it is firmware evidence and stays visible until the owner acknowledges it.
Records first seen since the last read are called new. The firmware's clock
zone is not known, so its timestamps are shown as recorded.

Not here: anything the firmware does not journal, such as fan, thermal or
battery chimes, and any record the firmware lost or never wrote.
"""
import json

from jarvis.core import collection
from jarvis.platform import broker

_STATE_KEY = "fwaudit_seen_v1"
_MAX_SEEN = 2048
_MAX_RECORDS = 512
_SEVERITY = {"Info": "low", "Warn": "medium", "Critical": "high"}
# Sources whose warnings describe an attack on the firmware rather than
# maintenance: runtime intrusion detection (Intel, AMD, EpSC), DMA
# protection, Sure Admin PIN lockout and Tamper Lock.
_ATTACK_SOURCES = {0x82, 0x83, 0x87, 0x88, 0x89, 0x8A}
# HP publishes HP.Firmware only inside the HPCMSL bundle (PSGallery has no
# standalone HP.Firmware, checked 2026-10-23); HPCMSL installs HP.Firmware,
# HP.Utility and HP.Private as the separate module folders the reader loads.
# Windows PowerShell 5.1 ships PowerShellGet 1.0.0.1, which has no
# -AcceptLicense, so PowerShellGet is updated first (measured 2026-10-23).
SETUP = ("to enable it, from an elevated PowerShell run `Install-Module PowerShellGet "
         "-Scope AllUsers -Force -AllowClobber`, open a new elevated PowerShell, run "
         "`Install-Module HPCMSL -Scope AllUsers -AcceptLicense` (all users, so it lands "
         "in Program Files), then "
         "`jarvis broker install` to stage the reader")


def _finding(severity, title, detail, category="firmware"):
    return {"host": "win", "severity": severity, "title": title,
            "detail": detail, "category": category,
            "where": "HP firmware audit log (Sure Start)"}


def _text(value, limit):
    return isinstance(value, str) and len(value) <= limit


def _int(value, low, high):
    return (isinstance(value, int) and not isinstance(value, bool)
            and low <= value <= high)


def _valid(data):
    if (not isinstance(data, dict) or data.get("schema") != 1
            or not isinstance(data.get("available"), bool)
            or not _text(data.get("reason"), 400)
            or not isinstance(data.get("records"), list)
            or len(data["records"]) > _MAX_RECORDS
            or not isinstance(data.get("problems", []), list)
            or not isinstance(data.get("errors", []), list)):
        return False
    if not all(_text(p, 400) for p in data.get("problems", []) + data.get("errors", [])):
        return False
    for row in data["records"]:
        if (not isinstance(row, dict)
                or not _int(row.get("message_number"), 0, 2**32)
                or not _int(row.get("source"), -1, 255)
                or not _int(row.get("event_id"), 0, 2**16)
                or not _text(row.get("severity"), 16)
                or not _text(row.get("source_name"), 80)
                or not _text(row.get("state"), 16)
                or not isinstance(row.get("exact"), bool)
                or not (row.get("timestamp") is None or _text(row["timestamp"], 32))
                or not _text(row.get("description"), 300)):
            return False
    return True


def _key(row):
    return f"{row['message_number']}|{row['source']}|{row['event_id']}|{row['timestamp']}"


def _severity(row):
    sev = _SEVERITY.get(row["severity"])
    if sev is None:
        # An event HP's table does not describe: unknown, so not dismissed.
        sev = "medium"
    if row["source"] in _ATTACK_SOURCES and sev == "medium":
        sev = "high"
    return sev


def findings(data, seen, first):
    """Findings for one valid, available read. Pure."""
    records = data["records"]
    groups = {}
    for row in records:
        groups.setdefault((row["source"], row["event_id"]), []).append(row)
    out = []
    info = []
    for (source, event), rows in sorted(groups.items()):
        latest = rows[-1]
        sev = _severity(latest)
        if sev == "low":
            info.extend(rows)
            continue
        new = [r for r in rows if _key(r) not in seen]
        stamps = [r["timestamp"] for r in rows if r["timestamp"]]
        out.append(_finding(
            sev, f"HP firmware: {latest['description'][:100] or f'event {event}'}",
            f"{len(rows)} record(s) from {latest['source_name']} (source {source}, "
            f"event {event}, HP severity {latest['severity']})"
            + (f", newest {stamps[-1]} firmware clock" if stamps else "")
            + f", system state {latest['state']}"
            + ("" if first or not new else f"; {len(new)} new since the last read")
            + ". Recorded by the firmware itself; confirm against what you did "
            "(a BIOS update, a recovery) before acknowledging"))
    if info:
        sources = sorted({r["source_name"] for r in info})
        out.append(_finding(
            "low", "HP firmware informational records",
            f"{len(info)} informational record(s) from {', '.join(sources)[:200]}; "
            f"most recent: {info[-1]['description'][:160]}"))
    stamps = [r["timestamp"] for r in records if r["timestamp"]]
    module = data.get("module") or {}
    out.append(_finding(
        "ok", "HP firmware audit log read",
        f"{len(records)} record(s){' (truncated to the newest)' if data.get('truncated') else ''}"
        + (f", {stamps[0]} to {stamps[-1]} firmware clock (zone unknown)" if stamps else "")
        + f", via HP CMSL {module.get('version', '?')} after its files' HP signatures "
        "and administrator-only permissions were verified. Sound or events the "
        "firmware does not journal (fan, thermal or battery chimes) are not here"))
    return out


def audit(store, hosts=("wsl", "win")):
    if "win" not in hosts:
        collection.failed("fwaudit", "Windows collection disabled")
        return [_finding("medium", "HP firmware audit log is not read",
                         "Windows collection is disabled", "visibility")]
    data, why = broker.result("fwaudit")
    if data is None:
        collection.failed("fwaudit", why)
        return [_finding("low", "HP firmware audit log is not read",
                         f"{why}; {SETUP}", "visibility")]
    if not _valid(data):
        collection.failed("fwaudit", "malformed reader output")
        return [_finding("medium", "HP firmware audit log output is malformed",
                         "the broker's reader returned output that does not match "
                         "its schema; previous evidence is retained", "visibility")]
    if not data["available"]:
        reason = data["reason"] or "no reason given"
        collection.failed("fwaudit", reason[:160])
        if reason.startswith("refused"):
            problems = "; ".join(data.get("problems", [])[:6])
            return [_finding(
                "medium", "HP firmware module failed JARVIS's integrity check",
                f"{reason}: {problems}. The elevated reader loaded nothing. A "
                "module file a non-administrator can change, or one not signed "
                "by HP, would let unelevated code run as administrator; "
                "reinstall the module for all users from an elevated shell",
                "visibility")]
        detail = reason + "; " + "; ".join(data.get("errors", [])[:2])
        if "not installed" in reason:
            detail = f"{reason}; {SETUP}"
        return [_finding("low", "HP firmware audit log is not read", detail,
                         "visibility")]
    try:
        stored = json.loads(store.get_meta(_STATE_KEY, "") or "null")
    except (ValueError, TypeError):
        stored = None
    first = not isinstance(stored, list)
    seen = set(stored) if not first else set()
    out = findings(data, seen, first)
    # The log itself is the history: remember exactly what it holds now.
    keys = [_key(r) for r in data["records"]][-_MAX_SEEN:]
    store.set_meta(_STATE_KEY, json.dumps(keys))
    collection.succeeded("fwaudit")
    return out

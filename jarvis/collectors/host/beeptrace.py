"""Who called Beep(): the elevated kernel trace (broker job beeptrace.ps1).

The listener in the input hook names a Beep() caller only when its handle-table
snapshot catches the caller still holding \\Device\\Beep, which a tone under
about 100 ms has already released (2026-11-03: four real double 50 ms tones
since 10-29, none named). The broker keeps a Microsoft-Windows-Kernel-File
trace filtered in the kernel to opens of \\Device\\Beep and reports each open
with the process that made it, as that process was at the time.

This module checks that output strictly (it is written by an elevated job but
read here as data), matches each open to the system-sounds tone it produced,
and reports the trace's own health: not installed, failed, refusing (the
kernel did not apply the filter), or blind (its silent canary went missing).
A tone is attributed only through an open in the trace; nothing is inferred.
"""

from jarvis.platform import broker

JOB = "beeptrace"
# An open precedes the audible tone by the IOCTL and the sound service's
# render latency; the listener's onset can lag the tone by one 25 ms poll and
# a second open in the same episode comes inside its duration.
LEAD_MS = 1000
LAG_MS = 500
MAX_OPENS = 500
_MODES = ("filtered", "refused", "stopped")
_TEXT = (("path", 400), ("name", 120), ("user", 120), ("via", 16), ("sig", 32), ("signer", 160))


def _int(value, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def _clean(value, limit):
    text = value if isinstance(value, str) else ""
    return "".join(c for c in text if c.isprintable())[:limit]


def _open(row):
    """One traced open as a dict, or None when malformed."""
    if not isinstance(row, dict):
        return None
    ms = _int(row.get("ms"), 1, 2**43)
    pid = _int(row.get("pid"), 1, 0xFFFFFFFF)
    start = _int(row.get("start"), 0, 2**33)
    if None in (ms, pid, start):
        return None
    out = {"ms": ms, "pid": pid, "start": start}
    for key, limit in _TEXT:
        out[key] = _clean(row.get(key), limit)
    if out["via"] not in ("live", "sysmon", "unresolved"):
        return None
    if out["via"] == "unresolved" and (start or out["path"]):
        return None
    return out


def parse(data):
    """(trace, why): the checked broker output, or (None, why)."""
    if not isinstance(data, dict) or data.get("version") != 1:
        return None, "the Beep() trace output has an unknown format"
    if data.get("mode") not in _MODES:
        return None, "the Beep() trace reports an unknown mode"
    opens = data.get("opens")
    if not isinstance(opens, list) or len(opens) > MAX_OPENS:
        return None, "the Beep() trace inventory is missing or over its bound"
    rows = [_open(r) for r in opens]
    if any(r is None for r in rows):
        return None, "the Beep() trace inventory has a malformed row"
    counts = {}
    for key in ("breaches", "parse_failures", "identity_failures", "rows_dropped",
                "dropped_files", "session_started", "runs"):
        counts[key] = _int(data.get(key, 0), 0, 2**40)
        if counts[key] is None:
            return None, f"the Beep() trace field {key} is not a count"
    errors = data.get("errors") or []
    if not isinstance(errors, list) or len(errors) > 8:
        return None, "the Beep() trace error list is malformed"
    seen = data.get("canary_seen")
    if seen not in (True, False, None):
        return None, "the Beep() trace canary result is malformed"
    return {"mode": data["mode"], "opens": rows, "canary_checked": data.get("canary_checked") is True,
            "canary_seen": seen, "capped": data.get("etl_capped") is True,
            "fresh": data.get("fresh_session") is True,
            "errors": [_clean(e, 200) for e in errors], **counts}, ""


def load(result=None):
    """(trace, why) from the broker, or (None, why) when there is none."""
    data, why = result if result is not None else broker.result(JOB)
    if data is None:
        return None, why
    return parse(data)


def callers(row, trace):
    """The traced opens that produced one recorded system-sounds tone."""
    if not trace or not row["sys"]:
        return []
    low, high = row["ms"] - LEAD_MS, row["ms"] + row["dur_ms"] + LAG_MS
    return [o for o in trace["opens"] if low <= o["ms"] <= high]


def describe(opens):
    """'powershell (pid 17760, started ..., user ...)' for each distinct process."""
    seen, parts = set(), []
    for o in opens:
        key = (o["pid"], o["start"])
        if key in seen:
            continue
        seen.add(key)
        who = o["name"] or f"process {o['pid']}"
        bits = [f"pid {o['pid']}"]
        if o["start"]:
            bits.append(f"started {o['start']}")
        if o["user"]:
            bits.append(f"user {o['user']}")
        if o["path"]:
            bits.append(o["path"])
        if o["sig"] and o["sig"] != "Valid":
            bits.append(f"signature {o['sig']}")
        if o["via"] == "unresolved":
            bits.append("exited before it could be named")
        parts.append(f"{who} ({', '.join(bits)})")
    return "; ".join(parts)


def health(trace, why, finding):
    """Findings about the trace itself; the caller passes its finding builder."""
    if trace is None:
        if "not installed" in why:
            return [finding("low", "Beep() caller trace not running",
                            "the elevated broker is not installed, so Beep() tones under "
                            "about 100 ms and Beep() calls from elevated programs are not "
                            "attributed; install it with: jarvis broker install", "visibility")]
        return [finding("medium", "Beep() caller trace unavailable",
                        f"{why}; short or elevated Beep() callers are not attributed. "
                        "If the broker's script differs, run: jarvis broker install",
                        "visibility")]
    out = []
    if trace["mode"] == "refused":
        out.append(finding(
            "medium", "Beep() caller trace refused: kernel filter not applied",
            "Windows logged other file opens despite the filter, so the trace was "
            "stopped at once rather than record every file open; short and "
            "elevated Beep() callers are not attributed. " + "; ".join(trace["errors"]),
            "visibility"))
    elif trace["mode"] == "stopped":
        out.append(finding(
            "medium", "Beep() caller trace not running",
            "the trace session could not start: " + ("; ".join(trace["errors"]) or "no reason given"),
            "visibility"))
    if trace["canary_checked"] and trace["canary_seen"] is False:
        out.append(finding(
            "medium", "Beep() caller trace is blind",
            "the broker's own silent open of the Beep device was not in the last "
            "window's trace, so the filter is dropping Beep-device opens and no "
            "caller would be named", "visibility"))
    if trace["breaches"]:
        out.append(finding(
            "medium", "Beep() caller trace logged other files",
            f"{trace['breaches']} event(s) for other files reached the trace; they were "
            "dropped unread, but the kernel filter is not holding", "visibility"))
    lost = trace["parse_failures"] + trace["dropped_files"] + (1 if trace["capped"] else 0)
    if lost:
        out.append(finding(
            "low", "Beep() caller trace incomplete",
            f"{trace['parse_failures']} unreadable file(s), {trace['dropped_files']} "
            f"dropped file(s){', a file at its size cap' if trace['capped'] else ''}: "
            "Beep() opens in them may be missing", "visibility"))
    return out

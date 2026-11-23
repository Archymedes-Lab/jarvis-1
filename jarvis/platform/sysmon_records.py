"""Parsing Sysmon for Linux records (XML or key/value text) into dicts.

Pure text handling, no I/O: shared by the Sysmon collector and by any other
collector that reads Sysmon lineage (collectors may not import each other).
"""

import re
import xml.etree.ElementTree as ET

# journalctl matches for Sysmon records journald itself attributes to the sysmon
# unit running as root. `-t sysmon` alone matches SYSLOG_IDENTIFIER, which any
# account sets freely: `logger -t sysmon ...` from uid 1000 was returned beside
# real events on 2026-11-01 (and FZ-04). Trusted (underscore) fields are written
# by journald, not the client, and journalctl ANDs matches on different fields.
TRUSTED_MATCH = ("_SYSTEMD_UNIT=sysmon.service", "_UID=0", "-t", "sysmon")

_TYPE_ID = {
    "processcreate": 1, "process create": 1,
    "networkconnect": 3, "network connection": 3, "networkconnection": 3,
    "processterminate": 5, "process terminated": 5, "processterminated": 5,
    "rawaccessread": 9, "raw access read": 9,
    "processaccess": 10, "process accessed": 10,
    "filecreate": 11, "file created": 11,
    "sysmonconfigstatechanged": 16, "configchange": 16,
    "filedelete": 23, "file delete": 23, "filedeletedetected": 26,
}


_EVENT_START = re.compile(r"<Event\b")
_EVENT_END = "</Event>"


def _event_blobs(text):
    """Each "<Event ...</Event>" span, as re.finditer(r"<Event\\b.*?</Event>", re.S) did,
    in linear time: that pattern rescanned to the end of the text from every unclosed
    "<Event", so text full of them (syslog lines any account can write) took
    quadratic time, 7 s for 56 KB and hours for the 8 MB syslog tail (FZ-06)."""
    pos = 0
    while True:
        m = _EVENT_START.search(text, pos)
        if not m:
            return
        end = text.find(_EVENT_END, m.end())
        if end < 0:
            return          # no later "<Event" can close either
        yield text[m.start():end + len(_EVENT_END)]
        pos = end + len(_EVENT_END)


def parse(text):
    """List of {id, ...fields}. Handles the XML form and the key/value form."""
    events = []

    for blob in _event_blobs(text):
        blob = re.sub(r'\sxmlns(:\w+)?="[^"]*"', "", blob)
        try:
            root = ET.fromstring(blob)
        except ET.ParseError:
            continue
        sysd, data = root.find("System"), root.find("EventData")
        # A non-numeric EventID (syslog fallback lines are written by anyone) raised
        # ValueError and lost every event in the window (FZ-06); skip that record only.
        raw_id = (sysd.findtext("EventID") or "0").strip() if sysd is not None else "0"
        # Real event ids are small; a digit string past Python's int conversion limit
        # (4300 digits) raised ValueError the same way (FZ-16, fuzz run 2026-11-06).
        ev = {"id": int(raw_id) if raw_id.isascii() and raw_id.isdigit() and len(raw_id) <= 5 else 0}
        # UtcTime in EventData is the process/event timestamp reported by
        # Sysmon. It can lag journal ingestion substantially while Sysmon is
        # draining its own queue, so retain TimeCreated separately for journal
        # continuity checks.
        created = sysd.find("TimeCreated") if sysd is not None else None
        if created is not None and created.get("SystemTime"):
            ev["SystemTime"] = created.get("SystemTime")
        for d in (list(data) if data is not None else []):
            if d.get("Name"):
                ev[d.get("Name")] = (d.text or "").strip()
        if ev["id"]:
            events.append(ev)
    if events:
        return events

    # Key/value block form: a "TypeName:" header line then "  Key: Value" lines,
    # blocks separated by blank lines.
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            if cur and cur.get("id"):
                events.append(cur)
            cur = None
            continue
        head = re.match(r"^([A-Za-z][A-Za-z ]+):$", s)
        if head and cur is None:
            cur = {"id": _TYPE_ID.get(head.group(1).strip().lower(), 0)}
            continue
        kv = re.match(r"^([A-Za-z][\w ]*):\s*(.*)$", s)
        if kv and cur is not None:
            cur[kv.group(1).replace(" ", "")] = kv.group(2).strip()
    if cur and cur.get("id"):
        events.append(cur)
    return events

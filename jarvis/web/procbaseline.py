"""The /procs change lens: which process names this machine has seen before.

The live map (web/procview.py) shows what runs now. This answers the other
half of "did anything change": for each name, when JARVIS first saw it on that
host, when it last saw it, how often, and whether you approved it. The source
is the scan collector's own fingerprint table (Store.procs), so the lens learns
nothing new and needs no collector of its own.

Invariants:

  * Metadata only, like the live map: names, times and counts. Never a path, a
    command line, a user or a fingerprint.
  * Bounded: one grouped query (about 0.5 s on 50,000 rows), cached for
    CACHE_S and computed by one caller at a time; every other request gets the
    cached copy. It shares no lane, lock or store handle with the collectors.
  * Unknown stays unknown: a host with no baseline rows is reported as such, so
    the page shows its processes as unknown, never as new (a false alarm) and
    never as known (a false calm). A failed read is reported as failed.
  * Advisory: the lens colours the picture. It raises no finding and changes
    no score; the scan collector's new-process findings remain the record.
"""

import re
import sqlite3
import threading
import time

CACHE_S = 300.0
RECENT_S = 86400           # first seen within a day: "new today"
# The views use "win" and "lin"; the scan collector records "win" and "wsl".
HOSTS = {"win": "win", "wsl": "lin"}
# Names whose disappearance is worth a mark on the map while it is open:
# protection, the event sources JARVIS reads, and the processes Windows cannot
# run without. Ordinary applications are left out: a closed browser is not news.
WATCH = {
    "win": ("msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "securityhealthservice.exe",
            "sysmon64.exe", "sysmon.exe", "jarvissensor.exe", "lsass.exe", "lsaiso.exe",
            "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "smss.exe", "vmmemwsl"),
    "lin": ("systemd", "sysmon", "systemd-journal", "init"),
}

# Some names carry a process id, e.g. WSL's "Relay(46877)": each would look new.
_PID_SUFFIX = re.compile(r"\(\d+\)$")


def norm(name):
    """The lens key for a process name (same rule as procs-model.js)."""
    return _PID_SUFFIX.sub("(#)", str(name or "").strip().lower())


_QUERY = ("SELECT host, lower(name), min(first_seen), max(last_seen), sum(seen_count), max(approved) "
          "FROM procs WHERE name IS NOT NULL AND name != '' GROUP BY host, lower(name)")


def build(db_path, now=None):
    """The lens document. Never raises: a failed read is returned as failed."""
    now = time.time() if now is None else now
    doc = {"at": int(now), "ok": True, "reason": "", "recent_s": RECENT_S,
           "watch": {h: list(v) for h, v in WATCH.items()},
           "hosts": {h: {"names": {}, "rows": 0} for h in HOSTS.values()}}
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
            for host, name, first, last, count, approved in db.execute(_QUERY):
                view = HOSTS.get(host)
                if view is None or not name:
                    continue
                entry = doc["hosts"][view]
                key = norm(name)
                row = [int(first or 0), int(last or 0), int(count or 0), 1 if approved else 0]
                prev = entry["names"].get(key)
                if prev:   # several raw names fold into one key: merge them
                    row = [min(prev[0], row[0]), max(prev[1], row[1]), prev[2] + row[2], max(prev[3], row[3])]
                else:
                    entry["rows"] += 1
                entry["names"][key] = row
    except sqlite3.Error as exc:
        doc.update(ok=False, reason=f"baseline unreadable: {type(exc).__name__}")
        for entry in doc["hosts"].values():
            entry["names"] = {}
    return doc


class Cache:
    """One rebuild per CACHE_S, done by one caller; the rest get the cached copy."""

    def __init__(self, ttl=CACHE_S, clock=time.monotonic, builder=build):
        self.ttl, self.clock, self.builder = ttl, clock, builder
        self._doc, self._at, self._lock = None, None, threading.Lock()

    def get(self, db_path):
        fresh = self._doc is not None and self._at is not None and self.clock() - self._at < self.ttl
        if fresh:
            return self._doc
        if not self._lock.acquire(blocking=self._doc is None):
            return self._doc            # someone else is rebuilding: serve the last copy
        try:
            if self._doc is None or self._at is None or self.clock() - self._at >= self.ttl:
                self._doc = self.builder(db_path)
                self._at = self.clock()
            return self._doc
        finally:
            self._lock.release()


shared = Cache()

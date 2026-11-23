"""The /procs identity check: is this the binary that usually carries this name?

The change lens (web/procbaseline.py) judges names. A name is weak evidence:
malware calls itself svchost.exe. This judges the image behind each live
process, on the daemon, from evidence JARVIS already keeps:

  place   where the image runs from, as a class: system, program, user, temp,
          kernel (no image file), fileless (a memfd), deleted (the file was
          replaced or removed since the process started), other, unknown.
  path    against every path the scan collector has recorded for that name
          (Store.procs):
            same     this path, established
            similar  another path in an established place (a new version folder)
            moved    the name is established elsewhere, never from this place
            new      the name itself is new: never recorded, or only today
            unknown  the path could not be read, or the name has no
                     established path to compare with (protected processes
                     whose path the scan cannot read)
  hash    against the start history: the event log's SHA-256 sightings on
          Windows (Sysmon starts since the sensor was installed), the
          start_images table on Linux (collectors/telemetry/sysmon_linux/
          history.py): known, recent (first seen within RECENT_S), new (never),
          unknown (no hash, or no history old enough to say), pending (the
          lookup has not run yet).

A start too short to sample (a Sysmon start with no table row) is judged by
judge_start: its path verdict asks the start history whether this exact image
has started here before (same) or not (new), because the once-a-minute scan
behind the path baseline has never recorded most short-lived programs. A
familiar name from a user-writable place is still "moved". A history younger
than RECENT_S answers "unknown", never "new": it has not seen enough yet.

"Established" means recorded more than RECENT_S ago, or approved by you. Two
rules close the slow-poisoning gap (Jev advisory 2026-10-24), so a masquerade
does not fade by running for a day:

  * the core Windows processes in SYSTEM_ONLY run from the system place or
    are "moved", whatever the baseline holds (their paths are often unreadable
    to the scan, so the baseline alone could not tell);
  * a Windows name established in the system place is never established
    from a place an ordinary user can write to (user, temp, other) without
    your approval.

Cost (measured 2026-10-24 on this machine): place and path for 315 processes
in a few milliseconds from a ~2 s baseline load; one recorded-hash lookup reads
about 100 scattered event-log rows (a pid is reused often in five weeks),
0.1-0.3 s cold. The feed therefore sends place and path at once and runs hash
lookups for already-running processes afterwards, one at a time, cached for
the life of the daemon.

Invariants:

  * Paths and hashes stay on the daemon. A verdict is three short words; the
    feed sends only those to a viewer.
  * Read-only. Two read-only SQLite connections (the store and the event log's
    index); no writes, no locks shared with collectors, no file reads of the
    images themselves.
  * Bounded: the baseline is one grouped query (~1,100 rows) rebuilt at most
    every CACHE_S; a hash lookup is two indexed reads. Results are cached per
    (host, name, path, hash), at most CACHE_MAX entries.
  * Unknown stays unknown. Missing evidence gives "unknown", never "same" or
    "moved". A failed read is reported, not guessed around.
  * Advisory: it colours the view. It raises no finding and changes no score.
"""

import re
import sqlite3
import threading
import time
from datetime import datetime, timezone

from jarvis.core import eventlog
from jarvis.web.procbaseline import HOSTS, RECENT_S, norm

CACHE_S = 300.0
CACHE_MAX = 20_000
START_SLACK_MS = 2_000     # a recorded start this close to the live creation time is the same run
USER_WRITABLE = ("user", "temp", "other")
SYSTEM_ONLY = frozenset({"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
                         "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe"})
RUN_CACHE_MAX = 8_192

_WIN_VERSION = re.compile(r"\d+(?:[._-]\d+)+")
_LIN_VERSION = re.compile(r"\d+(?:\.\d+)+")


# ---- places ------------------------------------------------------------------

def place(host, path):
    """The class of place an image runs from (see the module docstring)."""
    path = (path or "").strip()
    if host == "win":
        return _win_place(path.lower().replace("/", "\\"))
    return _linux_place(path)


def _win_place(p):
    if not p:
        return "unknown"
    if "\\" not in p:
        return "kernel"                      # Registry, MemCompression, vmmem
    p = p.removeprefix("\\\\?\\")
    if re.match(r"[a-z]:\\windows\\temp\\", p):
        return "temp"
    if re.match(r"[a-z]:\\windows\\", p):
        return "system"
    if re.match(r"[a-z]:\\program files( \(x86\))?\\", p) or \
            re.match(r"[a-z]:\\programdata\\microsoft\\windows defender\\", p):
        return "program"
    if re.search(r"\\appdata\\local\\temp\\|\\downloads\\", p) or re.match(r"[a-z]:\\users\\public\\", p):
        return "temp"
    if re.match(r"[a-z]:\\users\\", p):
        return "user"
    return "other"


def _linux_place(p):
    if not p:
        return "unknown"
    if p.startswith("/memfd:"):
        return "fileless"
    if p.endswith(" (deleted)"):
        return "deleted"
    if re.match(r"/(tmp|var/tmp|dev/shm|run/user)/", p):
        return "temp"
    if re.match(r"/(usr|bin|sbin|lib|lib32|lib64|opt|snap)/", p) or p == "/init":
        return "system"
    if p.startswith(("/home/", "/root/")):
        return "user"
    return "other"


def fold(host, path):
    """A path with version numbers folded, so an update in place stays "same"."""
    path = (path or "").strip()
    if host == "win":
        return _WIN_VERSION.sub("#", path.lower().replace("/", "\\"))
    return _LIN_VERSION.sub("#", path.removesuffix(" (deleted)"))


# ---- baseline ------------------------------------------------------------------

_QUERY = ("SELECT host, lower(name), coalesce(exe, ''), min(first_seen), max(approved) FROM procs "
          "WHERE name IS NOT NULL AND name != '' GROUP BY host, lower(name), coalesce(exe, '')")


class Baseline:
    """Per (host, name): the places and folded paths it has run from, each with
    its first sighting and whether you approved it."""

    def __init__(self, ok=True, reason=""):
        self.ok, self.reason = ok, reason
        self.names = {}       # (h, name) -> [first, approved], with or without a path
        self.places = {}      # (h, name) -> {place: [first, approved]}
        self.paths = {}       # (h, name) -> {folded: [first, approved]}

    def add(self, h, name, exe, first, approved):
        key = (h, norm(name))
        _merge(self.names, key, first, approved)
        if not exe:
            return
        _merge(self.places.setdefault(key, {}), place(h, exe), first, approved)
        _merge(self.paths.setdefault(key, {}), fold(h, exe), first, approved)


def _merge(table, key, first, approved):
    entry = table.setdefault(key, [first, approved])
    entry[0], entry[1] = min(entry[0], first), max(entry[1], approved)


def load_baseline(db_path):
    """The path baseline from the store. Never raises."""
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2) as db:
            base = Baseline()
            for host, name, exe, first, approved in db.execute(_QUERY):
                view = HOSTS.get(host)
                if view is not None:
                    base.add(view, name, exe, int(first or 0), 1 if approved else 0)
            return base
    except sqlite3.Error as exc:
        return Baseline(ok=False, reason=f"baseline unreadable: {type(exc).__name__}")


# ---- hash history ------------------------------------------------------------------

class HashHistory:
    """Read-only questions to the Windows event log's index (core/eventlog.py):
    the hash of one recorded run, and when a hash or an image first started."""

    def __init__(self, index_path=None):
        self.index_path = index_path or (eventlog.DEFAULT_ROOT / "index.db")
        self._db = None
        self._host = None

    def _open(self):
        if self._db is None:
            self._db = sqlite3.connect(f"file:{self.index_path}?mode=ro", uri=True, timeout=1,
                                       check_same_thread=False)
            row = self._db.execute("SELECT host FROM processes ORDER BY rowid DESC LIMIT 1").fetchone()
            self._host = row[0] if row else None
        return self._db

    def recorded_hash(self, pid, created_ms):
        """The SHA-256 the event log recorded for this exact run, or ""."""
        try:
            db = self._open()
            rows = db.execute("SELECT sha256, started FROM processes WHERE host=? AND pid=? "
                              "ORDER BY start_seq DESC LIMIT 8", (self._host, int(pid))).fetchall()
        except sqlite3.Error:
            self.close()
            return ""
        for sha, started in rows:
            at = _iso_ms(started)
            if sha and at is not None and abs(at - created_ms) <= START_SLACK_MS:
                return sha.lower()
        return ""

    def first_seen(self, sha):
        """Unix seconds the event log first saw this hash; None if never; raises
        sqlite3.Error when the index cannot be read."""
        return self._sighting("sha256", sha)

    def image_first_seen(self, path):
        """Unix seconds an image at this path first started; None if never."""
        return self._sighting("image", path)

    def _sighting(self, kind, value):
        row = self._open().execute("SELECT first_time FROM sightings WHERE kind=? AND value=?",
                                   (kind, index_key(value))).fetchone()
        if row is None:
            return None
        at = _iso_ms(row[0])
        return None if at is None else at / 1000

    def close(self):
        db, self._db = self._db, None
        if db is not None:
            db.close()


def index_key(value):
    """A sighting value as the event log's index stores sha256 and image values
    (core/eventlog._norm; tests/test_procidentity.py checks they agree)."""
    return str(value or "").strip().lower().rstrip(".")


class LinuxStarts:
    """Read-only questions to the Linux start history in the store."""

    def __init__(self, db_path):
        self.db_path = db_path
        self._db = None

    def _open(self):
        if self._db is None:
            self._db = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=1,
                                       check_same_thread=False)
        return self._db

    def since(self):
        """When recording began (unix seconds), or None; raises sqlite3.Error."""
        row = self._open().execute("SELECT v FROM meta WHERE k='start_history_since'").fetchone()
        return int(row[0]) if row and str(row[0]).isdigit() else None

    def first_seen(self, sha):
        return self._first("sha256", sha.lower())

    def image_first_seen(self, path):
        return self._first("image", path)

    def _first(self, column, value):
        row = self._open().execute(f"SELECT min(first_seen) FROM start_images WHERE host='wsl' AND {column}=?",
                                   (value,)).fetchone()
        return row[0] if row else None

    def close(self):
        db, self._db = self._db, None
        if db is not None:
            db.close()


def _iso_ms(text):
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")) \
            .replace(tzinfo=timezone.utc).timestamp() * 1000 if text else None
    except ValueError:
        return None


# ---- the judge -----------------------------------------------------------------

class Judge:
    """The feed's identity source (platform/procfeed.py, `identity=`):

      judge(host, name, path, sha256)       -> [place, path, hash]   a process row, fast
      judge_start(host, name, path, sha256) -> [place, path, hash]   a start no row showed
      recorded_hash(host, pid, created_ms)  -> sha256 or ""          slow, cached
      generation                            bumps when the baseline is rebuilt

    Called from the feed's one identity worker thread."""

    def __init__(self, db_path, *, history=None, linux=None, clock=time.monotonic, wall=time.time,
                 loader=load_baseline):
        self.db_path, self.clock, self.wall, self.loader = db_path, clock, wall, loader
        self.history = history if history is not None else HashHistory()
        self.linux = linux if linux is not None else LinuxStarts(db_path)
        self.baseline, self._at = None, None
        self.generation = 0
        self._cache = {}
        self._runs = {}       # (pid, created_ms) -> recorded sha256 ("" = none)
        self._lock = threading.Lock()

    def refresh(self):
        """Rebuild the baseline when it is older than CACHE_S; True when it did."""
        with self._lock:
            if self._at is not None and self.clock() - self._at < CACHE_S:
                return False
            self.baseline, self._at = self.loader(self.db_path), self.clock()
            self._cache.clear()
            self.generation += 1
            return True

    def state(self):
        """For the feed's status frame: is there a baseline to judge against?"""
        base = self.baseline
        if base is None:
            return {"baseline": "loading"}
        return {"baseline": "ok" if base.ok else "unavailable", "reason": base.reason}

    def recorded_hash(self, host, pid, created_ms):
        """The event log's hash for one Windows run, or "" (never for Linux)."""
        if host != "win" or not pid:
            return ""
        run = (int(pid), int(created_ms))
        if run not in self._runs:
            if len(self._runs) >= RUN_CACHE_MAX:
                self._runs.clear()
            self._runs[run] = self.history.recorded_hash(pid, created_ms)
        return self._runs[run]

    def judge(self, host, name, path, sha256=""):
        return self._cached(("row", host, norm(name), path, sha256), lambda: [
            place(host, path), self._path_verdict(host, name, path), self._hash_verdict(host, sha256)])

    def judge_start(self, host, name, path, sha256=""):
        return self._cached(("start", host, norm(name), path, sha256), lambda: [
            place(host, path), self._start_path_verdict(host, name, path), self._hash_verdict(host, sha256)])

    def _cached(self, key, compute):
        self.refresh()
        hit = self._cache.get(key)
        if hit is None:
            hit = compute()
            if len(self._cache) >= CACHE_MAX:
                self._cache.clear()
            self._cache[key] = hit
        return list(hit)

    def _starts(self, host):
        """The start history for a host and whether it is old enough to say "never"."""
        if host == "win":
            return self.history, True
        try:
            since = self.linux.since()
        except sqlite3.Error:
            self.linux.close()
            return self.linux, False
        return self.linux, since is not None and self.wall() - since >= RECENT_S

    def _first_start(self, host, kind, value):
        """(first sighting or None, mature) from the start history; (None, False) when unreadable."""
        source, mature = self._starts(host)
        try:
            first = source.image_first_seen(value) if kind == "image" else source.first_seen(value)
        except sqlite3.Error:
            source.close()
            return None, False
        return first, mature

    def _start_path_verdict(self, host, name, path):
        if self._path_verdict(host, name, path) == "moved":
            return "moved"                       # a familiar name from a user-writable place
        where = place(host, path)
        if where == "unknown":
            return "unknown"
        if where == "kernel":
            return "same"
        first, mature = self._first_start(host, "image", path)
        if first is not None and self.wall() - first >= RECENT_S:
            return "same"
        return "new" if mature else "unknown"

    def _established(self, entry):
        first, approved = entry
        return bool(approved) or first <= self.wall() - RECENT_S

    def _path_verdict(self, host, name, path):
        base = self.baseline
        where = place(host, path)
        if base is None or not base.ok or where == "unknown":
            return "unknown"
        if where == "kernel":
            return "same"
        key = (host, norm(name))
        exact = base.paths.get(key, {}).get(fold(host, path))
        if host == "win" and key[1] in SYSTEM_ONLY and where != "system" and not (exact and exact[1]):
            return "moved"
        if key not in base.names:
            return "new"
        settled = {p: e for p, e in base.places.get(key, {}).items() if self._established(e)}
        if not settled:
            # Nothing to compare with: a name new today, or one whose path the
            # scan has never been able to read.
            return "unknown" if self._established(base.names[key]) else "new"
        if exact and self._established(exact):
            verdict = "same"
        elif where in settled:
            verdict = "similar"
        else:
            return "moved"
        # A system name from a user-writable place needs your approval, however
        # long it has run (see the module docstring).
        if (host == "win" and "system" in settled and where in USER_WRITABLE
                and not (exact or settled[where])[1]):
            return "moved"
        return verdict

    def _hash_verdict(self, host, sha256):
        if not sha256:
            return "unknown"
        first, mature = self._first_start(host, "sha256", sha256)
        if first is None:
            return "new" if mature else "unknown"
        return "recent" if self.wall() - first < RECENT_S else "known"


_JUDGE = None
_JUDGE_LOCK = threading.Lock()


def shared(db_path):
    """The one judge of this process."""
    global _JUDGE
    with _JUDGE_LOCK:
        if _JUDGE is None:
            _JUDGE = Judge(db_path)
        return _JUDGE

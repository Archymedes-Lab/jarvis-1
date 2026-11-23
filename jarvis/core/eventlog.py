"""The temporal event log: an ordered, append-only history of the machine.

`jarvis.db` answers "what is true now, and what have we decided about it".
This answers "what happened, in what order" — at a volume SQLite should not
hold as rows. A day of Sysmon on a desktop is tens of thousands of events; the
store's `events` table already needed severity-based retention at 12 MB/day.

Layout under ~/.jarvis/eventlog/:

  active.jsonl        the open segment: one JSON event per line, and after each
                      source batch one cursor line recording how far that
                      source has been consumed. A batch is written with a
                      single write and fsync, so the cursor line is the commit
                      point: recovery truncates anything after the last one,
                      and those events are re-read from the sensor's spool.
  segments/N.jseg     a sealed segment: two concatenated gzip members, the
                      header line and then the active file's exact bytes.
  chain.jsonl         every sealed segment's header, in order. Each header
                      carries the previous header's hash, so deleting,
                      editing, reordering or inserting a segment breaks the
                      chain at that point.
  pruned.jsonl        segments removed whole, preserved as explicit gaps.
  compacted.jsonl     segments rewritten to keep only their suspicious events
                      (owner retention policy, 2026-11-04): the chain header is
                      unchanged, the record keeps the original payload hash and
                      what was dropped, and verify() checks the rewritten payload
                      against it. Retention never touches the newest 30 days,
                      held ranges, or anything suspicious (collectors/telemetry/
                      history_retention.py decides; this file only applies it).
  holds.jsonl         sequence ranges retention must not remove (evidence).
  index.db            a projection for fast questions — has this hash ever
                      run, which process started which. Rebuildable from the
                      segments at any time; never the authority.

Every event gets a global sequence number here, in ingest order, alongside the
source's own time. Source clocks disagree and can be changed; ingest order is
the one ordering this machine assigned itself.

What the hash chain does not do: a local administrator, or malware running as
this user, can rewrite every file here including the chain. Local hashing
makes tampering detectable against a copy of the chain head kept somewhere
else (`head()`), not impossible. There is no encryption at rest yet either —
the standard library has no authenticated cipher, and a hand-rolled one would
be worse than none. Both are recorded as open work, not implied.
"""

import gzip
import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path

from jarvis.core import event as event_mod
from jarvis.core import filelock, inflate, pagecache

DEFAULT_ROOT = Path(os.path.expanduser("~/.jarvis/eventlog"))
GENESIS = "0" * 64

# A segment seals at whichever comes first. Five minutes bounds how much history
# sits in the unsealed, unchained file; the sizes bound one segment's rewrite.
SEAL_EVENTS = 20_000
SEAL_BYTES = 32 * 1024 * 1024
# Read-side bounds for sealed (gzip) segments, so a planted decompression bomb
# is reported as an unreadable segment instead of exhausting the reader
# (core/inflate.py). Measured 2026-10-25: headers ~3 KB, longest line 78 KB,
# largest segment 324 MB plain.
MAX_HEADER_LINE = 256 * 1024
MAX_EVENT_LINE = 1024 * 1024
MAX_SEGMENT_PLAIN = 1024 * 1024 * 1024
SEAL_AGE = 300

# The payload cap that refuses new history when reached (raised from 2 GiB on
# 2026-11-04 by the owner, with retention compacting normal history after 30 days).
DEFAULT_BUDGET = 6 * 1024 ** 3

INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS segments (
  segment INTEGER PRIMARY KEY, first_seq INTEGER, last_seq INTEGER, count INTEGER,
  time_min TEXT, time_max TEXT, sealed_at REAL, bytes INTEGER, hash TEXT,
  state TEXT NOT NULL DEFAULT 'sealed');
-- One row per exact execution; the command line is a preview, the full one
-- is in the event. Rows appear for processes first seen doing
-- something other than starting, so lineage survives a sensor installed
-- after the process began; `start_seq` is then NULL.
CREATE TABLE IF NOT EXISTS processes (
  guid TEXT PRIMARY KEY, host TEXT, pid INTEGER, image TEXT, sha256 TEXT,
  cmdline TEXT, user TEXT, parent_guid TEXT, started TEXT, start_seq INTEGER,
  ended TEXT, end_seq INTEGER, first_seq INTEGER, last_seq INTEGER);
CREATE INDEX IF NOT EXISTS processes_parent ON processes(parent_guid);
CREATE INDEX IF NOT EXISTS processes_sha ON processes(sha256);
-- The 60-second scan resolves every live Windows PID through
-- process_instances(host, pid); without this the lookup is a full table
-- scan plus sort per PID (measured 17s for ~280 processes at 295k rows).
-- Read-only speedup: identical rows, only faster.
CREATE INDEX IF NOT EXISTS processes_host_pid ON processes(host, pid);
-- First and last sighting of each indicator. Every occurrence is in the
-- segments; this only says which range of them to replay.
CREATE TABLE IF NOT EXISTS sightings (
  kind TEXT NOT NULL, value TEXT NOT NULL, first_seq INTEGER, first_time TEXT,
  last_seq INTEGER, last_time TEXT, count INTEGER, PRIMARY KEY(kind, value));
CREATE TABLE IF NOT EXISTS counts (
  category TEXT NOT NULL, action TEXT NOT NULL, source_event INTEGER NOT NULL,
  n INTEGER NOT NULL, PRIMARY KEY(category, action, source_event));
"""


class LogError(RuntimeError):
    pass


class LogCapacityError(LogError):
    """Evidence is retained; a new batch cannot safely be committed."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _header_hash(header):
    body = {k: v for k, v in header.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


def header_hash(header):
    """The chain hash a segment header must carry; for independent verifiers."""
    return _header_hash(header)


def _free_bytes(path):
    """Bytes an unprivileged writer can still use on the volume holding `path`."""
    if hasattr(os, "statvfs"):
        disk = os.statvfs(path)
        return disk.f_bavail * disk.f_frsize
    return shutil.disk_usage(path).free


def _fsync_dir(path):
    if os.name == "nt":
        # Windows cannot open a directory to sync it. The file's own data is
        # fsynced by every caller; the directory entry rides on the NTFS
        # journal, which is weaker than an explicit sync and recorded as such.
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _jsonl(path):
    """Complete lines of an append-only JSON-lines file; a torn tail is ignored."""
    return [obj for obj, _n in _parsed_lines(path)]


# Parsed prefixes of the append-only files, shared by every EventLog opened in
# this process. Several jobs open the log every minute; each open used to
# re-parse the whole chain file (8 MB, 0.4 s CPU, 23 MiB, measured 2026-11-02)
# and the active segment. The cache never trusts file metadata: each call
# reads the bytes and reuses the parse only when the SHA-256 of the previously
# parsed prefix still matches, so a rewritten file is parsed afresh and the
# result is always what a fresh parse would return. Entries are (object,
# line length); callers must not mutate the objects.
_PARSE_CACHE = {}
_PARSE_LOCK = threading.Lock()
_PARSE_CACHE_FILES = 8         # chain + active of the live log, plus a few others
_SEALED_CACHE = {}


def _parsed_lines(path):
    """[(object, line_length)] for the complete, valid lines at the start of
    `path`, stopping at a torn or invalid line exactly like a fresh parse."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return []
    key = os.fspath(path)
    with _PARSE_LOCK:
        hit = _PARSE_CACHE.get(key)
    start, out = 0, []
    if hit and len(data) >= hit["size"] and \
            hashlib.sha256(memoryview(data)[:hit["size"]]).digest() == hit["digest"]:
        start, out = hit["size"], list(hit["items"])
        if hit["stopped"] and len(data) == hit["size"]:
            return out
    pos = start
    stopped = False
    while pos < len(data):
        end = data.find(b"\n", pos)
        if end < 0:
            stopped = True
            break
        try:
            obj = json.loads(data[pos:end + 1])
        except ValueError:
            stopped = True
            break
        out.append((obj, end + 1 - pos))
        pos = end + 1
    with _PARSE_LOCK:
        _PARSE_CACHE.pop(key, None)
        while len(_PARSE_CACHE) >= _PARSE_CACHE_FILES:
            _PARSE_CACHE.pop(next(iter(_PARSE_CACHE)))
        _PARSE_CACHE[key] = {"size": pos, "digest": hashlib.sha256(memoryview(data)[:pos]).digest(),
                             "items": tuple(out), "stopped": stopped}
    return out


def _append_line(path, obj):
    with open(path, "ab") as fh:
        fh.write((_canonical(obj) + "\n").encode())
        fh.flush()
        os.fsync(fh.fileno())


def _copy_cursors(head):
    """The head's cursors as this instance's own dicts (headers are shared)."""
    return {k: dict(v) for k, v in (head["cursors"] if head else {}).items()}


def _cursor_key(sensor, channel):
    return f"{sensor}\x1f{channel}"


class EventLog:
    """Open the log. Only a writer may append, seal, prune or repair.

    One writer at a time is enforced with a lock file; readers take no lock
    and see only committed batches, however the writer is interrupted.
    """

    def __init__(self, root=DEFAULT_ROOT, writer=False, budget=DEFAULT_BUDGET):
        self.root = Path(root)
        self.writer = writer
        if type(budget) is not int or budget < 0:
            raise ValueError("history budget must be a nonnegative byte count")
        self.budget = budget
        self.segdir = self.root / "segments"
        self.active = self.root / "active.jsonl"
        self.chain_path = self.root / "chain.jsonl"
        self.pruned_path = self.root / "pruned.jsonl"
        self.holds_path = self.root / "holds.jsonl"
        self.compacted_path = self.root / "compacted.jsonl"
        self._lock = None
        if writer:
            self.segdir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.root, 0o700)
            self._lock = open(self.root / "writer.lock", "a")
            try:
                filelock.acquire(self._lock)
            except OSError:
                self._lock.close()
                raise LogError("another process is writing the event log") from None
        self.db = None
        if writer or (self.root / "index.db").exists():
            self.db = (sqlite3.connect(self.root / "index.db", timeout=10) if writer else
                       sqlite3.connect((self.root / "index.db").resolve().as_uri()
                                       + "?mode=ro", uri=True, timeout=10))
            self.db.row_factory = sqlite3.Row
            if writer:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.executescript(INDEX_SCHEMA)
        self._load()
        self.sealed_bytes = self._sealed_total()
        if writer:
            self._reindex()

    def _sealed_total(self):
        """Bytes in sealed segments. Sealed files never change size, so the sum
        is reused while the chain head and the prune record are unchanged
        (stat of 3007 files on every open, measured 2026-11-02)."""
        try:
            pruned = self.pruned_path.stat().st_size
        except OSError:
            pruned = -1
        key = (os.fspath(self.segdir), len(self.chain), self.head_hash, pruned)
        with _PARSE_LOCK:
            hit = _SEALED_CACHE.get(os.fspath(self.segdir))
        if hit and hit[0] == key:
            return hit[1]
        total = 0
        try:
            with os.scandir(self.segdir) as it:
                for entry in it:
                    if entry.name.endswith(".jseg"):
                        total += entry.stat().st_size
        except FileNotFoundError:
            total = 0
        with _PARSE_LOCK:
            if len(_SEALED_CACHE) >= _PARSE_CACHE_FILES:
                _SEALED_CACHE.pop(next(iter(_SEALED_CACHE)))
            _SEALED_CACHE[os.fspath(self.segdir)] = (key, total)
        return total

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- state -------------------------------------------------------------

    def _load(self):
        """Rebuild in-memory state from the files, finishing an interrupted seal."""
        self.chain = _jsonl(self.chain_path)        # a new list; headers are shared, read-only
        if self.writer:
            self._adopt_orphan_segment()
        head = self.chain[-1] if self.chain else None
        self.head_hash = head["hash"] if head else GENESIS
        self.sealed_seq = head["last_seq"] if head else 0
        self.cursors = _copy_cursors(head)
        self.last_seq = self.sealed_seq
        self.active_events = 0
        self.active_bytes = 0
        self.active_started = None
        committed, stale = 0, False
        try:
            pending_seq = self.last_seq
            pending_count = 0
            offset = 0
            for obj, length in _parsed_lines(self.active):
                offset += length
                if "cursor" in obj:
                    c = dict(obj["cursor"])
                    self.cursors[_cursor_key(c["sensor"], c["channel"])] = c
                    self.last_seq = pending_seq
                    self.active_events += pending_count
                    pending_count = 0
                    if self.active_started is None:
                        self.active_started = c.get("at")
                    committed = offset
                else:
                    if obj.get("seq", 0) <= self.sealed_seq:
                        stale = True      # sealed already; the reset was interrupted
                        break
                    pending_seq = obj["seq"]
                    pending_count += 1
        except FileNotFoundError:
            pass
        if stale:
            self.last_seq, self.active_events, self.active_started = self.sealed_seq, 0, None
            self.cursors = _copy_cursors(head)
            committed = 0
        self.active_bytes = committed
        self._active_age_base = max(0, time.time() - self.active_started) if self.active_started else 0
        self._active_mono_at = time.monotonic()
        if self.writer and self.active.exists() and self.active.stat().st_size != committed:
            # Everything past the last cursor line is an uncommitted batch.
            with open(self.active, "r+b") as fh:
                fh.truncate(committed)
                fh.flush()
                os.fsync(fh.fileno())

    def _adopt_orphan_segment(self):
        """A segment renamed into place before its chain line was written."""
        nxt = (self.chain[-1]["segment"] + 1) if self.chain else 1
        path = self._segment_path(nxt)
        if not path.exists():
            return
        header = self._read_header(path)
        prev = self.chain[-1]["hash"] if self.chain else GENESIS
        if header.get("previous_hash") != prev or _header_hash(header) != header.get("hash"):
            raise LogError(f"segment {nxt} exists but does not extend the chain")
        _append_line(self.chain_path, header)
        self.chain.append(header)

    def _segment_path(self, n):
        return self.segdir / f"{n:012d}.jseg"

    @staticmethod
    def _read_header(path):
        with gzip.open(path, "rb") as fh:
            return json.loads(inflate.readline(fh, MAX_HEADER_LINE))

    def cursor(self, sensor, channel):
        return self.cursors.get(_cursor_key(sensor, channel))

    def head(self):
        """The chain head: copy it off this machine to make later rewriting visible."""
        head = self.chain[-1] if self.chain else None
        return {"segment": head["segment"] if head else 0, "last_seq": self.sealed_seq,
                "hash": self.head_hash}

    # -- writing -----------------------------------------------------------

    def append(self, events, cursor):
        """Append one source batch and its cursor as a single durable write.

        `cursor` must name `sensor` and `channel`; everything else in it is
        kept verbatim for delivery accounting. Returns (first_seq, last_seq).
        """
        if not self.writer:
            raise LogError("event log opened read-only")
        if not cursor.get("sensor") or not cursor.get("channel"):
            raise LogError("cursor must identify its sensor and channel")
        seq = self.last_seq
        lines = []
        stamped = []
        for ev in events:
            event_mod.validate(ev)
            seq += 1
            ev = dict(ev, seq=seq)
            stamped.append(ev)
            lines.append(_canonical(ev))
        cursor = dict(cursor, at=time.time(), through_seq=seq)
        lines.append(_canonical({"cursor": cursor}))
        data = ("\n".join(lines) + "\n").encode()
        # Never reclaim history to make an append succeed. Refusal happens
        # before the durable commit point, so native ingestion cannot ack it.
        metadata_bytes = sum(p.stat().st_size for p in
                             (self.chain_path, self.pruned_path, self.holds_path) if p.exists())
        if self.sealed_bytes + self.active_bytes + metadata_bytes + len(data) > self.budget:
            raise LogCapacityError("history capacity reached; retained evidence unchanged; "
                                   "new batch and source cursor not committed")
        if _free_bytes(self.root) < len(data) + 2 * SEAL_BYTES:
            raise LogCapacityError("history disk reserve reached; retained evidence unchanged; "
                                   "new batch and source cursor not committed")
        with open(self.active, "ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        first = self.last_seq + 1
        self.last_seq = seq
        self.active_events += len(stamped)
        self.active_bytes += len(data)
        if self.active_started is None:
            self.active_started = cursor["at"]
            self._active_age_base = 0
            self._active_mono_at = time.monotonic()
        self.cursors[_cursor_key(cursor["sensor"], cursor["channel"])] = cursor
        self._index(stamped)
        return first, seq

    def due(self, now=None):
        age = ((now - self.active_started) if now is not None and self.active_started is not None
               else max(self._active_age_base + time.monotonic() - self._active_mono_at,
                        time.time() - self.active_started if self.active_started is not None else 0))
        return self.active_events > 0 and (
            self.active_events >= SEAL_EVENTS or self.active_bytes >= SEAL_BYTES
            or age >= SEAL_AGE)

    def seal(self, force=False):
        """Close the active segment into the chain. Returns its header, or None."""
        if not self.writer:
            raise LogError("event log opened read-only")
        if not self.active_bytes or not (force or self.due()):
            return None
        with open(self.active, "rb") as fh:
            payload = fh.read(self.active_bytes)
        tmin = tmax = None
        first = None
        for line in payload.splitlines():
            obj = json.loads(line)
            if "cursor" in obj:
                continue
            first = obj["seq"] if first is None else first
            t = obj.get("time")
            if t:
                tmin = t if tmin is None or t < tmin else tmin
                tmax = t if tmax is None or t > tmax else tmax
        n = (self.chain[-1]["segment"] + 1) if self.chain else 1
        header = {
            "v": 1, "segment": n,
            "first_seq": first if first is not None else self.sealed_seq + 1,
            "last_seq": self.last_seq, "count": self.active_events,
            "time_min": tmin, "time_max": tmax, "sealed_at": time.time(),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "payload_bytes": len(payload), "previous_hash": self.head_hash,
            "cursors": dict(self.cursors),     # a snapshot; appends replace entries
        }
        header["hash"] = _header_hash(header)
        path = self._segment_path(n)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "wb") as raw:
            for part in ((_canonical(header) + "\n").encode(), payload):
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                    gz.write(part)
            raw.flush()
            os.fsync(raw.fileno())
        os.link(tmp, path)          # fails rather than replacing an existing segment
        os.unlink(tmp)
        _fsync_dir(self.segdir)
        _append_line(self.chain_path, header)
        self.chain.append(header)
        fresh = self.root / "active.new"
        with open(fresh, "wb") as fh:
            os.fsync(fh.fileno())
        os.replace(fresh, self.active)
        _fsync_dir(self.root)
        self.head_hash, self.sealed_seq = header["hash"], header["last_seq"]
        self.sealed_bytes += path.stat().st_size
        self.active_events = self.active_bytes = 0
        self.active_started = None
        self._active_age_base = 0
        self._active_mono_at = time.monotonic()
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO segments VALUES(?,?,?,?,?,?,?,?,?,'sealed')",
                (n, header["first_seq"], header["last_seq"], header["count"], tmin, tmax,
                 header["sealed_at"], path.stat().st_size, header["hash"]))
        return header

    # -- reading -----------------------------------------------------------

    def _pruned(self):
        return {p["segment"] for p in _jsonl(self.pruned_path)}

    def _compacted(self):
        """segment -> its compaction record (a segment is compacted at most once)."""
        return {c["segment"]: c for c in _jsonl(self.compacted_path)}

    def iter_events(self, after=0, until=None, since=None):
        """Committed events with after < seq <= until, in sequence order.

        `since` (an ISO time) skips sealed segments whose newest source time is
        older; it does not filter events, since source clocks are not ordered.
        Pruned segments are skipped; `missing()` says what range they covered.
        """
        pruned = self._pruned()
        for header in self.chain:
            if header["last_seq"] <= after or header["segment"] in pruned:
                continue
            if since is not None and header.get("time_max") and header["time_max"] < since:
                continue
            if until is not None and header["first_seq"] > until:
                return
            with gzip.open(self._segment_path(header["segment"]), "rb") as fh:
                inflate.readline(fh, MAX_HEADER_LINE)
                for line in inflate.lines(fh, MAX_EVENT_LINE):
                    obj = json.loads(line)
                    if "cursor" in obj:
                        continue
                    if obj["seq"] <= after:
                        continue
                    if until is not None and obj["seq"] > until:
                        return
                    yield obj
        yield from self._iter_active(after, until)

    def _iter_active(self, after, until):
        pending = []
        try:
            fh = open(self.active, "rb")
        except FileNotFoundError:
            return
        with fh:
            for line in fh:
                if not line.endswith(b"\n"):
                    return
                try:
                    obj = json.loads(line)
                except ValueError:
                    return
                if "cursor" in obj:
                    # Only a cursor line makes the lines before it committed.
                    for ev in pending:
                        if until is not None and ev["seq"] > until:
                            return
                        yield ev
                    pending = []
                elif obj.get("seq", 0) > max(after, self.sealed_seq):
                    pending.append(obj)

    def missing(self):
        """Sequence ranges removed by retention, oldest first."""
        pruned = self._pruned()
        return [(h["first_seq"], h["last_seq"]) for h in self.chain if h["segment"] in pruned]

    # -- integrity ---------------------------------------------------------

    def verify(self, anchor=None):
        """Walk the chain and every retained payload.

        `anchor` is a previously exported `head()`; the chain must still
        contain that exact segment hash. Without one, a consistent rewrite of
        the whole history cannot be distinguished from the original.
        """
        problems = []
        pruned = self._pruned()
        compacted = self._compacted()
        prev = GENESIS
        expected_seq = 1
        for i, header in enumerate(self.chain):
            n = header.get("segment")
            if n != i + 1:
                problems.append(f"segment {n}: out of order (expected {i + 1})")
            if header.get("previous_hash") != prev:
                problems.append(f"segment {n}: does not link to the previous segment")
            if _header_hash(header) != header.get("hash"):
                problems.append(f"segment {n}: header altered")
            if header.get("first_seq") != expected_seq and header.get("count"):
                problems.append(f"segment {n}: sequence gap before {header.get('first_seq')}")
            path = self._segment_path(n)
            if n in pruned:
                if path.exists():
                    problems.append(f"segment {n}: recorded as pruned but still present")
            elif not path.exists():
                problems.append(f"segment {n}: missing (not removed by retention)")
            else:
                try:
                    with open(path, "rb") as raw, gzip.open(raw, "rb") as fh:
                        try:
                            stored = json.loads(inflate.readline(fh, MAX_HEADER_LINE))
                            hasher = hashlib.sha256()
                            for block in inflate.chunks(fh, MAX_SEGMENT_PLAIN):
                                hasher.update(block)
                            digest = hasher.hexdigest()
                        finally:
                            pagecache.drop(raw)   # read once per verify; not worth keeping
                except (OSError, ValueError, EOFError) as exc:
                    problems.append(f"segment {n}: unreadable ({exc})")
                else:
                    if stored != header:
                        problems.append(f"segment {n}: file header differs from the chain")
                    record = compacted.get(n)
                    if record is not None:
                        if record.get("original_payload_sha256") != header.get("payload_sha256"):
                            problems.append(f"segment {n}: compaction record names another payload")
                        if digest != record.get("payload_sha256"):
                            problems.append(f"segment {n}: compacted payload altered")
                    elif digest != header.get("payload_sha256"):
                        problems.append(f"segment {n}: payload altered")
            prev = header.get("hash")
            expected_seq = header.get("last_seq", 0) + 1
        anchored = None
        if anchor:
            anchored = any(h.get("segment") == anchor.get("segment")
                           and h.get("hash") == anchor.get("hash") for h in self.chain)
            if not anchored:
                problems.append("the exported chain head is no longer part of this history")
        for n in sorted(pruned - {h["segment"] for h in self.chain}):
            problems.append(f"pruned record names segment {n}, which was never sealed")
        for n in sorted(set(compacted) - {h["segment"] for h in self.chain}):
            problems.append(f"compaction record names segment {n}, which was never sealed")
        return {"ok": not problems, "segments": len(self.chain), "pruned": len(pruned),
                "compacted": len(compacted),
                "sealed_through": self.sealed_seq, "unsealed_events": self.active_events,
                "head": self.head(), "anchored": anchored, "problems": problems}

    # -- retention ---------------------------------------------------------

    def holds(self):
        lines = _jsonl(self.holds_path)
        released = {(r["release"]["first_seq"], r["release"]["last_seq"], r["release"]["at"])
                    for r in lines if isinstance(r.get("release"), dict)}
        return [(h["first_seq"], h["last_seq"], h.get("reason", ""))
                for h in lines if "first_seq" in h and not h.get("released")
                and (h["first_seq"], h["last_seq"], h.get("at")) not in released]

    def hold_records(self):
        """Active holds with their identity (`at`), for an explicit owner release."""
        active = {(a, b) for a, b, _r in self.holds()}
        return [h for h in _jsonl(self.holds_path)
                if "first_seq" in h and (h["first_seq"], h["last_seq"]) in active]

    def release_hold(self, first_seq, last_seq, at, by):
        """Release one hold, identified exactly. Appended, never rewritten: the
        hold and its release both stay on record. Owner action only (CLI)."""
        if not self.writer:
            raise LogError("event log opened read-only")
        match = [h for h in self.hold_records() if h["first_seq"] == first_seq
                 and h["last_seq"] == last_seq and h.get("at") == at]
        if not match:
            raise LogError("no active hold matches exactly")
        _append_line(self.holds_path, {"release": {"first_seq": first_seq, "last_seq": last_seq,
                                                    "at": at}, "by": str(by)[:80], "at": time.time()})

    def hold(self, first_seq, last_seq, reason):
        """Keep a sequence range through retention (incident evidence)."""
        if not self.writer:
            raise LogError("event log opened read-only")
        _append_line(self.holds_path, {"first_seq": int(first_seq), "last_seq": int(last_seq),
                                       "reason": str(reason)[:200], "at": time.time()})

    def prune(self, budget=DEFAULT_BUDGET):
        """Compatibility hook: persistent forensic history is never pruned.

        A budget cannot authorize deletion. append() refuses before commit
        when full; existing pruned markers remain historical loss evidence.
        """
        if not self.writer:
            raise LogError("event log opened read-only")
        return []

    def compact(self, n, keep, reason, summary=None):
        """Rewrite sealed segment `n` to hold only the events `keep(event)` accepts
        (plus every event inside an active hold). Returns a summary dict.

        Applied by the retention job (collectors/telemetry/history_retention.py), which
        alone decides what is normal. The header and the chain stay as they were;
        compacted.jsonl records the original payload hash, the new one, and how
        many events went. A segment left with nothing is removed whole and
        recorded in pruned.jsonl. Never the newest segment, never twice."""
        if not self.writer:
            raise LogError("event log opened read-only")
        if not self.chain or n >= self.chain[-1]["segment"] or n < 1:
            raise LogError("only an older sealed segment can be compacted")
        header = self.chain[n - 1]
        if n in self._pruned() or n in self._compacted():
            raise LogError(f"segment {n} was already reduced")
        held = self.holds()
        path = self._segment_path(n)
        kept_lines, kept, dropped, dropped_events = [], 0, 0, []
        with gzip.open(path, "rb") as fh:
            stored = json.loads(inflate.readline(fh, MAX_HEADER_LINE))
            if stored != header:
                raise LogError(f"segment {n}: file header differs from the chain; not touching it")
            hasher = hashlib.sha256()
            for line in inflate.lines(fh, MAX_EVENT_LINE):
                hasher.update(line)
                obj = json.loads(line)
                if "cursor" in obj:
                    kept_lines.append(line)
                    continue
                seq = obj.get("seq", 0)
                if any(a <= seq <= b for a, b, _r in held) or keep(obj):
                    kept_lines.append(line)
                    kept += 1
                else:
                    dropped += 1
                    if summary:
                        dropped_events.append(obj)
        if hasher.hexdigest() != header.get("payload_sha256"):
            raise LogError(f"segment {n}: payload does not match its header; not touching it")
        before = path.stat().st_size
        if not dropped:
            return {"segment": n, "kept": kept, "dropped": 0, "freed": 0, "action": "kept"}
        now = time.time()
        if not kept:
            _append_line(self.pruned_path, {"segment": n, "at": now, "reason": str(reason)[:200],
                                            "dropped": dropped,
                                            "dropped_summary": summary(dropped_events) if summary else None})
            path.unlink()
            _fsync_dir(self.segdir)
            with self.db:
                self.db.execute("UPDATE segments SET state='pruned' WHERE segment=?", (n,))
            self.sealed_bytes -= before
            return {"segment": n, "kept": 0, "dropped": dropped, "freed": before, "action": "removed"}
        payload = b"".join(kept_lines)
        tmp = path.with_suffix(".compact")
        with open(tmp, "wb") as raw:
            for part in ((_canonical(header) + "\n").encode(), payload):
                with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
                    gz.write(part)
            raw.flush()
            os.fsync(raw.fileno())
        # The record first: a crash between the two leaves a record whose payload
        # hash does not match the old file, which verify() reports, never silence.
        _append_line(self.compacted_path, {
            "segment": n, "at": now, "reason": str(reason)[:200], "kept": kept,
            "dropped": dropped, "original_payload_sha256": header.get("payload_sha256"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(), "payload_bytes": len(payload),
            "dropped_summary": summary(dropped_events) if summary else None})
        os.replace(tmp, path)
        _fsync_dir(self.segdir)
        after = path.stat().st_size
        with self.db:
            self.db.execute("UPDATE segments SET bytes=?, state='compacted' WHERE segment=?",
                            (after, n))
        self.sealed_bytes -= before - after
        return {"segment": n, "kept": kept, "dropped": dropped, "freed": before - after,
                "action": "compacted"}

    # -- index projection --------------------------------------------------

    def _reindex(self):
        """Bring the index up to the log after a crash, restore or rebuild."""
        with self.db:
            for header in self.chain:
                path = self._segment_path(header["segment"])
                self.db.execute(
                    "INSERT OR IGNORE INTO segments VALUES(?,?,?,?,?,?,?,?,?,'sealed')",
                    (header["segment"], header["first_seq"], header["last_seq"],
                     header["count"], header["time_min"], header["time_max"],
                     header["sealed_at"], path.stat().st_size if path.exists() else 0,
                     header["hash"]))
            for n in self._pruned():
                self.db.execute("UPDATE segments SET state='pruned' WHERE segment=?", (n,))
            for n in self._compacted():
                self.db.execute("UPDATE segments SET state='compacted' WHERE segment=?", (n,))
        row = self.db.execute("SELECT value FROM meta WHERE key='indexed_through'").fetchone()
        done = int(row[0]) if row else 0
        if done > self.last_seq:
            raise LogError("index describes events this log does not contain; rebuild it")
        batch = []
        for ev in self.iter_events(after=done):
            batch.append(ev)
            if len(batch) >= 5000:
                self._index(batch)
                batch = []
        if batch:
            self._index(batch)

    def rebuild_index(self):
        if not self.writer:
            raise LogError("event log opened read-only")
        with self.db:
            for table in ("meta", "segments", "processes", "sightings", "counts"):
                self.db.execute(f"DELETE FROM {table}")
        self._reindex()

    def _index(self, events):
        if not events:
            return
        with self.db:
            for ev in events:
                self._index_one(ev)
            self.db.execute("INSERT INTO meta VALUES('indexed_through',?) ON CONFLICT(key) "
                            "DO UPDATE SET value=excluded.value", (str(events[-1]["seq"]),))

    def _index_one(self, ev):
        db, seq, t = self.db, ev["seq"], ev.get("time")
        db.execute("INSERT INTO counts VALUES(?,?,?,1) ON CONFLICT(category,action,source_event)"
                   " DO UPDATE SET n=n+1",
                   (ev["category"], ev["action"], int(ev.get("source_event") or 0)))
        proc, parent = ev.get("process") or {}, ev.get("parent") or {}
        guid = proc.get("guid")
        if guid:
            if ev["category"] == "process" and ev["action"] == "start":
                db.execute(
                    "INSERT INTO processes VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,?) "
                    "ON CONFLICT(guid) DO UPDATE SET pid=excluded.pid, image=excluded.image,"
                    " sha256=excluded.sha256, cmdline=excluded.cmdline, user=excluded.user,"
                    " parent_guid=excluded.parent_guid, started=excluded.started,"
                    " start_seq=excluded.start_seq, last_seq=excluded.last_seq",
                    (guid, ev["host"], proc.get("pid"), proc.get("image"), proc.get("sha256"),
                     (proc.get("cmdline") or "")[:512], proc.get("user"), parent.get("guid"),
                     t, seq, seq, seq))
            else:
                db.execute(
                    "INSERT INTO processes(guid,host,pid,image,first_seq,last_seq) "
                    "VALUES(?,?,?,?,?,?) ON CONFLICT(guid) DO UPDATE SET last_seq=excluded.last_seq",
                    (guid, ev["host"], proc.get("pid"), proc.get("image"), seq, seq))
            if ev["category"] == "process" and ev["action"] == "exit":
                db.execute("UPDATE processes SET ended=?, end_seq=? WHERE guid=?", (t, seq, guid))
        if parent.get("guid"):
            db.execute("INSERT OR IGNORE INTO processes(guid,host,pid,image,first_seq,last_seq) "
                       "VALUES(?,?,?,?,?,?)",
                       (parent["guid"], ev["host"], parent.get("pid"), parent.get("image"), seq, seq))
        for kind, value in _indicators(ev):
            db.execute(
                "INSERT INTO sightings VALUES(?,?,?,?,?,?,1) ON CONFLICT(kind,value) DO UPDATE SET"
                " last_seq=excluded.last_seq, last_time=excluded.last_time, count=count+1",
                (kind, value, seq, t, seq, t))

    # -- questions ---------------------------------------------------------

    def _need_index(self):
        if self.db is None:
            raise LogError("the event log has no index yet; nothing has been ingested")

    def sighting(self, kind, value):
        self._need_index()
        row = self.db.execute("SELECT * FROM sightings WHERE kind=? AND value=?",
                              (kind, _norm(kind, value))).fetchone()
        return dict(row) if row else None

    def process(self, guid):
        self._need_index()
        row = self.db.execute("SELECT * FROM processes WHERE guid=?", (guid,)).fetchone()
        return dict(row) if row else None

    def process_instances(self, host, pid, limit=32):
        """Exact executions recorded for one host/PID, newest first.

        PID is only a lookup key. Callers must compare `started` before
        treating a row as the same process instance.
        """
        self._need_index()
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM processes WHERE host=? AND pid=? "
            "ORDER BY start_seq DESC LIMIT ?", (host, int(pid), int(limit)))]

    def ancestry(self, guid, limit=32):
        """The process and its recorded ancestors, nearest first."""
        chain, seen = [], set()
        while guid and guid not in seen and len(chain) < limit:
            seen.add(guid)
            row = self.process(guid)
            if row is None:
                chain.append({"guid": guid, "unrecorded": True})
                break
            chain.append(row)
            guid = row.get("parent_guid")
        return chain

    def children(self, guid, limit=200):
        self._need_index()
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM processes WHERE parent_guid=? ORDER BY start_seq LIMIT ?",
            (guid, limit))]

    def counts(self):
        self._need_index()
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM counts ORDER BY n DESC")]

    def stats(self):
        sealed_bytes = sum(p.stat().st_size for p in self.segdir.glob("*.jseg")) \
            if self.segdir.exists() else 0
        return {"root": str(self.root), "last_seq": self.last_seq,
                "sealed_through": self.sealed_seq, "segments": len(self.chain),
                "pruned": len(self._pruned()), "sealed_bytes": sealed_bytes,
                "unsealed_events": self.active_events, "unsealed_bytes": self.active_bytes,
                "cursors": list(self.cursors.values()), "head": self.head(),
                "compacted": len(self._compacted()),
                "retention": "everything for 30 days; after that only suspicious events "
                             "(collectors/telemetry/history_retention.py), reductions recorded",
                "payload_budget_bytes": self.budget,
                "payload_capacity_remaining": max(0, self.budget - sealed_bytes
                                                   - self.active_bytes),
                "deletion_protection": "application only; local administrator can delete"}


def _norm(kind, value):
    value = str(value or "").strip()
    return value.lower().rstrip(".") if kind in ("sha256", "dns", "image") else value


def _indicators(ev):
    """(kind, value) pairs worth answering "has this ever happened?" about."""
    proc, target = ev.get("process") or {}, ev.get("target") or {}
    cat, act = ev["category"], ev["action"]
    if cat == "process" and act == "start":
        if proc.get("sha256"):
            yield "sha256", _norm("sha256", proc["sha256"])
        if proc.get("image"):
            yield "image", _norm("image", proc["image"])
    elif cat in ("process", "driver") and act in ("image_load", "load"):
        if target.get("sha256"):
            yield "sha256", _norm("sha256", target["sha256"])
    elif cat == "network" and act == "dns_query" and target.get("query"):
        yield "dns", _norm("dns", target["query"])
    elif cat == "network" and act == "connect" and target.get("ip"):
        yield "ip", _norm("ip", target["ip"])

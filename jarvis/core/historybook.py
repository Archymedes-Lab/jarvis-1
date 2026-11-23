"""Local forensic review, sampled observations and verifiable case copies.

Canonical EventLog remains the authority. No model, network, deletion or
security response is involved. Export hashes prove bytes against a retained
anchor, not source truth or administrator-proof survival.
"""
import datetime
import gzip
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from jarvis.core import event
from jarvis.core.eventlog import (
    DEFAULT_ROOT,
    GENESIS,
    SEAL_BYTES,
    EventLog,
    LogError,
    _canonical,
    _fsync_dir,
    header_hash,
)

MAX_PROCESSES = 2000
LOCK_ATTEMPTS = 3
LOCK_DELAY = 0.05
MAX_SCAN = 100_000
MAX_ROWS = 1000
MAX_EXPORT_BYTES = 256 * 1024 * 1024
MAX_FILES = 4096
MAX_CHAIN_BYTES = 16 * 1024 * 1024
MAX_SEGMENT_PLAIN = 2 * SEAL_BYTES
CHANNEL = "Jarvis/ProcessSnapshots"


def _utc(stamp):
    return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat()


def record_snapshot(processes, hosts, observed_at, root=DEFAULT_ROOT):
    """One bounded sampled snapshot. Never infer lifecycle or source completeness."""
    if len(processes) > MAX_PROCESSES:
        raise LogError("process history snapshot exceeds count bound; not recorded")
    generation = uuid.uuid4().hex
    rows = []
    for i, proc in enumerate(processes):
        host = proc.get("host")
        pid = proc.get("pid")
        if host not in ("win", "wsl") or type(pid) is not int or pid < 0:
            raise LogError("process history snapshot has invalid identity")
        started = proc.get("started") or ""
        rows.append(event.make(
            host=host, sensor="jarvis-process-snapshot", channel=CHANNEL,
            generation=generation, record=i + 1, source="process-snapshot",
            source_event=0, time=_utc(observed_at), received=_utc(time.time()),
            category="sensor", action="state",
            process={"pid": pid, "ppid": proc.get("ppid"),
                     "name": str(proc.get("name") or "")[:256],
                     "image": str(proc.get("exe") or "")[:4096],
                     "started": str(started)[:128]},
            attrs={"observation": "process_present", "sampled": True,
                   "instance_identity": "host,pid,started" if started else "incomplete"}))
    counts = {h: sum(p.get("host") == h for p in processes) for h in hosts}
    # A separate receipt records empty/missing sources without inventing events.
    rows.append(event.make(
        host="wsl", sensor="jarvis-process-snapshot", channel=CHANNEL,
        generation=generation, record=len(rows) + 1, source="process-snapshot",
        source_event=0, time=_utc(observed_at), received=_utc(time.time()),
        category="sensor", action="state",
        attrs={"observation": "snapshot_receipt", "counts": counts,
               "coverage": "sampled; source completeness not attested",
               "missing_sources": [h for h, n in counts.items() if n == 0]}))
    for attempt in range(LOCK_ATTEMPTS):
        try:
            log = EventLog(root, writer=True)
        except LogError:
            if attempt + 1 == LOCK_ATTEMPTS:
                raise
            time.sleep(LOCK_DELAY)
        else:
            with log:
                first, last = log.append(rows, {
                    "sensor": "jarvis-process-snapshot", "channel": CHANNEL,
                    "generation": generation, "sequence": int(observed_at),
                    "status": "partial", "gap": "sampled process presence; not lifecycle",
                    "events": len(rows)})
                log.seal()
                return {"first_seq": first, "last_seq": last, "counts": counts}


def query(log, after=0, until=None, host=None, category=None, image=None,
          since=None, before=None, limit=100, scan_limit=MAX_SCAN, raw=False):
    """Sequence-paged review. Source-time filtering never establishes ordering."""
    if not 1 <= limit <= MAX_ROWS or not 1 <= scan_limit <= MAX_SCAN:
        raise ValueError("history query bounds exceeded")
    if type(after) is not int or after < 0 or (until is not None and until < after):
        raise ValueError("invalid history sequence range")
    def parse(value):
        if value is None:
            return None
        stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("history dates require a timezone")
        return stamp.timestamp()
    start, end = parse(since), parse(before)
    if start is not None and end is not None and start > end:
        raise ValueError("history time range reversed")
    rows, scanned, next_after = [], 0, after
    through = min(log.last_seq, until if until is not None else log.last_seq)
    unknown_times = 0
    for ev in log.iter_events(after=after, until=through):
        scanned += 1
        next_after = ev["seq"]
        matches = ((not host or ev["host"] == host)
                   and (not category or ev["category"] == category)
                   and (not image or image.casefold() in str(
                       (ev.get("process") or {}).get("image") or "").casefold()))
        if matches and (start is not None or end is not None):
            try:
                stamp = parse(ev["time"])
            except (ValueError, TypeError):
                unknown_times += 1
                matches = False
            else:
                matches = ((start is None or stamp >= start)
                           and (end is None or stamp <= end))
        if matches:
            if raw:
                rows.append(ev)
            else:
                proc = ev.get("process") or {}
                rows.append({k: ev.get(k) for k in (
                    "seq", "id", "host", "time", "received", "mono", "category",
                    "action", "sensor", "channel", "generation", "record")}
                    | {"process": {k: proc.get(k) for k in
                       ("guid", "pid", "ppid", "image", "name", "started")}})
        if len(rows) == limit or scanned == scan_limit:
            break
    return {"events": rows, "scanned": scanned, "next_after": next_after,
            "through_seq": through, "truncated": next_after < through,
            "legacy_missing_ranges": log.missing(), "unparseable_source_times": unknown_times,
            "coverage": "recorded observations only; snapshots are not lifecycle coverage"}


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def export_case(log, destination, after=0, until=None, max_bytes=MAX_EXPORT_BYTES):
    """Copy complete source segments and a committed active prefix, never originals.

    Adjacent events in the same source segment are included for independent
    verification. No existing destination is ever overwritten. A manifest is
    the completion point; failed/incomplete bundles stay available for review.
    """
    if not 1 <= max_bytes <= MAX_EXPORT_BYTES:
        raise ValueError("export byte bound exceeded")
    through = log.last_seq if until is None else min(until, log.last_seq)
    if type(after) is not int or after < 0 or through <= after:
        raise ValueError("export needs a nonempty committed sequence range")
    # Verify the retained sealed source before giving copies an integrity claim.
    verified = log.verify()
    if not verified["ok"]:
        raise LogError("source integrity failed; preserve and investigate originals")
    dest = Path(destination)
    if dest.resolve().is_relative_to(log.root.resolve()) or log.root.resolve().is_relative_to(dest.resolve()):
        raise ValueError("case directory must be separate from the source history")
    dest.mkdir(mode=0o700)  # exclusive: prior cases are never overwritten
    files, used = {}, 0
    def put(name, data):
        nonlocal used
        if used + len(data) > max_bytes or len(files) >= MAX_FILES:
            raise LogError("case export capacity reached; incomplete case retained")
        path = dest / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(path.parent)
        files[name] = {"sha256": _digest(data), "bytes": len(data)}
        used += len(data)
    chain = ("".join(_canonical(h) + "\n" for h in log.chain)).encode()
    if len(chain) > MAX_CHAIN_BYTES:
        raise LogError("case chain exceeds verification bound")
    put("chain.jsonl", chain)
    selected = []
    missing = log._pruned()
    for header in log.chain:
        n = header["segment"]
        if header["last_seq"] > after and header["first_seq"] <= through and n not in missing:
            source = log._segment_path(n)
            if source.stat().st_size > max_bytes - used:
                raise LogError("case export capacity reached; incomplete case retained")
            data = source.read_bytes()
            put("segments/" + source.name, data)
            selected.append(n)
    # Use the committed byte offset captured at reader open; never copy a
    # pending tail. A concurrent seal may replace active.jsonl: detect it,
    # retain an incomplete case, and require a fresh reader/retry.
    active = b""
    if through > log.sealed_seq and log.active_bytes:
        if log.active_bytes > max_bytes - used:
            raise LogError("active case source exceeds remaining export capacity")
        with open(log.active, "rb") as fh:
            active = fh.read(log.active_bytes)
        last = None
        for line in active.splitlines():
            last = json.loads(line)
        if (len(active) != log.active_bytes or not last or "cursor" not in last
                or last["cursor"].get("through_seq") != log.last_seq):
            raise LogError("source active segment changed; incomplete case retained; retry")
        put("active.jsonl", active)
    manifest = {"v": 1, "kind": "jarvis-forensic-case", "created_at": _utc(time.time()),
                "after": after, "until": through, "source_head": log.head(),
                "source_committed_through": log.last_seq, "segments": selected,
                "legacy_missing_ranges": log.missing(), "files": files,
                "source_cursors": list(log.cursors.values()),
                "scope": "original source segments include adjacent events and raw records",
                "custody": "local copy; keep manifest digest independently; no WORM claim"}
    body = (_canonical(manifest) + "\n").encode()
    if used + len(body) > max_bytes:
        raise LogError("case manifest exceeds capacity; incomplete case retained")
    fd = os.open(dest / "manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(body); fh.flush(); os.fsync(fh.fileno())
    _fsync_dir(dest)
    _fsync_dir(dest.parent)
    return {"path": str(dest), "manifest_sha256": _digest(body), "bytes": used + len(body),
            "after": after, "until": through, "complete": True}


def verify_case(destination, anchor=None):
    """Offline bounded verification; no index, repair or original log needed."""
    dest = Path(destination)
    problems = []
    try:
        manifest_path = dest / "manifest.json"
        if manifest_path.is_symlink() or manifest_path.stat().st_size > MAX_CHAIN_BYTES:
            raise ValueError("unsafe case manifest")
        body = manifest_path.read_bytes()
        m = json.loads(body)
        if m.get("v") != 1 or m.get("kind") != "jarvis-forensic-case":
            raise ValueError("unsupported case manifest")
        files = m["files"]
        if not isinstance(files, dict) or len(files) > MAX_FILES or "chain.jsonl" not in files:
            raise ValueError("invalid case file inventory")
        if not 0 <= m["after"] < m["until"] <= m["source_committed_through"]:
            raise ValueError("invalid case sequence selection")
        total = len(body)
        for name, info in files.items():
            if name not in ("chain.jsonl", "active.jsonl") and not (
                    name.startswith("segments/") and len(name) == 26
                    and name[9:21].isdigit() and name.endswith(".jseg")):
                raise ValueError("unsafe case file name")
            path = dest / name
            if path.is_symlink() or path.parent.is_symlink():
                raise ValueError("case contains a symlink")
            size = path.stat().st_size
            total += size
            if total > MAX_EXPORT_BYTES or size != info["bytes"]:
                raise ValueError("case size disagrees with manifest or exceeds bound")
            if _digest(path.read_bytes()) != info["sha256"]:
                problems.append(f"{name}: digest mismatch")
        headers = [json.loads(line) for line in (dest / "chain.jsonl").read_bytes().splitlines()]
        prev, expected = GENESIS, 1
        for i, header in enumerate(headers):
            if (header["segment"] != i + 1 or header["previous_hash"] != prev
                    or header_hash(header) != header["hash"]
                    or header["first_seq"] != expected):
                raise ValueError("case chain is inconsistent")
            prev, expected = header["hash"], header["last_seq"] + 1
        head = ({"segment": len(headers), "last_seq": headers[-1]["last_seq"],
                 "hash": headers[-1]["hash"]} if headers else
                {"segment": 0, "last_seq": 0, "hash": GENESIS})
        if head != m["source_head"]:
            raise ValueError("case source head disagrees with chain")
        selected = [h["segment"] for h in headers
                    if h["last_seq"] > m["after"] and h["first_seq"] <= m["until"]
                    and not any(a <= h["first_seq"] and h["last_seq"] <= b
                                for a, b in m["legacy_missing_ranges"])]
        if selected != m["segments"]:
            raise ValueError("case source segment selection incomplete")
        for n in selected:
            name = f"segments/{n:012d}.jseg"
            if name not in files:
                raise ValueError("required case segment missing from inventory")
            with gzip.open(dest / name, "rb") as fh:
                header_line = fh.readline(MAX_CHAIN_BYTES + 1)
                payload = fh.read(MAX_SEGMENT_PLAIN + 1)
            if len(header_line) > MAX_CHAIN_BYTES or len(payload) > MAX_SEGMENT_PLAIN:
                raise ValueError("case segment expanded beyond bound")
            header = headers[n - 1]
            if json.loads(header_line) != header or _digest(payload) != header["payload_sha256"]:
                problems.append(f"segment {n}: source payload mismatch")
        if m["until"] > head["last_seq"]:
            if "active.jsonl" not in files:
                raise ValueError("required active source missing")
            active = (dest / "active.jsonl").read_bytes()
            next_seq, last = head["last_seq"] + 1, None
            for line in active.splitlines():
                last = json.loads(line)
                if "cursor" not in last:
                    if last.get("seq") != next_seq:
                        raise ValueError("active source sequence mismatch")
                    next_seq += 1
            if (not active.endswith(b"\n") or not last or "cursor" not in last
                    or last["cursor"].get("through_seq") != m["source_committed_through"]
                    or next_seq - 1 != m["source_committed_through"]):
                raise ValueError("active source commit/sequence mismatch")
        digest = _digest(body)
        if anchor is not None and digest != anchor:
            problems.append("independent manifest anchor disagrees")
        return {"ok": not problems, "problems": problems, "manifest_sha256": digest,
                "anchored": None if anchor is None else digest == anchor,
                "after": m["after"], "until": m["until"],
                "legacy_missing_ranges": m["legacy_missing_ranges"],
                "limitations": "unanchored consistent rewrites and source lies are not detectable"}
    except (OSError, ValueError, KeyError, TypeError, EOFError, OverflowError) as exc:
        return {"ok": False, "problems": problems + ["case incomplete or invalid: " + type(exc).__name__],
                "anchored": False if anchor is not None else None}

"""The decision journal: an append-only hash chain, one record per decision.

Same shape as the canary journal and the event log: each record carries the
previous record's hash, so editing, deleting or reordering a record breaks the
chain at a point verify() names. Records hold metadata only — tool name,
verdict, reasons, label levels and a digest of the arguments — never argument
values, so the journal cannot itself become the leak it records.

The monitor allows nothing it could not record: append() raises on failure and
the monitor turns that into a deny.
"""

import hashlib
import json
import os
import time
from pathlib import Path

from jarvis.core import filelock

GENESIS = "0" * 64


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False, default=str)


def record_hash(record):
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


class JournalError(Exception):
    pass


class Journal:
    def __init__(self, root):
        self.root = Path(root)
        self.path = self.root / "decisions.jsonl"

    def _read(self):
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"__corrupt__": True})
        return out

    def records(self):
        return [r for r in self._read() if not r.get("__corrupt__")]

    def verify(self):
        """The first broken link, or None if the whole chain verifies."""
        prev, seq = GENESIS, 1
        for i, rec in enumerate(self._read()):
            if rec.get("__corrupt__"):
                return {"index": i, "reason": "corrupt record"}
            if rec.get("seq") != seq:
                return {"index": i, "reason": "sequence break"}
            if rec.get("prev") != prev:
                return {"index": i, "reason": "broken link"}
            if rec.get("hash") != record_hash(rec):
                return {"index": i, "reason": "record altered"}
            prev, seq = rec["hash"], seq + 1
        return None

    def append(self, payload):
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            lock = open(self.root / "writer.lock", "a")
        except OSError as exc:
            raise JournalError(f"journal unavailable: {type(exc).__name__}") from exc
        try:
            try:
                filelock.acquire(lock)
            except OSError as exc:
                raise JournalError("another writer holds the journal") from exc
            recs = self._read()
            if recs and recs[-1].get("__corrupt__"):
                raise JournalError("journal tail is corrupt")
            prev = recs[-1]["hash"] if recs else GENESIS
            seq = recs[-1]["seq"] + 1 if recs else 1
            rec = {"seq": seq, "at": time.time(), "prev": prev, "payload": payload}
            rec["hash"] = record_hash(rec)
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(_canonical(rec) + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError as exc:
                raise JournalError(f"journal write failed: {type(exc).__name__}") from exc
            return rec
        finally:
            lock.close()

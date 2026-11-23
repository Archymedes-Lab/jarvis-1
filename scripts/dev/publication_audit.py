#!/usr/bin/env python3
"""Read-only, bounded secret-pattern audit of locally reachable Git history.

No matched content, paths or credentials are printed. No finding is suppressed
for docs or tests. This is triage, never publication authorization: arbitrary
private prose, unknown secret formats, remote refs, LFS and GitHub surfaces need
separate review. Run after fetching the refs intended for publication.
"""
import argparse
import collections
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from standard_check import SECRET_PATTERNS

PATTERNS = SECRET_PATTERNS + [
    ("stripe-secret", re.compile(rb"\b[rs]k_live_[A-Za-z0-9]{16,}")),
    ("generic-assignment-review", re.compile(
        rb"(?im)^\s*(?:export\s+)?[A-Z_]*(?:API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*[\"']?[^\s\"'\r\n]{16,}")),
]
MAX_OUTPUT = 16 * 1024 * 1024
MAX_OBJECT = 8 * 1024 * 1024
MAX_BYTES = 256 * 1024 * 1024
MAX_SECONDS = 120
MAX_OBJECTS = 100000


def git(root, *args, timeout=10, input_data=None):
    # Stream to a temporary file so a large repository cannot fill Python RAM.
    with tempfile.TemporaryFile() as output:
        subprocess.run(["git", "-C", str(root), *args], stdout=output,
                       stderr=subprocess.DEVNULL, timeout=timeout, check=True, input=input_data)
        size = output.tell()
        if size > MAX_OUTPUT:
            raise ValueError("git output budget exhausted")
        output.seek(0)
        return output.read()


def scan(root, max_seconds=MAX_SECONDS, max_bytes=MAX_BYTES):
    start = time.monotonic()
    result = {"scope": "local reachable Git blobs only", "scan_complete": False,
              "publication_authorized": False, "objects_scanned": 0, "bytes_scanned": 0,
              "detections": {}, "limitations": ["worktree changes not scanned",
              "remote refs and hosting surfaces not inspected", "unknown secrets and private prose not detected"]}
    counts = collections.Counter()
    try:
        refs = git(root, "show-ref")
        result["refs_sha256"] = hashlib.sha256(refs).hexdigest()
        result["head"] = git(root, "rev-parse", "HEAD").decode().strip()
        listing = git(root, "rev-list", "--objects", "--all", "--no-object-names").splitlines()
        if len(listing) > MAX_OBJECTS:
            raise ValueError("object count budget exhausted")
        metadata = git(root, "cat-file", "--batch-check", input_data=b"\n".join(listing) + b"\n")
        rows = metadata.splitlines()
        if len(rows) != len(listing):
            raise ValueError("incomplete metadata")
        selected = []
        selected_bytes = 0
        skipped = 0
        exhausted = False
        for expected, row in zip(listing, rows):
            oid, kind, raw_size = row.split()
            if oid != expected or not re.fullmatch(rb"[0-9a-f]{40,64}", oid):
                raise ValueError("invalid object metadata")
            if kind != b"blob":
                continue
            size = int(raw_size)
            if size < 0:
                raise ValueError("invalid object size")
            if size > MAX_OBJECT:
                skipped += 1
                continue
            if selected_bytes + size > max_bytes:
                exhausted = True
                continue
            selected.append((oid, size))
            selected_bytes += size
        remaining = max_seconds - (time.monotonic() - start)
        if remaining <= 0:
            raise ValueError("time budget exhausted")
        # Immutable object IDs and checked lengths bound this private temporary
        # spool to the selected byte budget plus one short header per object.
        with tempfile.TemporaryFile() as spool:
            subprocess.run(["git", "-C", str(root), "cat-file", "--batch"],
                           input=b"\n".join(oid for oid, _ in selected) + b"\n",
                           stdout=spool, stderr=subprocess.DEVNULL,
                           timeout=remaining, check=True)
            spool.seek(0)
            for oid, size in selected:
                if time.monotonic() - start >= max_seconds:
                    raise ValueError("time budget exhausted")
                header = spool.readline(200)
                if header != oid + b" blob " + str(size).encode() + b"\n":
                    raise ValueError("object stream mismatch")
                data = spool.read(size)
                if len(data) != size or spool.read(1) != b"\n":
                    raise ValueError("truncated object stream")
                for name, pattern in PATTERNS:
                    if pattern.search(data):
                        counts[name] += 1
                result["objects_scanned"] += 1
                result["bytes_scanned"] += len(data)
        result["oversize_objects_skipped"] = skipped
        if git(root, "show-ref") != refs or git(root, "rev-parse", "HEAD").decode().strip() != result["head"]:
            raise ValueError("refs changed during scan")
        result["byte_budget_exhausted"] = exhausted
        result["scan_complete"] = skipped == 0 and not exhausted
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        # Error type only: command exceptions may embed sensitive arguments.
        result["incomplete_reason"] = type(exc).__name__
    result["detections"] = dict(counts)
    result["elapsed_seconds"] = round(time.monotonic() - start, 3)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    report = scan(args.root)
    print(json.dumps(report, indent=2))
    return 0 if report["scan_complete"] and not report["detections"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

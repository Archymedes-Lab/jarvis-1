#!/usr/bin/env python3
"""Carry build outputs' SHA-256 between CI jobs, and check them on arrival.

    python3 release/digests.py record DIR NAME        writes `NAME=<json>` and `NAME_key=<cache key>` to $GITHUB_OUTPUT
    python3 release/digests.py verify DIR JSON [JSON...]

release.yml passes builds between jobs through the Actions cache: it costs no
account storage, and the build jobs need no write token. A cache entry is
written by whatever ran in that job, though, and another job could save a
different entry. So each build job records the digest of every file it
produced as a job output, which only that job can set. The consuming job
restores the files and refuses unless the folder holds exactly the recorded
files with exactly those digests: nothing missing, nothing extra, nothing changed.
Standard library only.
"""

import hashlib
import json
import os
import sys
from pathlib import Path


def digest_folder(folder):
    out = {}
    for f in sorted(Path(folder).iterdir()):
        if f.is_symlink():
            sys.exit(f"{f}: links are not build outputs")
        if f.is_file():
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
            out[f.name] = h.hexdigest()
    return out


def record(folder, name):
    found = digest_folder(folder)
    if not found:
        sys.exit(f"{folder} holds no files to record")
    blob = json.dumps(found, sort_keys=True, separators=(",", ":"))
    # The cache key names the run and the content, so a re-run never collides
    # with an earlier entry and a restored entry is the one these digests describe.
    key = f"argus-release-{os.environ.get('GITHUB_RUN_ID', 'local')}-{name}-{hashlib.sha256(blob.encode()).hexdigest()[:16]}"
    line = f"{name}={blob}\n{name}_key={key}\n"
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a") as fh:
            fh.write(line)
    print(line, end="")
    return found


def verify(folder, expected):
    """Problems if `folder` does not hold exactly the files in `expected` (merged dicts)."""
    found = digest_folder(folder)
    problems = [f"{n}: missing" for n in sorted(set(expected) - set(found))]
    problems += [f"{n}: not produced by a recorded build" for n in sorted(set(found) - set(expected))]
    problems += [f"{n}: digest differs from the build's record" for n in sorted(set(found) & set(expected))
                 if found[n] != expected[n]]
    return problems


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "record":
        record(sys.argv[2], sys.argv[3])
        return 0
    if len(sys.argv) >= 4 and sys.argv[1] == "verify":
        expected = {}
        for blob in sys.argv[3:]:
            part = json.loads(blob or "{}")
            clash = set(part) & set(expected)
            if clash:
                sys.exit(f"two builds claim the same file: {sorted(clash)}")
            expected.update(part)
        if not expected:
            sys.exit("no recorded digests to verify against")
        problems = verify(sys.argv[2], expected)
        for p in problems:
            print("REFUSED  " + p)
        if problems:
            return 1
        print(f"digests: {len(expected)} files match their builds' records")
        return 0
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())

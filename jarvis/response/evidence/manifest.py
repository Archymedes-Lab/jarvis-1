"""Content hashes for collected evidence.

A manifest answers two questions later: is this the same bytes that were
collected, and is this the same bytes the alert named. Both are needed to
tell "the artefact changed under us" from "our copy is fine".
"""

import json
import os

from .paths import secure_file

MANIFEST = "manifest.json"
SUMS = "SHA256SUMS.txt"

# Large enough that hashing a 67 MB event log is a handful of reads, small
# enough not to hold the whole file in memory when several run in sequence.
CHUNK = 1 << 20


def sha256_file(path, chunk=CHUNK):
    """Streaming SHA-256, so log size does not bound memory."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


class Manifest:
    """The record of what a case directory holds.

    Kept as JSON for the tooling and as a plain SHA256SUMS.txt so the case can
    be verified with coreutils alone, by someone who does not have JARVIS.
    """

    def __init__(self, directory):
        self.dir = directory
        self.path = os.path.join(directory, MANIFEST)
        self.entries = {}
        self.meta = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            self.entries = raw.get("entries") or {}
            self.meta = raw.get("meta") or {}

    def record(self, name, sha256, size, source="", kind="", note=""):
        self.entries[name] = {
            "sha256": sha256, "size": size, "source": source,
            "kind": kind, "note": note,
        }

    def get(self, name):
        return self.entries.get(name)

    def save(self):
        payload = {"meta": self.meta, "entries": self.entries}
        tmp = self.path + ".new"
        # Written beside the target and renamed: a crash mid-write must not
        # leave a case with a truncated manifest and no way to tell.
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)
        secure_file(self.path)
        self._write_sums()

    def _write_sums(self):
        lines = ["%s  %s\n" % (e["sha256"], n)
                 for n, e in sorted(self.entries.items())]
        path = os.path.join(self.dir, SUMS)
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        secure_file(path)

    def verify(self):
        """Re-hash every recorded file.

        Returns (ok, changed, missing). `changed` means the bytes on disk no
        longer match what was collected — treated as a finding, not an error,
        because that is exactly what tampering looks like.
        """
        ok, changed, missing = [], [], []
        for name, entry in sorted(self.entries.items()):
            full = os.path.join(self.dir, name)
            if not os.path.isfile(full):
                missing.append(name)
                continue
            if sha256_file(full) == entry.get("sha256"):
                ok.append(name)
            else:
                changed.append(name)
        return ok, changed, missing

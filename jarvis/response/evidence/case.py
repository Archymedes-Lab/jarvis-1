"""One investigation: its directory, its artefacts, its manifest.

A case is the unit of compartmentalisation. Each investigation owns a
directory under the evidence root, and nothing outside that directory is
written on its behalf, so one case can be archived, handed over or deleted
without touching another.
"""

import json
import os
import platform
import time

from . import sources
from .manifest import CHUNK, Manifest, sha256_file
from .paths import case_dir, evidence_root, safe_name, secure_file

NOTES = "NOTES.md"


def _copy_hash(src, dst):
    """Copy and hash in a single pass.

    Evidence files run to tens of megabytes; hashing after copying reads every
    byte a second time for no benefit.
    """
    import hashlib
    h = hashlib.sha256()
    size = 0
    with open(src, "rb") as fin, open(dst, "wb") as fout:
        for block in iter(lambda: fin.read(CHUNK), b""):
            h.update(block)
            fout.write(block)
            size += len(block)
    return h.hexdigest(), size


class Case:
    def __init__(self, name, create=True):
        self.name = safe_name(name)
        self.dir = case_dir(self.name, create=create)
        self.manifest = Manifest(self.dir)
        if create and not self.manifest.meta.get("opened"):
            self.manifest.meta.update({
                "case": self.name,
                "opened": int(time.time()),
                "host": platform.node(),
            })
            self.manifest.save()

    # -- artefacts --------------------------------------------------------

    def add_file(self, path, name=None, kind="", note="", search=True):
        """Collect one file into the case.

        Returns a result dict rather than raising when the source cannot be
        read: a collection run gathers what it can and reports the rest, so
        one unreadable log does not abandon the other five.
        """
        readable, how = sources.resolve(path, search=search)
        if readable is None:
            return {"name": name or os.path.basename(path), "ok": False,
                    "source": path, "error": sources.diagnose(path)}

        name = safe_name(name or os.path.basename(readable))
        dst = os.path.join(self.dir, name)
        try:
            digest, size = _copy_hash(readable, dst)
        except OSError as exc:
            return {"name": name, "ok": False, "source": path,
                    "error": exc.strerror or str(exc)}
        secure_file(dst)

        prior = self.manifest.get(name)
        self.manifest.record(name, digest, size, source=path,
                             kind=kind, note=note)
        self.manifest.meta.setdefault("access", {})[name] = how
        self.manifest.save()
        return {"name": name, "ok": True, "sha256": digest, "size": size,
                "source": path, "how": how,
                "changed": bool(prior and prior.get("sha256") != digest)}

    def add_text(self, name, text, kind="", note=""):
        """Store derived output — scan results, parsed summaries — in the case."""
        name = safe_name(name)
        dst = os.path.join(self.dir, name)
        data = text if isinstance(text, str) else json.dumps(text, indent=2)
        with open(dst, "w", encoding="utf-8") as fh:
            fh.write(data)
        secure_file(dst)
        blob = data.encode("utf-8", "replace")
        import hashlib
        self.manifest.record(name, hashlib.sha256(blob).hexdigest(), len(blob),
                             source="derived", kind=kind, note=note)
        self.manifest.save()
        return {"name": name, "ok": True, "size": len(blob)}

    def note(self, text):
        """Append a timestamped line to the case's own notes file."""
        path = os.path.join(self.dir, NOTES)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("- %s %s\n" % (stamp, text))
        secure_file(path)

    # -- inspection -------------------------------------------------------

    def files(self):
        return dict(self.manifest.entries)

    def path(self, name):
        return os.path.join(self.dir, safe_name(name))

    def verify(self):
        return self.manifest.verify()

    def size(self):
        return sum(e.get("size", 0) for e in self.manifest.entries.values())


def adopt(name, note=""):
    """Index files already sitting in a case directory into a manifest.

    Collections made before this package existed, or copied in by hand, are
    real evidence. Re-collecting them is not equivalent: a live circular log
    loses its oldest records between snapshots, so an older copy can be the
    only place some records still exist.
    """
    case = Case(name)
    added = []
    for entry in sorted(os.listdir(case.dir)):
        full = os.path.join(case.dir, entry)
        if not os.path.isfile(full) or entry in (NOTES, "manifest.json",
                                                 "manifest.json.new",
                                                 "SHA256SUMS.txt"):
            continue
        if case.manifest.get(entry):
            continue
        case.manifest.record(entry, sha256_file(full),
                             os.path.getsize(full), source="adopted",
                             kind="", note=note)
        secure_file(full)
        added.append(entry)
    if added:
        case.manifest.save()
        case.note("adopted %d pre-existing artefact(s)" % len(added))
    return case, added


def list_cases():
    """Every case on disk, newest first, without loading their artefacts."""
    root = evidence_root()
    out = []
    for name in os.listdir(root):
        directory = os.path.join(root, name)
        if not os.path.isdir(directory):
            continue
        m = Manifest(directory)
        out.append({
            "case": name,
            "opened": m.meta.get("opened", 0),
            "files": len(m.entries),
            "bytes": sum(e.get("size", 0) for e in m.entries.values()),
            "dir": directory,
        })
    out.sort(key=lambda c: (c["opened"], c["case"]), reverse=True)
    return out

"""The on-disk index of fixed package versions, and which release this is.

The read side of intel/distrovuln.py, in core so that collectors (a lower
layer than intel) can read the index the daily job writes.
"""

import json
import os

ROOT = os.path.expanduser("~/.jarvis/distrovuln")
OS_RELEASE = "/etc/os-release"


def release(path=OS_RELEASE):
    """(id, codename) from os-release, lower-case; ("", "") when unreadable."""
    fields = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    fields[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        return "", ""
    codename = fields.get("VERSION_CODENAME") or fields.get("UBUNTU_CODENAME") or ""
    return fields.get("ID", "").lower(), codename.lower()


def index_path(distro, codename, root=ROOT):
    return os.path.join(root, f"{distro}-{codename}.json")


def load(distro, codename, root=ROOT):
    """The stored index, or None."""
    try:
        with open(index_path(distro, codename, root), encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) and isinstance(doc.get("packages"), dict) else None
    except (OSError, ValueError):
        return None

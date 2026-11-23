"""Content-addressed release identity.

A release is its files. `release_id` is the SHA-256 of the canonical file
manifest (path -> SHA-256 of contents), so the same tree has the same
identity wherever it was built from: a staging clone in ~/.cache, the
checkout, or anywhere else. Paths are locations, never identity
(EVIDENCE-FABRIC.md, P1).

RELEASE.json carries "files" (written by scripts/deploy_root_runtime.py) and,
from 2026-09-24, "release_id" and "base_release_id". Older releases have no
"release_id". It is recomputed from "files" and is identical, because the
definition only uses "files".

Standard library only: scripts/deploy_root_runtime.py loads this file by
path, as root, before any other JARVIS code is trusted.
"""

import hashlib
import json
import os

MANIFEST = "RELEASE.json"
PREFIX = "sha256:"


def release_id(files):
    """Identity of a release from its {relative path: sha256 hex} manifest."""
    if not isinstance(files, dict) or not files:
        raise ValueError("a release manifest needs a non-empty files map")
    h = hashlib.sha256()
    for path in sorted(files):
        digest = files[path]
        if (not isinstance(path, str) or not path or path.startswith("/")
                or "\n" in path or "\0" in path or ".." in path.split("/")):
            raise ValueError(f"unsafe manifest path {path!r}")
        if not (isinstance(digest, str) and len(digest) == 64
                and all(c in "0123456789abcdef" for c in digest)):
            raise ValueError(f"bad digest for {path!r}")
        h.update(path.encode("utf-8", "surrogateescape"))
        h.update(b"\0")
        h.update(digest.encode())
        h.update(b"\n")
    return PREFIX + h.hexdigest()


def read_manifest(root):
    """RELEASE.json of a release directory, or None if absent or unreadable."""
    try:
        with open(os.path.join(root, MANIFEST), encoding="utf-8", errors="replace") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError):
        return None
    return manifest if isinstance(manifest, dict) else None


def manifest_release_id(manifest):
    """The release_id a manifest proves, recomputed from its files.

    A recorded "release_id" that disagrees with its own files is a
    tampered or corrupt manifest, and raises ValueError."""
    computed = release_id((manifest or {}).get("files"))
    recorded = (manifest or {}).get("release_id")
    if recorded is not None and recorded != computed:
        raise ValueError("recorded release_id does not match the manifest's files")
    return computed


def short(identity):
    """Display form: the first 12 hex digits."""
    return (identity or "")[len(PREFIX):len(PREFIX) + 12] or "unknown"


def world_writable_ancestor(path):
    """The first directory on `path`'s way to / that anyone can write, or "".

    Covers /tmp and /var/tmp (sticky or not): a sticky bit stops deletion,
    not creation, so a sibling can still plant files next to a build
    (EVIDENCE-FABRIC.md, P6)."""
    path = os.path.realpath(path)
    while True:
        try:
            st = os.stat(path)
        except FileNotFoundError:
            st = None               # not created yet: judge the existing ancestors
        except OSError:
            return path             # unreadable: fail closed
        if st is not None and st.st_mode & 0o002:
            return path
        parent = os.path.dirname(path)
        if parent == path:
            return ""
        path = parent

"""Stage a narrow release: the running sealed release plus named reviewed files.

    jarvis release stage --file jarvis/platform/provenance/persistence.py --file tests/x.py

This is the unprivileged half of the release controller (EVIDENCE-FABRIC.md,
P1/P5/P6). It

  1. copies every file of the live sealed release (/opt/jarvis/current),
     checking each against the release's own manifest, so the base is exactly
     what runs, never the dirty checkout;
  2. overlays only the files named (from the checkout) and applies the
     removals named;
  3. commits the result in a private git repository under
     ~/.cache/jarvis-release-staging/, never /tmp;
  4. prints the one root command that deploys it with --expect-base, so it
     refuses if any other release was switched in meanwhile.

Nothing here needs or gains privilege. The deploy still runs the full test
suite of the staged tree and is still the human's to run.
"""

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from jarvis.platform.provenance import release

LIVE = Path("/opt/jarvis/current")
STAGING = Path(os.path.expanduser("~/.cache/jarvis-release-staging"))
DEPLOY = "/opt/jarvis/current/scripts/deploy_root_runtime.py"


class StageError(RuntimeError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_rel(rel):
    rel = os.path.normpath(rel)
    if rel.startswith(("/", "..")) or rel in (".", "") or "\0" in rel:
        raise StageError(f"refusing path {rel!r}: must be inside the checkout")
    if rel == release.MANIFEST or rel.split("/")[0] in (".git", "__pycache__"):
        raise StageError(f"refusing path {rel!r}")
    return rel


def stage(files, removals=(), *, checkout, live=LIVE, staging=STAGING, name=None, now=None):
    """Build the staged tree. Returns a dict describing it."""
    live = Path(os.path.realpath(live))
    manifest = release.read_manifest(live)
    if not manifest or not manifest.get("files"):
        raise StageError(f"{live} has no readable release manifest")
    try:
        base_id = release.manifest_release_id(manifest)
    except ValueError as exc:
        raise StageError(f"live release manifest is inconsistent: {exc}") from exc
    files = sorted({_safe_rel(f) for f in files})
    removals = sorted({_safe_rel(f) for f in removals})
    if not files and not removals:
        raise StageError("name at least one reviewed --file or --remove")
    for rel in removals:
        if rel not in manifest["files"]:
            raise StageError(f"{rel} is not in the live release")
    checkout = Path(checkout)
    for rel in files:
        src = checkout / rel
        if src.is_symlink() or not src.is_file():
            raise StageError(f"{rel} is not a regular file in {checkout}")

    staging = Path(staging)
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    bad = release.world_writable_ancestor(staging)
    if bad:
        raise StageError(f"staging directory is under world-writable {bad}")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    target = staging / (name or f"{stamp}-on-{release.short(base_id)}")
    target.mkdir(mode=0o700)
    try:
        for rel, digest in manifest["files"].items():
            if rel in removals:
                continue
            dst = target / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(live / rel, dst)
            if _sha256(dst) != digest:
                raise StageError(f"live release file {rel} does not match its manifest")
        changed, added = [], []
        for rel in files:
            dst = target / rel
            (changed if dst.exists() else added).append(rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(checkout / rel, dst)
        git = ["git", "-C", str(target), "-c", "core.fsmonitor=false",
               "-c", "user.name=jarvis-release-stage", "-c", "user.email=stage@localhost"]
        for args in (["init", "-q"], ["add", "-A"],
                     ["commit", "-q", "-m", f"Narrow release on {base_id}\n\n"
                      + "\n".join(f"{k}: {v}" for k, v in
                                  (("changed", changed), ("added", added),
                                   ("removed", removals)) if v)]):
            subprocess.run(git + args, check=True, capture_output=True)
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise
    info = {"stage": str(target), "base_release_id": base_id, "changed": changed,
            "added": added, "removed": removals, "checkout": str(checkout),
            "staged_at": int(time.time() if now is None else now),
            "deploy": ["sudo", "python3", "-I", DEPLOY, "--source", str(target),
                       "--checkout", str(checkout), "--expect-base", base_id]}
    record = staging / (target.name + ".stage.json")
    record.write_text(json.dumps(info, indent=1), encoding="utf-8")
    os.chmod(record, 0o600)
    return info

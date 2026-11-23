#!/usr/bin/env python3
"""Promote a verified dry run to a release instead of rebuilding it.

    python3 release/promote.py find    --repo R --sha S --tag-version V --actor A [--allowed a,b]
    python3 release/promote.py stage   --release-out DIR --records DIR --out DIR --sha S --version V
    python3 release/promote.py suggest [--repo R] [--sha S]

A dry run (a push to a release-test/* branch) builds every artifact on clean GitHub runners,
installs the Windows Setup on clean hosts, assembles and gates the release, and keeps the files
(`release-out`) and each build's record (`build-records`) for seven days. A tag on the very same
commit can reuse that work: `find` decides, `stage` re-checks the files against their records and
against the dry run's manifest, and release/assemble.py then runs again (version, commit, every
digest, the content gate) under the tag's own name. The releaser still checks and signs the
draft as before (release/sign.py); nothing here publishes.

The default is the old behaviour. `find` promotes only a dry run that is
  * a push to release-test/* of exactly this commit, finished with success,
  * started by the person who pushed the tag (or one named in ARGUS_PROMOTE_ACTORS),
  * still holding both artifacts, and
  * of exactly the tag's version (the dry run's version is `YYYY.MM.DD-<run number>`: tag it v<that>).
With no dry run of the commit the tag builds cold. A dry run that exists but does not match is a
refusal that names the tag to use, so a typo does not silently cost a 65-minute cold build.

A dry run builds with a warm compiler cache, which a writer of the branch could have filled; the
cold build of a tag does not. Promotion trades that for time, and is limited to the people who may
push release-test branches and tags. Standard library only.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

WORKFLOW = "release.yml"
NEEDED = ("release-out", "build-records")


@dataclass
class Decision:
    kind: str                 # "promote" | "build" | "refuse"
    run_id: int = 0
    reason: str = ""
    run_url: str = ""
    version: str = ""


def decide(runs, artifacts, *, sha, tag_version, actor, allowed_actors=(), read_record):
    """Pure decision over the API's answers. read_record(run_id) -> (version, commit)."""
    candidates = [r for r in runs
                  if r.get("head_sha") == sha and r.get("event") == "push"
                  and str(r.get("head_branch", "")).startswith("release-test/")]
    if not candidates:
        return Decision("build", reason="no dry run of this commit")
    finished = [r for r in candidates if r.get("status") == "completed" and r.get("conclusion") == "success"]
    if not finished:
        return Decision("build", reason="no successful dry run of this commit")
    skipped = []
    for run in sorted(finished, key=lambda r: r.get("created_at", ""), reverse=True):
        live = {a["name"] for a in artifacts.get(run["id"], []) if not a.get("expired")}
        if not set(NEEDED) <= live:
            skipped.append(f"run {run['id']}: artifacts expired or missing")
            continue
        who = (run.get("actor") or {}).get("login", "")
        if who != actor and who not in allowed_actors:
            skipped.append(f"run {run['id']}: started by {who or '?'}, tag pushed by {actor}")
            continue
        version, commit = read_record(run["id"])
        if not (commit.startswith(sha[:12]) or sha.startswith(commit[:12])):
            return Decision("refuse", run["id"], f"run {run['id']} recorded commit {commit}, not {sha}")
        if version != tag_version:
            return Decision("refuse", run["id"],
                            f"dry run {run['id']} built version {version}, but this tag says {tag_version}: "
                            f"tag the commit v{version} to promote it (or delete this tag to build cold)")
        return Decision("promote", run["id"], "verified dry run", run.get("html_url", ""), version)
    return Decision("build", reason="; ".join(skipped))


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def stage(release_out, records_dir, stage_dir, *, sha, version):
    """Put each recorded file beside its record, after re-checking it two independent ways:
    against the build record, and against the manifest the dry run gated."""
    release_out, records_dir, stage_dir = Path(release_out), Path(records_dir), Path(stage_dir)
    records = sorted(records_dir.rglob("*-build.json"))
    if not records:
        sys.exit("no build records in the dry run's artifacts")
    try:
        manifest = json.loads((release_out / "manifest.json").read_text())
    except (OSError, ValueError):
        sys.exit("the dry run's release-out has no readable manifest.json")
    if manifest.get("version") != version or not str(manifest.get("commit", "")).startswith(sha[:12]):
        sys.exit(f"the dry run's manifest is for {manifest.get('version')} @ {manifest.get('commit')}, "
                 f"not {version} @ {sha}")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from assemble import INTERNAL_INPUTS  # the files assemble.py itself never publishes
    stage_dir.mkdir(parents=True, exist_ok=True)
    for rec_path in records:
        rec = json.loads(rec_path.read_text())
        if rec.get("version") != version or not str(rec.get("commit", "")).startswith(sha[:12]):
            sys.exit(f"{rec_path.name} is for {rec.get('version')} @ {rec.get('commit')}, not {version} @ {sha}")
        for name, meta in rec["files"].items():
            if name in INTERNAL_INPUTS:
                continue
            if Path(name).name != name or name in ("", ".", ".."):
                sys.exit(f"{rec_path.name}: {name!r} is not a plain file name")
            src = release_out / name
            if src.is_symlink() or not src.is_file():
                sys.exit(f"{name} is recorded by {rec_path.name} but missing from the dry run's files")
            if _sha256(src) != meta["sha256"]:
                sys.exit(f"{name} differs from the digest its build recorded")
            listed = (manifest.get("files") or {}).get(name)
            if not listed or listed.get("sha256") != meta["sha256"]:
                sys.exit(f"{name} differs between the build record and the dry run's manifest")
            (stage_dir / name).write_bytes(src.read_bytes())
        (stage_dir / rec_path.name).write_bytes(rec_path.read_bytes())
    return sorted(p.name for p in stage_dir.iterdir())


# ---- GitHub access (kept thin; the decisions above are what the tests exercise) ----

def _gh(*args):
    out = subprocess.run(["gh", *args], capture_output=True, text=True, errors="replace", check=True)
    return out.stdout


def _read_record(repo):
    def read(run_id):
        with tempfile.TemporaryDirectory() as tmp:
            _gh("run", "download", str(run_id), "-R", repo, "-n", "build-records", "-D", tmp)
            for rec in sorted(Path(tmp).rglob("*-build.json")):
                data = json.loads(rec.read_text())
                return data.get("version", ""), data.get("commit", "")
        return "", ""
    return read


def _runs_and_artifacts(repo, sha):
    runs = json.loads(_gh("api", f"repos/{repo}/actions/workflows/{WORKFLOW}/runs?head_sha={sha}&per_page=50")
                      )["workflow_runs"]
    artifacts = {}
    for run in runs:
        listing = json.loads(_gh("api", f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=50"))
        artifacts[run["id"]] = listing.get("artifacts", [])
    return runs, artifacts


def _output(**kv):
    line = "".join(f"{k}={v}\n" for k, v in kv.items())
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    print(line, end="")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("find")
    f.add_argument("--repo", required=True)
    f.add_argument("--sha", required=True)
    f.add_argument("--tag-version", required=True)
    f.add_argument("--actor", required=True)
    f.add_argument("--allowed", default="")
    s = sub.add_parser("stage")
    s.add_argument("--release-out", required=True)
    s.add_argument("--records", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--sha", required=True)
    s.add_argument("--version", required=True)
    g = sub.add_parser("suggest")
    g.add_argument("--repo", default="")
    g.add_argument("--sha", default="")
    a = ap.parse_args()

    if a.cmd == "find":
        runs, artifacts = _runs_and_artifacts(a.repo, a.sha)
        allowed = tuple(x.strip() for x in a.allowed.split(",") if x.strip())
        d = decide(runs, artifacts, sha=a.sha, tag_version=a.tag_version, actor=a.actor,
                   allowed_actors=allowed, read_record=_read_record(a.repo))
        print(f"promotion: {d.kind}: {d.reason}")
        if d.kind == "refuse":
            print(f"::error::{d.reason}")
            sys.exit(1)
        _output(promote_run=d.run_id if d.kind == "promote" else "", promote_url=d.run_url)
    elif a.cmd == "stage":
        names = stage(a.release_out, a.records, a.out, sha=a.sha, version=a.version)
        print("staged: " + ", ".join(names))
    else:
        repo = a.repo or json.loads(_gh("repo", "view", "--json", "nameWithOwner"))["nameWithOwner"]
        sha = a.sha or subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                                      errors="replace", check=True).stdout.strip()
        runs, artifacts = _runs_and_artifacts(repo, sha)
        ok = [r for r in runs if r.get("event") == "push" and str(r.get("head_branch", "")).startswith("release-test/")
              and r.get("conclusion") == "success"]
        if not ok:
            print("no successful dry run of this commit: push it to the dry-run branch first")
            sys.exit(1)
        run = sorted(ok, key=lambda r: r.get("created_at", ""), reverse=True)[0]
        version = _read_record(repo)(run["id"])[0]
        print(f"git tag v{version} {sha}   # promotes dry run {run['id']} ({run.get('html_url', '')})")


if __name__ == "__main__":
    main()

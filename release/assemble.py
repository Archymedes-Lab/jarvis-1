#!/usr/bin/env python3
"""Assemble the release folder from the per-platform CI builds and gate it.

    python3 release/assemble.py --builds DIR --out DIR --version V --tag T --commit C
                                [--run-url URL] [--previous MANIFEST_URL_OR_PATH]

Collects the artifacts each build recorded (*-build.json), checks every one
was built from the same commit, and writes next to them:

    manifest.json        version, tag, commit, the CI run, the content policy's
                         SHA-256, each artifact's size, SHA-256 and file count
    SHA256SUMS(.txt)     what a releaser signs; .txt for Windows PowerShell 5.1
    release-report.md    what changed since the previous release, for the
                         person who signs: artifacts and file counts
    sbom.cdx.json        CycloneDX list of the third-party components built in

then runs the content gate over the folder, with the previous release's file
counts, and exits non-zero on any problem.
"""

import argparse
import hashlib
import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    # A refusal must print, not crash on a cp1252 console. Some runners replace the
    # stream with one that cannot be reconfigured (unittest buffering), so ask first.
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate  # noqa: E402

REPO = HERE.parent

# Build inputs that are never published. The Windows desktop app on its own has no
# monitoring program: as a download it opens, finds nothing to talk to and leaves the
# customer to install the rest. It ships only inside Argus-Setup.exe.
# Kept published for now (2026-11-04): the live download page links it and the
# 2026.11.03-0 release ships it. Add it here once the page offers only the Setup.
INTERNAL_INPUTS = set()


def load_previous(where):
    if not where:
        return {}
    try:
        if where.startswith("https://"):
            req = urllib.request.Request(where, headers={"User-Agent": "argus-release"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        return json.loads(Path(where).read_text())
    except (OSError, ValueError) as exc:
        print(f"previous manifest unavailable ({type(exc).__name__}); no comparison", file=sys.stderr)
        return {}


def _licences():
    """{(name, version): SPDX expression} from release/third_party.json."""
    try:
        snap = json.loads((HERE / "third_party.json").read_text())
    except (OSError, ValueError):
        return {}
    return {(c["name"].lower(), c.get("version", "")): c["license"]
            for section in ("python", "cargo") for c in snap.get(section, [])}


def _with_licence(comp, licences):
    lic = licences.get((comp["name"].lower(), comp["version"]))
    if lic:
        comp["licenses"] = [{"expression": lic}]
    return comp


def sbom(version, commit):
    """CycloneDX 1.5: the pinned Python build inputs and the Rust crates of the desktop app,
    each with its licence from release/third_party.json where one is recorded."""
    comps = []
    licences = _licences()
    for req in ("requirements-build.txt", "requirements-runtime.txt"):
        for line in (HERE / req).read_text().splitlines():
            m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", line)
            if m:
                comps.append(_with_licence({"type": "library", "name": m[1], "version": m[2],
                                            "purl": f"pkg:pypi/{m[1].lower()}@{m[2]}"}, licences))
    lock = REPO / "desktop" / "Cargo.lock"
    if lock.exists():
        for name, ver in re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock.read_text()):
            comps.append(_with_licence({"type": "library", "name": name, "version": ver,
                                        "purl": f"pkg:cargo/{name}@{ver}"}, licences))
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "argus", "version": version,
                                       "licenses": [{"license": {"id": "PolyForm-Noncommercial-1.0.0",
                                                                 "name": "PolyForm Noncommercial License 1.0.0"}}],
                                       "properties": [{"name": "commit", "value": commit}]}},
            "components": comps}


def report(manifest, previous):
    lines = [f"## Argus {manifest['version']}", "",
             f"Tag `{manifest['tag']}`, commit `{manifest['commit']}`, built by {manifest['run_url']}.", "",
             "| artifact | size | files | previous |", "|---|---:|---:|---:|"]
    prev_counts = previous.get("member_counts") or {}
    for name, meta in manifest["files"].items():
        key = re.sub(r"_\d[\w.]*?_", "_*_", name)
        before = prev_counts.get(key, prev_counts.get(name, "new"))
        lines.append(f"| {name} | {meta['bytes'] / 1e6:.1f} MB | {manifest['member_counts'].get(name, '?')} | {before} |")
    gone = sorted(set(re.sub(r"_\d[\w.]*?_", "_*_", n) for n in (previous.get("files") or {}))
                  - set(re.sub(r"_\d[\w.]*?_", "_*_", n) for n in manifest["files"]))
    if gone:
        lines += ["", "No longer published: " + ", ".join(gone)]
    lines += ["", f"Content policy SHA-256 `{manifest['policy_sha256'][:16]}`; every file passed the gate."]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--builds", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--run-url", default="")
    ap.add_argument("--previous", default="")
    ap.add_argument("--proposal", action="append", default=[], help="dry run only: an additive policy proposal")
    args = ap.parse_args()
    builds, out = Path(args.builds), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    for rec_path in sorted(builds.rglob("*-build.json")):
        rec = json.loads(rec_path.read_text())
        if not args.commit.startswith(rec["commit"]) and not rec["commit"].startswith(args.commit[:12]):
            sys.exit(f"{rec_path.name} was built from {rec['commit']}, not {args.commit}")
        if rec["version"] != args.version:
            sys.exit(f"{rec_path.name} is version {rec['version']}, not {args.version}")
        for name, meta in rec["files"].items():
            if name in INTERNAL_INPUTS:
                continue
            src = rec_path.parent / name
            if hashlib.sha256(src.read_bytes()).hexdigest() != meta["sha256"]:
                sys.exit(f"{name} changed after its build recorded it")
            shutil.copyfile(src, out / name)
            files[name] = meta
    if not files:
        sys.exit("no build records found")
    policy = gate.load_policy(proposals=args.proposal)
    for line in policy["_proposals"]:
        print("PROPOSAL ACTIVE (dry run only): " + line)
    counts = {}
    for name in files:
        problems, counts[name] = gate.check_artifact(out / name, gate.rule_for(name, policy), policy)
    manifest = {"version": args.version, "tag": args.tag, "commit": args.commit, "run_url": args.run_url,
                "policy_sha256": gate.sha256(gate.POLICY), "member_counts": counts, "files": files}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    sums = "".join(f"{v['sha256']}  {k}\n" for k, v in files.items())
    (out / "SHA256SUMS").write_text(sums)
    (out / "SHA256SUMS.txt").write_text(sums)
    previous = load_previous(args.previous)
    (out / "release-report.md").write_text(report(manifest, previous))
    (out / "sbom.cdx.json").write_text(json.dumps(sbom(args.version, args.commit), indent=2) + "\n")
    for name in ("LICENSE.txt", "THIRD-PARTY-NOTICES.txt"):
        shutil.copyfile(REPO / name, out / name)
    prev_path = None
    if previous:
        prev_path = out.parent / "previous-manifest.json"
        prev_path.write_text(json.dumps(previous))
    problems, _ = gate.check_release(out, policy, prev_path)
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        sys.exit(f"the release fails the content gate ({len(problems)} problems)")
    print(f"release {args.version} assembled and gated: {', '.join(files)}")


if __name__ == "__main__":
    main()

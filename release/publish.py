#!/usr/bin/env python3
"""Publish a signed release to the site, then read the live site back.

    python3 release/publish.py --release DIR --site SITE_CHECKOUT --tag T [--rollback]
    python3 release/publish.py --readback --version V [--timeout 1200]

Run by .github/workflows/publish.yml when a releaser publishes a signed draft.
Before anything changes, release/check.py must pass over DIR (content gate and
a pinned releaser's signature). Then, in the site checkout:

  * public/downloads/argus/ is replaced by exactly the release's files, so a
    withdrawn download disappears with the next release;
  * scripts/argus/release-gate/ receives this commit's gate, policy and
    signature check, which the site's deploy job runs over the downloads;
  * one commit, limited to those two paths, is pushed to master, which the
    site's own workflow deploys after running that check.

--readback waits until www.archymedes.xyz serves this version, downloads every
published file and runs the same check over what the public now gets.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import gate  # noqa: E402
import signers  # noqa: E402
import versioning  # noqa: E402

LIVE = os.environ.get("ARGUS_LIVE_BASE", "https://www.archymedes.xyz/downloads/argus/")
DOWNLOADS = Path("public/downloads/argus")
GATE_DIR = Path("scripts/argus/release-gate")
UA = {"User-Agent": "argus-release-readback"}


def pinned():
    found = signers.pinned_from(os.environ.get("ARGUS_RELEASE_SIGNERS", ""))
    if not found:
        sys.exit("ARGUS_RELEASE_SIGNERS is not set: an admin pins the releasers' key fingerprints first")
    return found


def git(site, *args):
    return subprocess.run(["git", "-C", str(site), *args], check=True, capture_output=True, text=True).stdout


def live_version(site):
    """The version the site's master serves now: its published manifest."""
    try:
        return json.loads((site / DOWNLOADS / "manifest.json").read_text()).get("version") or ""
    except FileNotFoundError:
        return ""
    except ValueError:
        sys.exit("the site's current manifest.json is not valid JSON: refusing to publish over it")


def publish(release, site, tag, rollback=False):
    allowed = signers.ALLOWED.read_text()
    problems, _counts, signer = check.check(release, allowed, pinned())
    if problems:
        for p in problems:
            print("REFUSED  " + p)
        sys.exit("the release fails its check: the site was not changed")
    principal, fp = signer
    manifest = json.loads((release / "manifest.json").read_text())
    if manifest.get("tag") != tag:
        sys.exit(f"the manifest is for {manifest.get('tag')}, not {tag}")
    try:
        versioning.check_ordering(manifest["version"], live_version(site), rollback)
    except versioning.VersionError as exc:
        sys.exit(f"REFUSED  {exc}: the site was not changed")
    lines, _ = signers.trusted_lines(allowed, pinned())
    (release / "allowed_signers").write_text("\n".join(lines) + "\n")
    dest = site / DOWNLOADS
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    for f in sorted(release.iterdir()):
        if f.is_file() and (f.name in gate.META or gate.rule_for(f.name, gate.load_policy())):
            shutil.copyfile(f, dest / f.name)
    gd = site / GATE_DIR
    shutil.rmtree(gd, ignore_errors=True)
    gd.mkdir(parents=True)
    for name in ("gate.py", "policy.json", "signers.py", "check.py"):
        shutil.copyfile(HERE / name, gd / name)
    # The copy at the destination must pass too, exactly as the deploy job will run it.
    r = subprocess.run([sys.executable, str(gd / "check.py"), str(dest), "--allowed", str(dest / "allowed_signers"),
                        "--policy", str(gd / "policy.json")], capture_output=True, text=True,
                       env={**os.environ})
    print(r.stdout.strip())
    if r.returncode:
        sys.exit("the site copy fails its check: nothing was committed")
    git(site, "add", "-A", "--", str(DOWNLOADS), str(GATE_DIR))
    msg = (f"Argus {manifest['version']}: signed release of {manifest['commit'][:12]}\n\n"
           f"Tag {tag}, built by {manifest.get('run_url')}, signed by {principal} ({fp}).\n"
           f"Published by release/publish.py; only {DOWNLOADS} and {GATE_DIR} change.\n")
    # Committed as the releaser (the site checkout's own git identity): Vercel
    # blocks a deployment whose commit author has no Git account, which is what
    # happened to the 2026.11.03-0 publish committed as "argus-release".
    email = subprocess.run(["git", "-C", str(site), "config", "user.email"],
                           capture_output=True, text=True).stdout.strip()
    if not email:
        sys.exit("the site checkout has no git user.email: set it to your GitHub account's email")
    git(site, "commit", "-q", "-m", msg, "--", str(DOWNLOADS), str(GATE_DIR))
    git(site, "push", "-q", "origin", "HEAD:master")
    print(f"pushed {git(site, 'rev-parse', '--short', 'HEAD').strip()} to the site's master")


def fetch(name, dest):
    req = urllib.request.Request(LIVE + name + f"?t={int(time.time())}", headers=UA)
    with urllib.request.urlopen(req, timeout=300) as r:
        dest.write_bytes(r.read())


def readback(version, timeout):
    deadline = time.time() + timeout
    with tempfile.TemporaryDirectory(prefix="argus-readback-") as tmp:
        d = Path(tmp)
        while True:
            try:
                fetch("manifest.json", d / "manifest.json")
                if json.loads((d / "manifest.json").read_text()).get("version") == version:
                    break
            except (OSError, ValueError):
                pass
            if time.time() > deadline:
                sys.exit(f"the site still does not serve {version} after {timeout} s")
            time.sleep(20)
        manifest = json.loads((d / "manifest.json").read_text())
        for name in [*manifest["files"], "SHA256SUMS", "SHA256SUMS.txt", "SHA256SUMS.sig", "allowed_signers"]:
            fetch(name, d / name)
        problems, counts, signer = check.check(d, (d / "allowed_signers").read_text(), pinned())
        for p in problems:
            print("REFUSED  " + p)
        if problems:
            sys.exit("LIVE SITE FAILS ITS CHECK: roll back (docs/guides/RELEASING.md, 'Rolling back')")
        print(f"live readback: {version} served, {len(counts)} artifacts verified, signed by {signer[0]}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--release")
    ap.add_argument("--site")
    ap.add_argument("--tag")
    ap.add_argument("--rollback", action="store_true", help="allow an equal or older signed release")
    ap.add_argument("--readback", action="store_true")
    ap.add_argument("--version")
    ap.add_argument("--timeout", type=int, default=1200)
    args = ap.parse_args()
    if args.readback:
        readback(args.version, args.timeout)
    else:
        publish(Path(args.release), Path(args.site), args.tag, args.rollback)


if __name__ == "__main__":
    main()

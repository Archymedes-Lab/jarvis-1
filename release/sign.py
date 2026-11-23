#!/usr/bin/env python3
"""Sign an Argus release that CI built: run on a releaser's own machine.

    python3 release/sign.py v2026.11.01 [--key ~/.config/argus-release/signing_key]

1. Downloads the draft GitHub Release of that tag from Argus-1 (gh CLI,
   your own GitHub login) into a temporary folder.
2. Runs the content gate over exactly those files, and checks that they are
   the files CI recorded (manifest, SHA256SUMS, the run that built them).
3. Shows what you are about to sign: version, commit, every artifact with its
   size and file count, and the report's changes since the last release.
4. Asks you to type the version to confirm, then signs SHA256SUMS with your
   key (ssh-keygen asks for its passphrase), verifies the signature against
   release/allowed_signers, and uploads SHA256SUMS.sig to the draft.

Publishing is a separate, explicit step: `gh release edit <tag> --draft=false`
(or the Publish button), which starts the publish workflow.
Your private key never leaves this machine and is never passed to any tool
but ssh-keygen.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate  # noqa: E402
import signers  # noqa: E402

REPO = os.environ.get("ARGUS_RELEASE_REPO", "Archymedes-Lab/argus-1")
KEY = Path(os.environ.get("ARGUS_RELEASE_KEY", "~/.config/argus-release/signing_key")).expanduser()


def gh(*args, capture=True):
    return subprocess.run(["gh", *args], check=True, capture_output=capture, text=True).stdout


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tag")
    ap.add_argument("--key", default=str(KEY))
    args = ap.parse_args()
    key = Path(args.key).expanduser()
    if not key.is_file() or not Path(str(key) + ".pub").is_file():
        sys.exit(f"no signing key at {key}: see docs/guides/RELEASING.md, 'Adding a releaser'")
    login = gh("api", "user", "-q", ".login").strip()
    info = json.loads(gh("release", "view", args.tag, "-R", REPO, "--json", "isDraft,tagName,assets,url"))
    if not info["isDraft"]:
        sys.exit(f"{args.tag} is already published; sign drafts only")
    with tempfile.TemporaryDirectory(prefix="argus-sign-") as tmp:
        d = Path(tmp)
        gh("release", "download", args.tag, "-R", REPO, "-D", str(d), capture=False)
        for stale in d.glob("SHA256SUMS*.sig"):
            stale.unlink()
        policy = gate.load_policy()
        problems, counts = gate.check_release(d, policy)
        manifest = json.loads((d / "manifest.json").read_text())
        print(f"\nArgus {manifest['version']}  tag {manifest.get('tag')}  commit {manifest.get('commit')}")
        print(f"built by {manifest.get('run_url')}")
        for name, meta in manifest["files"].items():
            print(f"  {name:44s} {meta['bytes'] / 1e6:7.1f} MB  {counts.get(name, '?'):>5} files")
        report = d / "release-report.md"
        if report.exists():
            print("\n" + report.read_text()[:4000])
        if problems:
            for p in problems:
                print("REFUSED  " + p)
            sys.exit("the content gate refuses these files: nothing was signed")
        if manifest.get("tag") != args.tag:
            sys.exit(f"the manifest says tag {manifest.get('tag')}, not {args.tag}")
        typed = input(f"\nSign Argus {manifest['version']} as {login}? Type the version to confirm: ").strip()
        if typed != manifest["version"]:
            sys.exit("not confirmed: nothing was signed")
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", signers.NAMESPACE,
                        str(d / "SHA256SUMS")], check=True)
        pub = Path(str(key) + ".pub").read_text().split()
        pinned = {signers.fingerprint(f"{pub[0]} {pub[1]}")}
        principal, fp = signers.verify(d / "SHA256SUMS", d / "SHA256SUMS.sig",
                                       signers.ALLOWED.read_text(), pinned)
        if principal != login:
            sys.exit(f"your key is listed for {principal}, but gh is logged in as {login}; nothing was uploaded")
        gh("release", "upload", args.tag, str(d / "SHA256SUMS.sig"), "--clobber", "-R", REPO)
    print(f"\nsigned by {principal} ({fp}) and uploaded to {info['url']}")
    print(f"publish it when ready:  gh release edit {args.tag} --draft=false -R {REPO}")


if __name__ == "__main__":
    main()

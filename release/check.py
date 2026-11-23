#!/usr/bin/env python3
"""Check a release folder end to end: content gate plus signature.

    python3 release/check.py DIR [--allowed FILE] [--pinned "SHA256:..."] [--pinned-file FILE]

The single check every later stage runs: the publish job before it touches
the site, the site's deploy job over the downloads it is about to serve, the
publish job's readback of the live site, and the owner's live audit
(release/audit.py). Pinned fingerprints come from --pinned, --pinned-file or
the ARGUS_RELEASE_SIGNERS environment variable; with none, the check fails.
Exit 0 only when every file passes the gate and SHA256SUMS.sig is a valid
signature by one pinned releaser.
"""

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate  # noqa: E402
import signers  # noqa: E402


def check(folder, allowed_text, pinned, policy_path=gate.POLICY):
    folder = Path(folder)
    problems, counts = gate.check_release(folder, gate.load_policy(policy_path))
    signer = None
    try:
        signer = signers.verify(folder / "SHA256SUMS", folder / "SHA256SUMS.sig", allowed_text, pinned)
    except signers.SignatureError as exc:
        problems.append(f"signature: {exc}")
    return problems, counts, signer


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--allowed", default=str(signers.ALLOWED))
    ap.add_argument("--pinned", default=os.environ.get("ARGUS_RELEASE_SIGNERS", ""))
    ap.add_argument("--pinned-file")
    ap.add_argument("--policy", default=str(gate.POLICY))
    args = ap.parse_args()
    pinned = signers.pinned_from(args.pinned)
    if args.pinned_file:
        pinned |= signers.pinned_from(Path(args.pinned_file).expanduser().read_text())
    problems, counts, signer = check(args.folder, Path(args.allowed).read_text(), pinned, args.policy)
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        print(f"check: FAILED ({len(problems)} problems)")
        sys.exit(1)
    print(f"check: PASSED ({len(counts)} artifacts, {sum(counts.values())} files; signed by {signer[0]} {signer[1]})")


if __name__ == "__main__":
    main()

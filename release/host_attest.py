#!/usr/bin/env python3
"""A releaser-signed record that the host-bound tests passed on the right host.

    python3 release/host_attest.py make        run them here (WSL2) and write release/host-attestation.json
    python3 release/host_attest.py check       verify the attestation for the checked-out commit

`make` refuses a tree with uncommitted changes under the code paths, runs
`scripts/dev/ci_suite.py --host`, and records the commit, the exact list of
tests it ran and the result. The releaser then signs that file with the same
offline key they sign releases with:

    ssh-keygen -Y sign -f ~/.config/argus-release/signing_key -n argus-release release/host-attestation.json

`check` (run by release.yml before a tagged release builds anything) requires:
a valid signature by a pinned releaser (release/signers.py); a passing result
with no failures covering exactly the tests now listed in tests/host-bound.txt;
and that nothing under the code paths changed between the attested commit and
this one. CI cannot run these tests, so without this a release could ship code
whose host-bound tests nobody ran.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import signers  # noqa: E402

ATTEST = Path("release/host-attestation.json")
CODE_PATHS = ["jarvis", "tests", "desktop", "release", "scripts/dev", "windows-sensor", "windows-sysmon"]
EXCLUDE = [f":(exclude){ATTEST}", f":(exclude){ATTEST}.sig"]
ENVIRONMENT = "wsl2-windows-interop"


def git(root, *args, check=True):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=check)


def listed_tests(root):
    text = (Path(root) / "tests" / "host-bound.txt").read_text()
    return sorted(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def sha(root):
    return hashlib.sha256("\n".join(listed_tests(root)).encode()).hexdigest()


def make(root):
    root = Path(root)
    dirty = git(root, "status", "--porcelain", "--", *CODE_PATHS, *EXCLUDE).stdout.strip()
    if dirty:
        sys.exit("uncommitted changes under the code paths: commit first, so the result names a real commit\n" + dirty)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "result.json"
        r = subprocess.run([sys.executable, str(root / "scripts/dev/ci_suite.py"), "--host", "--json", str(out)])
        if not out.exists():
            sys.exit(f"the host-bound tests did not run (exit {r.returncode}): no attestation written")
        result = json.loads(out.read_text())
    record = {"schema": 1, "environment": ENVIRONMENT, "commit": git(root, "rev-parse", "HEAD").stdout.strip(),
              "host_bound_sha256": sha(root), "result": result}
    (root / ATTEST).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote {ATTEST}: {result['ran']} tests, {len(result['failed'])} failed. "
          "Sign it with the ssh-keygen command in this script's docstring.")
    return 0 if not result["failed"] else 1


def check(root, allowed_text, pinned):
    """List of problems; empty means the attestation is valid for HEAD."""
    root = Path(root)
    path = root / ATTEST
    problems = []
    if not path.is_file():
        return [f"{ATTEST} is missing: run release/host_attest.py make on the WSL2 host and sign it"]
    try:
        who = signers.verify(path, Path(str(path) + ".sig"), allowed_text, pinned)
    except signers.SignatureError as exc:
        return [f"host attestation signature: {exc}"]
    try:
        rec = json.loads(path.read_text())
        res = rec["result"]
    except (ValueError, KeyError):
        return ["host attestation is malformed"]
    if rec.get("environment") != ENVIRONMENT or res.get("environment") != ENVIRONMENT:
        problems.append("host attestation is for a different environment")
    if res.get("failed") or res.get("ran") != len(res.get("tests", [])) or res.get("ran", 0) < 1:
        problems.append(f"host attestation records failures or an incomplete run ({res.get('failed')})")
    if sorted(res.get("tests", [])) != listed_tests(root) or rec.get("host_bound_sha256") != sha(root):
        problems.append("host attestation does not cover exactly the tests in tests/host-bound.txt: re-run it")
    commit = rec.get("commit", "")
    if git(root, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode != 0:
        problems.append("attested commit is not in this repository")
    elif git(root, "merge-base", "--is-ancestor", commit, "HEAD", check=False).returncode != 0:
        problems.append("attested commit is not an ancestor of this commit")
    else:
        changed = git(root, "diff", "--name-only", commit, "HEAD", "--", *CODE_PATHS, *EXCLUDE).stdout.split()
        if changed:
            problems.append(f"{len(changed)} file(s) changed since the attested commit (e.g. {changed[0]}): re-run the host tests")
    if not problems:
        print(f"host attestation OK: {res['ran']} tests passed on {ENVIRONMENT} at {commit[:12]}, signed by {who[0]}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("action", choices=["make", "check"])
    ap.add_argument("--allowed", default=str(signers.ALLOWED))
    ap.add_argument("--pinned", default=os.environ.get("ARGUS_RELEASE_SIGNERS", ""))
    args = ap.parse_args()
    if args.action == "make":
        sys.exit(make(ROOT))
    problems = check(ROOT, Path(args.allowed).read_text(), signers.pinned_from(args.pinned))
    for p in problems:
        print("REFUSED  " + p)
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()

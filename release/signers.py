"""Who may sign an Argus release, and checking a release's signature.

A release is signed by one allowed releaser: any one of them is enough. Each
releaser holds their own ed25519 SSH key, offline and passphrase-protected,
and signs SHA256SUMS with `ssh-keygen -Y sign -n argus-release` (release/sign.py
does it). The signature file is SHA256SUMS.sig.

Trust comes from two places that must agree:

  * release/allowed_signers (in the repository): each releaser's public key,
    under their GitHub login, in ssh-keygen's allowed-signers format;
  * the fingerprints pinned outside the repository: the ARGUS_RELEASE_SIGNERS
    variable (admin-only in GitHub settings; a push cannot change it) in CI,
    and ~/.config/argus-release/trusted_signers on the owner's machine for the
    live audit.

A key in the file but not pinned does not count: a push that adds a key to
allowed_signers cannot make that key a releaser.
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path

NAMESPACE = "argus-release"
HERE = Path(__file__).resolve().parent
ALLOWED = HERE / "allowed_signers"
FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


class SignatureError(Exception):
    pass


def pinned_from(text):
    """Fingerprints from a variable or file: any SHA256:... tokens in it."""
    return set(FP.findall(text or ""))


def fingerprint(key_line):
    """SHA256 fingerprint of one public key ("ssh-ed25519 AAAA...")."""
    with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as fh:
        fh.write(key_line.strip() + "\n")
        name = fh.name
    try:
        r = subprocess.run(["ssh-keygen", "-lf", name], capture_output=True, text=True)
    finally:
        os.unlink(name)
    found = FP.findall(r.stdout)
    return found[0] if r.returncode == 0 and found else None


def parse_allowed(text):
    """[(principal, key_type, key_b64)] of the ed25519 lines in allowed_signers."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        keys = [i for i, p in enumerate(parts) if p == "ssh-ed25519"]
        if not keys or keys[0] + 1 >= len(parts):
            continue
        i = keys[0]
        if f'namespaces="{NAMESPACE}"' not in parts[1:i]:
            continue
        out.append((parts[0], parts[i], parts[i + 1]))
    return out


def trusted_lines(allowed_text, pinned):
    """allowed_signers lines whose key fingerprint is pinned, and their owners."""
    lines, owners = [], {}
    for principal, ktype, key in parse_allowed(allowed_text):
        fp = fingerprint(f"{ktype} {key}")
        if fp and fp in pinned:
            lines.append(f'{principal} namespaces="{NAMESPACE}" {ktype} {key}')
            owners[principal] = fp
    return lines, owners


def verify(sums_path, sig_path, allowed_text, pinned):
    """The principal (GitHub login) whose pinned key signed sums_path.

    Raises SignatureError when the signature is missing, malformed, made by a
    key that is not both listed and pinned, or does not cover these bytes."""
    if not pinned:
        raise SignatureError("no pinned signer fingerprints: set ARGUS_RELEASE_SIGNERS")
    if not Path(sig_path).is_file():
        raise SignatureError(f"{Path(sig_path).name} is missing")
    lines, owners = trusted_lines(allowed_text, pinned)
    if not lines:
        raise SignatureError("no key in allowed_signers matches a pinned fingerprint")
    with tempfile.TemporaryDirectory() as tmp:
        signers = Path(tmp) / "allowed"
        signers.write_text("\n".join(lines) + "\n")
        found = subprocess.run(["ssh-keygen", "-Y", "find-principals", "-f", str(signers),
                                "-s", str(sig_path)], capture_output=True, text=True)
        principals = [p for p in found.stdout.split() if p in owners]
        if found.returncode != 0 or len(principals) != 1:
            raise SignatureError("the signature was not made by a pinned releaser key")
        principal = principals[0]
        with open(sums_path, "rb") as fh:
            r = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", principal,
                                "-n", NAMESPACE, "-s", str(sig_path)], stdin=fh, capture_output=True, text=True)
        if r.returncode != 0:
            raise SignatureError(f"the signature does not verify: {(r.stdout + r.stderr).strip()[-200:]}")
    return principal, owners[principal]

"""Verify an `ssh-keygen -Y sign` signature against keys pinned in code.

The same mechanism release/signers.py uses for program releases (ed25519 SSH
signatures, one namespace per purpose), shaped for the daemon: the trust root is
a tuple of allowed-signers lines shipped inside the signed program, not a file
anyone can edit. release/ is not part of the installed package, so this module
carries its own copy of the verification steps; tests/test_rulepack.py holds it
to the same behaviour with throwaway keys made at test time.

Invariants:
    S1  only a key listed in `allowed` can verify, and only for `namespace`
        (a release signature never verifies as a rule-pack signature)
    S2  any failure (no ssh-keygen, timeout, malformed input, wrong key, wrong
        bytes) raises SignatureError; there is no "unknown, accept" path
    S3  bounded: inputs are size-capped and every subprocess has a deadline;
        no shell, no secret ever on a command line
"""

import os
import re
import shutil
import subprocess
import tempfile

KEY_LINE = re.compile(r"^([A-Za-z0-9_.@-]{1,64}) (ssh-ed25519) ([A-Za-z0-9+/]{68})$")
FP = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
MAX_SIGNATURE = 4096
TIMEOUT_S = 10.0


class SignatureError(Exception):
    pass


def parse_allowed(lines):
    """[(principal, key type, base64 key)] of well-formed ed25519 lines; others raise."""
    out = []
    for line in lines:
        m = KEY_LINE.match(line.strip())
        if not m:
            raise SignatureError("a pinned signer line is not `<principal> ssh-ed25519 <key>`")
        out.append(m.groups())
    return out


def fingerprint(key_line):
    """SHA256 fingerprint of one public key ("ssh-ed25519 AAAA..."), or None."""
    tool = shutil.which("ssh-keygen")
    if not tool:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "k.pub")
        with open(p, "w") as fh:
            fh.write(key_line.strip() + "\n")
        try:
            r = subprocess.run([tool, "-lf", p], capture_output=True, text=True, errors="replace",
                               timeout=TIMEOUT_S)
        except (OSError, subprocess.SubprocessError):
            return None
    found = FP.findall(r.stdout)
    return found[0] if r.returncode == 0 and found else None


def verify(data, signature, allowed, namespace):
    """(principal, fingerprint) of the pinned key that signed `data` (bytes).

    `signature` is the armored text `ssh-keygen -Y sign` writes; `allowed` is a
    sequence of `<principal> ssh-ed25519 <key>` lines. Raises SignatureError."""
    if not allowed:
        raise SignatureError("no pinned signer keys: built-in content only")
    if not isinstance(signature, str) or len(signature) > MAX_SIGNATURE \
            or "BEGIN SSH SIGNATURE" not in signature:
        raise SignatureError("the signature is missing or malformed")
    if not re.fullmatch(r"[a-z0-9-]{1,32}", namespace):
        raise SignatureError("bad namespace")
    tool = shutil.which("ssh-keygen")
    if not tool:
        raise SignatureError("ssh-keygen is not installed: signatures cannot be checked")
    keys = parse_allowed(allowed)
    principals = {p for p, _t, _k in keys}
    with tempfile.TemporaryDirectory() as tmp:
        signers = os.path.join(tmp, "allowed")
        with open(signers, "w") as fh:
            for p, t, k in keys:
                fh.write(f'{p} namespaces="{namespace}" {t} {k}\n')
        sig = os.path.join(tmp, "data.sig")
        with open(sig, "w") as fh:
            fh.write(signature)
        try:
            found = subprocess.run([tool, "-Y", "find-principals", "-f", signers, "-s", sig],
                                   capture_output=True, text=True, errors="replace",
                                   timeout=TIMEOUT_S)
            who = [p for p in found.stdout.split() if p in principals]
            if found.returncode != 0 or len(who) != 1:
                raise SignatureError("the signature was not made by a pinned key")
            r = subprocess.run([tool, "-Y", "verify", "-f", signers, "-I", who[0], "-n", namespace,
                                "-s", sig], input=data, capture_output=True, timeout=TIMEOUT_S)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SignatureError(f"signature check could not run: {type(exc).__name__}") from None
        if r.returncode != 0:
            raise SignatureError("the signature does not verify for these bytes and this namespace")
        m = FP.search(r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace"))
    return who[0], (m.group(0) if m else "")

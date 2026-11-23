#!/usr/bin/env python3
"""Download a guest base image for the clean-machine matrix and verify it before use.

    python3 release/vmtest/fetch_image.py debian-12
    python3 release/vmtest/fetch_image.py ubuntu-24.04 --check   # verify what is there

Invariants (tests/test_vmtest.py):
- Fail closed: the image is written as <file>.part, hashed against the checksum list and
  only then renamed; any mismatch, missing entry or download error deletes the part file.
- Signed lists are trusted only when gpg reports VALIDSIG by a fingerprint pinned here,
  in a lab-only keyring (ROOT/gnupg), never the user's keyring.
- Debian publishes no signature for its cloud image lists: those images are fetched from
  a fixed dated directory over HTTPS and recorded as trust "https-only", which every run
  result repeats. Nothing is upgraded to "signature" without a verified signature.
- Bounded: HTTPS only, a size cap per file, a timeout per request.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from jarvis.lab import vmlab  # noqa: E402

MAX_IMAGE_BYTES = 2 * 1024 ** 3
MAX_LIST_BYTES = 1024 * 1024
TIMEOUT_S = 60
KEYSERVER = "hkps://keyserver.ubuntu.com"
# Ubuntu Cloud Image Builder (Canonical Internal Cloud Image Builder). Observed as the
# signer of the noble SHA256SUMS.gpg already in the lab on 2026-11-02.
UBUNTU_CLOUD_KEY = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"


@dataclass(frozen=True)
class Source:
    base: str                 # directory URL, ends with /
    sig: str | None           # detached signature of the list, or None (https-only)
    pinned: tuple = ()


SOURCES = {
    "ubuntu-24.04": Source("https://cloud-images.ubuntu.com/releases/noble/release/", "SHA256SUMS.gpg",
                           (UBUNTU_CLOUD_KEY,)),
    "ubuntu-22.04": Source("https://cloud-images.ubuntu.com/releases/jammy/release/", "SHA256SUMS.gpg",
                           (UBUNTU_CLOUD_KEY,)),
    # Fixed dated build, so the digest cannot move under a run. No signature is published.
    "debian-12": Source("https://cloud.debian.org/images/cloud/bookworm/20261026-2643/", None),
}


class FetchError(Exception):
    pass


def trust_path(root, img):
    return Path(root) / "images" / (Path(img.sums).parent / "TRUST.json")


def read_trust(root, key):
    """{'trust': 'signature'|'https-only', ...} recorded at download, or {'trust': 'unknown'}."""
    img = vmlab.IMAGES[key]
    try:
        return json.loads(trust_path(root, img).read_text())
    except (OSError, ValueError):
        return {"trust": "unknown"}


def _get(url, dest, cap, opener=urllib.request.urlopen):
    if not url.startswith("https://"):
        raise FetchError(f"refusing a non-HTTPS URL: {url}")
    n = 0
    try:
        with opener(url, timeout=TIMEOUT_S) as r, open(dest, "wb") as out:
            while True:
                block = r.read(1 << 20)
                if not block:
                    break
                n += len(block)
                if n > cap:
                    raise FetchError(f"{url} is larger than {cap} bytes")
                out.write(block)
    except (OSError, ValueError) as exc:
        raise FetchError(f"download failed for {url}: {type(exc).__name__}") from exc


def valid_signer(status_text, pinned):
    """The pinned primary fingerprint from gpg --status-fd output, or None. Pure.

    VALIDSIG's last field is the primary key fingerprint; a good signature by any key
    that is not pinned, or a status without VALIDSIG, is not trusted."""
    pins = {p.upper() for p in pinned}
    for line in status_text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            primary = parts[-1].upper()
            if primary in pins:
                return primary
    return None


def verify_signature(root, sums, sig, pinned, run=subprocess.run):
    home = Path(root) / "gnupg"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {**os.environ, "GNUPGHOME": str(home)}
    for fpr in pinned:
        have = run(["gpg", "--batch", "--list-keys", fpr], env=env, capture_output=True)
        if have.returncode != 0:
            got = run(["gpg", "--batch", "--keyserver", KEYSERVER, "--recv-keys", fpr], env=env,
                      capture_output=True, timeout=120)
            if got.returncode != 0:
                raise FetchError(f"could not fetch pinned key {fpr}")
    r = run(["gpg", "--batch", "--status-fd", "1", "--verify", str(sig), str(sums)], env=env,
            capture_output=True, text=True, timeout=120)
    signer = valid_signer(r.stdout, pinned)
    if r.returncode != 0 or not signer:
        raise FetchError("the checksum list is not signed by a pinned key")
    return signer


def digest_of(sums_text, name):
    for line in sums_text.splitlines():
        digest, _, fname = line.partition(" ")
        if fname.strip().lstrip("*") == name:
            return digest.strip().lower()
    return None


def fetch(key, root=vmlab.ROOT, opener=urllib.request.urlopen, run=subprocess.run, force=False):
    if key not in vmlab.IMAGES or key not in SOURCES:
        raise FetchError(f"unknown image {key!r}")
    img, src = vmlab.IMAGES[key], SOURCES[key]
    images = Path(root) / "images"
    target = images / img.file
    sums = images / img.sums
    if target.exists() and not force:
        raise FetchError(f"{target} exists; use --check to verify it or --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    name = Path(img.file).name
    list_part = sums.with_name(sums.name + ".part")
    part = target.with_name(target.name + ".part")
    sig_path = None
    try:
        _get(src.base + Path(img.sums).name, list_part, MAX_LIST_BYTES, opener)
        if src.sig:
            sig_path = sums.with_name(src.sig)
            _get(src.base + src.sig, sig_path, MAX_LIST_BYTES, opener)
            signer = verify_signature(root, list_part, sig_path, src.pinned, run)
            trust = {"trust": "signature", "signer": signer}
        else:
            trust = {"trust": "https-only", "source": src.base,
                     "note": "the publisher signs no checksum list for this image"}
        want = digest_of(list_part.read_text(), name)
        if not want:
            raise FetchError(f"{name} is not in the checksum list")
        _get(src.base + name, part, MAX_IMAGE_BYTES, opener)
        if vmlab._hex(part, algo=img.algo) != want:
            raise FetchError(f"{name} does not match its {img.algo} checksum")
        os.replace(list_part, sums)
        os.replace(part, target)
        trust_path(root, img).write_text(json.dumps({**trust, "file": img.file}, indent=1))
        return trust
    finally:
        for p in (part, list_part):
            p.unlink(missing_ok=True)


def check(key, root=vmlab.ROOT, run=subprocess.run):
    """Re-verify an image in place: hash against the list, and the list's signature if any."""
    img, src = vmlab.IMAGES[key], SOURCES[key]
    cfg = vmlab.Config(root=Path(root), image=key)
    out = {"image": key, "hash_ok": vmlab.verify_base_image(cfg), **read_trust(root, key)}
    sig = Path(root) / "images" / Path(img.sums).parent / src.sig if src.sig else None
    if sig is not None and sig.exists():
        try:
            out["signer"] = verify_signature(root, Path(root) / "images" / img.sums, sig, src.pinned, run)
            out["trust"] = "signature"
            if out["hash_ok"]:      # record only a fully verified image
                trust_path(root, img).write_text(json.dumps(
                    {"trust": "signature", "signer": out["signer"], "file": img.file}, indent=1))
        except FetchError as exc:
            out["signature_error"] = str(exc)
            out["trust"] = "unverified"
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image", choices=sorted(SOURCES))
    ap.add_argument("--check", action="store_true", help="verify the image already in the lab")
    ap.add_argument("--force", action="store_true", help="replace an existing image")
    args = ap.parse_args()
    try:
        print(json.dumps(check(args.image) if args.check else fetch(args.image, force=args.force), indent=1))
    except FetchError as exc:
        sys.exit(f"not fetched: {exc}")


if __name__ == "__main__":
    main()

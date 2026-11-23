#!/usr/bin/env python3
"""Release consistency checks: the manifest, the checksums and the download URLs.

    python release/verify_release.py FOLDER [--version V] [--base URL]

FOLDER is an assembled release (assemble.py output) or the site's downloads
folder. Exits non-zero, listing every problem, unless:

  * manifest.json lists exactly the artifacts present (none missing, none extra),
    each with the recorded size and SHA-256;
  * SHA256SUMS and SHA256SUMS.txt list exactly the same files and digests as the manifest;
  * every artifact whose name carries a version carries the manifest's version, and
    the installer is among them (a release without it is not a Windows release);
  * with --base URL: every artifact URL under it answers 200 and serves bytes with
    the manifest's SHA-256 (the page a customer clicks reaches the file we built).

Standard library only, so CI, the releaser's machine and the site deploy run the same code.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    # A refusal must print, not crash on a cp1252 console. Some runners replace the
    # stream with one that cannot be reconfigured (unittest buffering), so ask first.
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(errors="replace")

NOT_ARTIFACTS = {"manifest.json", "SHA256SUMS", "SHA256SUMS.txt", "SHA256SUMS.sig", "allowed_signers",
                 "release-report.md", "sbom.cdx.json"}
REQUIRED = ("Argus-Setup.exe", "argus-server-linux-x86_64.tar.gz")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_sums(text):
    out = {}
    for line in text.splitlines():
        if line.strip():
            digest, _, name = line.partition("  ")
            out[name.strip()] = digest.strip()
    return out


def check_folder(folder, version=None, required=REQUIRED):
    folder = Path(folder)
    problems = []
    try:
        manifest = json.loads((folder / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        return [f"manifest.json is unreadable: {exc}"]
    files = manifest.get("files") or {}
    present = {p.name for p in folder.iterdir() if p.is_file()} - NOT_ARTIFACTS
    for name in sorted(set(files) - present):
        problems.append(f"{name} is in the manifest but not in the folder")
    for name in sorted(present - set(files)):
        problems.append(f"{name} is in the folder but not in the manifest")
    for name, meta in sorted(files.items()):
        path = folder / name
        if not path.is_file():
            continue
        if path.stat().st_size != meta.get("bytes"):
            problems.append(f"{name}: size {path.stat().st_size} differs from the manifest's {meta.get('bytes')}")
        if sha256_file(path) != meta.get("sha256"):
            problems.append(f"{name}: SHA-256 differs from the manifest")
    for sums_name in ("SHA256SUMS", "SHA256SUMS.txt"):
        try:
            sums = parse_sums((folder / sums_name).read_text())
        except OSError:
            problems.append(f"{sums_name} is missing")
            continue
        want = {n: m.get("sha256") for n, m in files.items()}
        if sums != want:
            problems.append(f"{sums_name} does not list exactly the manifest's files and digests")
    want_version = version or manifest.get("version")
    if version and manifest.get("version") != version:
        problems.append(f"manifest version {manifest.get('version')} is not {version}")
    for name in files:
        m = re.search(r"_(\d[\w.]*?)_", name)
        if m and want_version and m.group(1) != str(want_version).replace("-", "."):
            problems.append(f"{name} carries version {m.group(1)}, not {want_version}")
    for req in required:
        if req not in files:
            problems.append(f"the release has no {req}")
    return problems


def check_urls(folder, base, opener=None):
    """Every artifact URL under `base` answers and serves the manifest's bytes."""
    manifest = json.loads((Path(folder) / "manifest.json").read_text())
    base = base.rstrip("/") + "/"
    opener = opener or urllib.request.build_opener()
    problems = []
    for name, meta in sorted((manifest.get("files") or {}).items()):
        url = base + name
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "argus-release-check"})
            h = hashlib.sha256()
            with opener.open(req, timeout=120) as r:
                if r.status != 200:
                    problems.append(f"{url} answered HTTP {r.status}")
                    continue
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != meta.get("sha256"):
                problems.append(f"{url} serves different bytes than the manifest's {name}")
        except urllib.error.HTTPError as exc:
            problems.append(f"{url} answered HTTP {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            problems.append(f"{url} is unreachable ({exc})")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("folder")
    ap.add_argument("--version")
    ap.add_argument("--base", help="downloads URL to resolve every artifact against")
    args = ap.parse_args()
    problems = check_folder(args.folder, args.version)
    if args.base:
        problems += check_urls(args.folder, args.base)
    for p in problems:
        print("REFUSED  " + p)
    if problems:
        sys.exit(f"the release is inconsistent ({len(problems)} problems)")
    print("manifest, checksums" + (" and download URLs" if args.base else "") + " agree with the artifacts")


if __name__ == "__main__":
    main()

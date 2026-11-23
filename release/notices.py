#!/usr/bin/env python3
"""THIRD-PARTY-NOTICES.txt: every third-party component built into an Argus release.

    python3 release/notices.py refresh   # dev only: cargo metadata + SPDX texts (network)
    python3 release/notices.py render    # writes THIRD-PARTY-NOTICES.txt from the snapshot
    python3 release/notices.py check     # exit 1 unless the committed file is current

ARGUS-1 itself is PolyForm-Noncommercial-1.0.0 (LICENSE.txt; LICENSING.md). What it ships also contains other
people's code, whose licences require their notices to travel with it (MIT and
BSD: the copyright line and licence text; Apache-2.0: the licence; MPL-2.0:
where the source of those files is). This file is the record, shipped in every
artifact. release/third_party.json is the reviewed snapshot it is rendered from:

  native   the CPython runtime and the native libraries the server build
           bundles (read from the published server tarball 2026-11-02)
  python   the pinned runtime packages (release/requirements-runtime.txt)
  web      vendored dashboard assets
  cargo    the desktop app's crates (desktop/Cargo.lock), from cargo metadata

tests/test_licensing.py fails when a pinned package or a locked crate has no
entry, when an entry carries a licence that is not on ALLOWED, or when the
committed THIRD-PARTY-NOTICES.txt differs from what render() produces.
"""

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SNAPSHOT = HERE / "third_party.json"
TEXTS = HERE / "licences"
OUT = REPO / "THIRD-PARTY-NOTICES.txt"

# Reviewed dependency licenses retained during source publication preparation. For an
# "A OR B" expression the first permitted alternative is the one Archymedes takes.
PREFERENCE = ("MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "Zlib", "0BSD",
              "MIT-0", "Unlicense", "CC0-1.0", "BSL-1.0", "Unicode-3.0", "PSF-2.0",
              "OFL-1.1", "MPL-2.0", "OpenSSL", "bzip2-1.0.6", "blessing", "X11",
              # AGPL-3.0 compiler whose runtime exception lets proprietary output use it
              # (verified 2026-11-02 in Nuitka's LICENSE-RUNTIME.txt).
              "Nuitka-Runtime-Exception", "LicenseRef-Public-Domain",
              # Detection Rule License 1.1: permissive for rule content; every alert built
              # from a rule names its author (enforced in jarvis/core/sigma.py).
              "DRL-1.1")
ALLOWED = frozenset(PREFERENCE)
# Additional copyleft dependencies require a separate compatibility/source review.
FORBIDDEN = re.compile(r"\b(A?GPL|LGPL|SSPL|BUSL|CC-BY-NC|Commons-Clause)\b", re.I)
MAX_PROJECT_NOTICE_BYTES = 64 * 1024


def project_notices(path=None):
    """Required project notices also travel in the existing packaged notice file."""
    path = path if path is not None else REPO / "NOTICE"
    with path.open("rb") as source:
        raw = source.read(MAX_PROJECT_NOTICE_BYTES + 1)
    if len(raw) > MAX_PROJECT_NOTICE_BYTES:
        raise ValueError("project notice exceeds byte budget")
    lines = [line for line in raw.decode("utf-8").splitlines()
             if line.startswith("Required Notice:")]
    if not lines or any(not line[len("Required Notice:"):].strip() for line in lines):
        raise ValueError("project Required Notices missing or empty")
    return lines


def choose(expression):
    """The licence Archymedes takes for an SPDX expression, or None."""
    expr = expression.replace("/", " OR ").strip()
    for alternative in re.split(r"\s+OR\s+", expr):
        parts = [p.strip(" ()") for p in re.split(r"\s+AND\s+", alternative.strip(" ()"))]
        parts = [p.replace(" WITH LLVM-exception", "") for p in parts]
        if parts and all(p in ALLOWED for p in parts):
            return " AND ".join(parts)
    return None


def load():
    return json.loads(SNAPSHOT.read_text())


def entries(snapshot):
    """(section, name, version, chosen licence, copyright, source) for every component."""
    out = []
    for section in ("native", "python", "web", "cargo", "content"):
        for c in snapshot.get(section, []):
            out.append((section, c["name"], c.get("version", ""), choose(c["license"]) or "",
                        c.get("copyright", ""), c.get("source", "")))
    return out


def render(snapshot=None, texts=TEXTS):
    snapshot = snapshot or load()
    rows = entries(snapshot)
    head = [
        "THIRD-PARTY NOTICES FOR ARGUS-1",
        "",
        *project_notices(),
        "",
        "ARGUS-1 is licensed under PolyForm-Noncommercial-1.0.0 (see LICENSE.txt and LICENSING.md). It",
        "includes the third-party components below, each under its own licence, which",
        "is the licence that governs that component. Where a component is offered",
        "under a choice of licences, the licence named here is the one Archymedes uses.",
        "Source code for MPL-2.0 components is available at the source address listed.",
        "",
        "Generated by release/notices.py from release/third_party.json; do not edit.",
        "",
    ]
    by_licence = {}
    for section, name, version, lic, copyright_, source in rows:
        by_licence.setdefault(lic, []).append((section, name, version, copyright_, source))
    body = []
    for lic in sorted(by_licence):
        comps = sorted(by_licence[lic], key=lambda c: (c[1].lower(), c[2]))
        body += ["=" * 78, f"{lic} ({len(comps)} components)", "=" * 78, ""]
        for section, name, version, copyright_, source in comps:
            line = f"{name} {version}".strip()
            if copyright_:
                line += f" -- {copyright_}"
            body.append(line)
            if source:
                body.append(f"    source: {source}")
        body.append("")
        for part in lic.split(" AND "):
            path = texts / f"{part}.txt"
            if path.exists():
                body += [f"--- {part} licence text ---", path.read_text().rstrip(), ""]
    return "\n".join(head + body).rstrip() + "\n"


def refresh():
    """Rebuild the cargo section from cargo metadata and fetch licence texts (dev only)."""
    snapshot = load() if SNAPSHOT.exists() else {}
    meta = json.loads(subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"],
                                     cwd=REPO / "desktop", capture_output=True, text=True,
                                     check=True).stdout)
    lock = (REPO / "desktop" / "Cargo.lock").read_text()
    locked = set(re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', lock))
    crates = []
    for p in meta["packages"]:
        if (p["name"], p["version"]) not in locked or p["source"] is None:
            continue  # our own crate
        authors = ", ".join(a.split(" <")[0] for a in p.get("authors") or [])
        crates.append({"name": p["name"], "version": p["version"], "license": p.get("license") or "",
                       "copyright": f"Copyright (c) {authors}" if authors else "",
                       "source": p.get("repository") or ""})
    snapshot["cargo"] = sorted(crates, key=lambda c: (c["name"], c["version"]))
    SNAPSHOT.write_text(json.dumps(snapshot, indent=1, sort_keys=True) + "\n")
    TEXTS.mkdir(exist_ok=True)
    needed = {part for _s, _n, _v, lic, _c, _src in entries(snapshot) for part in lic.split(" AND ") if part}
    for spdx in sorted(needed):
        path = TEXTS / f"{spdx}.txt"
        if path.exists():
            continue
        url = f"https://raw.githubusercontent.com/spdx/license-list-data/main/text/{spdx}.txt"
        with urllib.request.urlopen(url, timeout=30) as r:
            path.write_bytes(r.read())


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "refresh":
        refresh()
        OUT.write_text(render())
    elif cmd == "render":
        OUT.write_text(render())
    elif cmd == "check":
        if not OUT.exists() or OUT.read_text() != render():
            sys.exit("THIRD-PARTY-NOTICES.txt is stale: run python3 release/notices.py render")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)

"""Writes windows-markers.json: the Windows marker change under review.

A script, not hand-written JSON, so the regular expression is written once, as a
Python raw string, instead of being escaped twice. Run it from the repo root:

    python release/proposals/make_windows_markers.py

The same values are what the staged policy change (branch
policy/windows-third-party-paths) puts into release/policy.json.

Two changes, and no more:

1. `windows-build-path` matches OUR runner path only. GitHub Actions uses D:\\a\\ for
   every project, so the old pattern also refused the Python project's, Microsoft's
   and PyCA's pipelines that are written into their signed binaries.
2. One digest-pinned exemption: cryptography's `_rust.pyd` carries its maintainers'
   CI home folder (C:\\Users\\runneradmin\\). `windows-home-path` is NOT loosened (a
   runner home folder is a leak: tests/test_release_gate.py pins that); the single
   file is exempted by SHA-256, so any other file, or this file changed, is refused.
"""

import json
from pathlib import Path

# This repository's runner checkout and a self-hosted runner; not other projects'.
BUILD_PATH = r"(?i)(?:[A-Z]:\\a\\Argus-1\\|[A-Z]:\\actions-runner\\)"

# SHA-256 of cryptography/hazmat/bindings/_rust.pyd in cryptography-50.0.2-cp311-abi3-win_amd64.whl,
# the wheel release/requirements-windows.txt pins by hash. Read from the wheel's own RECORD and
# checked equal to the file Nuitka copies into the install. Changes with every cryptography update.
RUST_PYD_SHA256 = "1d4332a447cab13dec8e3a533ad579e0e562b79e40822c931f33769758fc7156"

EXEMPTIONS = [{
    "member": "cryptography/hazmat/bindings/_rust.pyd",
    "marker": "windows-home-path",
    "sha256": RUST_PYD_SHA256,
    "reason": ("cryptography 50.0.2 (PyCA) wheel binary; carries its maintainers' CI home folder. "
               "Signed vendor file, cannot be rebuilt here. Re-pin on every cryptography update."),
}]

doc = {
    "_comment": ("PROPOSAL, not policy. See windows-third-party-paths.md. Only dry runs "
                 "(release-test/*) load this file; a tagged build never does. It may replace a "
                 "marker by id and add digest-pinned exemptions; it cannot add or remove a marker "
                 "or touch any other list."),
    "deny_markers": [{"id": "windows-build-path", "regex": BUILD_PATH}],
    "marker_exemptions": EXEMPTIONS,
}

if __name__ == "__main__":
    out = Path(__file__).with_name("windows-markers.json")
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print("wrote", out)

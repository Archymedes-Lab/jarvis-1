#!/usr/bin/env python3
"""The owner's independent check of what the site serves right now.

    python3 release/audit.py [--alert]

Runs on the owner's own machine from a systemd user timer (release/audit.timer),
outside GitHub: a collaborator who can edit the workflows cannot edit this.
It downloads the live manifest, SHA256SUMS, signature and every listed
artifact, and runs release/check.py over them with the fingerprints pinned in
~/.config/argus-release/trusted_signers (the owner's file, in no repository).
It also probes download names that once leaked source (the 2026-10-29
withdrawal) and fails if any of them answers again.

Every run appends one line to ~/.local/state/argus-release-audit.log. With
--alert, a change of state (a new problem, or the problems clearing) and a
daily reminder while a problem lasts go out on every alert channel JARVIS has
configured (jarvis/response/alert.py, imported from ~/jarvis). It exits 1 on
a problem and never changes the site: rolling back stays an explicit owner
action (docs/guides/RELEASING.md).
"""

import argparse
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import check  # noqa: E402
import signers  # noqa: E402

LIVE = "https://www.archymedes.xyz/downloads/argus/"
TRUSTED = Path("~/.config/argus-release/trusted_signers").expanduser()
LOG = Path("~/.local/state/argus-release-audit.log").expanduser()
STATE = Path("~/.local/state/argus-release-audit.state.json").expanduser()
JARVIS = Path(os.environ.get("JARVIS_REPO", "~/jarvis")).expanduser()
REMIND_S = 24 * 3600
UA = {"User-Agent": "argus-release-audit"}
# Downloads that shipped source or bytecode and were withdrawn 2026-10-29.
WITHDRAWN = ("argus-windows-x64.zip", "Argus-Setup.exe", "argus-server-linux.tar.gz",
             "argus-server_2026.10.30_all.deb", "argus-server_2026.10.27_all.deb")


def get(name, dest=None):
    req = urllib.request.Request(LIVE + name, headers=UA)
    with urllib.request.urlopen(req, timeout=300) as r:
        data = r.read()
    if dest:
        dest.write_bytes(data)
    return data


def answers(name):
    req = urllib.request.Request(LIVE + name, headers=UA, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status == 200
    except urllib.error.HTTPError:
        return False


def audit():
    problems = [f"withdrawn download {n} is served again" for n in WITHDRAWN if answers(n)]
    if not TRUSTED.is_file():
        return problems + [f"{TRUSTED} is missing: pin the releasers' fingerprints there"], None
    pinned = signers.pinned_from(TRUSTED.read_text())
    with tempfile.TemporaryDirectory(prefix="argus-audit-") as tmp:
        d = Path(tmp)
        try:
            manifest = json.loads(get("manifest.json", d / "manifest.json"))
            for name in [*manifest.get("files", {}), "SHA256SUMS", "SHA256SUMS.sig", "allowed_signers"]:
                get(name, d / name)
        except (OSError, ValueError) as exc:
            return problems + [f"live files unreadable: {type(exc).__name__}: {exc}"], None
        found, _counts, signer = check.check(d, (d / "allowed_signers").read_text(), pinned)
    return problems + found, (manifest.get("version"), signer)


def alert(problems, what):
    """Send on JARVIS's alert channels when the state changed or a day passed."""
    now = time.time()
    try:
        state = json.loads(STATE.read_text())
    except (OSError, ValueError):
        state = {}
    key = sorted(problems)
    if key == state.get("problems") and (not key or now - state.get("sent", 0) < REMIND_S):
        return "unchanged"
    if key:
        subject = f"Argus downloads: {len(key)} problem(s) on the live site"
        text = ("The release audit found problems with what www.archymedes.xyz serves:\n\n"
                + "\n".join(f"- {p}" for p in key[:30])
                + "\n\nRoll back or withdraw: docs/guides/RELEASING.md, 'Rolling back'.")
    else:
        subject = "Argus downloads: the live site passes its audit again"
        text = f"Argus {what and what[0]} is served, signed by {what and what[1] and what[1][0]}."
    sys.path.insert(0, str(JARVIS))
    try:
        from jarvis.response import alert as jalert
        err = jalert.deliver(jalert.load_conf(), subject, text)
    except Exception as exc:  # noqa: BLE001 - the audit result stands without the alert
        err = f"alert unavailable: {type(exc).__name__}"
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"problems": key, "sent": now if not err else state.get("sent", 0),
                                 "last_error": err}))
    return err or "sent"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--alert", action="store_true", help="alert on JARVIS's channels when the state changes")
    args = ap.parse_args()
    problems, what = audit()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = {"at": stamp, "ok": not problems, "version": what and what[0],
            "signer": what and what[1] and what[1][0], "problems": problems[:20]}
    if args.alert:
        line["alert"] = alert(problems, what)
    with open(LOG, "a") as fh:
        fh.write(json.dumps(line) + "\n")
    for p in problems:
        print("LIVE PROBLEM  " + p)
    if problems:
        sys.exit(1)
    print(f"live site OK: Argus {what[0]}, signed by {what[1][0]}")


if __name__ == "__main__":
    main()

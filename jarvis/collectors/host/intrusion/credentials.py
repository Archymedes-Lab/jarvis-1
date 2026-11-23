"""Browser credential theft: a non-browser process naming the password or cookie store.

A browser keeps its credential databases locked while it runs, so an
infostealer's usual first step is to copy them somewhere it can read, and the
copy names the file on a command line: `esentutl /y "...\\Login Data"`, a
robocopy of the profile, a script handed the profile path. The payload lists
running processes whose command line references a store; this decides which of
them are the browser itself and which are not.

The limit is stated in the finding and the gaps report alike: only command
lines of running processes are seen. Code that opens the files through the API
without naming them on its command line is not.
"""

import re

from jarvis.platform.windows import aslist

from .common import _finding

# A store file as a path component anywhere in a command line. The payload
# applies the same expression before returning processes; this re-checks it so
# the decision does not rest on the PowerShell side alone.
CRED_STORES = re.compile(
    r"[\\/](Login Data|Cookies|Web Data|Local State|key4\.db|logins\.json|"
    r"cookies\.sqlite|places\.sqlite)(?=[\"'\s]|$)", re.I)

BROWSER_PROC = re.compile(r"^(chrome|msedge|firefox|opera|brave|vivaldi|"
                          r"chromium|thorium)\.exe$", re.I)

# Written into the payload's own text. Its command line names every store file,
# so a process carrying the marker is this collector, not a thief.
PAYLOAD_MARKER = "jarvis-intrusion-payload"

TITLE = "a non-browser process references browser credential stores"


def credential_findings(data):
    if not data.get("credReadersOk"):
        return [_finding("credential access", "low",
                         "browser credential-store check unavailable",
                         "the process list could not be read, so a copy of the "
                         "password or cookie stores would not have been seen")]
    stores = [s for s in aslist(data.get("credAccess")) if isinstance(s, dict)]
    out = []
    for proc in aslist(data.get("credReaders")):
        if not isinstance(proc, dict):
            continue
        name = str(proc.get("name") or "")
        cmd = str(proc.get("cmd") or "")
        if BROWSER_PROC.match(name) or PAYLOAD_MARKER in cmd:
            continue
        touched = sorted({m.group(1) for m in CRED_STORES.finditer(cmd)})
        if not touched:
            continue
        out.append(_finding(
            "credential access", "high", TITLE,
            f"{name or 'unknown process'} (pid {proc.get('pid')}) names "
            f"{', '.join(touched)} — copying these is how browser passwords and "
            f"session cookies are stolen. Command line: {cmd[:160]}",
            proc.get("exe") or name))
    if not out:
        out.append(_finding(
            "credential access", "ok",
            "no other process references the browser credential stores",
            f"{len(stores)} password store(s) present; checked the command line "
            f"of every running process"))
    return out

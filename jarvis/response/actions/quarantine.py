"""Quarantine a dropped file: move it out of reach, keep it for evidence.

Deleting a suspected payload destroys the one copy an investigation needs and
cannot be undone if the detection was wrong. Quarantine is the reversible
alternative: the file is copied into an evidence case, then moved into a
locked store where nothing can execute or open it, leaving a marker where it
was. Undo puts it back byte for byte.
"""

import json
import os
import shutil
import stat
import time

from jarvis.response.evidence.paths import STATE_ROOT

from .base import AUTO, Action, register

QUARANTINE_DIR = os.path.join(STATE_ROOT, "quarantine")


def _store_dir():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    os.chmod(QUARANTINE_DIR, 0o700)
    return QUARANTINE_DIR


@register
class QuarantineFile(Action):
    id = "quarantine_file"
    title = "Quarantine a dropped file"
    autonomy = AUTO
    reversible = True
    host = "wsl"
    enable_flag = "auto_quarantine"

    def match(self, finding, job):
        # Only files that actually exist on the Linux side, named by a
        # threat-intel path match or a staged-executable finding.
        if (finding or {}).get("host") != "wsl" or job != "hunt":
            return None
        if (finding or {}).get("category") not in ("sample match", "dropped file"):
            return None
        path = (finding or {}).get("where") or ""
        if not path.startswith("/") or not os.path.isfile(path):
            return None
        # Never touch a package-owned or system path: those are not drops.
        real = os.path.realpath(path)
        if real.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/etc/", "/boot/")):
            return None
        return {"path": path}

    def auto_eligible(self, finding, job, target):
        # Exact SHA-256 sample matches are collision-resistant corroboration.
        # Path and filename indicators can collide with legitimate files and
        # therefore remain proposals even when their severity is high.
        return (job == "hunt" and finding.get("category") == "sample match"
                and finding.get("severity") == "critical"
                and "SHA-256 " in (finding.get("detail") or ""))

    def evidence(self, target):
        return [target["path"]]

    def preview(self, target):
        return (f"Move {target['path']} into the locked quarantine store and "
                f"leave a marker in its place. Reversible.")

    def apply(self, target, case):
        path = target["path"]
        if not os.path.isfile(path):
            return False, {}, "file is no longer there"
        try:
            st = os.stat(path)
            token = f"{int(time.time())}-{os.getpid()}-{os.path.basename(path)}"
            dst = os.path.join(_store_dir(), token)
            shutil.move(path, dst)
            os.chmod(dst, 0o400)
            record = {"path": path, "stored": dst, "mode": stat.S_IMODE(st.st_mode),
                      "uid": st.st_uid, "gid": st.st_gid, "at": int(time.time())}
            marker = path + ".jarvis-quarantined"
            try:
                with open(marker, "w") as fh:
                    json.dump({"quarantined": record["at"], "stored": dst,
                               "restore": "jarvis defend undo (see the email)"}, fh)
            except OSError:
                marker = ""
            record["marker"] = marker
            return True, record, f"quarantined to {dst}"
        except OSError as exc:
            return False, {}, f"could not quarantine: {exc.strerror or exc}"

    def undo(self, target, record):
        stored = record.get("stored")
        path = record.get("path")
        if not stored or not os.path.isfile(stored):
            return False, "the quarantined copy is gone"
        if os.path.exists(path):
            return False, f"{path} exists again; not overwriting it"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            shutil.move(stored, path)
            if record.get("mode"):
                os.chmod(path, record["mode"])
            marker = record.get("marker")
            if marker and os.path.exists(marker):
                os.remove(marker)
            return True, f"restored {path}"
        except OSError as exc:
            return False, f"could not restore: {exc.strerror or exc}"

    def recover(self, target, record):
        """Recover only from a durable marker and matching quarantined copy.

        A missing marker is deliberately not treated as proof that no move
        happened: an interruption can occur after the move and before marker
        creation.  In that state a person must inspect the evidence store.
        """
        path = target.get("path") if isinstance(target, dict) else ""
        marker = (record or {}).get("marker") or (path + ".jarvis-quarantined")
        if not path or not os.path.isabs(path):
            return "unknown", {}, "invalid quarantine target"
        try:
            if os.path.exists(path):
                return "not_applied", {}, "the original file is present"
            if not os.path.isfile(marker):
                return "unknown", {}, "file is absent but no trustworthy quarantine marker exists"
            with open(marker, encoding="utf-8", errors="replace") as fh:
                saved = json.load(fh)
            stored = saved.get("stored") if isinstance(saved, dict) else ""
            if not isinstance(stored, str) or not os.path.isfile(stored):
                return "unknown", {}, "quarantine marker does not identify a retained file"
            # Do not call _store_dir(): recovery probes must not create or
            # chmod anything merely by inspecting an interrupted action.
            root = os.path.realpath(QUARANTINE_DIR) + os.sep
            if not os.path.realpath(stored).startswith(root):
                return "unknown", {}, "quarantine marker points outside the quarantine store"
            return "applied", {"path": path, "stored": stored, "marker": marker,
                                "at": int(saved.get("quarantined") or 0)}, \
                "verified quarantined file and marker"
        except (OSError, ValueError, TypeError):
            return "unknown", {}, "could not safely read quarantine recovery state"

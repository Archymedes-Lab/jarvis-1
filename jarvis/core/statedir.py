"""The daemon's state directory under its own service account.

Default install (docs/guides/SERVICE-ACCOUNT.md): the daemon runs as the system
account `jarvis` with HOME=/var/lib/jarvis, so its state is /var/lib/jarvis/.jarvis.
That directory is 0700 and every token, key and database file in it 0600, all
owned by `jarvis`. The installer writes MARKER so other programs know the
daemon's store is not the caller's own ~/.jarvis.

Two checks live here:
  * private_problems(): what makes a state directory readable or writable by
    anyone but its owner. serve() refuses to start in service-account mode
    while any problem remains (it would hand the API token and the evidence
    to other accounts); in the legacy per-user mode it warns.
  * cli_refusal(): a CLI command run by the owner's account would otherwise
    open that account's ~/.jarvis -- stale or empty, not the daemon's store --
    and report it as the truth. It is refused with the two working routes.
"""

import json
import os
import shlex
import stat

MARKER = "/etc/jarvis/service-account.json"
# Files that must be owner-only. Directories are checked separately.
SENSITIVE_SUFFIXES = (".db", ".db-wal", ".db-shm", ".token", ".env", ".key", ".json")


def load_marker(path=MARKER):
    """The service-account record, or None in the legacy per-user mode."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            value = json.load(fh)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) and value.get("state_dir") else None


WINDOWS_NOTE = ("Windows does not use these permission bits; the folder is private through "
                "your user profile's access list, which this check does not read")


def private_problems(state_dir, uid=None, os_name=None):
    """Human-readable problems that expose `state_dir` to other accounts.

    Checked: the directory itself (owner, no group/other bits) and every
    sensitive file directly inside it (owner, no group/other bits, not a link).
    An empty list means private. A missing directory is one problem.
    """
    if (os_name or os.name) == "nt":
        # POSIX modes read 0777/0666 on every Windows file: reporting them would
        # be noise, and calling the folder private would be a claim not checked.
        return [f"{state_dir}: {WINDOWS_NOTE}"] if os.path.isdir(state_dir) else \
            [f"{state_dir}: not a real directory"]
    uid = os.geteuid() if uid is None and hasattr(os, "geteuid") else uid
    problems = []
    try:
        st = os.lstat(state_dir)
    except OSError as exc:
        return [f"{state_dir}: cannot be inspected ({exc.strerror})"]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return [f"{state_dir}: not a real directory"]
    if uid is not None and st.st_uid != uid:
        problems.append(f"{state_dir}: owned by uid {st.st_uid}, not {uid}")
    if st.st_mode & 0o077:
        problems.append(f"{state_dir}: mode {stat.S_IMODE(st.st_mode):04o}, must be 0700")
    try:
        names = sorted(os.listdir(state_dir))[:4096]
    except OSError as exc:
        return problems + [f"{state_dir}: cannot be listed ({exc.strerror})"]
    for name in names:
        if not name.endswith(SENSITIVE_SUFFIXES):
            continue
        path = os.path.join(state_dir, name)
        try:
            fst = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(fst.st_mode):
            problems.append(f"{path}: is a link")
            continue
        if not stat.S_ISREG(fst.st_mode):
            continue
        if uid is not None and fst.st_uid != uid:
            problems.append(f"{path}: owned by uid {fst.st_uid}, not {uid}")
        if fst.st_mode & 0o077:
            problems.append(f"{path}: mode {stat.S_IMODE(fst.st_mode):04o}, must be 0600")
    return problems


def cli_refusal(db, default_db, argv, marker_path=MARKER):
    """A message when this CLI run would read the wrong store, else None.

    Only in service-account mode, only for the default database, and only when
    this account does not own the daemon's state directory. An explicit --db
    is the caller's own choice and is left alone.
    """
    marker = load_marker(marker_path)
    if not marker or os.path.abspath(os.path.expanduser(db)) != os.path.abspath(
            os.path.expanduser(default_db)):
        return None
    state_dir = str(marker["state_dir"])
    try:
        if hasattr(os, "geteuid") and os.stat(state_dir).st_uid == os.geteuid():
            return None
    except OSError:
        pass
    user = str(marker.get("user") or "jarvis")
    cli = str(marker.get("cli") or f"sudo -u {user} -H jarvis")
    args = " ".join(shlex.quote(a) for a in argv)
    return (f"ARGUS-INSTINCT runs as its own account ({user}); its store is {state_dir}, not this "
            f"account's ~/.jarvis, so this command would show the wrong state.\n"
            f"  run it as the daemon's account:  {cli} {args}\n"
            f"  or use the dashboard or the desktop app (pair them with "
            f"`{cli} desktop pair --name NAME`).")

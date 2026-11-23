"""What WSL runs, and whether it should (owner request 2026-10-31).

Every process is attributed to its owner by the kernel's own record, its
cgroup (/proc/<pid>/cgroup), never by its name:

    unit:<name>          a systemd unit (system.slice/<unit>); snap mount
                         revisions are folded ("snap-core24-N.mount")
    containers           any Docker/containerd container, tracked by the
                         binaries it runs (container ids change on recreate)
    user-manager:<uid>   the user's systemd manager and its units
    login-session        a login session (session-N.scope)
    systemd              PID 1
    wsl-plumbing         WSL's own /init processes outside systemd
    wsl-session:<user>   everything started into WSL from Windows (terminals,
                         wsl.exe commands) lands in init.scope; a root one
                         that is not plumbing is what `wsl -u root` looks like

The owner approves the observed set once (`jarvis wslmanifest --approve`,
written owner-only to ~/.jarvis/wsl-manifest.json); after that each run reports
drift against it:

    new owner      an owner running that the manifest does not list      medium
    new binary     a binary running under a listed owner that the
                   manifest does not list for it                         medium
    risky binary   a running binary that was deleted from disk or lives
                   in a world-writable directory                         high
    root session   a root process launched from Windows (not plumbing)   high
                   unless the manifest approved one
    missing        an approved unit that is not running                  medium;
                   high for JARVIS's own and the sensor's units

Invariants (tests/test_wslmanifest.py holds each):
    I1  attribution comes only from /proc/<pid>/cgroup and /proc/<pid>/exe
    I2  an unreadable process is counted and reported as reduced visibility,
        never treated as matching the manifest
    I3  bounded: at most MAX_PROCS processes read, findings aggregated per
        owner, at most MAX_NAMES names in any one finding
    I4  read-only: nothing is started or stopped; the manifest is written only
        by the owner's --approve command, never by a run

Not seen: a process that starts and exits between two runs (5 minutes); the
Linux Sysmon start history (start_images) records those images.
"""

import json
import os
import re
import stat

from jarvis.core.finding import finding as _finding
from jarvis.core.util import iso, now

MANIFEST = os.path.expanduser("~/.jarvis/wsl-manifest.json")
OBS_META = "wslmanifest_observed_v1"   # the daemon's latest full view, for --approve
OBS_FRESH_S = 900
MAX_PROCS = 4000
MAX_NAMES = 12
ANY = "*"
SECURITY_UNITS = ("jarvis", "argus", "sysmon", "auditd")
WRITABLE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")
_DOCKER = re.compile(r"/(docker|containerd|libpod|cri-containerd)[-/][0-9a-f]{12,}")
_REVISION = re.compile(r"-\d+(?=\.(mount|scope|service)$)")
_SNAP_PATH = re.compile(r"^/snap/([^/]+)/\d+/")      # /snap/<name>/<revision>/ changes on refresh
# A JARVIS release folder changes on every deploy (2026-11-01: the approved
# jarvis.service binary named its release id, so each deploy read as drift).
_RELEASE_PATH = re.compile(r"/\d{8}T\d{6}Z-[0-9a-f]{12}/")


def norm(exe):
    """The stable identity of a binary path: no " (deleted)", folded revisions."""
    path = exe.replace(" (deleted)", "")
    path = _SNAP_PATH.sub(r"/snap/\1/N/", path)
    return _RELEASE_PATH.sub("/N/", path)


def owner_of(cgroup, exe, pid, user):
    """The owner key for one process, from its cgroup path; "" for a kernel thread."""
    path = cgroup or ""
    if not path:
        return ""
    if _DOCKER.search(path):
        return "containers"
    parts = [p for p in path.split("/") if p]
    if parts and parts[0] == "user.slice":
        manager = next((p for p in parts if p.startswith("user@") and p.endswith(".service")), "")
        if manager:
            return "user-manager:" + manager[5:-8]
        if any(p.startswith("session-") and p.endswith(".scope") for p in parts):
            return "login-session"
        return "user-slice"
    if parts and parts[0] == "system.slice":
        unit = parts[-1] if parts[-1].endswith((".service", ".scope", ".mount", ".socket")) else \
            next((p for p in reversed(parts) if p.endswith((".service", ".scope", ".mount"))), parts[-1])
        return "unit:" + _REVISION.sub("-N", unit)
    if path == "/init.scope" or (parts and parts[0] == "init.scope"):
        if pid == 1:
            return "systemd"
        if exe == "/init" or exe.startswith("/init "):
            return "wsl-plumbing"
        return "wsl-session:" + (user or "?")
    if path == "/":
        return "wsl-plumbing" if exe in ("", "/init") else "wsl-session:" + (user or "?")
    return "other:" + parts[0] if parts else "other"


def read_procs(proc="/proc"):
    """[(pid, owner, exe, user)] plus the count of processes that could not be read."""
    rows, unreadable = [], 0
    try:
        pids = sorted(int(p) for p in os.listdir(proc) if p.isdigit())
    except OSError:
        return [], -1
    users = {}
    for pid in pids[:MAX_PROCS]:
        base = os.path.join(proc, str(pid))
        try:
            with open(os.path.join(base, "cgroup"), encoding="utf-8", errors="replace") as fh:
                line = next((ln for ln in fh.read().splitlines() if ln.startswith("0::")), "")
            cgroup = line[3:]
            uid = os.stat(base).st_uid
        except OSError:
            continue                      # exited between listdir and read
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            exe = None
        if exe is None:
            try:
                with open(os.path.join(base, "stat"), encoding="utf-8", errors="replace") as fh:
                    ppid = int(fh.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                ppid = -1
            if ppid in (0, 2) or pid == 2:
                continue                  # kernel thread
            unreadable += 1
            continue
        if uid not in users:
            users[uid] = _user(uid)
        owner = owner_of(cgroup, exe, pid, users[uid])
        if owner:
            rows.append((pid, owner, exe, users[uid]))
    return rows, unreadable


def _user(uid):
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return str(uid)


def observe(rows):
    """{owner: {"binaries": sorted list, "users": sorted list, "pids": n}}."""
    seen = {}
    for _pid, owner, exe, user in rows:
        o = seen.setdefault(owner, {"binaries": set(), "users": set(), "pids": 0})
        o["binaries"].add(norm(exe))
        o["users"].add(user)
        o["pids"] += 1
    return {k: {"binaries": sorted(v["binaries"]), "users": sorted(v["users"]), "pids": v["pids"]}
            for k, v in seen.items()}


def proposal(observed):
    """The manifest --approve writes: every observed owner with its binaries,
    except interactive non-root sessions, where any binary is expected."""
    owners = {}
    for owner, o in observed.items():
        interactive = owner.startswith(("wsl-session:", "login-session", "user-manager:")) \
            and owner != "wsl-session:root"
        owners[owner] = {"binaries": ANY if interactive else o["binaries"],
                         "required": owner.startswith("unit:")}
    return {"version": 1, "approved_at": now(), "owners": owners}


def load(path=MANIFEST):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("owners"), dict) else None


def daemon_view(store):
    """(observed, unreadable, age_s) from the daemon's latest run, or None."""
    try:
        data = json.loads(store.get_meta(OBS_META, "") or "{}")
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("observed"), dict):
        return None
    return data["observed"], int(data.get("unreadable") or 0), now() - int(data.get("ts") or 0)


def approve(observed, path=MANIFEST):
    data = proposal(observed)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)
    return data


def _names(items):
    items = sorted(items)
    more = len(items) - MAX_NAMES
    return ", ".join(items[:MAX_NAMES]) + (f" (+{more} more)" if more > 0 else "")


def risky(exe):
    return exe.endswith(" (deleted)") or exe.startswith(WRITABLE_DIRS)


def drift(observed, manifest, rows=()):
    """Findings for the observed processes against an approved manifest."""
    out = []
    approved = manifest.get("owners") or {}
    new_owners = sorted(o for o in observed if o not in approved)
    if new_owners:
        detail = "; ".join(f"{o} ({_names(observed[o]['binaries'])})" for o in new_owners[:MAX_NAMES])
        if len(new_owners) > MAX_NAMES:
            detail += f" (+{len(new_owners) - MAX_NAMES} more)"
        root = [o for o in new_owners if o == "wsl-session:root"]
        out.append(_finding(
            "process", "high" if root else "medium",
            f"{len(new_owners)} process owner(s) in WSL not in the approved manifest",
            f"running now and not approved on {iso(int(manifest.get('approved_at') or 0))}: {detail}. "
            + ("A root process launched from Windows (wsl -u root) is among them. " if root else "")
            + "Approve them with `jarvis wslmanifest --approve` if you added them.",
            "wslmanifest"))
    for owner in sorted(o for o in observed if o in approved):
        allowed = approved[owner].get("binaries")
        if allowed == ANY:
            continue
        # Both sides normalised: a manifest approved before a folding rule
        # existed (release ids, snap revisions) still matches.
        extra = sorted(set(observed[owner]["binaries"]) - {norm(a) for a in allowed or []})
        if extra:
            out.append(_finding(
                "process", "medium",
                f"{owner} is running {len(extra)} binary(ies) not in the approved manifest",
                f"{_names(extra)}. An update can change a unit's binaries; an injected "
                f"helper or a replaced service binary looks the same here.", "wslmanifest"))
    # A running binary whose file was replaced at the same, approved path is an
    # update or a self-reinstall: Sysmon for Linux runs `sysmon -i` at every
    # service start, which copies a new binary over the one already running.
    replaced, flagged = set(), set()
    for pid, owner, exe, _u in rows:
        if not risky(exe):
            continue
        allowed = (approved.get(owner) or {}).get("binaries")
        same = exe.endswith(" (deleted)") and os.path.exists(exe[:-10]) and \
            (allowed == ANY or norm(exe) in {norm(a) for a in allowed or []})
        (replaced if same else flagged).add(f"{exe} [{owner}, pid {pid}]")
    if replaced:
        out.append(_finding(
            "process", "low", f"{len(replaced)} WSL process(es) run a binary replaced on disk since they started",
            f"{_names(replaced)}. The approved path exists again, so this is an update or a "
            f"self-reinstall still running the old copy; a restart runs the current file.",
            "wslmanifest"))
    flagged = sorted(flagged)
    if flagged:
        out.append(_finding(
            "process", "high", f"{len(flagged)} WSL process(es) run a deleted or world-writable binary",
            f"{_names(flagged)}. A running binary whose file was deleted, or one launched "
            f"from /tmp, /var/tmp or /dev/shm, is how droppers hide.", "wslmanifest"))
    missing = sorted(o for o, spec in approved.items()
                     if spec.get("required") and o not in observed)
    if missing:
        security = [o for o in missing if any(s in o for s in SECURITY_UNITS)]
        out.append(_finding(
            "process", "high" if security else "medium",
            f"{len(missing)} approved WSL unit(s) are not running",
            f"{_names(missing)}" + (". JARVIS's own or the sensor's unit is among them"
                                    if security else "")
            + ". A unit that should run and does not is either broken or was stopped.",
            "wslmanifest"))
    return out


def audit(store=None, hosts=None, proc="/proc", path=MANIFEST, record=True):
    rows, unreadable = read_procs(proc)
    if unreadable < 0:
        return [_finding("process", "medium", "WSL processes could not be listed",
                         f"{proc} was not readable; nothing about what runs is known", "wslmanifest")]
    observed = observe(rows)
    if store is not None and record:
        # The daemon reads every process (CAP_SYS_PTRACE); an owner's shell
        # does not, so --approve approves this view, not its own. The CLI
        # passes record=False: on 2026-10-31 its partial view overwrote the
        # daemon's and was then approved as if it were complete.
        store.set_meta(OBS_META, json.dumps({"ts": now(), "observed": observed,
                                             "unreadable": unreadable}))
    manifest = load(path)
    out = []
    if unreadable:
        out.append(_finding(
            "process", "low", f"{unreadable} WSL process(es) could not be attributed",
            "their executable link was unreadable (the collector needs CAP_SYS_PTRACE for "
            "other users' processes); they are not counted as matching the manifest",
            "wslmanifest"))
    summary = "; ".join(f"{o}: {observed[o]['pids']}" for o in sorted(observed))
    if manifest is None:
        out.append(_finding(
            "process", "low", "no approved WSL process manifest yet",
            f"{len(rows)} processes under {len(observed)} owners ({summary[:1200]}). "
            f"Review them with `jarvis wslmanifest` and approve with "
            f"`jarvis wslmanifest --approve`; until then nothing is reported as drift.",
            "wslmanifest"))
        return out
    out += drift(observed, manifest, rows)
    out.append(_finding(
        "process", "ok", f"{len(rows)} WSL processes under {len(observed)} owners",
        f"manifest approved {iso(int(manifest.get('approved_at') or 0))}; {summary[:1500]}",
        "wslmanifest"))
    return out

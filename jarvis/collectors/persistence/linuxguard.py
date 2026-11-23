"""Linux system integrity: the files and facts attackers change, watched by state.

Measured 2026-11-11 on a disposable runner (scripts/security/live_bench.py, cases
17-29): a PAM module line, a file capability, a udev rule, a line in the system
bash startup file, LD_PRELOAD in /etc/environment, a login-message script, a new
sudo-group member, an emptied authentication log and an APT hook were all carried
out and none was reported. Each is a change to a small, known set of files or
facts, not a command line a rule could match.

So this collector watches state, in two ways:

  * Drift from a per-install baseline (DETECTION-CONTENT section 3: learn per
    install, never per source). The first pass records a digest of each watched
    file and the members of each privileged group. Later passes report what is
    new, changed or removed, until the baseline is reset by a person
    (`jarvis linuxguard accept`). Learning never happens silently later.
  * Invariants that hold on any machine and need no baseline, so a change made
    before the first pass is still seen: PAM running an external program,
    LD_PRELOAD or LD_AUDIT set for every session, a dangerous file capability
    outside the system program folders, a log cut shorter in place.

Invariants of the collector itself
  1. Read-only. Files are read without following links (core.safe_files) and are
     never quoted: findings carry the path, what kind of change, and digests.
  2. Evidence continuity: an unreadable or capped source is reported as a gap and
     never as unchanged; the baseline keeps its previous entry for it.
  3. Bounded: files, bytes, directory entries and seconds per pass are capped.
  4. Severity is fixed per family, never raised by the content of a file.
  5. Findings are file evidence: never acted on automatically.

Limits, stated: only the listed paths; a change made before the first pass is a
drift only if an invariant also covers it; a package upgrade that rewrites a
watched file is reported as drift until accepted; capabilities are read only in
the listed directories; a log truncated and then refilled past its old size
between two passes is not seen; an attacker with root can rewrite the baseline in
the store (the tamper-evident event log is the record of record).
"""

import hashlib
import json
import os
import re
import stat
import struct
import time

try:
    import grp  # Unix only: this module is imported by the job table everywhere
except ImportError:                 # native Windows: the collector is Linux-domain and never runs there
    grp = None

from jarvis.core import collection, safe_files
from jarvis.core.finding import file_finding, finding

META = "linuxguard_v1"
GETXATTR = getattr(os, "getxattr", None)      # Linux only
MAX_FILES = 1500
MAX_FILE_BYTES = 512 * 1024
MAX_BYTES = 16 * 1024 * 1024
MAX_SECONDS = 15.0
MAX_CAP_ENTRIES = 60000
MAX_CAP_DEPTH = 6
MAX_LISTED = 12
WHERE = "system integrity"

# (family, files, directories, severity of a drift, what the family controls)
FAMILIES = (
    ("pam", (), ("/etc/pam.d",), "high", "how Linux checks passwords at every sign-in"),
    ("environment", ("/etc/environment",), ("/etc/environment.d",), "high",
     "variables set for every session, including which libraries load first"),
    ("shell", ("/etc/bash.bashrc", "/etc/profile", "/etc/zsh/zshrc", "/etc/zsh/zprofile", "/etc/zshrc",
               "/etc/bashrc", "/etc/csh.cshrc"), (), "medium", "commands every user's shell runs"),
    ("sudo", ("/etc/sudoers",), ("/etc/sudoers.d",), "high", "who may act as root"),
    ("loader", ("/etc/ld.so.preload", "/etc/ld.so.conf"), ("/etc/ld.so.conf.d",), "high",
     "libraries loaded into every program"),
    ("udev", (), ("/etc/udev/rules.d",), "medium", "programs run when a device appears"),
    ("apt", (), ("/etc/apt/apt.conf.d",), "medium", "programs the package manager runs"),
    ("motd", (), ("/etc/update-motd.d",), "medium", "scripts run as root at every sign-in"),
    ("modules", ("/etc/modules",), ("/etc/modules-load.d", "/etc/modprobe.d"), "medium",
     "kernel modules loaded at start"),
    ("security", ("/etc/security/access.conf", "/etc/security/limits.conf"), ("/etc/security/limits.d",),
     "medium", "sign-in access rules"),
    ("nsswitch", ("/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf"), (), "medium",
     "where Linux looks up accounts and names"),
)
SEVERITY = {f[0]: f[3] for f in FAMILIES}
WHAT = {f[0]: f[4] for f in FAMILIES}
PRIVILEGED_GROUPS = ("root", "sudo", "wheel", "admin", "adm", "docker", "lxd", "libvirt", "disk", "shadow")
LOGS = ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log",
        "/var/log/audit/audit.log", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog")
# Staging and add-on folders first; home folders last, as far as the budget allows.
CAP_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/usr/local", "/opt", "/srv", "/var/www", "/root", "/home")
CAP_SKIP = frozenset({".git", "node_modules", ".cache", ".npm", ".cargo", ".rustup", ".venv", "venv",
                      "site-packages", ".local", "go", ".m2", ".gradle", "proc"})
# Bits of capabilities that each amount to root (capability(7)).
DANGEROUS_CAPS = {0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search", 3: "cap_fowner",
                  6: "cap_setgid", 7: "cap_setuid", 16: "cap_sys_module", 17: "cap_sys_rawio",
                  19: "cap_sys_ptrace", 21: "cap_sys_admin"}
PAM_SYSTEM_DIRS = re.compile(r"^/(usr/)?lib(64|32)?/(([a-z0-9_]+-linux-gnu)/)?security/")
PAM_LINE = re.compile(r"^\s*-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)(.*)$")
ENV_LOADER = re.compile(r"^\s*(export\s+)?(LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH)\s*=", re.M)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class Pass:
    def __init__(self, clock):
        self.clock, self.started = clock, clock()
        self.files = self.bytes = 0
        self.gaps, self.cut = [], False
        self.denied = []            # root-only files this account cannot read
        self.cap_cut = ""           # the capability walk stopped in this folder

    def over(self):
        if self.clock() - self.started >= MAX_SECONDS:
            self.cut = True
        return self.cut

    def lstat(self, path):
        try:
            parent = safe_files.open_safe(os.path.dirname(path) or "/", directory=True)
            try:
                return os.stat(os.path.basename(path), dir_fd=parent, follow_symlinks=False)
            finally:
                os.close(parent)
        except FileNotFoundError:
            return None
        except OSError:
            self.gaps.append(path)
            return None

    def read(self, path):
        """(stat, bytes) of a regular file, or None when absent; a gap when unreadable."""
        if self.over():
            return None
        meta = self.lstat(path)
        if meta is None:
            return None
        if stat.S_ISLNK(meta.st_mode):
            return meta, b"link:" + os.fsencode(self._readlink(path) or "")
        if not stat.S_ISREG(meta.st_mode):
            return None
        if meta.st_size > MAX_FILE_BYTES or self.files >= MAX_FILES or self.bytes + meta.st_size > MAX_BYTES:
            self.cut = True
            return None
        if not os.access(path, os.R_OK, follow_symlinks=False):
            self.denied.append(path)
            return None
        data = safe_files.read_start(path, limit=meta.st_size + 1, expected=safe_files.identity(meta))
        if data is None or len(data) != meta.st_size:
            self.gaps.append(path)
            return None
        self.files += 1
        self.bytes += len(data)
        return meta, data

    def _readlink(self, path):
        try:
            parent = safe_files.open_safe(os.path.dirname(path), directory=True)
            try:
                return os.readlink(os.path.basename(path), dir_fd=parent)
            finally:
                os.close(parent)
        except OSError:
            self.gaps.append(path)
            return None

    def listdir(self, directory):
        if self.over():
            return []
        try:
            fd = safe_files.open_safe(directory, directory=True)
        except FileNotFoundError:
            return []
        except OSError:
            self.gaps.append(directory)
            return []
        try:
            with os.scandir(fd) as rows:
                return sorted(os.path.join(directory, r.name) for r in rows if not r.is_dir(follow_symlinks=False))
        except OSError:
            self.gaps.append(directory)
            return []
        finally:
            os.close(fd)


def watched_files(scan, families=FAMILIES):
    """{path: (family, stat, bytes)} for every watched file that exists."""
    out = {}
    for family, files, dirs, _sev, _what in families:
        paths = list(files)
        for d in dirs:
            paths += scan.listdir(d)
        for path in paths:
            got = scan.read(path)
            if got is not None:
                out[path] = (family, got[0], got[1])
    return out


def privileged_members(groups=PRIVILEGED_GROUPS, getgrnam=None):
    getgrnam = getgrnam or (grp.getgrnam if grp else None)
    out = {}
    if getgrnam is None:
        return out
    for name in groups:
        try:
            out[name] = sorted(getgrnam(name).gr_mem)
        except KeyError:
            continue
    return out


def file_caps(raw):
    """Names of dangerous capabilities in a security.capability xattr, or []."""
    if not raw or len(raw) < 12:
        return []
    magic, perm_lo, inh_lo = struct.unpack_from("<III", raw, 0)
    perm_hi = inh_lo_hi = 0
    if len(raw) >= 20:
        perm_hi, inh_lo_hi = struct.unpack_from("<II", raw, 12)
    bits = perm_lo | inh_lo | (perm_hi << 32) | (inh_lo_hi << 32)
    return [name for bit, name in sorted(DANGEROUS_CAPS.items()) if bits >> bit & 1]


def capability_files(scan, roots=CAP_DIRS, getxattr=GETXATTR):
    """[(path, [cap names])] for files under `roots` that carry dangerous capabilities."""
    out, seen = [], 0
    if getxattr is None:
        return out
    for root in roots:
        if scan.cut or not os.path.isdir(root) or os.path.islink(root):
            continue
        base = root.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if dirpath.count("/") - base >= MAX_CAP_DEPTH:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in CAP_SKIP]
            for name in filenames:
                seen += 1
                if seen > MAX_CAP_ENTRIES or scan.over():
                    scan.cap_cut = root
                    return out
                path = os.path.join(dirpath, name)
                try:
                    raw = getxattr(path, "security.capability", follow_symlinks=False)
                except OSError:
                    continue
                caps = file_caps(raw)
                if caps:
                    out.append((path, caps))
    return out


def pam_programs(data):
    """[(line number, module)] of PAM lines that run a program or load a module from outside
    the system module folders. Never returns the line itself."""
    out = []
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        m = PAM_LINE.match(line)
        if not m:
            continue
        module = m.group(3)
        if os.path.basename(module) == "pam_exec.so" or (module.startswith("/") and not PAM_SYSTEM_DIRS.match(module)):
            out.append((number, os.path.basename(module)))
    return out


def log_sizes(scan, logs=LOGS):
    out = {}
    for path in logs:
        meta = scan.lstat(path)
        if meta is not None and stat.S_ISREG(meta.st_mode):
            out[path] = [meta.st_dev, meta.st_ino, meta.st_size]
    return out


def _load(store):
    try:
        state = json.loads(store.get_meta(META, "") or "{}")
    except (TypeError, ValueError):
        return None
    if not isinstance(state, dict) or not isinstance(state.get("files"), dict):
        return None
    return state


def audit(store, hosts=("wsl",), clock=time.monotonic, families=FAMILIES, logs=LOGS, cap_roots=CAP_DIRS,
          getgrnam=None, getxattr=GETXATTR):
    if "wsl" not in hosts:
        return []
    scan = Pass(clock)
    files = watched_files(scan, families)
    groups = privileged_members(getgrnam=getgrnam)
    sizes = log_sizes(scan, logs)
    out = []

    # -- invariants: hold on any machine, need no baseline -------------------------
    for path, (family, _meta, data) in files.items():
        if family == "pam":
            hits = pam_programs(data)
            if hits:
                out.append(file_finding(
                    "persistence", "high", f"PAM runs a program at sign-in: {os.path.basename(path)}",
                    f"{path}: line(s) {', '.join(str(n) for n, _ in hits[:6])} load "
                    f"{', '.join(sorted({m for _, m in hits}))}. A PAM line that runs a program or loads a module "
                    "from outside the system module folders sees every password typed at sign-in. Confirm it is "
                    "yours. The lines are not shown.", path))
        elif family == "environment" and ENV_LOADER.search(data.decode("utf-8", "replace")):
            names = sorted(set(re.findall(r"(LD_PRELOAD|LD_AUDIT|LD_LIBRARY_PATH)\s*=", data.decode("utf-8", "replace"))))
            out.append(file_finding(
                "persistence", "high", f"{', '.join(names)} set for every session in {os.path.basename(path)}",
                f"{path} sets {', '.join(names)} for every session: a library named there is loaded into every "
                "program anyone starts. The value is not shown. Confirm it is yours.", path))
    for path, caps in capability_files(scan, cap_roots, getxattr):
        out.append(file_finding(
            "privilege escalation", "high", f"program with root-level capabilities outside system folders: {os.path.basename(path)}",
            f"{path} carries {', '.join(caps)}. Anyone who can run it gains that power, which amounts to root. "
            "System programs that need capabilities live in system folders; this one does not.", path))

    state = _load(store) if store is not None else None
    fresh = store is not None and state is None
    if state is None:
        state = {"since": int(time.time()), "files": {}, "groups": groups, "logs": {}}

    # -- logs: cut shorter in place since the last pass --------------------------------
    previous_logs = state.get("logs") or {}
    for path, (dev, ino, size) in sizes.items():
        before = previous_logs.get(path)
        if isinstance(before, list) and len(before) == 3 and before[0] == dev and before[1] == ino and size < before[2]:
            out.append(file_finding(
                "defense evasion", "high", f"log cut shorter in place: {os.path.basename(path)}",
                f"{path} shrank from {before[2]} to {size} bytes without being rotated (same file). Rotation "
                "starts a new file; emptying the same file is how sign-in records are erased. Earlier copies, "
                "if any, are in the rotated files and the journal.", path))

    # -- drift from the per-install baseline ----------------------------------------
    if not fresh:
        known = state["files"]
        drift = {}
        for path, (family, _meta, data) in files.items():
            digest = _digest(data)
            entry = known.get(path)
            if entry is None:
                drift.setdefault(family, []).append((path, "new"))
            elif entry.get("sha") != digest:
                drift.setdefault(family, []).append((path, "changed"))
        gap_set = set(scan.gaps) | set(scan.denied)
        for path, entry in known.items():
            if path not in files and path not in gap_set and not scan.cut:
                drift.setdefault(entry.get("family", "?"), []).append((path, "removed"))
        for family, items in sorted(drift.items()):
            sev = SEVERITY.get(family, "medium")
            for path, kind in items[:MAX_LISTED]:
                out.append(file_finding(
                    "persistence", "low" if kind == "removed" else sev,
                    f"{kind} since first seen: {path}",
                    f"{path} is {kind} since Argus first recorded this machine's {WHAT.get(family, family)} "
                    f"({time.strftime('%Y-%m-%d', time.gmtime(state.get('since', 0)))}). Contents are not shown. "
                    "A package update or your own change does this too; if so, accept it with  jarvis linuxguard "
                    "accept . If not, look at the file.", path))
            if len(items) > MAX_LISTED:
                out.append(finding("persistence", sev, f"{len(items) - MAX_LISTED} more {family} files changed",
                                   "Only the first are listed; all are kept in the comparison.", WHERE))
        for group, members in sorted(groups.items()):
            added = sorted(set(members) - set((state.get("groups") or {}).get(group, [])))
            if added:
                out.append(finding(
                    "privilege escalation", "high", f"new member of the {group} group: {', '.join(added[:6])}",
                    f"{', '.join(added)} joined {group} since Argus first recorded this machine. Members of "
                    f"{group} can act with root's power. Confirm the account and who added it.", "/etc/group"))
    else:
        out.append(finding("persistence", "ok", "system integrity baseline recorded",
                           f"{len(files)} watched files and {len(groups)} privileged groups recorded as this "
                           "machine's starting point; later changes are reported.", WHERE))

    # -- persist: the baseline only grows by first sight of a path that a gap hid ----
    if fresh:
        state["files"] = {p: {"family": f, "sha": _digest(d)} for p, (f, _m, d) in files.items()}
    state["logs"] = {**previous_logs, **sizes}
    if store is not None:
        store.set_meta(META, json.dumps(state, sort_keys=True))

    parts = []
    if scan.gaps:
        parts.append(f"{len(scan.gaps)} source(s) changed while read or could not be opened "
                     f"({', '.join(sorted(set(scan.gaps))[:4])})")
    if scan.cut:
        parts.append(f"the pass reached its limit ({MAX_FILES} files, {MAX_BYTES // (1024 * 1024)} MiB or "
                     f"{int(MAX_SECONDS)} s)")
    if scan.denied:
        parts.append(f"{len(scan.denied)} file(s) only root can read ({', '.join(sorted(set(scan.denied))[:4])}); "
                     "the service-account install reads them")
    if scan.cap_cut:
        parts.append(f"capabilities were checked up to {scan.cap_cut}, not beyond (budget {MAX_CAP_ENTRIES} files)")
    if parts:
        collection.failed("linuxguard", "system integrity evidence incomplete")
        out.append(finding(
            "visibility", "low", "System integrity was not completely checked",
            "; ".join(parts) + ". A source that was not read is never reported as unchanged.", WHERE))
    else:
        collection.succeeded("linuxguard")
    return out


def accept(store):
    """Make the current state the baseline (a person's decision). -> files recorded."""
    scan = Pass(time.monotonic)
    files = watched_files(scan)
    if scan.gaps or scan.cut or scan.denied:
        raise RuntimeError("not every watched file could be read; the baseline was not changed")
    state = _load(store) or {"logs": {}}
    state.update(since=int(time.time()), files={p: {"family": f, "sha": _digest(d)} for p, (f, _m, d) in files.items()},
                 groups=privileged_members())
    store.set_meta(META, json.dumps(state, sort_keys=True))
    return len(files)

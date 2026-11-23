"""Shared helpers: fingerprinting, IP classification, time."""

import hashlib
import ipaddress
import os
import re
import socket
import subprocess
import threading
import time

# Values that legitimately change between runs of the same program. Collapsing
# them keeps a process's fingerprint stable so restarts don't look like drift.
_VOLATILE = [
    (re.compile(r"/tmp/[^\s]*"), "/tmp/<tmp>"),
    (re.compile(r"/proc/\d+"), "/proc/<pid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d{4,}\b"), "<num>"),
    # Per-session random tokens in generated script names. Without this every
    # new shell session mints a fresh fingerprint for the same command and
    # reports it as drift forever, which is how a baseline system gets ignored.
    # Only the token is replaced — the directory stays in the fingerprint, so
    # something else appearing at that path is still unknown and still scored on
    # its own traits.
    (re.compile(r"(?<=-)[a-z0-9]{5,10}(?=\.(sh|ps1|bat|cmd)\b)", re.I), "<token>"),
    (re.compile(r"\s+"), " "),
]


def normalize_cmdline(cmdline: str) -> str:
    out = cmdline.strip()
    for pat, repl in _VOLATILE:
        out = pat.sub(repl, out)
    return out.strip()


def fingerprint(host: str, exe: str, cmdline: str, user: str) -> str:
    """Stable identity for 'this program, run this way, by this user'."""
    raw = "\x00".join([host, exe or "", normalize_cmdline(cmdline), user or ""])
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def now() -> int:
    return int(time.time())


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def classify_ip(ip: str) -> str:
    """Bucket an address so public egress stands out from local chatter."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_private:
        return "private"
    return "public"


_rdns_cache: dict[str, str] = {}


def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    """Best-effort PTR lookup. Only called when --enrich is passed."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ""
    finally:
        socket.setdefaulttimeout(old)
    _rdns_cache[ip] = name
    return name


def short(text: str, width: int = 70) -> str:
    text = (text or "").replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


# Directories that usrmerge collapsed. dpkg records exactly one spelling of a
# path and it is not always the one you have in hand: /usr/bin/fusermount3 is
# on disk, but dpkg knows it as /bin/fusermount3. Asking with the wrong form
# returns "no path found" for a perfectly packaged file — which reported a
# stock setuid binary as an unowned root backdoor.
_USRMERGE = (("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"),
             ("/lib/", "/usr/lib/"), ("/lib64/", "/usr/lib64/"))


def dpkg_candidates(path: str) -> list:
    """Every spelling of this path that dpkg might have recorded."""
    out = [path]
    try:
        real = os.path.realpath(path)
        if real != path:
            out.append(real)
    except OSError:
        pass
    for cand in list(out):
        for bare, under_usr in _USRMERGE:
            if cand.startswith(bare):
                out.append(under_usr + cand[len(bare):])
            elif cand.startswith(under_usr):
                out.append(bare + cand[len(under_usr):])
    return list(dict.fromkeys(out))


def package_manager(exists=os.path.exists) -> str:
    """"dpkg", "rpm" or "" for the package database this system keeps."""
    if exists("/var/lib/dpkg/status"):
        return "dpkg"
    if exists("/var/lib/rpm") or exists("/usr/lib/sysimage/rpm"):
        return "rpm"
    return ""


# Package ownership answers, per process (perf/lighter-faster, 2026-11-04).
# Measured on the live daemon: the PAM, setuid and key-reader audits asked
# `dpkg -S` once per path spelling, about 0.12 s CPU each because dpkg-query
# reads every *.list file, and the same few hundred paths every run. Ownership
# changes only when the package database changes, so an answer is reused only
# while the database stamp (mtime and size of the status file and the info
# directory, or the rpm database) is unchanged, and never beyond OWNS_TTL_S.
# Errors and timeouts are never cached: they keep the old "unknown" answer.
# The TTL is longer than the hourly audits' cadence (implant, backdoor), or
# every hourly run would find its answers just expired; the stamp is what
# invalidates, the TTL only bounds what an in-place edit of a *.list file
# (which keeps the directory mtime) could hold back.
OWNS_TTL_S = 6 * 3600.0
OWNS_MAX = 4096
_OWNS = {}
_OWNS_STAMP = [None]
_OWNS_LOCK = threading.Lock()
_PKGDB_PATHS = {"dpkg": ("/var/lib/dpkg/status", "/var/lib/dpkg/info", "/var/lib/dpkg/diversions"),
                "rpm": ("/var/lib/rpm", "/usr/lib/sysimage/rpm",
                        "/var/lib/rpm/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite")}


def pkgdb_stamp(manager, stat=os.stat):
    """What changes whenever packages are installed, removed or diverted."""
    out = [manager]
    for path in _PKGDB_PATHS.get(manager, ()):
        try:
            st = stat(path)
            out.append((path, st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((path, None, None))
    return tuple(out)


def _owns_cached(key, stamp, now):
    with _OWNS_LOCK:
        if _OWNS_STAMP[0] != stamp:
            _OWNS.clear()
            _OWNS_STAMP[0] = stamp
            return None
        hit = _OWNS.get(key)
        if hit is None or now - hit[0] > OWNS_TTL_S or now < hit[0]:
            return None
        return hit[1]


def _owns_remember(key, stamp, now, value):
    with _OWNS_LOCK:
        if _OWNS_STAMP[0] != stamp:
            return
        if len(_OWNS) >= OWNS_MAX:
            _OWNS.clear()
        _OWNS[key] = (now, value)


def _dpkg_search(cands, run):
    """True/False from one `dpkg -S` over every spelling; None when dpkg failed.

    Same verdict as asking each spelling alone (exit 0 and a "pkg: path" line):
    a spelling is found unless dpkg-query names it in "no path found". Exit
    status 1 only means some spelling was not found; anything else is an error.
    """
    r = run(["dpkg", "-S", *cands], capture_output=True, text=True, errors="replace", timeout=8)
    if r.returncode not in (0, 1):
        return None
    missing = {line.split("matching pattern ", 1)[1].strip()
               for line in (r.stderr or "").splitlines() if "no path found matching pattern " in line}
    found = [c for c in cands if c not in missing]
    if r.returncode == 0 and not found:
        return None         # exit 0 yet every spelling reported missing: not a format we know
    return bool(found) and ":" in (r.stdout or "")


def dpkg_owns(path: str, manager=None, run=None, clock=time.time) -> bool:
    """True when a package owns this file, under any of its path spellings.

    Asks dpkg on Debian-family systems and rpm on Red Hat/SUSE-family ones
    (before 2026-10-24 only dpkg, so on RPM systems every file read as
    unowned). A False here is used to escalate findings, so a wrong False is
    expensive: it turns stock system files into critical alerts. When no
    package manager answers, this returns False and callers should treat that
    as "unknown", not as proof the file is unmanaged.

    dpkg is asked once for every spelling, and an answer is reused while the
    package database is unchanged (OWNS_TTL_S at most); see _OWNS above.
    """
    manager = package_manager() if manager is None else manager
    run = subprocess.run if run is None else run
    cands = dpkg_candidates(path)
    stamp, now = pkgdb_stamp(manager), clock()
    # The key holds every spelling, the resolved target included: a symlink
    # repointed elsewhere is a new question, never an old answer.
    key = (manager, tuple(cands))
    cached = _owns_cached(key, stamp, now)
    if cached is not None:
        return cached
    if manager == "rpm":
        argv, owned = ["rpm", "-qf"], lambda r: r.returncode == 0 and r.stdout.strip()
    else:
        try:
            verdict = _dpkg_search(cands, run)
        except (OSError, subprocess.SubprocessError):
            return False
        if verdict is not None:
            _owns_remember(key, stamp, now, verdict)
            return verdict
        argv, owned = ["dpkg", "-S"], lambda r: r.returncode == 0 and ":" in r.stdout
    for cand in cands:
        try:
            r = run(argv + [cand], capture_output=True,
                    text=True, errors="replace", timeout=8)
            if owned(r):
                _owns_remember(key, stamp, now, True)
                return True
        except (OSError, subprocess.SubprocessError):
            return False
    # A nonzero rpm exit (or a dpkg that failed the batched form) can be an
    # error rather than "not owned": that False is not remembered.
    return False
    return False

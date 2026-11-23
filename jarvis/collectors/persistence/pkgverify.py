"""Have the binaries an intruder replaces changed since their package installed
them? (ARGUS-SERVER.md W3)

`dpkg --verify` / `rpm -V` recompute file digests against the package
database for a fixed set of packages that a persistent intruder targets
(sshd, sudo, PAM, the C library, login, coreutils, procps, systemd, the
shell). Configuration files are expected to change and are skipped; a changed
digest of any other packaged file is critical, a missing one medium.

The package database is on the same disk as the files, so root can rewrite
both: a clean result is evidence against casual tampering, not proof against a
careful one. Bounded: one package set, a time budget, governed and daily.
"""

import re
import subprocess

from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import package_manager

TIMEOUT_S = 240
MAX_REPORTED = 40
PACKAGES = {
    "dpkg": ("openssh-server", "openssh-client", "sudo", "libc6", "libc-bin", "libpam-modules",
             "libpam-runtime", "login", "passwd", "coreutils", "util-linux", "procps", "systemd",
             "bash", "iproute2", "cron",
             # curlRAT (2025) replaces atd and polkitd (spyware research 2026-10-29);
             # a name that is not installed is skipped by dpkg --verify.
             "at", "polkitd", "policykit-1", "pkexec"),
    "rpm": ("openssh-server", "openssh-clients", "sudo", "glibc", "pam", "shadow-utils", "coreutils",
            "util-linux", "procps-ng", "systemd", "bash", "iproute", "cronie", "at", "polkit"),
}
# dpkg --verify: "??5??????   /usr/bin/x" or "??5?????? c /etc/x"; rpm -V the same
# shape with dots, or "missing   /path".
LINE = re.compile(r"^(?P<flags>missing|[.?SM5DLUGTP]{8,9})\s+(?P<kind>[cdglr]\s+)?(?P<path>/\S.*)$")


def parse(text):
    """([(path, changed_digest, missing)], unverifiable count) for
    non-configuration files. "?" in the digest column means the file could not
    be read (no privilege): not checked, never clean (I1)."""
    out, unverifiable = [], 0
    for line in (text or "").splitlines():
        m = LINE.match(line.strip())
        if not m or (m["kind"] or "").strip() == "c":
            continue
        flags = m["flags"]
        missing = flags == "missing"
        digest = not missing and len(flags) >= 3 and flags[2] == "5"
        if not missing and len(flags) >= 3 and flags[2] == "?":
            unverifiable += 1
        elif missing or digest:
            out.append((m["path"].strip(), digest, missing))
    return out, unverifiable


def run_verify(manager, run=subprocess.run):
    """(text, problem)."""
    pkgs = PACKAGES[manager]
    argv = ["dpkg", "--verify", *pkgs] if manager == "dpkg" else ["rpm", "-V", *pkgs]
    try:
        r = run(argv, capture_output=True, text=True, errors="replace", timeout=TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        return "", f"{argv[0]} verification took longer than {TIMEOUT_S} s"
    except OSError as exc:
        return "", f"{argv[0]} could not run: {exc.strerror or exc}"
    # Both exit non-zero when anything differs or a listed package is absent.
    if not r.stdout.strip() and r.returncode != 0 and "not installed" not in (r.stderr or ""):
        return "", f"{argv[0]} failed: " + ((r.stderr or "").strip().splitlines() or [""])[-1][:200]
    return r.stdout, ""


def audit(manager=None, run=subprocess.run):
    manager = package_manager() if manager is None else manager
    if manager not in PACKAGES:
        return [_finding("visibility", "low", "package integrity not checked",
                         "no dpkg or rpm database on this system", "pkgverify", host="wsl")]
    text, problem = run_verify(manager, run=run)
    if problem:
        return [_finding("visibility", "medium", "package integrity not checked", problem,
                         "pkgverify", host="wsl")]
    out = []
    changed, unverifiable = parse(text)
    if unverifiable:
        out.append(_finding("visibility", "low", "some packaged files could not be verified",
                            f"{unverifiable} file(s) were unreadable to the verifier", "pkgverify", host="wsl"))
    for path, digest, missing in changed[:MAX_REPORTED]:
        if digest:
            out.append(_finding("integrity", "critical", f"packaged file changed: {path}",
                                f"its digest no longer matches what {manager} installed; a replaced "
                                "system binary or library is a classic persistence step", path, host="wsl"))
        elif missing:
            out.append(_finding("integrity", "medium", f"packaged file missing: {path}",
                                f"{manager} installed it and it is gone", path, host="wsl"))
    return out

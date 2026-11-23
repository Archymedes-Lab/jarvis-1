"""Security fixes this server has not installed, pending updates and pending reboots.

docs/architecture/ARGUS-SERVER.md W11. Local reads only: the package database,
a simulated upgrade (nothing is installed or changed), the package lists' age,
the reboot markers and the kernels on disk, and the index the `distrovuln` job
built from the distribution's own security data. CISA KEV (a feed already in
the store) ranks what matters first.

Only a fix that exists and is not installed is reported: that is the one thing
an operator can act on today. Data that cannot be read is said so, never
treated as "no CVEs".
"""

import glob
import os
import platform
import subprocess
import time

from jarvis.core import debver, vulnindex
from jarvis.core.finding import LOCAL_HOST

LISTS_STALE_DAYS = 7
REBOOT_GRACE_S = 86400
MAX_LISTED = 10
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def _f(severity, title, detail, where=""):
    return {"category": "patches", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}


def _run(argv, timeout=120):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                           timeout=timeout, env=ENV, cwd="/")
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


# --- facts -----------------------------------------------------------------

def installed_dpkg(run=_run):
    """{binary: (version, source, source_version)} of installed packages, or None."""
    fmt = "${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n"
    code, out = run(["dpkg-query", "-W", "-f", fmt])
    if code != 0:
        return None
    pkgs = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or not parts[0].startswith("ii"):
            continue
        name = parts[1].split(":", 1)[0]
        pkgs[name] = (parts[2], parts[3] or name, parts[4] or parts[2])
    return pkgs


def pending_apt(run=_run):
    """(all pending, security pending) package names from a simulated upgrade, or None."""
    code, out = run(["apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "dist-upgrade"])
    if code != 0:
        return None
    pending, security = [], []
    for line in out.splitlines():
        if not line.startswith("Inst "):
            continue
        name = line.split()[1]
        pending.append(name)
        if "-security" in line or "Security" in line:
            security.append(name)
    return pending, security


def pending_dnf(run=_run):
    """(None, security advisories pending) on RPM systems, or None."""
    for tool in ("dnf", "yum"):
        code, out = run([tool, "-q", "--cacheonly", "updateinfo", "list", "--security"])
        if code == 0:
            return None, [line.split()[-1] for line in out.splitlines() if line.strip()]
    return None


def lists_age_days(now, lists="/var/lib/apt/lists", stamp="/var/lib/apt/periodic/update-success-stamp"):
    """Days since the package lists were last refreshed, or None when unknown."""
    times = []
    for path in [stamp, *glob.glob(os.path.join(lists, "*Release"))]:
        try:
            times.append(os.stat(path).st_mtime)
        except OSError:
            continue
    return (now - max(times)) / 86400 if times else None


def reboot_state(now, marker="/run/reboot-required", modules="/lib/modules", running=None):
    """(since or None, packages asking, newest installed kernel newer than running)."""
    since, why = None, []
    try:
        since = os.stat(marker).st_mtime
        with open(marker + ".pkgs", encoding="utf-8", errors="replace") as fh:
            why = sorted({line.strip() for line in fh if line.strip()})[:MAX_LISTED]
    except OSError:
        pass
    running = running or platform.release()
    kernels = [os.path.basename(p) for p in glob.glob(os.path.join(modules, "*"))
               if os.path.isdir(os.path.join(p, "kernel"))]
    newest = max(kernels, key=_kernel_key) if kernels else ""
    stale_kernel = bool(newest and running in kernels and _kernel_key(newest) > _kernel_key(running))
    return since, why, (newest if stale_kernel else "")


def _kernel_key(release):
    # 6.8.0-45-generic: numeric fields in order; flavour ignored.
    out = []
    for part in release.replace("-", ".").split("."):
        if part.isdigit():
            out.append(int(part))
        else:
            break
    return out


def kev_set(store):
    """CVE ids from the CISA KEV feed already in the store (empty when absent)."""
    try:
        rows = store.db.execute("SELECT value FROM indicators WHERE kind='cve'").fetchall()
    except Exception:  # noqa: BLE001 - a missing table means no KEV data, stated below
        return set()
    return {str(r[0]).upper() for r in rows}


# --- judgement --------------------------------------------------------------

def fixable(installed, index):
    """{package: (installed version, fixed version, [cves], advisory)} where a
    published fix is newer than what is installed. Ubuntu indexes binary names,
    Debian source names (with source versions)."""
    by_source = index.get("match") == "source"
    packages = index.get("packages") or {}
    out = {}
    seen = set()
    for binary, (version, source, source_version) in installed.items():
        key, have = (source, source_version) if by_source else (binary, version)
        if key in seen:
            continue
        entries = packages.get(key)
        if not entries:
            continue
        cves, fixed_max, advisory = set(), "", ""
        for fixed, ids, adv, _sev in entries:
            if debver.older(have, fixed):
                cves.update(ids)
                if not fixed_max or debver.compare(fixed, fixed_max) > 0:
                    fixed_max, advisory = fixed, adv
        if fixed_max:
            seen.add(key)
            out[key] = (have, fixed_max, sorted(cves), advisory)
    return out


def group_by_source(fixes, installed):
    """Per source package: one entry for ffmpeg, not one per libav* binary."""
    out = {}
    for name, (have, fixed, cves, advisory) in fixes.items():
        source = installed.get(name, (None, name, None))[1] if name in installed else name
        g = out.setdefault(source, {"binaries": [], "cves": set(), "have": have, "fixed": fixed,
                                    "advisory": advisory, "pro": False})
        g["binaries"].append(name)
        g["cves"].update(cves)
        if debver.compare(fixed, g["fixed"]) > 0:
            g["fixed"], g["advisory"], g["have"] = fixed, advisory, have
        g["pro"] = g["pro"] or "esm" in fixed
    for g in out.values():
        g["cves"] = sorted(g["cves"])
        g["binaries"].sort()
    return out


def audit(store=None, *, run=_run, now=None, index=None, kev=None, release=None):
    now = time.time() if now is None else now
    out = []
    installed = installed_dpkg(run)
    if installed is None:
        dnf = pending_dnf(run)
        if dnf is None:
            return [_f("low", "installed packages could not be read",
                       "neither dpkg nor dnf/yum answered; pending security fixes are not "
                       "observed, which is not the same as none", "package database")]
        security = dnf[1]
        out.append(_f("medium" if security else "ok",
                      f"{len(security)} security advisories pending" if security
                      else "no security advisories pending",
                      ", ".join(security[:MAX_LISTED]) + (" ..." if len(security) > MAX_LISTED else "")
                      if security else "dnf updateinfo (cached metadata) lists none", "dnf updateinfo"))
    else:
        out.extend(_debian_family(store, installed, run, now, index, kev, release))
    out.extend(_reboot(now))
    return out


def _debian_family(store, installed, run, now, index, kev, release):
    out = []
    age = lists_age_days(now)
    if age is None or age > LISTS_STALE_DAYS:
        out.append(_f("medium", "package lists are stale — pending updates unknown",
                      f"the apt lists were last refreshed {'never' if age is None else f'{age:.0f} days ago'}; "
                      f"enable apt-daily (or unattended-upgrades) so this server learns about fixes",
                      "/var/lib/apt/lists"))
    pending = pending_apt(run)
    distro, codename = release or vulnindex.release()
    index = index if index is not None else vulnindex.load(distro, codename)
    kev = kev if kev is not None else (kev_set(store) if store is not None else set())
    # No index, or one without package data, is "not observed": never a clean result.
    if not index or not index.get("packages"):
        out.append(_f("low", "fixable CVEs not observed yet",
                      "the distribution's security data has not been downloaded (the daily "
                      "`distrovuln` job does it); until then only pending updates are reported",
                      "distrovuln"))
        if pending and pending[1]:
            sec = pending[1]
            out.append(_f("medium", f"{len(sec)} security updates pending",
                          ", ".join(sec[:MAX_LISTED]) + (" ..." if len(sec) > MAX_LISTED else ""),
                          "apt-get -s dist-upgrade"))
        return out
    fixes = group_by_source(fixable(installed, index), installed)
    known = {p: f for p, f in fixes.items() if any(c.upper() in kev for c in f["cves"])}
    for pkg, f in sorted(known.items()):
        exploited = [c for c in f["cves"] if c.upper() in kev]
        via = " (Ubuntu Pro / ESM)" if f["pro"] else ""
        out.append(_f("high", f"known-exploited vulnerability fixed but not installed: {pkg}",
                      f"{', '.join(exploited[:5])} (CISA KEV) affect {pkg} {f['have']} "
                      f"({', '.join(f['binaries'][:4])}); {f['advisory'] or 'the advisory'} fixed it in "
                      f"{f['fixed']}{via}. Install the update and restart what uses it.", pkg))
    rest = {p: f for p, f in fixes.items() if p not in known}
    for pro, title in ((False, "{n} packages have security fixes not installed"),
                       (True, "{n} packages have security fixes only through Ubuntu Pro (ESM)")):
        group = {p: f for p, f in rest.items() if f["pro"] == pro}
        if not group:
            continue
        ranked = sorted(group.items(), key=lambda kv: -len(kv[1]["cves"]))
        listed = "; ".join(f"{p} {f['have']} → {f['fixed']} ({len(f['cves'])} CVE)" for p, f in ranked[:MAX_LISTED])
        total = len({c for f in group.values() for c in f["cves"]})
        hint = (" Enable Ubuntu Pro (`pro attach`, free for a few personal machines) or accept the "
                "exposure; plain `apt upgrade` cannot install these." if pro else
                " `apt upgrade` installs them.")
        out.append(_f("medium", title.format(n=len(group)),
                      f"{total} CVEs fixed; {listed}" + (" ..." if len(group) > MAX_LISTED else "") + "." + hint,
                      "distrovuln"))
    if not fixes:
        out.append(_f("ok", "no published security fix is missing",
                      f"{len(installed)} installed packages checked against {index.get('distro')} "
                      f"{index.get('codename')} security data from {index.get('generated') or 'an undated feed'}",
                      "distrovuln"))
    fetched = index.get("fetched_at") or 0
    if fetched and (time.time() if now is None else now) - fetched > 3 * 86400:
        out.append(_f("low", "distribution security data is more than three days old",
                      "the daily `distrovuln` job has not refreshed it; newer fixes are not judged",
                      "distrovuln"))
    return out


def _reboot(now):
    since, why, kernel = reboot_state(now)
    if since is None and not kernel:
        return []
    late = (since is not None and now - since > REBOOT_GRACE_S) or bool(kernel)
    parts = []
    if since is not None:
        parts.append(f"requested {int((now - since) // 3600)} h ago"
                     + (f" by {', '.join(why)}" if why else ""))
    if kernel:
        parts.append(f"kernel {kernel} is installed but {platform.release()} is running, "
                     f"so its fixes are not in effect")
    return [_f("medium" if late else "low", "a reboot is pending",
               "; ".join(parts), "/run/reboot-required")]

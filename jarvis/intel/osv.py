"""The public OSV advisories for the application dependencies this server runs.

docs/architecture/ARGUS-SERVER.md W12. Same privacy rule as distrovuln (owner
decision 2026-10-25): nothing about this machine leaves it. OSV's per-ecosystem
dumps are public files; the job downloads only the ecosystems the `appcode`
inventory found here, keeps only advisories naming an inventoried package, and
deletes the dump. Matching happens locally (collectors/appcode/deps.py).

Measured 2026-10-28: npm all.zip 219 MB, PyPI 37 MB, Go 13 MB, Packagist 11 MB,
Maven 10 MB, RubyGems 5 MB, crates.io 4 MB. The dumps are streamed to disk
under a byte cap and read one member at a time under a member cap, so memory
stays at one advisory plus the filtered index, never a whole dump. A failed
download keeps the last good copy of that ecosystem and says so.
"""

import json
import os
import time
import urllib.request
import zipfile

from jarvis.core import osvindex
from jarvis.core.finding import LOCAL_HOST

DUMP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
UA = "jarvis-osv/1.0 (+local dependency audit)"
MAX_DOWNLOAD = 384 * 1024 * 1024       # npm measured at 219 MB
MAX_MEMBER = 4 * 1024 * 1024           # one advisory; the largest seen is well under 1 MB
MAX_MEMBERS = 1_000_000                # npm measured at ~220 000
MAX_SUMMARY = 160
FETCH_TIMEOUT = 600
CHUNK = 1024 * 1024
SEVERITIES = {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}


def _download(url, dest, max_bytes, timeout):
    """Stream `url` into `dest`, refusing more than `max_bytes`."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    size = 0
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as out:
        while True:
            block = resp.read(CHUNK)
            if not block:
                break
            size += len(block)
            if size > max_bytes:
                raise ValueError(f"download exceeds {max_bytes} bytes")
            out.write(block)


def _intervals(events):
    """OSV range events, in order, as [introduced, fixed, last_affected] triples."""
    out, start = [], None
    for ev in events or ():
        if not isinstance(ev, dict):
            continue
        if "introduced" in ev:
            if start is not None:
                out.append([start, None, None])
            start = str(ev["introduced"])
        elif "fixed" in ev and start is not None:
            out.append([start, str(ev["fixed"]), None])
            start = None
        elif "last_affected" in ev and start is not None:
            out.append([start, None, str(ev["last_affected"])])
            start = None
    if start is not None:
        out.append([start, None, None])
    return out


def _entries(doc, eco, wanted):
    """(normalised name, compact entry) for each affected package we run."""
    if not isinstance(doc, dict) or doc.get("withdrawn"):
        return
    vid = str(doc.get("id") or "")
    severity = str((doc.get("database_specific") or {}).get("severity") or "").upper()
    for aff in doc.get("affected") or ():
        pkg = (aff or {}).get("package") or {}
        if pkg.get("ecosystem") != eco:
            continue
        name = osvindex.normalise(eco, pkg.get("name"))
        if name not in wanted:
            continue
        ranges = [iv for r in aff.get("ranges") or () if r.get("type") in ("ECOSYSTEM", "SEMVER")
                  for iv in _intervals(r.get("events"))]
        versions = [str(v) for v in aff.get("versions") or ()][:2000]
        if not ranges and not versions:
            continue
        yield name, {"id": vid, "aliases": [str(a) for a in doc.get("aliases") or ()][:20],
                     "severity": severity if severity in SEVERITIES else "",
                     "summary": str(doc.get("summary") or "")[:MAX_SUMMARY],
                     "malicious": vid.startswith("MAL-"), "ranges": ranges, "versions": versions}


def parse_dump(path, eco, wanted):
    """{name: [entry]} for `wanted` names from one ecosystem dump on disk."""
    out = {}
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            raise ValueError(f"more than {MAX_MEMBERS} advisories in {eco}")
        for info in infos:
            if not info.filename.endswith(".json"):
                continue
            with zf.open(info) as fh:
                raw = fh.read(MAX_MEMBER + 1)
            if len(raw) > MAX_MEMBER:
                raise ValueError(f"{info.filename} exceeds {MAX_MEMBER} bytes")
            # One malformed advisory (nested past the parser depth, or a list
            # where an object belongs) is skipped; it must not fail the refresh.
            try:
                doc = json.loads(raw)
                found = list(_entries(doc, eco, wanted))
            except (ValueError, RecursionError, AttributeError, TypeError):
                continue
            for name, entry in found:
                out.setdefault(name, []).append(entry)
    return out


def refresh(download=_download, root=osvindex.ROOT, now=None):
    """Refresh the advisories for every ecosystem in the inventory. Returns findings."""
    now = int(time.time() if now is None else now)
    inventory = osvindex.load(osvindex.inventory_path(root)) or {}
    wanted = {}
    for p in inventory.get("packages") or ():
        if p.get("eco") in osvindex.ECOSYSTEMS:
            wanted.setdefault(p["eco"], set()).add(osvindex.normalise(p["eco"], p.get("name")))
    if not wanted:
        return [_f("low", "no application dependencies to look up yet",
                   "the `appcode` scan has not recorded any lockfile or virtual environment "
                   "here, so no OSV data was downloaded", "osv")]
    index = osvindex.load(osvindex.index_path(root)) or {}
    ecosystems = index.get("ecosystems") if isinstance(index.get("ecosystems"), dict) else {}
    failed, counts = [], []
    for eco in sorted(wanted):
        url = DUMP_URL.format(eco=eco)
        part = os.path.join(root, f"{eco}.zip.part")
        os.makedirs(root, mode=0o700, exist_ok=True)
        try:
            download(url, part, MAX_DOWNLOAD, FETCH_TIMEOUT)
            packages = parse_dump(part, eco, wanted[eco])
        except (OSError, ValueError, zipfile.BadZipFile, EOFError) as exc:
            old = (ecosystems.get(eco) or {}).get("fetched_at")
            failed.append(f"{eco} ({type(exc).__name__}: {str(exc)[:120]}; "
                          + (f"last good copy {time.strftime('%Y-%m-%d', time.gmtime(old))})"
                             if old else "no earlier copy)"))
            continue
        finally:
            try:
                os.unlink(part)
            except OSError:
                pass
        ecosystems[eco] = {"fetched_at": now, "source": url, "packages": packages}
        counts.append(f"{eco} {sum(len(v) for v in packages.values())} advisories "
                      f"for {len(packages)}/{len(wanted[eco])} packages")
    osvindex.write_json(osvindex.index_path(root), {"ecosystems": ecosystems})
    if failed:
        return [_f("low", "dependency advisories could not be refreshed",
                   "; ".join(failed) + ". Dependencies are judged on older data, or not at all, "
                   "until the next run.", "osv")]
    return [_f("ok", "dependency advisories are current", "; ".join(counts) + ".", "osv")]


def _f(severity, title, detail, where):
    return {"category": "appcode", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}

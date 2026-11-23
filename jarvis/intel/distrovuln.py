"""The distribution's own security data, reduced to "which package versions fix which CVEs".

docs/architecture/ARGUS-SERVER.md W11. Owner decision 2026-10-25: local data
only, nothing about this machine leaves it. Once a day the `distrovuln` job
downloads the release's OVAL definitions (Canonical USN OVAL for Ubuntu, Debian
OVAL for Debian; public files, fetched like any other feed), parses them as a
stream under byte and count caps, and writes a compact index beside the store:

    {"distro", "codename", "source", "generated", "fetched_at",
     "match": "binary" | "source",
     "packages": {name: [[fixed_version, [CVE, ...], advisory, severity], ...]}}

Ubuntu names binary packages (match installed binary name and version); Debian
names source packages (match installed source name and source version).
`collectors/host/patches.py` compares installed versions with core/debver.py
and reports only fixes that exist and are not installed.

Unknown distributions and unreadable data are stated, never treated as clean.
"""

import bz2
import io
import json
import os
import time
import xml.etree.ElementTree as ET

from jarvis.core import inflate
from jarvis.core.finding import LOCAL_HOST
from jarvis.core.vulnindex import OS_RELEASE, ROOT, index_path, load, release
from jarvis.intel import feeds

MAX_DOWNLOAD = 32 * 1024 * 1024          # measured 2026-10-25: Debian 12 9.7 MB, Ubuntu 24.04 1.3 MB
MAX_PLAIN = 512 * 1024 * 1024            # measured: Debian 12 129 MB, Ubuntu 24.04 36 MB
MAX_DEFINITIONS = 400_000                # measured: Debian 12 60 031
MAX_TEXT = 4096
FETCH_TIMEOUT = 180

SOURCES = {
    "ubuntu": ("https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.usn.oval.xml.bz2", "binary"),
    "debian": ("https://www.debian.org/security/oval/oval-definitions-{codename}.xml.bz2", "source"),
}


def source_for(distro, codename):
    """(url, match) for a supported release, or None."""
    spec = SOURCES.get(distro)
    if not spec or not codename or not codename.isalnum():
        return None
    return spec[0].format(codename=codename), spec[1]


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _text(el):
    return (el.text or "").strip()[:MAX_TEXT]


def parse_oval(stream):
    """{package: [[fixed_version, [cves], advisory, severity], ...]} and the
    generator timestamp, from an OVAL definitions stream. Holds one element at a
    time plus the small maps that link definitions to package versions."""
    defs = {}              # def id -> (cves, advisory, severity, [test refs])
    tests, objects, variables, states = {}, {}, {}, {}
    generated = ""
    count = 0
    for _, el in ET.iterparse(stream, events=("end",)):
        tag = _local(el.tag)
        if tag == "timestamp" and not generated:
            generated = _text(el)
        elif tag == "definition":
            count += 1
            if count > MAX_DEFINITIONS:
                raise inflate.InflateLimit(f"more than {MAX_DEFINITIONS} OVAL definitions")
            if el.get("class") in ("patch", "vulnerability"):
                cves, advisory, severity = [], "", ""
                for ref in el.iter():
                    t = _local(ref.tag)
                    if t == "reference":
                        rid = (ref.get("ref_id") or "")[:64]
                        if ref.get("source") == "CVE" and rid.startswith("CVE-"):
                            cves.append(rid)
                        elif not advisory and ref.get("source") in ("USN", "DSA", "DLA"):
                            advisory = rid
                    elif t == "severity" and not severity:
                        severity = _text(ref)[:32]
                    elif t == "title" and not advisory:
                        advisory = _text(ref)[:120]
                refs = [c.get("test_ref") for c in el.iter() if _local(c.tag) == "criterion" and c.get("test_ref")]
                if refs:
                    defs[el.get("id")] = (sorted(set(cves)), advisory, severity, refs)
            el.clear()
        elif tag == "dpkginfo_test":
            obj = state = None
            for c in el:
                if _local(c.tag) == "object":
                    obj = c.get("object_ref")
                elif _local(c.tag) == "state":
                    state = c.get("state_ref")
            if obj and state:
                tests[el.get("id")] = (obj, state)
            el.clear()
        elif tag == "dpkginfo_object":
            for c in el:
                if _local(c.tag) == "name":
                    objects[el.get("id")] = ("var", c.get("var_ref")) if c.get("var_ref") else ("name", _text(c))
            el.clear()
        elif tag == "constant_variable":
            variables[el.get("id")] = [_text(v) for v in el if _local(v.tag) == "value"][:256]
            el.clear()
        elif tag == "dpkginfo_state":
            for c in el:
                if _local(c.tag) == "evr" and c.get("operation") == "less than":
                    states[el.get("id")] = _text(c)
            el.clear()
    index = {}
    for cves, advisory, severity, refs in defs.values():
        for ref in refs:
            test = tests.get(ref)
            if not test:
                continue                       # inventory or architecture checks
            fixed = states.get(test[1], "")
            # A "less than 0:0" style state marks an unfixed issue: nothing to install.
            if not fixed or fixed.split(":")[-1] in ("0", ""):
                continue
            kind, value = objects.get(test[0], ("", ""))
            names = variables.get(value, []) if kind == "var" else ([value] if value else [])
            for name in names:
                index.setdefault(name, []).append([fixed, cves, advisory, severity])
    return index, generated


def refresh(fetch=feeds.fetch, path=OS_RELEASE, root=ROOT, now=None):
    """Download and index this release's security data. Returns findings."""
    now = time.time() if now is None else now
    distro, codename = release(path)
    src = source_for(distro, codename)
    if not src:
        return [_finding("low", "distribution security data is not available here",
                         f"CVE matching supports Debian and Ubuntu releases; this system reports "
                         f"'{distro or 'unknown'} {codename}'. Fixable CVEs are not observed, which is "
                         f"not the same as none.", OS_RELEASE)]
    url, match = src
    try:
        raw = fetch(url, MAX_DOWNLOAD, timeout=FETCH_TIMEOUT)
        stream = inflate.Bounded(bz2.open(io.BytesIO(raw)), MAX_PLAIN)
        packages, generated = parse_oval(stream)
    except (OSError, ValueError, EOFError, ET.ParseError) as exc:
        old = load(distro, codename, root)
        age = f"; the last good copy is from {time.strftime('%Y-%m-%d', time.gmtime(old['fetched_at']))}" \
            if old else "; there is no earlier copy"
        return [_finding("low", "distribution security data could not be refreshed",
                         f"{type(exc).__name__}: {str(exc)[:160]}{age}. Fixable CVEs are judged on "
                         f"older data until the next run.", url)]
    if not packages:
        return [_finding("low", "distribution security data was empty",
                         "The downloaded definitions named no package versions; the index was kept "
                         "as it was rather than replaced with nothing.", url)]
    doc = {"distro": distro, "codename": codename, "source": url, "generated": generated,
           "fetched_at": int(now), "match": match, "packages": packages}
    os.makedirs(root, mode=0o700, exist_ok=True)
    target = index_path(distro, codename, root)
    tmp = target + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"))
    os.replace(tmp, target)
    advisories = sum(len(v) for v in packages.values())
    return [_finding("ok", "distribution security data is current",
                     f"{advisories} fixed versions for {len(packages)} {distro} {codename} packages "
                     f"(published {generated or 'undated'}).", url)]


def _finding(severity, title, detail, where):
    return {"category": "patches", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}

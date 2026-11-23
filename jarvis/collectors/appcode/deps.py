"""Which installed application dependencies OSV lists as vulnerable or malicious.

Severity (Jev advisory 2026-10-28 agreed 0.94 on the first): a dependency OSV
lists as a known malicious package is critical, one per package and project; a
dependency with a CISA KEV CVE is high, one per package and project; everything
else is one finding per project, medium when any advisory is rated high or
critical, low otherwise. An ecosystem without OSV data, or with data more than
three days old, is said so and never reported clean.
"""

from jarvis.core import osvindex
from jarvis.core.finding import LOCAL_HOST

STALE_S = 3 * 86400
MAX_LISTED = 10
SERIOUS = {"CRITICAL", "HIGH"}


def _f(severity, title, detail, where):
    return {"category": "appcode", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": LOCAL_HOST}


def kev_set(store):
    """CVE ids from the CISA KEV feed already in the store (empty when absent).
    The same read as collectors/host/patches.py; collector domains do not
    import each other."""
    try:
        rows = store.db.execute("SELECT value FROM indicators WHERE kind='cve'").fetchall()
    except Exception:  # noqa: BLE001 - a missing table means no KEV data
        return set()
    return {str(r[0]).upper() for r in rows}


def _fix_for(version, entry):
    """The first fixed version above `version` in the range that holds it, or ""."""
    fixes = [f for intro, f, _last in entry.get("ranges") or ()
             if f and osvindex.compare(version, f) < 0
             and (intro in (None, "", "0") or osvindex.compare(version, intro) >= 0)]
    return min(fixes, key=_Key) if fixes else ""


class _Key:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return osvindex.compare(self.v, other.v) < 0


def _ids(entries):
    ids = []
    for e in entries:
        cves = [a for a in e.get("aliases") or () if a.upper().startswith("CVE-")]
        ids.append(e["id"] + (f" ({cves[0]})" if cves else ""))
    return ids


def judge(inventory, index, kev, now):
    """Findings for `inventory` ([{eco, name, version, path, project}])."""
    ecosystems = (index or {}).get("ecosystems") or {}
    seen, unjudged, judged, stale = set(), {}, 0, set()
    hits = {}                                   # project -> [(pkg, version, entries)]
    out = []
    for p in inventory:
        key = (p["eco"], p["name"], p["version"], p["project"])
        if key in seen:
            continue
        seen.add(key)
        data = ecosystems.get(p["eco"])
        if not data:
            unjudged[p["eco"]] = unjudged.get(p["eco"], 0) + 1
            continue
        judged += 1
        if now - (data.get("fetched_at") or 0) > STALE_S:
            stale.add(p["eco"])
        entries = [e for e in (data.get("packages") or {}).get(p["name"]) or ()
                   if osvindex.affected(p["version"], e)]
        if not entries:
            continue
        label = f"{p['name']} {p['version']}"
        malicious = [e for e in entries if e.get("malicious")]
        if malicious:
            out.append(_f("critical", f"known malicious package installed: {p['name']}",
                          f"{label} ({p['eco']}, {p['path']}) is listed by OSV as malicious "
                          f"({', '.join(e['id'] for e in malicious[:3])}). Remove it, rotate every "
                          f"credential the application could reach, and treat the host as "
                          f"compromised until checked.", p["project"]))
            continue
        exploited = sorted({a for e in entries for a in e.get("aliases") or () if a.upper() in kev})
        if exploited:
            fix = max((_fix_for(p["version"], e) for e in entries), key=lambda v: _Key(v or "0"))
            out.append(_f("high", f"known-exploited vulnerability in dependency {p['name']}",
                          f"{', '.join(exploited[:5])} (CISA KEV) affect {label} ({p['eco']}, "
                          f"{p['path']}); "
                          + (f"fixed in {fix}. Upgrade and redeploy." if fix else
                             "no fixed version is published; remove or isolate it."),
                          p["project"]))
            continue
        hits.setdefault(p["project"], []).append((p, entries))
    for project, items in sorted(hits.items()):
        serious = any(e.get("severity") in SERIOUS for _p, es in items for e in es)
        ranked = sorted(items, key=lambda it: (-sum(e.get("severity") in SERIOUS for e in it[1]),
                                               -len(it[1]), it[0]["name"]))
        parts = []
        for p, entries in ranked[:MAX_LISTED]:
            fixes = [_fix_for(p["version"], e) for e in entries]
            fix = "no fix published" if not all(fixes) else \
                f"fixed in {max(fixes, key=_Key)}"
            parts.append(f"{p['name']} {p['version']} → {fix} ({', '.join(_ids(entries)[:3])})")
        out.append(_f("medium" if serious else "low",
                      f"vulnerable dependencies in {project.rstrip('/').rsplit('/', 1)[-1] or project}",
                      f"{len(items)} packages: " + "; ".join(parts) + (" ..." if len(items) > MAX_LISTED else "")
                      + ". Matched locally against OSV advisories.", project))
    for eco in sorted(stale):
        out.append(_f("low", f"{eco} dependency advisory data is more than three days old",
                      "the daily `osv` job has not refreshed it; newer advisories are not judged",
                      "osv"))
    if unjudged:
        out.append(_f("low", "dependencies not checked yet",
                      ", ".join(f"{eco} ({n} packages)" for eco, n in sorted(unjudged.items()))
                      + " have no OSV data here yet (the daily `osv` job downloads it). Not "
                      "observed, which is not the same as no vulnerabilities.", "osv"))
    if judged and not out:
        projects = len({p["project"] for p in inventory})
        out.append(_f("ok", "no known-vulnerable application dependency",
                      f"{judged} dependencies in {projects} projects checked against OSV data",
                      "osv"))
    return out

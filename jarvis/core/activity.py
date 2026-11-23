"""One unified activity model: correlate streams into chains, not alerts.

Phase 9 groundwork. The user must not receive separate streams from Sysmon,
Defender, Geo, Veil, Network, Forge, Firewall, Input and Secrets. This
module groups findings that plausibly belong to one story — same host,
overlapping subject, close in time — into a single chain with one headline.

Conservative by design: correlation is grouping, not causality. A chain
never claims process A caused connection B unless an explicit causal edge
(parent guid, subject id, correlation id) says so. Unexplained members are
labelled as such; uncertainty is preserved, never invented.
"""

import time

WINDOW_SECONDS = 900.0


def _subject(finding):
    for key in ("subject_id", "fp", "where", "title"):
        value = finding.get(key)
        if value:
            return str(value)[:160]
    return ""


def correlate(findings, window=WINDOW_SECONDS, now=None):
    """Group findings into chains. Pure; input order is preserved in output."""
    now = time.time() if now is None else now
    chains = []
    for finding in findings:
        host = finding.get("host", "?")
        subject = _subject(finding)
        stamp = finding.get("last_seen", finding.get("updated_at",
                                                     finding.get("first_seen", now)))
        try:
            stamp = float(stamp)
        except (TypeError, ValueError):
            stamp = now
        placed = False
        for chain in chains:
            if chain["host"] != host:
                continue
            if abs(stamp - chain["last"]) > window:
                continue
            members_subjects = {m["_subject"] for m in chain["members"]}
            if subject and (subject in members_subjects or not members_subjects):
                chain["members"].append({**finding, "_subject": subject})
                chain["last"] = max(chain["last"], stamp)
                chain["first"] = min(chain["first"], stamp)
                placed = True
                break
            # Same causal edge (explicit subject/rule identity) always joins.
            edge = finding.get("subject_id") or finding.get("rule_id")
            if edge and edge == chain.get("edge"):
                chain["members"].append({**finding, "_subject": subject})
                chain["last"] = max(chain["last"], stamp)
                placed = True
                break
        if not placed:
            chains.append({
                "host": host,
                "edge": finding.get("subject_id") or finding.get("rule_id") or "",
                "first": stamp, "last": stamp,
                "members": [{**finding, "_subject": subject}],
            })
    out = []
    for chain in chains:
        members = chain["members"]
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
        worst = min(members, key=lambda m: sev_rank.get(m.get("severity"), 9))
        jobs = sorted({m.get("job", "?") for m in members})
        out.append({
            "host": chain["host"],
            "first": chain["first"], "last": chain["last"],
            "count": len(members),
            "worst_severity": worst.get("severity"),
            "headline": _headline(members, worst),
            "jobs": jobs,
            "causal": bool(chain["edge"]),
            "members": [{k: v for k, v in m.items() if not k.startswith("_")}
                        for m in members],
        })
    out.sort(key=lambda c: (sev_rank.get(c["worst_severity"], 9), -c["last"]))
    return out


def _headline(members, worst):
    if len(members) == 1:
        return str(worst.get("title", "one observation"))
    jobs = sorted({str(m.get("job", "?")) for m in members})
    return (f"{len(members)} related observations across "
            f"{', '.join(jobs[:3])}: {worst.get('title', 'see timeline')}")

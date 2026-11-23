"""What changed since the last report.

The complaint this answers: every report read the same. A finding that has
been open for eight days was presented identically to one seen for the first
time, so there was nothing to read for — no sense of whether the system was
getting better or worse.

So each report is diffed against the last one and states movement first:
what appeared, what got worse, what cleared, and what is simply still there.
Repetition becomes progression.
"""

import json

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}

# Stored on the store's meta table so a report can be compared with the one
# before it across restarts.
META_KEY = "report_last_state"


def _key(finding):
    return "%s|%s|%s" % (finding.get("category", ""), finding.get("title", ""),
                         finding.get("where", ""))


def snapshot(findings):
    """The comparable shape of one report: key -> severity."""
    return {_key(f): f.get("severity", "ok") for f in findings
            if f.get("severity") != "ok"}


def load_previous(store):
    try:
        raw = store.get_meta(META_KEY, "") or ""
        data = json.loads(raw) if raw else {}
    except (ValueError, AttributeError):
        return {}, 0
    if not isinstance(data, dict):
        return {}, 0
    state = data.get("state")
    return (state if isinstance(state, dict) else {}), int(data.get("ts", 0))


def save(store, findings, ts):
    store.set_meta(META_KEY, json.dumps({"ts": int(ts),
                                         "state": snapshot(findings)}))


def compare(previous, current):
    """Movement between two report snapshots.

    Returns appeared / worsened / improved / resolved / unchanged, each a list
    of (key, ...) tuples ready to render.
    """
    appeared, worsened, improved, resolved, unchanged = [], [], [], [], []
    for key, sev in current.items():
        if key not in previous:
            appeared.append((key, sev))
            continue
        was = previous[key]
        if SEV_RANK.get(sev, 9) < SEV_RANK.get(was, 9):
            worsened.append((key, was, sev))
        elif SEV_RANK.get(sev, 9) > SEV_RANK.get(was, 9):
            improved.append((key, was, sev))
        else:
            unchanged.append((key, sev))
    for key, sev in previous.items():
        if key not in current:
            resolved.append((key, sev))
    order = lambda item: SEV_RANK.get(item[-1], 9)
    return {
        "appeared": sorted(appeared, key=order),
        "worsened": sorted(worsened, key=order),
        "improved": sorted(improved, key=order),
        "resolved": sorted(resolved, key=order),
        "unchanged": sorted(unchanged, key=order),
    }


def counts(findings):
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity")
        if sev in out:
            out[sev] += 1
    return out


def trend_line(previous_counts, current_counts):
    """A one-line posture trend, or "" when there is nothing to compare."""
    if not previous_counts:
        return ""
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        was, now_ = int(previous_counts.get(sev, 0)), int(current_counts.get(sev, 0))
        if was == now_:
            continue
        arrow = "up" if now_ > was else "down"
        parts.append("%s %d to %d (%s)" % (sev, was, now_, arrow))
    return "; ".join(parts) if parts else "no change in severity counts"


def title_of(key):
    """The human half of a diff key."""
    bits = key.split("|")
    return bits[1] if len(bits) > 1 else key


def describe(movement, trend=""):
    """Plain-text 'what changed' block. Empty when nothing moved."""
    lines = []
    if trend:
        lines.append("Posture since the last report: %s" % trend)
    labels = (
        ("appeared", "NEW", lambda i: "  [%s] %s" % (i[1].upper(), title_of(i[0]))),
        ("worsened", "WORSENED",
         lambda i: "  [%s -> %s] %s" % (i[1].upper(), i[2].upper(), title_of(i[0]))),
        ("improved", "IMPROVED",
         lambda i: "  [%s -> %s] %s" % (i[1].upper(), i[2].upper(), title_of(i[0]))),
        ("resolved", "NO LONGER OBSERVED (not proof of remediation)",
         lambda i: "  [was %s] %s" % (i[1].upper(), title_of(i[0]))),
    )
    for field, heading, fmt in labels:
        items = movement.get(field) or []
        if not items:
            continue
        lines.append("")
        lines.append("%s (%d):" % (heading, len(items)))
        lines.extend(fmt(i) for i in items[:12])
        if len(items) > 12:
            lines.append("  ... and %d more" % (len(items) - 12))

    still = movement.get("unchanged") or []
    if still:
        lines.append("")
        lines.append("UNCHANGED: %d finding(s) still open and already reported. "
                     "They are not re-listed here; run `jarvis outstanding` for "
                     "the backlog." % len(still))
    return "\n".join(lines).strip()

"""What kind of news a notification is: one table for every channel.

The owner asked that notifications and alerts be categorized, so a phone,
an email client or a chat webhook can sort, filter and mute them. A category
is about what the owner should do, not about how bad it is (severity says
that):

    threat      Security threat      something may be attacking now: look
    exposure    Weakness to fix      a hardening gap, missing fix or risky setting
    updates     Updates              outdated software, or what Argus installed
    monitoring  Not being checked    Argus cannot see something (a blind spot)
    system      Argus itself         the monitor, its channels, its supervisors
    test        Test                 a test the owner asked for

Deterministic: computed from the finding's own category and its job's score
area. A model never chooses it, and the order below is the precedence when
one message carries several.
"""

from __future__ import annotations

ORDER = ("threat", "system", "monitoring", "exposure", "updates", "test")
LABELS = {
    "threat": "Security threat",
    "exposure": "Weakness to fix",
    "updates": "Updates",
    "monitoring": "Not being checked",
    "system": "Argus itself",
    "test": "Test",
}
MONITORING = frozenset({"visibility", "collectors", "telemetry", "limits", "feed",
                        "reporting", "connectivity"})
SYSTEM = frozenset({"daemon"})
UPDATES = frozenset({"updates", "patches"})
THREAT_AREA = "Active threats"
# Findings that are about a person or program acting on this machine, whatever
# collector found them (beepcheck: someone else possibly at the controls).
THREAT_CATEGORIES = frozenset({"presence"})


def of_finding(finding, job=""):
    """The category of one finding."""
    cat = str((finding or {}).get("category") or "")
    if cat in UPDATES or job in ("updates", "patches"):
        return "updates"
    if cat in SYSTEM:
        return "system"
    if cat in MONITORING or _upkeep(cat):
        return "monitoring"
    try:
        # The registry the score's areas come from (reporting/score.py AREA_OF),
        # read here directly: categories sits below reporting.
        from jarvis.core import mechanisms
        area = next((a for a, jobs in mechanisms.score_areas() if job in jobs), None)
    except Exception:
        area = None
    if area == THREAT_AREA or cat in THREAT_CATEGORIES:
        return "threat"
    return "exposure"


def _upkeep(name):
    """A finding category named after a collector the registry leaves unscored
    (feeds, intel, the local model): Argus's own upkeep, not the machine."""
    try:
        from jarvis.core import mechanisms
        declared = mechanisms.BY_NAME.get(name)
    except Exception:
        return False
    return declared is not None and declared.area is None


def dominant(categories):
    """The one category a message carrying several is filed under."""
    present = [c for c in categories if c in LABELS]
    if not present:
        return "exposure"
    return min(present, key=ORDER.index)


def label(category):
    return LABELS.get(category, LABELS["exposure"])


def counts(categories):
    out = {}
    for c in categories:
        if c in LABELS:
            out[c] = out.get(c, 0) + 1
    return {c: out[c] for c in ORDER if c in out}

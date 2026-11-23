"""Baselines: the same event means different things. Pure.

Every transition is labeled against history: FIRST_SEEN (never observed),
RARE (below frequency floor), EXPECTED (within baseline), CHANGED (known
entity, new attributes), ANOMALOUS (outside bands + corroborating
context). Labels are context, never verdicts. No IO, no model calls.
"""

LABELS = ("FIRST_SEEN", "RARE", "EXPECTED", "CHANGED", "ANOMALOUS")


def label(*, seen_before=True, frequency=1.0, rare_floor=0.01,
          within_bands=True, attributes_changed=False,
          corroborated=False):
    if not seen_before:
        return "FIRST_SEEN"
    if not within_bands and corroborated:
        return "ANOMALOUS"
    if attributes_changed:
        return "CHANGED"
    if frequency < rare_floor:
        return "RARE"
    return "EXPECTED"

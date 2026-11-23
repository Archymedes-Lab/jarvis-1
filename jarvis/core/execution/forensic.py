"""Forensic capture: short, frozen, retrospective, then back to normal.

Deep trace activates only on gated authorization for a bounded window
(default 10s): freeze the relevant ring buffer (evidence from *before*
detection), capture stacks/memory/CLR/PMU, promote T±30min to forensic
hold, then return to LEVEL 1. Expressed as data; executes nothing. Pure.
"""

WINDOW_S = 10
HOLD_S = 1800


def plan(*, authorized=False, level="L2", window_s=WINDOW_S):
    """Next forensic step for one entity. Returns a plan dict."""
    if not authorized:
        return {"action": "hold-at-" + str(level), "authorized": False,
                "detail": "no gated authorization: cheap/deep watch only"}
    return {"action": "forensic-capture", "authorized": True,
            "window_s": int(window_s),
            "steps": ["freeze ring buffer (pre-detection evidence)",
                      "capture stacks/memory-map/CLR snapshot/PMU",
                      f"promote T-{HOLD_S}s..T+{HOLD_S}s to FORENSIC_HOLD",
                      "decode relevant path, preserve evidence",
                      "return to LEVEL 1"],
            "hold_s": HOLD_S}

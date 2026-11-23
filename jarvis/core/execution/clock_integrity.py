"""Wall-clock stability from paired realtime/monotonic samples (pure).

Realtime and monotonic clocks advance together except when something steps the
wall clock. A step breaks event ordering across sources and makes journald
rotate its files, so retained evidence shrinks. This module only measures and
labels; it never adjusts a clock. Too little data is `unknown`, never `stable`.
"""

STEP_TOLERANCE_S = 0.5      # scheduler jitter between two paired reads stays below this
MIN_SPAN_S = 5.0            # shorter windows cannot show a periodic step
UNSTABLE_STEPS = 2          # backward steps in the window
UNSTABLE_JOURNAL = 5        # journald "Time jumped backwards" lines per window
MAX_SAMPLES = 512


def steps(samples):
    """Steps between consecutive (realtime, monotonic) pairs, oldest first."""
    rows = [s for s in samples[-MAX_SAMPLES:]
            if isinstance(s, (tuple, list)) and len(s) == 2
            and all(isinstance(x, (int, float)) for x in s)]
    out = []
    for (r0, m0), (r1, m1) in zip(rows, rows[1:]):
        if m1 <= m0:
            continue                    # monotonic must advance; skip a bad pair
        drift = (r1 - r0) - (m1 - m0)
        if abs(drift) > STEP_TOLERANCE_S:
            out.append({"at_monotonic": m1, "step_s": round(drift, 3),
                        "direction": "backward" if drift < 0 else "forward"})
    return out


def analyze(samples, *, journal_backward=None):
    """Return status stable|unstable|unknown with the evidence behind it.

    `journal_backward` is the count journald recorded for the same period, or
    None when the journal could not be read (which is not zero).
    """
    rows = [s for s in samples if isinstance(s, (tuple, list)) and len(s) == 2]
    span = (rows[-1][1] - rows[0][1]) if len(rows) >= 2 else 0.0
    found = steps(samples)
    back = [s for s in found if s["direction"] == "backward"]
    journal_bad = journal_backward is not None and journal_backward >= UNSTABLE_JOURNAL
    if len(back) >= UNSTABLE_STEPS or journal_bad:
        status = "unstable"
    elif span >= MIN_SPAN_S and journal_backward is not None:
        status = "stable" if not found else "stepped_once"
    else:
        status = "unknown"
    return {"status": status, "window_s": round(span, 1), "steps": found,
            "backward_steps": len(back), "journal_backward": journal_backward,
            "largest_step_s": max((abs(s["step_s"]) for s in found), default=0.0),
            "effects": ["event ordering across sources is unreliable",
                        "journald rotates on each backward step, shortening retained evidence",
                        "wall-clock windows in detectors can miss (use monotonic time)"]
            if status == "unstable" else []}

"""Confidence everywhere: certainty is a first-class, testable value.

Phase 18. JARVIS must never pretend every observation is equally certain.
Perception verdicts, Veil aggregates and fusion scores already emit 0.0-1.0
scores; this module standardizes what they mean and gates autonomy on them:

  high confidence + reversible + low impact  -> act automatically
  medium confidence                           -> observe more
  high impact and anything less than high     -> ask the human
  unknown                                     -> ask, never assume

Pure: no IO, no clocks. Thresholds are parameters so tests pin the
contract, not the tuning. Inference alone can never reach certainty —
only direct verified observation scores 1.0 (see perception.RECONCILED).
"""

HIGH = 0.85
MEDIUM = 0.5

# Inference caps below certainty even in total agreement; agreement among
# derived signals is still derivation. Direct verified observation is the
# only path to 1.0, granted by the caller, never computed here.
INFERENCE_CAP = 0.95


def level(score):
    """Score -> high/medium/low/unknown. Unknown stays unknown, never low."""
    if score is None:
        return "unknown"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if not 0.0 <= score <= 1.0:
        return "unknown"
    if score >= HIGH:
        return "high"
    if score >= MEDIUM:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def combine(scores, verified=False):
    """Noisy-OR over independent corroborating signals. Pure, capped.

    Weak signals cannot manufacture certainty: without `verified` direct
    observation the result caps at INFERENCE_CAP. Empty input is 0.0
    (unknown), never a default middle value.
    """
    scores = [float(s) for s in (scores or [])
              if isinstance(s, (int, float)) and 0.0 <= s <= 1.0]
    if not scores:
        return 0.0
    product = 1.0
    for s in scores:
        product *= 1.0 - s
    combined = 1.0 - product
    if not verified:
        combined = min(combined, INFERENCE_CAP)
    return round(combined, 3)


def decide(confidence, *, impact="low", reversible=True):
    """Autonomy gate. Returns {"decision": act/observe/ask, "reason": str}.

    `impact` is low (reversible notification, extra observation) or high
    (containment, deletion, credential or network change). Irreversible
    high-impact action never fires automatically however confident the
    signal — that is the human's call.
    """
    band = level(confidence)
    if band == "high" and reversible and impact == "low":
        return {"decision": "act",
                "reason": f"high confidence ({confidence:.2f}) with a "
                          "reversible low-impact action: automatic"}
    if band == "medium" and impact == "low":
        return {"decision": "observe",
                "reason": f"medium confidence ({confidence:.2f}): increase "
                          "observation, do not act yet"}
    return {"decision": "ask",
            "reason": (f"{band} confidence ({confidence if confidence is not None else 'none'})"
                       f", impact={impact}, "
                       f"{'reversible' if reversible else 'irreversible'}: "
                       "human judgment required")}

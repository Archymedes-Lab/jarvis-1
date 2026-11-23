"""Bounded Jev annotation for unrecognised memory images.

This lives above collectors in the package dependency order. Severity remains
in the deterministic collector; this module can add explanatory text only.
"""

import hashlib
import json

from jarvis.collectors.process import assemblies
from jarvis.response import jev

_ADVICE = {}  # feature hash -> advisory note, for the life of the daemon


def advisor():
    if not jev.available():
        return None
    budget = [jev.MEMORY_MAX_CALLS]

    def advise(row):
        if assemblies.severity(row) == "low":
            return ""
        feats = assemblies.features(row)
        key = hashlib.sha256(json.dumps(feats, sort_keys=True).encode()).hexdigest()
        if key not in _ADVICE:
            if budget[0] <= 0:
                return "Jev advisory skipped this scan (per-scan budget used)"
            budget[0] -= 1
            answer = jev.judge_memory_image(feats).get("answers") or {}
            p = answer.get("offensive_probability")
            if isinstance(p, (int, float)) and not isinstance(p, bool) and 0 <= p <= 1:
                _ADVICE[key] = (f"Jev advisory (not a verdict, severity unchanged): "
                                f"{p:.2f} probability these features resemble "
                                "offensive tooling")
            else:
                return "Jev advisory unavailable; the severity is deterministic"
        return _ADVICE[key]

    return advise

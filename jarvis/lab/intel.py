"""The transformation boundary between threat research and the Arena.

A threat report is attacker-controlled text. It is never turned into something
executable. It is turned into a candidate *specification*: a structured behavior
mapped to ATT&CK, with the telemetry JARVIS should have seen and whether it can
see it today. Making a candidate runnable is a separate, reviewed step, and a
novel behavior defaults to a tier automation cannot execute.

This module only builds and classifies candidates. Research retrieval lives in
`jarvis.intel`; nothing here fetches or runs anything.
"""

from .scenario import Scenario

# ATT&CK technique -> the JARVIS telemetry that would show it, as a starting
# coverage map. Extend as detectors gain reach.
TECHNIQUE_TELEMETRY = {
    "T1003.001": {"channel": "sysmon", "events": [10], "detector_category": "credential access"},
    "T1055": {"channel": "sysmon", "events": [8, 10, 25], "detector_category": "injection"},
    "T1055.001": {"channel": "sysmon", "events": [7, 8], "detector_category": "injection"},
    "T1490": {"channel": "sysmon", "events": [1], "detector_category": "impact"},
    "T1071.004": {"channel": "sysmon", "events": [22], "detector_category": "intel match"},
    "T1547.001": {"channel": "sysmon", "events": [12, 13], "detector_category": "tampering"},
    "T1053.005": {"channel": "tasks", "events": [106], "detector_category": None},
}


def coverage(technique):
    """What JARVIS can see for a technique today: (known, telemetry, has_detector)."""
    t = TECHNIQUE_TELEMETRY.get(technique)
    if t is None:
        return {"known": False, "telemetry": None, "has_detector": False}
    return {"known": True, "telemetry": t, "has_detector": t["detector_category"] is not None}


def candidate(*, report_id, title, technique, platform="win", observed=None,
              classified=None, provenance="", confidence="low"):
    """Build a candidate scenario spec from an already-structured behavior.

    The result is never `synthetic`/runnable automatically: a novel candidate is
    `prohibited_in_automation` until a human rewrites it into concrete telemetry.
    """
    cov = coverage(technique)
    spec = {"note": "candidate specification; not runnable until reviewed",
            "provenance": provenance, "confidence": confidence,
            "coverage": cov, "proposed_events": (cov["telemetry"] or {}).get("events")}
    return Scenario(
        id=f"candidate-{report_id}",
        title=title[:200],
        platform=platform,
        safety="prohibited_in_automation",
        source="live",                     # marks it as not-yet-telemetry; guard refuses it
        techniques=[technique],
        provider="atomic",                 # produce() refuses; must be converted
        spec=spec,
        origin="exa-candidate",
        detector="sysmon" if platform == "win" else "sysmon_linux",
        expect={"observed": observed or [],
                "classified": classified or ({} if not cov["has_detector"] else
                                             {"category": cov["telemetry"]["detector_category"],
                                              "min_severity": "high"})},
    )


def candidates_from(behaviors):
    """A list of structured behaviors (from research) -> [candidate Scenario].

    Each behavior is `{report_id, title, technique, platform?, observed?,
    provenance?, confidence?}` — the shape the research pipeline (`jarvis.intel`,
    Exa-fed) already produces once a report is reduced to a technique and
    indicators. Nothing here fetches or executes; it only classifies coverage.
    """
    out = []
    for b in behaviors:
        if not b.get("report_id") or not b.get("technique"):
            continue
        out.append(candidate(
            report_id=b["report_id"], title=b.get("title", b["technique"]),
            technique=b["technique"], platform=b.get("platform", "win"),
            observed=b.get("observed"), classified=b.get("classified"),
            provenance=b.get("provenance", ""), confidence=b.get("confidence", "low")))
    return out


def coverage_summary(candidates):
    """How many candidate behaviors JARVIS can already see, and the gaps."""
    known = [c for c in candidates if (c.spec.get("coverage") or {}).get("known")]
    with_detector = [c for c in candidates
                     if (c.spec.get("coverage") or {}).get("has_detector")]
    gaps = [{"id": c.id, "technique": c.techniques[0] if c.techniques else None,
             "verdict": gap_report(c)["verdict"]}
            for c in candidates if c not in with_detector]
    return {"total": len(candidates), "known_technique": len(known),
            "has_detector": len(with_detector), "gaps": gaps}


def gap_report(candidate_scenario):
    """A short 'can JARVIS see this yet?' answer for a candidate."""
    cov = (candidate_scenario.spec or {}).get("coverage") or {}
    tel = cov.get("telemetry") or {}
    return {
        "technique": candidate_scenario.techniques[0] if candidate_scenario.techniques else None,
        "known_technique": cov.get("known", False),
        "relevant_events": tel.get("events"),
        "has_detector": cov.get("has_detector", False),
        "existing_arena_test": False,
        "verdict": ("coverage gap: no detector maps to this technique"
                    if not cov.get("has_detector") else
                    "technique is understood; add a synthetic Arena test to prove it"),
    }

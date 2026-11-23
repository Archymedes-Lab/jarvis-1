"""Veil privacy correlation: many metadata-only sightings, one verdict per site.

Phase 12. A single browser report is weak evidence; the same origin showing
fingerprinting-plus-export across many reports is a pattern. This module
aggregates validated reports (see analysis.validate_report) into per-origin
verdicts with confidence that grows with corroboration — and caps below
certainty, because metadata-only evidence can indicate tracking but never
prove compromise.

Load-bearing privacy rule, tested: only origins and bounded counters cross
this boundary. Listener shapes (which APIs were touched), never content
(typed text, timing series, pointer coordinates, cookies, paths). The
output carries no per-visit detail at all — sighting counts, not trails.
"""

from .analysis import validate_report

# Metadata-only evidence can indicate, never prove — and never act alone.
# The cap sits below confidence.HIGH on purpose: a browser-privacy pattern,
# however corroborated, cannot cross the autonomy threshold by itself. It
# takes host-side proof to act; Veil remains evidence-only.
CONFIDENCE_CAP = 0.8
BASE_CONFIDENCE = 0.4
CORROBORATION_STEP = 0.05


def _confidence(sightings, exported_sightings):
    """Confidence from corroboration. Pure; capped, monotonic, never 1.0."""
    if sightings <= 0:
        return 0.0
    score = BASE_CONFIDENCE + CORROBORATION_STEP * (sightings - 1)
    if exported_sightings <= 0:
        score -= 0.15
    return round(max(0.0, min(CONFIDENCE_CAP, score)), 2)


def aggregate(reports):
    """Fold validated reports into per-origin privacy verdicts.

    `reports` are raw sensor dicts; malformed ones are skipped, never
    errors. Returns {origin: {sightings, exported_sightings,
    interaction_sightings, fingerprint_sightings, confidence, worst}}.
    `worst` is the strongest single-report severity observed, kept as a
    label — the verdict's own confidence comes only from corroboration.
    """
    from .analysis import REPLAY_VENDORS, _vendors
    from .analysis import classify as _classify
    verdicts = {}
    for report in reports or []:
        clean = validate_report(report)
        if clean is None:
            continue
        top = clean["top_origin"]
        entry = verdicts.setdefault(top, {
            "sightings": 0, "exported_sightings": 0,
            "interaction_sightings": 0, "fingerprint_sightings": 0,
            "replay_sightings": 0, "worst": "ok",
        })
        entry["sightings"] += 1
        third_party = [o for o in clean["egress_origins"] if o != top]
        exported = bool(third_party and sum(clean["transports"].values()))
        if exported:
            entry["exported_sightings"] += 1
        interaction = {n for n, c in clean["listeners"].items() if c}
        surfaces = {n for n, c in clean["surfaces"].items() if c}
        if len(interaction) >= 4 or ({"input", "keydown"} & interaction):
            entry["interaction_sightings"] += 1
        if len(surfaces) >= 4:
            entry["fingerprint_sightings"] += 1
        if _vendors([o for o in clean["script_origins"] + clean["egress_origins"]
                     if o != top], REPLAY_VENDORS):
            entry["replay_sightings"] += 1
        for finding in _classify(report):
            rank = {"low": 0, "medium": 1, "high": 2}
            if rank.get(finding.get("severity"), -1) > rank.get(entry["worst"], -1):
                entry["worst"] = finding["severity"]
    for origin, entry in verdicts.items():
        entry["confidence"] = _confidence(entry["sightings"],
                                          entry["exported_sightings"])
    return verdicts


def findings(verdicts, min_sightings=2):
    """Verdicts worth surfacing: corroborated patterns only.

    A single sighting is never a finding — one report is observation, not
    a pattern. Returns findings in the common shape, metadata-only.
    """
    from jarvis.core.finding import finding as _finding
    out = []
    for origin in sorted(verdicts):
        entry = verdicts[origin]
        if entry["sightings"] < min_sightings:
            continue
        if entry["worst"] == "ok" and entry["exported_sightings"] == 0:
            continue
        out.append(_finding(
            "privacy-veil", "medium" if entry["worst"] == "high" else "low",
            f"repeated tracking-indicative behavior by {origin}",
            f"seen in {entry['sightings']} metadata-only reports "
            f"({entry['exported_sightings']} with cross-origin export, "
            f"{entry['fingerprint_sightings']} with fingerprinting surfaces, "
            f"{entry['replay_sightings']} with a session recorder); "
            f"pattern confidence {entry['confidence']:.2f} — an indicator, "
            f"not a compromise verdict. No content was retained.",
            origin, host="browser"))
    return out

"""Trustworthy perception states.

Phase 1 foundation: if JARVIS says it knows the current machine state, it
must be able to demonstrate why. A bare snapshot row or a bare event is not
knowledge; the agreement (or disagreement) between independent observations
is.

Four states, deliberately coarse so they stay honest:

  OBSERVED     one source saw it (event XOR snapshot), not yet corroborated.
  INFERRED     derived from related evidence (parent lineage, hash match),
               never presented as direct observation.
  RECONCILED   snapshot presence AND matching start event agree on the exact
               execution (host/boot/pid/started within tolerance). This is
               the only state that may be presented as VERIFIED.
  UNOBSERVED   expected evidence is absent (e.g. snapshot present but no
               start event past the continuous-coverage boundary), or the
               stream cannot contradict the snapshot (stale/gapped/pre-
               coverage). The reason is always recorded; absence of alerts
               never establishes absence of compromise.

Every verdict carries confidence, source, freshness and corroboration so
autonomy decisions can depend on certainty (Phase 18 groundwork):

  fact           what is claimed (e.g. "pid 42 is execution X")
  confidence     0.0-1.0; 1.0 only for RECONCILED with exact identity match
  source         which observations contributed
  freshness      seconds since the newest contributing observation
  corroboration  how many independent sources agree
"""

OBSERVED = "OBSERVED"
INFERRED = "INFERRED"
RECONCILED = "RECONCILED"
UNOBSERVED = "UNOBSERVED"

# Presentation label used by reporting/UX layers.
VERIFIED = "VERIFIED"
UNRECONCILED = "UNRECONCILED"
UNKNOWN = "UNKNOWN"


def classify(*, event_present, snapshot_present, identity_match=False,
             parent_known=False, coverage_valid=True):
    """Classify one process instance into a perception state.

    Pure function; no IO. `coverage_valid` means the stream was in a
    position to contradict the snapshot (fresh, complete, continuous
    coverage predates the start, settling window passed). When False,
    absence proves nothing and the verdict is UNOBSERVED with low
    confidence rather than a false discrepancy.
    """
    if event_present and snapshot_present and identity_match:
        return {
            "state": RECONCILED,
            "label": VERIFIED,
            "confidence": 1.0,
            "source": ["event", "snapshot"],
            "corroboration": 2,
            "reason": "start event and snapshot agree on the exact execution",
        }
    if event_present and snapshot_present:
        return {
            "state": OBSERVED,
            "label": UNRECONCILED,
            "confidence": 0.6,
            "source": ["event", "snapshot"],
            "corroboration": 1,
            "reason": "both sources saw activity but exact identity disagrees",
        }
    if snapshot_present and not event_present:
        if not coverage_valid:
            return {
                "state": UNOBSERVED,
                "label": UNKNOWN,
                "confidence": 0.2,
                "source": ["snapshot"],
                "corroboration": 0,
                "reason": "snapshot present but stream cannot contradict it "
                          "(stale, gapped, pre-coverage or settling)",
            }
        return {
            "state": UNOBSERVED,
            "label": UNRECONCILED,
            "confidence": 0.75,
            "source": ["snapshot"],
            "corroboration": 0,
            "reason": "snapshot present with no matching start event under "
                      "continuous coverage: event-log gap, filtered telemetry, "
                      "sensor tampering or hidden process",
        }
    if event_present and not snapshot_present:
        return {
            "state": OBSERVED,
            "label": UNRECONCILED,
            "confidence": 0.5,
            "source": ["event"],
            "corroboration": 1,
            "reason": "start event recorded but process absent from snapshot "
                      "(exited between scans or snapshot missed it)",
        }
    if parent_known or identity_match:
        return {
            "state": INFERRED,
            "label": UNKNOWN,
            "confidence": 0.3,
            "source": ["lineage"],
            "corroboration": 0,
            "reason": "no direct observation; inferred from related evidence",
        }
    return {
        "state": UNOBSERVED,
        "label": UNKNOWN,
        "confidence": 0.0,
        "source": [],
        "corroboration": 0,
        "reason": "no evidence from any source",
    }


def summarize(verdict):
    """One-line human explanation of a verdict, for logs and UX."""
    return (f"{verdict['label']} ({verdict['state']}, "
            f"confidence {verdict['confidence']:.2f}): {verdict['reason']}")

"""The assurance score: evidence of trust in JARVIS, separate from the machine.

Invariants: 100 is unreachable while the register holds incomplete claims;
unobservable capabilities earn nothing; the number can never claim safety.
"""
import unittest

from jarvis.core import assurance


def obs(*states):
    """Observations mapping covering every capability's required sources."""
    out = {}
    for name, sources in assurance.OBSERVATION_REQUIREMENTS.items():
        for source in sources:
            out[source] = {"status": "complete"}
    return out


class AssuranceScoreTests(unittest.TestCase):
    def test_perfect_observations_cannot_reach_100(self):
        # The register holds 'partial' and 'unverified' claims; even with
        # every source complete, incomplete evidence keeps the ceiling < 100.
        value = assurance.score(obs())
        self.assertLess(value, 100)
        self.assertGreater(value, 0)

    def test_blind_sources_earn_nothing(self):
        blind = {s: {"status": "unavailable"} for sources in
                 assurance.OBSERVATION_REQUIREMENTS.values() for s in sources}
        self.assertEqual(assurance.score(blind), 0)

    def test_partially_observable_scores_between_blind_and_full(self):
        sources = sorted({s for sources in
                          assurance.OBSERVATION_REQUIREMENTS.values()
                          for s in sources})
        full = assurance.score({s: {"status": "complete"} for s in sources})
        # Half the sources complete: half the observable evidence.
        half = assurance.score({s: {"status": "complete" if i % 2 == 0
                                    else "unavailable"}
                                for i, s in enumerate(sources)})
        blind = assurance.score({s: {"status": "unavailable"}
                                 for s in sources})
        self.assertGreater(full, half)
        self.assertGreater(half, blind)
        # Fully blind is fully unassured: claims without observation earn
        # nothing, including capabilities with no observation mapping.
        self.assertEqual(blind, 0)
        self.assertLess(full, 100)

    def test_report_carries_the_score_and_its_definition(self):
        rep = assurance.report(obs())
        self.assertIsInstance(rep["score"], int)
        self.assertIn("not machine protection health", rep["score_definition"])
        self.assertFalse(rep["complete"])
        self.assertFalse(rep["absence_of_alerts_proves_safety"])

    def test_performance_claim_requires_measured_gpu_evidence(self):
        entry = assurance.report()["capabilities"]["performance"]
        self.assertEqual(entry["implementation"], "partial")
        self.assertIn("GPU", entry["basis"])
        self.assertIn("GPU", entry["blind_spot"] + entry["basis"])


if __name__ == "__main__":
    unittest.main()

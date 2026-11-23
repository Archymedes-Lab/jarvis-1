"""Shared vocabulary for advisory posture views; no execution authority."""

SECURITY = "security"
COVERAGE = "coverage"
ACCEPTED = "accepted"
DEBT_KINDS = (SECURITY, COVERAGE, ACCEPTED)


def category(finding, accepted=False):
    if finding.get("category") in ("visibility", "telemetry", "collectors", "daemon"):
        return COVERAGE
    return ACCEPTED if accepted else SECURITY

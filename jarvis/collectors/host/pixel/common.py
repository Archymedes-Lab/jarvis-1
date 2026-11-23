"""Shared shape for the tracking and capture checks."""

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9),
                                           f["category"], f["title"]))



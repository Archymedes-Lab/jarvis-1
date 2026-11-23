"""Bounded, metadata-only open-source transition review; never authorizes publication."""
import json

from jarvis.response import jev

STATE = {
    "alternatives": ["permissive license", "distribution copyleft", "network copyleft"],
    "selected_preparation": "AGPL-3.0-only selected by owner; pending rights review",
    "goal": "allow commercial reuse while preserving reciprocal source availability and official identity",
    "controls": ["preserve copyright and third-party notices", "separate trademark policy",
                 "maintainer review for external contributions", "DCO without assignment",
                 "preserve binary content and signature gates", "isolated preparation branch"],
    "open_gates": ["coauthor relicensing authority", "full-history privacy and secrets review",
                   "collaboration artifacts review", "corresponding source for binaries",
                   "hosted modified version source offer", "external PR CI", "full validation"],
    "implementation": {"history_inventory": "bounded Git batch stream, no raw matches in output",
                       "regressions": "clean and deleted-secret histories, budgets, interruption, timeout, changed refs",
                       "independent_check": "pinned Gitleaks history step passed",
                       "runtime": "no production service or assurance changes"},
    "publication": "readiness unestablished while privacy and rights gates remain open",
}
QUESTIONS = {
    "fit": {"type": "choice", "instructions":
        "Which license family best matches the stated reciprocal-source goal, ignoring publication authority?",
        "criteria": {"permissive": "Permissive reuse", "gpl": "Distribution copyleft",
                     "agpl": "Network copyleft", "uncertain": "Insufficient information"}},
    "gap": {"type": "choice", "instructions":
        "Which unresolved gate deserves first human review before making this private repository public?",
        "criteria": {"rights": "Coauthor relicensing authority", "privacy": "Private history and artifacts",
                     "source": "Corresponding-source completeness", "ci": "External contributor CI",
                     "uncertain": "Cannot prioritize from the metadata"}},
    "ready": {"type": "noul", "instructions":
        "Does the metadata establish publication readiness while the listed gates remain open?",
        "criteria": {"true": "Readiness established", "false": "Readiness not established"}},
}

if __name__ == "__main__":
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({"model": result.get("model"), "answers": result["answers"]}))
    except jev.JevError:
        print(json.dumps({"unavailable": True}))

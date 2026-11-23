"""Metadata-only advisory on contributor CI; never authorizes publication."""

import json

from jarvis.response import jev

STATE = {
    "scope": "AGPL preparation already merged; repository currently private",
    "alternatives": {
        "push_only": "Every repository push; no external fork PR trigger",
        "both": "Every push and every PR; duplicate branch CI cost",
        "pr_main": "Every main-targeting PR, main push, explicit Windows test push, manual dispatch",
    },
    "selected": "both",
    "policy": "ASES DEV-11 and DEV-13 require checks on every push; preserve this scope",
    "invariants": ["required PR jobs always execute", "read-only token", "no secrets",
                   "GitHub hosted runners", "no persisted checkout credentials",
                   "main-only shared Rust cache writes", "no release or runtime change"],
    "open_gates": ["coauthor rights", "history and operational-data privacy review",
                   "Actions logs and artifact review", "exact-binary corresponding source",
                   "actual external-fork CI execution"],
}
QUESTIONS = {
    "routing": {
        "type": "choice",
        "instructions": "Which proposed routing supports external contributors while preserving the stated every-push standard without a waiver?",
        "criteria": {"push_only": "Push only", "both": "Every push and PR",
                     "pr_main": "PRs plus main and explicit test pushes", "unknown": "Insufficient evidence"},
    },
    "readiness": {
        "type": "noul",
        "instructions": "Does the available metadata establish public publication readiness with the listed gates still undocumented?",
        "criteria": {"true": "Readiness established", "false": "Readiness remains unestablished"},
    },
    "implementation_gap": {
        "type": "choice",
        "instructions": "Which validation best checks that contributor CI actually works after the routing edit?",
        "criteria": {"fork": "Observe all required jobs on a maintainer-approved external-fork PR",
                     "text": "Only inspect workflow text", "model": "Only rely on this advisory",
                     "unknown": "Cannot determine"},
    },
}

if __name__ == "__main__":
    try:
        response = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({"model": response.get("model"), "answers": response["answers"]}))
    except jev.JevError:
        print(json.dumps({"unavailable": True}))

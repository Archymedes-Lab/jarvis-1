"""Metadata-only review of the owner's revised noncommercial licensing goal."""

import json

from jarvis.response import jev

STATE = {
    "owner_goal": "source available for permitted noncommercial uses; paid permission for other commercial uses",
    "selected": "unmodified PolyForm-Noncommercial-1.0.0 for the new distribution",
    "prior_license": "AGPL-3.0-only grants to earlier recipients remain valid",
    "organization_exception": "standard license expressly permits listed government and nonprofit organization uses",
    "rights": "owner separately confirmed both original authors authorize noncommercial distribution and paid commercial permissions; no assignment or executed CLA asserted",
    "inbound_policy": "DCO required, but outside contributions cannot merge without an approved grant supporting commercial licensing",
    "scope": "license text, manifests, SBOM identity, notices, contributor and release documentation; no runtime or protection changes",
    "implementation": {"notices": "bounded fail-closed Required Notice reader; notices travel in existing packaged file",
                       "checks": "48 focused tests, static gate, corrected fixture modules 56 tests",
                       "canonical_license": "unchanged publisher text hash-checked", "runtime": "unchanged"},
    "open_gates": ["private history and draft advisory review",
                   "CI account payment/spending block", "dependency alerts", "all-module run nonzero; targeted fixture repairs passed"],
}
QUESTIONS = {
    "fit": {
        "type": "choice",
        "instructions": "Which license approach matches the stated owner goal while using a standard software license?",
        "criteria": {"polyform": "PolyForm Noncommercial with separate authorized commercial permission",
                     "agpl": "AGPL permits commercial competitors", "cc": "Creative Commons content license",
                     "unknown": "Insufficient evidence"},
    },
    "prior_grants": {
        "type": "noul",
        "instructions": "Can changing the license offered for a new distribution revoke compliant earlier recipients' AGPL grants?",
        "criteria": {"true": "Earlier grants can be revoked by this change", "false": "Earlier grants must remain respected"},
    },
    "dco_enough": {
        "type": "noul",
        "instructions": "Does a DCO sign-off under noncommercial terms alone establish the maintainer's right to grant commercial licenses over that contribution?",
        "criteria": {"true": "Separate commercial rights established", "false": "A further rights grant is needed"},
    },
}

if __name__ == "__main__":
    try:
        result = jev._call(STATE, QUESTIONS, timeout=20)
        print(json.dumps({"model": result.get("model"), "answers": result["answers"]}))
    except jev.JevError:
        print(json.dumps({"unavailable": True}))

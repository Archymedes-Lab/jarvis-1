"""Bounded metadata-only forensic design/implementation review; never authority."""
import json
import sys
from jarvis.response import jev

STATE = {
    "scope": "local persistent forensic history; no external evidence upload",
    "alternatives": ["existing canonical log plus vault", "second full database",
                     "remote WORM as sole store"],
    "selected": "existing canonical log plus vault",
    "invariants": ["no automatic evidence deletion", "capacity refusal before cursor/ack",
                   "committed-only reads", "sampled process observations not lifecycle",
                   "metadata-only observations", "bounded lock retries and queries",
                   "nonoverwriting exports with final manifest and SHA256"],
    "local_custody": "administrator-only vault and independent digest timestamps already exist",
    "limits": ["local administrator can delete", "no remote WORM",
               "snapshots miss transient processes", "hashes do not attest truthful sources",
               "an unanchored export can be rewritten consistently"],
    "authority": "advisory only; tests and measured service readback remain authoritative",
}
QUESTIONS = {
    "design": {"type": "choice", "instructions":
        "Which alternative best preserves the stated local scope, existing evidence, privacy, "
        "and bounded failure behavior? No option authorizes cloud setup or deletion.",
        "criteria": {"canonical": "Existing canonical log plus protected vault",
                     "database": "Second full database", "remote": "Remote WORM sole store",
                     "insufficient": "Insufficient information"}},
    "deletion_limit": {"type": "noul", "instructions":
        "Does local administrator deletion remain an explicit limitation despite local hashes, "
        "administrator-only vault and independently witnessed digests?",
        "criteria": {"true": "Local storage cannot guarantee survival against its administrator",
                     "false": "The stated design prevents administrator deletion"}},
}

if __name__ == "__main__":
    if "--implementation" in sys.argv:
        STATE["verification"] = {
            "focused_tests": 64, "focused_result": "passed",
            "measured_case_copy": "real committed source exported and independently verified offline",
            "query_wall_seconds": 0.254, "case_peak_memory_mib": 51,
            "snapshot_cpu_seconds_for_three_passes": 0.128,
            "checked_failure_paths": ["restart", "pending tail", "missing/modified case files",
                                      "native capacity refusal before ack", "lock retry exhaustion",
                                      "backward clock sealing", "nonoverwriting export"],
            "deployment": "not yet live; full host suite and fresh scheduled readback still required",
        }
        QUESTIONS["coverage_gap"] = {
            "type": "noul", "instructions":
                "Do the stated limits prevent claiming complete forensic coverage or "
                "administrator-proof undeletability despite the measured checks?",
            "criteria": {"true": "Coverage and deletion guarantees remain limited",
                         "false": "Measured checks prove complete coverage and undeletability"},
        }
    try:
        result = jev._call(STATE, QUESTIONS, timeout=15)
        print(json.dumps({"model": result.get("model"), "answers": result["answers"]}))
    except jev.JevError as exc:
        print(json.dumps({"unavailable": str(exc)}))

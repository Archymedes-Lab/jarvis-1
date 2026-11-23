"""Forge scenario candidates: turn coverage gaps into validation work.

Phase 13. The continuous immune-system loop starts here: intelligence says
a technique matters, nothing checks for it, so a safe synthetic scenario
should. This module converts `gaps()` closeable tuples into scenario
candidate dicts — proposals, not executions. Running them stays behind
`isolation.guard`; candidates carry safety="synthetic" and status
"candidate" so nothing mistakes a proposal for validated coverage.

Pure: no IO, no execution. Dedupes against already-known scenario ids so
each gap proposes work exactly once.
"""

import re


def _slug(tid):
    return "forge-" + re.sub(r"[^a-z0-9]+", "-", tid.lower()).strip("-")


def candidates(closeable, known_ids=()):
    """Closeable gap tuples -> scenario candidate dicts.

    `closeable` is gaps()' third element: (tid, doc_count, why, name).
    `known_ids` holds scenario ids that already exist (candidates or
    implemented); those gaps propose nothing. Candidates are ordered by
    descending doc_count — the most-discussed technique first.
    """
    known = set(known_ids or ())
    out = []
    for item in sorted(closeable or [], key=lambda t: -t[1]):
        tid, count, why, name = item
        cid = _slug(tid)
        if cid in known or any(c["id"] == cid for c in out):
            continue
        title = f"Forged validation for {tid}" + (f" ({name})" if name else "")
        out.append({
            "id": cid,
            "title": title[:200],
            "technique": tid,
            "doc_count": count,
            "coverage_gap": str(why)[:500],
            "safety": "synthetic",
            "status": "candidate",
            "expected_telemetry": ("synthetic detector probes only; no OS "
                                   "execution, no persistence, no credentials"),
            "validation": ("passes when a detector flags the synthetic "
                           "behavior; fails openly otherwise"),
        })
    return out

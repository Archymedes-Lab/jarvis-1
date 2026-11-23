"""Visibility scores: per-entity and global observability. Pure.

Distinct from protection health: per-dimension coverage (lifecycle,
threads, modules, memory, execution, network, CLR) rolls into an entity
score; entity scores roll into machine observability with a separate
contradiction count. Restricted-but-agreeing protected processes keep
their memory dimension as restricted (not failed). N/A dimensions are
excluded, never zeroed. No IO.
"""

DIMENSIONS = ("lifecycle", "threads", "modules", "memory", "execution",
              "network", "clr")


def entity_score(dims):
    """0-100 over applicable dimensions. 'restricted' and 'na' excluded."""
    vals = [v for k, v in (dims or {}).items()
            if k in DIMENSIONS and v not in ("na", "restricted", None)]
    if not vals:
        return {"score": None, "note": "no applicable dimensions"}
    return {"score": round(100 * sum(vals) / len(vals), 1),
            "dimensions": len(vals)}


def global_score(entities, *, contradictions=0):
    """Machine observability across entities plus contradiction count."""
    scores = [e for e in (entities or []) if isinstance(e, (int, float))]
    avg = round(sum(scores) / len(scores), 1) if scores else None
    return {"observability": avg, "entities": len(scores),
            "cross_view_contradictions": int(contradictions or 0)}

"""Transitions, not polling: the event-sourced machine model.

Observation layer is extraordinarily sensitive: every security-relevant
state transition it can observe becomes a canonical event, even one that
lasts milliseconds. Interpretation stays disciplined: a transition is a
fact with sequence numbers, never a verdict.

Snapshots are consistency checks against event-derived state, not the
primary source. Deltas (create/exit, added/removed, before->after) are
stored; steady state is checkpointed, not repeated.

Pure, bounded, no IO, no clocks, no model calls.
"""

# Canonical (category, action) transition catalog. Mirrors
# jarvis.core.event.CATEGORIES; this table is the reviewable contract for
# "what JARVIS considers a state transition".
TRANSITIONS = frozenset({
    ("process", "start"), ("process", "exit"),
    ("process", "image_load"), ("process", "image_unload"),
    ("thread", "start"), ("thread", "exit"),
    ("network", "connect"), ("network", "end"),
    ("network", "dns_query"),
    ("file", "create"), ("file", "write"), ("file", "rename"),
    ("file", "delete"),
    ("registry", "value_set"), ("registry", "key_create"),
    ("registry", "key_delete"), ("registry", "rename"),
    ("service", "created"), ("service", "changed"),
    ("service", "started"), ("service", "stopped"),
    ("task", "registered"), ("task", "updated"), ("task", "deleted"),
    ("driver", "load"),
    ("account", "changed"),
    ("device", "connected"), ("device", "removed"),
    ("memory", "protection_changed"),
})

# Observation levels per process: cheap always, deep on discrepancy.
# L0 lifecycle, L1 standard telemetry, L2 deep watch, L3 forensic trace.
LEVELS = ("L0", "L1", "L2", "L3")


def is_transition(category, action):
    return (category, action) in TRANSITIONS


def summarize_window(events, limit=200):
    """Bounded 'what changed' summary over ordered canonical events. Pure."""
    events = list(events or [])[:max(0, int(limit))]
    counts = {}
    seqs = []
    for e in events:
        key = (e.get("category"), e.get("action"))
        if key in TRANSITIONS:
            label = f"{key[0]}:{key[1]}"
            counts[label] = counts.get(label, 0) + 1
            if e.get("seq") is not None:
                seqs.append(e.get("seq"))
    return {"changes": counts,
            "transitions_folded": len(events),
            "first_seq": min(seqs) if seqs else None,
            "last_seq": max(seqs) if seqs else None}


def level_for(verdict, current="L1", pressured=False):
    """Deterministic adaptive depth. No LLM decision required.

    CROSS_VIEW_MISMATCH / UNEXPLAINED_PROCESS -> L2; human authorization
    (handled by escalate.decide) is the only path to L3; everything else
    relaxes toward L1/L0. Pressure never escalates.
    """
    if pressured:
        return "L1" if current in ("L2", "L3") else current
    if verdict in ("CROSS_VIEW_MISMATCH", "UNEXPLAINED_PROCESS"):
        return "L2"
    if verdict in ("VERIFIED_PROCESS", "VERIFIED_EXIT"):
        return "L1"
    return current

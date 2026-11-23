"""Change ledger: every transition queryable with integrity. Pure.

A JarvisChange wraps one canonical event with a global sequence, entity
identity, before/after digests (never raw values for sensitive state),
actor/target, source confidence, and a chained integrity hash. Warm
storage holds compressed transitions; HOT holds recent high-resolution
samples; COLD holds aggregates and forensic holds. Promotion to
FORENSIC_HOLD (T-30min..T+30min) pins evidence against ageing.
Pure helpers; the durable log owns bytes. No IO.
"""

import hashlib


def change_id(global_seq, entity_id, change_type):
    raw = "\x1f".join(str(x) for x in (global_seq, entity_id, change_type))
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def chain(prev_hash, body):
    return hashlib.sha256(
        f"{prev_hash}\x1f{body}".encode()).hexdigest()


def build(*, global_seq, entity_type="", entity_id="", change_type="",
          prev_digest="", cur_digest="", actor="", target="",
          source="", confidence=0.0, prev_hash="0" * 64):
    body = "\x1f".join((entity_type, entity_id, change_type,
                        prev_digest, cur_digest, actor, target, source))
    return {"change_id": change_id(global_seq, entity_id, change_type),
            "global_sequence": global_seq, "entity_type": entity_type,
            "entity_id": entity_id, "change_type": change_type,
            "previous_state_digest": prev_digest,
            "current_state_digest": cur_digest, "actor": actor,
            "target": target, "source": source, "confidence": confidence,
            "integrity_hash": chain(prev_hash, body)}


def digest(value):
    """Before/after digest for sensitive state (never the raw value)."""
    return hashlib.sha256(str(value or "").encode()).hexdigest()[:16]


def what_changed(changes, limit=200):
    """Bounded 'what changed' rollup for questions like the last 10s."""
    counts = {}
    for c in list(changes or [])[:max(0, int(limit))]:
        key = str(c.get("change_type") or "?")
        counts[key] = counts.get(key, 0) + 1
    return counts

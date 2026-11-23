"""Loaded-code reconciliation: expected vs current module map. Pure.

Every change is a delta: added/removed/replaced/hash-changed/
signer-changed. Unsigned or user-writable first-seen modules are
recorded as context with network/behavior correlation upstream, never
standalone verdicts. Bounded, no IO.
"""


def diff(expected, current, limit=200):
    """Diff two {base: {path, hash, signer}} maps. Returns [delta]."""
    expected, current = expected or {}, current or {}
    out = []
    for base in list(current)[:max(0, int(limit))]:
        old, new = expected.get(base, {}), current.get(base, {})
        if base not in expected:
            out.append({"change": "module_added", "base": base,
                        "path": new.get("path"), "signed": bool(new.get("signer"))})
        elif old.get("hash") and new.get("hash") \
                and old["hash"] != new["hash"]:
            out.append({"change": "module_hash_changed", "base": base,
                        "path": new.get("path")})
        elif (old.get("signer") or "") != (new.get("signer") or ""):
            out.append({"change": "module_signer_changed", "base": base,
                        "path": new.get("path")})
    for base in list(expected)[:max(0, int(limit))]:
        if base not in current:
            out.append({"change": "module_removed", "base": base})
    return out


def noteworthy(delta, *, user_writable=False, first_seen=False,
               unsigned=False):
    """Context flags for one added-module delta. Advisory only."""
    flags = []
    if unsigned:
        flags.append("unsigned")
    if user_writable:
        flags.append("user-writable-path")
    if first_seen:
        flags.append("first-seen")
    return {"delta": delta, "flags": flags,
            "note": "correlate with network/behavior; not malicious alone"}

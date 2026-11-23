"""Memory as first-class observable state: maps, deltas, activation chains.

For selected processes JARVIS keeps a region map (base, size, perms,
backing: image/file/private, identity) and records deltas, not repeated
full maps: added/removed/protection-change. The high-value pattern is the
activation sequence: RW alloc -> write -> RW→RX -> thread starts inside.
That sequence is evidence (JIT does it legitimately); the process
baseline decides interpretation. Pure, bounded, no IO.
"""

PERMS = ("R", "RW", "RX", "RWX", "RWC", "N")


def summarize(regions, limit=200):
    """Coarse counts by backing and permission. Pure."""
    out = {}
    for r in list(regions or [])[:max(0, int(limit))]:
        key = f"{r.get('backing', '?')}:{r.get('perms', '?')}"
        out[key] = out.get(key, 0) + 1
    return out


def flags(regions, *, known_image_bases=frozenset(), jit_ranges=frozenset(),
          limit=200):
    """Flag noteworthy regions. Returns [{region, flag, severity}]."""
    known = set(known_image_bases or ())
    jit = set(jit_ranges or ())
    out = []
    for r in list(regions or [])[:max(0, int(limit))]:
        base, perms = r.get("base"), str(r.get("perms", ""))
        backing = str(r.get("backing", ""))
        if perms == "RWX" and backing == "private":
            out.append({"region": base, "flag": "private-rwx",
                        "severity": "high"})
        elif "X" in perms and backing == "private" \
                and base not in known and base not in jit:
            out.append({"region": base, "flag": "private-executable",
                        "severity": "medium"})
        elif "X" in perms and not backing:
            out.append({"region": base, "flag": "executable-no-backing",
                        "severity": "medium"})
    return out


def deltas(before, after, limit=200):
    """Region-map diff: added/removed/protection-changed. Bounded."""
    b = {r.get("base"): r for r in (before or []) if r.get("base")}
    a = {r.get("base"): r for r in (after or []) if r.get("base")}
    out = []
    for base in list(a)[:max(0, int(limit))]:
        if base not in b:
            out.append({"change": "region-added", "base": base,
                        "perms": a[base].get("perms")})
        elif a[base].get("perms") != b[base].get("perms"):
            out.append({"change": "protection-changed", "base": base,
                        "before": b[base].get("perms"),
                        "after": a[base].get("perms")})
    for base in list(b)[:max(0, int(limit))]:
        if base not in a:
            out.append({"change": "region-removed", "base": base})
    return out


def activation_sequence(events, limit=50):
    """Detect RW→write→RX→thread-start chains per region. Pure.

    `events`: [{region, kind}] where kind in allocated/written/
    protection/thread_start with optional perms/after. Returns matches.
    """
    events = list(events or [])[:max(0, int(limit))]
    by_region, out = {}, []
    for e in events:
        region = e.get("region")
        if region is not None:
            by_region.setdefault(region, []).append(e)
    for region, region_events in by_region.items():
        # Require the entire ordered chain. A list of unordered event kinds
        # must never be promoted to evidence of code activation.
        stage = 0
        for e in region_events:
            kind = e.get("kind")
            if kind == "allocated":
                stage = 1 if e.get("perms") == "RW" else 0
            elif kind == "written" and stage == 1:
                stage = 2
            elif kind == "protection" and stage == 2:
                if e.get("before") == "RW" and e.get("after") == "RX":
                    stage = 3
                else:
                    stage = 0
            elif kind == "thread_start" and stage == 3:
                out.append({"region": region, "pattern": "activation-sequence",
                            "severity": "medium",
                            "detail": f"{region}: RW allocation, write, RW to RX, "
                                      "thread start; JIT can be legitimate"})
                break
    return out

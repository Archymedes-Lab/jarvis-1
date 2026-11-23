"""Causal chains: one process instance, one ordered story. Pure.

Composes already-recorded transitions (file, network, registry, module,
thread, memory, service) that share a process key into a single
time-ordered chain: opened -> wrote -> renamed -> loaded -> connected.
Raw changes stay individually recorded; this is a view, not a copy.
Bounded, no IO, no model calls.
"""

CHAINABLE = frozenset({
    ("file", "create"), ("file", "write"), ("file", "rename"),
    ("file", "delete"), ("file", "executable_detected"),
    ("network", "connect"), ("network", "end"), ("network", "dns_query"),
    ("registry", "value_set"), ("registry", "key_create"),
    ("process", "image_load"), ("process", "image_unload"),
    ("thread", "start"), ("memory", "protection_changed"),
    ("service", "created"), ("service", "started"),
})


def _proc_key(ev):
    proc = ev.get("process") or {}
    guid = proc.get("guid")
    if guid:
        return f"guid:{guid}"
    return f"pid:{ev.get('host')}:{proc.get('pid')}"


def chain(events, proc_key, limit=100):
    """Ordered chainable transitions for one process instance. Pure."""
    out = []
    for e in list(events or [])[:max(0, int(limit))]:
        if (e.get("category"), e.get("action")) not in CHAINABLE:
            continue
        if _proc_key(e) != proc_key:
            continue
        out.append({"seq": e.get("seq"), "change": f"{e.get('category')}:"
                    f"{e.get('action')}", "time": e.get("time"),
                    "target": e.get("target")})
    return sorted(out, key=lambda c: (c.get("seq") is None,
                                      c.get("seq") or 0))

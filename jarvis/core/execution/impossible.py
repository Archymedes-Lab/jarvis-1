"""Impossible combinations: the anti-hiding engine's tripwires.

Each check names the exact sequence numbers / sample ids that triggered it
so a later rule can replay the same window. Pure, bounded, no IO, no clocks,
no model calls. Severity is risk evidence, never a compromise verdict.
"""

SEVERITY = ("low", "medium", "high", "critical")


def _bounded(items, limit):
    items = list(items or [])
    return items[:max(0, int(limit))]


def cpu_without_process(samples, known_keys, limit=50):
    """CPU execution attributed to no known process instance.

    `samples`: [{key, pid, cpu_pct, sample}] with key as presence.key().
    `known_keys`: set of reconciled/observed instance keys.
    """
    out = []
    for s in _bounded(samples, limit):
        if (s.get("key") or "") not in (known_keys or set()):
            out.append({
                "detector": "visibility-anomaly",
                "severity": "high",
                "detail": (f"CPU activity ({s.get('cpu_pct')}%) attributed "
                           f"to pid {s.get('pid')} with no known process "
                           f"instance ({s.get('key') or 'unknown key'})"),
                "pid": s.get("pid"),
                "key": s.get("key"),
                "sample": s.get("sample"),
            })
    return out


def thread_without_start(thread_owners, start_keys, limit=50):
    """ThreadStart with no corresponding ProcessStart.

    `thread_owners`: [{pid, key, thread_count, sample}].
    `start_keys`: set of instance keys with a creation record.
    """
    out = []
    for t in _bounded(thread_owners, limit):
        if (t.get("key") or "") not in (start_keys or set()):
            out.append({
                "detector": "cross-view-anomaly",
                "severity": "high",
                "detail": (f"pid {t.get('pid')} owns "
                           f"{t.get('thread_count', '?')} running threads "
                           f"with no ProcessStart record"),
                "pid": t.get("pid"),
                "key": t.get("key"),
                "sample": t.get("sample"),
            })
    return out


def network_without_process(connections, known_keys, limit=50):
    """Network connection owned by an invisible process."""
    out = []
    for c in _bounded(connections, limit):
        if (c.get("key") or "") not in (known_keys or set()):
            out.append({
                "detector": "network-orphan",
                "severity": "critical",
                "detail": (f"{c.get('proto', 'TCP')} {c.get('local', '?')} -> "
                           f"{c.get('remote', '?')} owned by pid "
                           f"{c.get('pid')} with no process instance"),
                "pid": c.get("pid"),
                "key": c.get("key"),
            })
    return out


def image_without_process(images, known_keys, limit=50):
    """Executable image / module attributed to no known instance."""
    out = []
    for i in _bounded(images, limit):
        if (i.get("key") or "") not in (known_keys or set()):
            out.append({
                "detector": "image-orphan",
                "severity": "high",
                "detail": (f"executable image {i.get('image', '?')} mapped "
                           f"for pid {i.get('pid')} with no process instance"),
                "pid": i.get("pid"),
                "key": i.get("key"),
            })
    return out


def check_all(*, samples=(), threads=(), connections=(), images=(),
              known_keys=frozenset(), start_keys=frozenset(), limit=50):
    """Run every tripwire over one bounded window. Returns a flat list."""
    known = set(known_keys or ())
    starts = set(start_keys or ())
    out = []
    out.extend(cpu_without_process(samples, known, limit=limit))
    out.extend(thread_without_start(threads, starts, limit=limit))
    out.extend(network_without_process(connections, known, limit=limit))
    out.extend(image_without_process(images, known, limit=limit))
    return out

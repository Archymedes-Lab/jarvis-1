"""Threads as first-class security entities. Pure, bounded, no IO.

Per thread: tid, creation time, start address, owning module, CPU share,
lifecycle, selected stack samples. Detections: start address outside any
known image, sudden explosion vs baseline band. Evidence only.
"""


def anomalies(*, threads=(), known_bases=frozenset(),
              baseline_band=(0, 64), limit=50):
    """Evaluate one window of thread observations. Returns [finding]."""
    known = set(known_bases or ())
    lo, hi = baseline_band
    threads = list(threads or [])[:max(0, int(limit))]
    out = []
    if len(threads) > hi:
        out.append({"detector": "thread-explosion", "severity": "medium",
                    "detail": (f"{len(threads)} threads vs baseline "
                               f"{lo}-{hi}: behavioral transition, "
                               "not a verdict"),
                    "count": len(threads)})
    for t in threads:
        base = t.get("module_base")
        if base is not None and base not in known:
            out.append({"detector": "thread-outside-image",
                        "severity": ("high" if t.get("private_exec_nearby")
                                     else "medium"),
                        "detail": (f"tid {t.get('tid')} starts at "
                                   f"{t.get('start', '?')} outside any known "
                                   "module"),
                        "tid": t.get("tid")})
    return out

"""Explicit visibility invariants: mathematically rigorous tripwires.

Each invariant is a universal claim over one bounded window; a violation
is a factual VisibilityViolation with cited keys/seqs, never "malware":

  I1  every active thread resolves to a known process instance
  I2  every network connection resolves to a known process instance
  I3  every executable module reconciles with a load event, JIT code,
      or an approved mapping (else unexplained-module)
  I4  snapshot presence with continuous coverage but no creation
      evidence is a reconciliation anomaly (not proof of hiding when
      coverage is gapped/pre-boot/settling)
  I5  terminated instances must not accrue new CPU samples

Pure, bounded, no IO, no model calls.
"""

VIOLATIONS = ("thread-without-process", "connection-without-process",
              "unexplained-module", "creation-gap-anomaly",
              "exit-contradiction")


def check(threads=(), connections=(), modules=(), creations=(),
          snapshots=(), post_exit_samples=(), known_processes=frozenset(),
          start_keys=frozenset(), approved_modules=frozenset(),
          jit_keys=frozenset(), load_keys=frozenset(),
          coverage_valid=True, limit=50):
    """Evaluate all invariants over one window. Returns [violation, ...]."""
    limit = max(0, int(limit))
    known = set(known_processes or ())
    starts = set(start_keys or ())
    out = []
    for t in list(threads or [])[:limit]:
        if (t.get("process_key") or "") not in known:
            out.append({"invariant": "I1",
                        "violation": "thread-without-process",
                        "severity": "high",
                        "detail": (f"thread {t.get('key')} active with owner "
                                   "absent from every process view"),
                        "key": t.get("key"), "seqs": t.get("seqs", [])[:5]})
    for c in list(connections or [])[:limit]:
        if (c.get("process_key") or "") not in known:
            out.append({"invariant": "I2",
                        "violation": "connection-without-process",
                        "severity": "critical",
                        "detail": (f"connection {c.get('key')} owned by "
                                   "no known process instance"),
                        "key": c.get("key"), "seqs": c.get("seqs", [])[:5]})
    approved = set(approved_modules or ())
    jit = set(jit_keys or ())
    loads = set(load_keys or ())
    for m in list(modules or [])[:limit]:
        key = m.get("key") or ""
        if key in approved or key in jit or key in loads:
            continue
        out.append({"invariant": "I3",
                    "violation": "unexplained-module",
                    "severity": "medium",
                    "detail": (f"executable module {key} reconciles with no "
                               "load event, JIT range, or approved mapping"),
                    "key": key, "seqs": m.get("seqs", [])[:5]})
    if coverage_valid:
        for s in list(snapshots or [])[:limit]:
            if (s.get("key") or "") not in starts:
                out.append({"invariant": "I4",
                            "violation": "creation-gap-anomaly",
                            "severity": "medium",
                            "detail": (f"snapshot {s.get('key')} under "
                                       "continuous coverage with no creation "
                                       "evidence"),
                            "key": s.get("key"),
                            "seqs": s.get("seqs", [])[:5]})
    for p in list(post_exit_samples or [])[:limit]:
        out.append({"invariant": "I5",
                    "violation": "exit-contradiction",
                    "severity": "high",
                    "detail": (f"terminated instance {p.get('key')} accrued "
                               f"CPU after exit ({p.get('sample')})"),
                    "key": p.get("key"), "seqs": p.get("seqs", [])[:5]})
    return out[:limit] if limit else []

"""Execution fingerprints: behavioral identity per process. Pure.

A ProcessExecutionProfile accumulates executable, signer, parent lineage,
modules, JIT presence, memory summary, CPU profile, syscall/thread
behavior, network/filesystem/registry habits, .NET runtime if present,
and a historical baseline. compare() reports deviations with expected
bands; interpretation uses the baseline (Chrome/V8 JIT vs Notepad RWX).
No IO, no model calls.
"""

FIELDS = ("executable", "signer", "parent", "modules", "jit", "memory",
          "cpu", "threads", "network", "files", "registry", "dotnet")


def compare(baseline, current):
    """List deviations between two profile dicts. Bounded, deterministic."""
    out = []
    for field in FIELDS:
        old, new = (baseline or {}).get(field), (current or {}).get(field)
        if old is None or new is None:
            continue
        if isinstance(old, (int, float)) and isinstance(new, (int, float)):
            band = (baseline or {}).get(f"{field}_band")
            if band and len(band) == 2 and not (band[0] <= new <= band[1]):
                out.append({"field": field, "before": old, "after": new,
                            "severity": "medium",
                            "detail": f"{field} left baseline band "
                                      f"{band[0]}-{band[1]}"})
            elif not band and old != new:
                out.append({"field": field, "before": old, "after": new,
                            "severity": "low",
                            "detail": f"{field} changed"})
        elif old != new:
            out.append({"field": field, "before": old, "after": new,
                        "severity": "low",
                        "detail": f"{field} changed"})
    return out

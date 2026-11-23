"""CLR intelligence: light EventPipe watch, gated ClrMD depth. Pure.

Continuous observation uses a lightweight profile only: assembly loads,
JIT rate, exception bursts, thread-pool growth. Deep inspection (ClrMD
snapshot of threads/assemblies/heap/handles) is incident-triggered and
expressed here as a gated request, never an automatic attach. IL->native
mapping resolves a native sample back to assembly/type/method for display.

All inputs are metadata (names, counts, ranges); no code is executed and
no dump contents are parsed here. No IO, no model calls.
"""

ASSEMBLY_FIELDS = ("name", "version", "hash", "signed", "path",
                   "load_context", "time", "dynamic")


def assembly_anomalies(loads, *, known_paths=frozenset(), limit=50):
    """Flag first-seen / temp-path / dynamic / identity-mismatch loads."""
    known = {str(p).lower() for p in (known_paths or ())}
    out = []
    for a in list(loads or [])[:max(0, int(limit))]:
        path = str(a.get("path") or "")
        reasons = []
        if a.get("dynamic"):
            reasons.append("dynamic-assembly")
        if path and ("temp" in path.lower() or "tmp" in path.lower()):
            reasons.append("temp-path")
        if path and path.lower() not in known and not a.get("dynamic"):
            reasons.append("first-seen-path")
        if reasons:
            out.append({"detector": "assembly-load", "severity": "medium",
                        "assembly": a.get("name"), "reasons": reasons,
                        "detail": ("; ".join(reasons) + ": correlate, "
                                   "do not convict")})
    return out


def runtime_anomalies(*, jit_per_window=0, jit_baseline=5,
                      exceptions_per_min=0, exc_baseline=10,
                      threads=0, thread_baseline=32):
    """JIT bursts, exception storms, managed thread explosions. Pure."""
    out = []
    if jit_per_window > max(jit_baseline * 5, 20):
        out.append({"detector": "jit-burst", "severity": "medium",
                    "detail": f"{jit_per_window} methods compiled after idle"})
    if exceptions_per_min > max(exc_baseline * 5, 50):
        out.append({"detector": "exception-storm", "severity": "medium",
                    "detail": f"{exceptions_per_min} exceptions/min"})
    if threads > max(thread_baseline * 3, 96):
        out.append({"detector": "managed-thread-explosion",
                    "severity": "medium",
                    "detail": f"{threads} managed threads"})
    return out


def resolve_sample(address, jit_ranges):
    """Map a native address to its managed method, if inside a JIT range.

    `jit_ranges`: [{start, end, assembly, type, method}]. Integer compare;
    returns the method record or None. Display only.
    """
    try:
        addr = int(address, 16) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return None
    for r in jit_ranges or ():
        try:
            lo = int(r["start"], 16) if isinstance(r["start"], str) \
                else int(r["start"])
            hi = int(r["end"], 16) if isinstance(r["end"], str) \
                else int(r["end"])
        except (TypeError, ValueError, KeyError):
            continue
        if lo <= addr <= hi:
            return {"assembly": r.get("assembly"), "type": r.get("type"),
                    "method": r.get("method")}
    return None


def snapshot_request(verdict, *, human_authorized=False):
    """Gated ClrMD snapshot request. Never automatic."""
    if verdict not in ("CROSS_VIEW_MISMATCH", "UNEXPLAINED_PROCESS",
                       "DOTNET_ANOMALY"):
        return None
    if not human_authorized:
        return {"level": "L6-clr", "authorized": False,
                "action": "await explicit human authorization; "
                          "snapshot (brief suspend) then read-only ClrMD"}
    return {"level": "L6-clr", "authorized": True,
            "action": "capture snapshot first, then ClrMD threads/"
                      "assemblies/heap/handles read-only"}

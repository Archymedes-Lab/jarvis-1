"""Protected processes: honest semantics, never suspicion by default.

Some Windows processes (lsass, csrss, services, Defender) run as
Protected Process Light and refuse PROCESS_VM_READ/WRITE and thread
creation from ordinary processes by design. JARVIS respects that
boundary: lifecycle/thread/image agreement with restricted memory reads
"EXPECTED_PROTECTED_PROCESS", never a finding. No PPL bypass is attempted.
Pure.
"""

EXPECTED_PROTECTED = frozenset({
    "lsass", "csrss", "smss", "wininit", "services", "lsaiso",
    "msmpeng", "mssense", "memory compression", "registry", "system",
})


def classify(*, name="", lifecycle_ok=False, memory_restricted=False,
             protection=""):
    name = str(name or "").lower().strip()
    prot = str(protection or "")
    if lifecycle_ok and memory_restricted and (
            name in EXPECTED_PROTECTED or prot.upper().startswith("PPL")
            or "protected" in prot.lower()):
        return {"state": "EXPECTED_PROTECTED_PROCESS", "severity": "ok",
                "detail": (f"{name or 'process'} agrees across lifecycle "
                           "views; memory inspection restricted by the OS "
                           f"({prot or 'PPL'}); respected, not bypassed")}
    if memory_restricted and not lifecycle_ok:
        return {"state": "RESTRICTED_UNVERIFIED", "severity": "low",
                "detail": ("memory restricted and lifecycle views disagree; "
                           "reconcile first, do not infer from restriction")}
    return {"state": "ORDINARY", "severity": "ok",
            "detail": "no protected-process semantics apply"}

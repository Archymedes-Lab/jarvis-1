"""Synthetic visibility-evasion telemetry: Forge fuel, nothing runs.

Generators write canonical events straight into a throwaway sequence;
nothing executes on the OS (safety tier: synthetic, runnable anywhere).
Each yields (events, expectation) for reconciliation/invariant tests:

  short_lived_process   create + exit inside one snapshot interval
  rapid_module_loads    burst of image loads for one instance
  creation_exit_race    exit reordered before create (transport skew)
  protected_process     PPL lifecycle agreement, restricted memory
  dropped_events        gap with no creation evidence (coverage invalid)

Pure, bounded, no IO.
"""

SEQ = [0]


def _next():
    SEQ[0] += 1
    return SEQ[0]


def _ev(category, action, **kw):
    e = {"seq": _next(), "category": category, "action": action}
    e.update(kw)
    return e


def short_lived_process(pid=9001, guid="short-1"):
    proc = {"pid": pid, "guid": guid, "image": "evil.exe"}
    return [(_ev("process", "start", process=proc),
             _ev("process", "exit", process=proc))]


def rapid_module_loads(pid=9002, guid="mod-1", n=25):
    proc = {"pid": pid, "guid": guid}
    return [_ev("process", "image_load", process=proc,
                target={"path": f"C:\\t\\m{i}.dll"}) for i in range(n)]


def creation_exit_race(pid=9003, guid="race-1"):
    proc = {"pid": pid, "guid": guid}
    # Transport skew delivers exit first; ordering is by seq, so the
    # projection must still end with the instance gone, not stuck alive.
    return [(_ev("process", "exit", process=proc),
             _ev("process", "start", process=proc))]


def protected_process(pid=4, name="lsass.exe"):
    return [{"pid": pid, "name": name, "protection": "PPL-WindowsTCB",
             "lifecycle_ok": True, "memory_restricted": True}]


def dropped_events():
    # A gap before coverage: snapshot presence with no creation record
    # must read UNKNOWN, never a hiding verdict.
    return {"coverage_valid": False, "snapshot_without_creation": True}

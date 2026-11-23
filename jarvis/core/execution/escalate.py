"""Escalation policy: cheap always, deep only on discrepancy.

L0/L1/L2/L5/L7 run every interval (bounded, event-driven). L3 (native
stack sampling) and L4 (.NET runtime: memscan + CLR settings) run only for
selected pids: a CROSS_VIEW_MISMATCH or UNEXPLAINED_PROCESS verdict, with
governor pressure clear and a per-interval budget remaining.

L6 (memory dump / instruction trace) never runs automatically: it needs
explicit human authorization, a forensic copy before acting, and a recovery
contract. This module expresses that as data; it executes nothing.

Pure, no IO, no clocks, no model calls.
"""

MAX_DEEP_PER_INTERVAL = 5
MAX_STACK_SAMPLES_PER_PID = 32

DEEP_VERDICTS = frozenset({"CROSS_VIEW_MISMATCH", "UNEXPLAINED_PROCESS"})
WATCH_VERDICTS = frozenset({"EXITED", "UNKNOWN"})


def decide(verdicts, *, pressured=False, deep_used=0,
           human_authorized_pids=(), limit=MAX_DEEP_PER_INTERVAL):
    """Decide the next observation depth per process instance. Pure.

    `verdicts`: iterable of reconcile() verdict dicts (each with key,
    verdict, severity). Returns {"cheap": [...], "deep": [...],
    "gated": [...], "deferred": [...], "reason": str}.
    """
    verdicts = list(verdicts or [])
    deep_allowed = max(0, int(limit) - int(deep_used or 0))
    authorized = {str(p) for p in (human_authorized_pids or ())}
    cheap, deep, gated, deferred = [], [], [], []
    for v in verdicts:
        key = str(v.get("key") or "")
        verdict = str(v.get("verdict") or "UNKNOWN")
        if verdict in DEEP_VERDICTS:
            if pressured:
                deferred.append({"key": key, "level": "L3/L4",
                                 "reason": "host pressured; governor yields"})
            elif deep_allowed > 0:
                deep_allowed -= 1
                deep.append({"key": key, "level": "L3+L4",
                             "actions": ["bounded stack sample "
                                         f"(<= {MAX_STACK_SAMPLES_PER_PID})",
                                         "memscan regions + assemblies + "
                                         "CLR settings for this pid only"],
                             "reason": f"{verdict}; discrepancy-escalated"})
                if key and key in authorized:
                    gated.append({"key": key, "level": "L6",
                                  "actions": ["forensic memory capture first",
                                              "instruction trace under "
                                              "explicit authorization"],
                                  "reason": "human authorized; dump before act"})
            else:
                deferred.append({"key": key, "level": "L3/L4",
                                 "reason": "per-interval deep budget exhausted"})
        elif verdict in WATCH_VERDICTS:
            cheap.append({"key": key, "level": "L1+L2+L7",
                          "reason": f"{verdict}; cheap re-check next interval"})
        else:
            cheap.append({"key": key, "level": "L1+L2+L5+L7",
                          "reason": f"{verdict}; routine cheap watch"})
    if pressured:
        reason = ("host pressured: cheap layers only, "
                  f"{len(deferred)} deep escalations deferred")
    elif deep:
        reason = (f"{len(deep)} discrepancy-escalated deep inspection(s), "
                  f"{len(deferred)} deferred on budget")
    else:
        reason = "no discrepancy: cheap watch only"
    return {"cheap": cheap, "deep": deep, "gated": gated,
            "deferred": deferred, "reason": reason}

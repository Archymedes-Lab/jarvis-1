"""Score a scenario across the whole defensive chain, one property at a time.

A test is not pass/fail. It is a row of properties — observed, understood,
correlated, classified, and, when a live response was exercised, intervened
through verified — each scored on its own. A "100% Arena score" then means a
defined validation suite passes end to end, not the impossible claim that no
attack could ever succeed.

The chain also records the earliest point at which JARVIS had, in the recorded
telemetry, enough to classify the attack: the metric the design ultimately
optimises — how early could it have acted, not merely whether it did.
"""

from .scenario import PROPERTIES

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
PASS, PARTIAL, FAIL, NA = "pass", "partial", "fail", "not_exercised"


def _norm(kind, value):
    value = str(value or "").strip()
    return value.lower().rstrip(".") if kind in ("sha256", "dns", "image") else value


def _indicator_in(event, kind, value):
    want = _norm(kind, value)
    proc, target = event.get("process") or {}, event.get("target") or {}
    if kind == "sha256":
        return want in (_norm("sha256", proc.get("sha256")), _norm("sha256", target.get("sha256")))
    if kind == "dns":
        return want == _norm("dns", target.get("query"))
    if kind == "ip":
        return want == _norm("ip", target.get("ip"))
    if kind == "image":
        return want == _norm("image", proc.get("image"))
    if kind == "cmdline":
        return want.lower() in (proc.get("cmdline") or "").lower()
    return False


def _observed(scenario, events):
    want = scenario.expect.observed
    matched, hits = [], []
    for ind in want:
        kind, value = ind["kind"], ind["value"]
        found = [e for e in events if _indicator_in(e, kind, value)]
        matched.append(bool(found))
        hits += found
    n = sum(matched)
    status = PASS if n == len(want) else PARTIAL if n else FAIL
    detail = f"{n}/{len(want)} expected indicators present in {len(events)} recorded events"
    return status, detail, hits


def _understood(hits):
    if not hits:
        return FAIL, "no events to interpret", 0.0
    known = [e for e in hits if e.get("category") != "unknown"]
    frac = len(known) / len(hits)
    return (PASS if frac == 1 else PARTIAL if frac else FAIL,
            f"{len(known)}/{len(hits)} events normalized to a known category", frac)


def _correlated(hits):
    if len(hits) < 2:
        return NA, "fewer than two events to correlate", None
    guids = {}
    for e in hits:
        g = (e.get("process") or {}).get("guid")
        if g:
            guids[g] = guids.get(g, 0) + 1
    linked = max(guids.values()) if guids else 0
    parents = {(e.get("parent") or {}).get("guid") for e in hits} & set(guids)
    if linked >= 2 or parents:
        return PASS, f"events share a process identity (parent/child linked: {bool(parents)})", linked
    return FAIL, "events could not be tied to one execution", linked


def _classified(scenario, findings):
    want = scenario.expect.classified
    if not want:
        return NA, "no classification expected", None
    floor = SEV.get(want.get("min_severity", "low"), 3)
    for f in findings:
        if want.get("category") and f["category"] != want["category"]:
            continue
        if SEV.get(f["severity"], 9) > floor:
            continue
        if want.get("title") and want["title"].lower() not in f["title"].lower():
            continue
        return PASS, f"classified: [{f['severity']}] {f['title']}", f
    got = ", ".join(f"[{f['severity']}] {f['category']}" for f in findings[:6]) or "nothing"
    return FAIL, f"expected {want}; detector produced {got}", None


def _response(scenario, response, prop):
    if not getattr(scenario.expect, prop):
        return NA, f"{prop} not expected", None
    if not response or prop not in response:
        return FAIL, f"{prop} expected but no response was exercised", None
    ok = bool(response[prop])
    return (PASS if ok else FAIL), f"{prop}: {response.get(prop)}", response[prop]


def earliest_decision(scenario, hits):
    """The earliest recorded event that constitutes the attack: when JARVIS
    first had, in telemetry, enough to have acted."""
    trigger = set(scenario.trigger_events)
    candidates = [e for e in hits if not trigger or int(e.get("source_event") or 0) in trigger]
    candidates = candidates or hits
    if not candidates:
        return None
    first = min(candidates, key=lambda e: e.get("seq", 1 << 62))
    return {"seq": first.get("seq"), "time": first.get("time"),
            "source_event": first.get("source_event"),
            "action": f"{first.get('category')}.{first.get('action')}"}


def score(scenario, events, findings, response=None):
    card = {}
    obs_status, obs_detail, hits = _observed(scenario, events) if scenario.expect.observed \
        else (NA, "no telemetry expected", [])
    card["observed"] = {"status": obs_status, "detail": obs_detail}
    if scenario.expect.observed:
        u_s, u_d, _ = _understood(hits)
        c_s, c_d, _ = _correlated(hits)
        card["understood"] = {"status": u_s, "detail": u_d}
        card["correlated"] = {"status": c_s, "detail": c_d}
    cl_s, cl_d, _ = _classified(scenario, findings)
    card["classified"] = {"status": cl_s, "detail": cl_d}
    for prop in ("intervened", "contained", "removed", "restored", "verified"):
        s, d, _ = _response(scenario, response, prop)
        card[prop] = {"status": s, "detail": d}

    exercised = [p for p in PROPERTIES if card.get(p, {}).get("status", NA) != NA]
    passed = [p for p in exercised if card[p]["status"] == PASS]
    partial = [p for p in exercised if card[p]["status"] == PARTIAL]
    return {
        "scenario": scenario.id,
        "title": scenario.title,
        "techniques": scenario.techniques,
        "properties": {p: card[p] for p in PROPERTIES if p in card},
        "exercised": exercised,
        "passed": passed,
        "score": round(100 * len(passed) / len(exercised)) if exercised else 0,
        "ok": len(passed) == len(exercised) and bool(exercised),
        "partial": partial,
        "earliest_decision": earliest_decision(scenario, hits),
    }

"""Explicit experience invariants: the personality of the system, tested.

Phase 22: these describe what JARVIS must feel like, not which features it
has. Each check is a pure function returning {"ok": bool, "reason": str} so
the same logic runs in unit tests, the scheduler self-audit and (later) the
dashboard. Thresholds are parameters, never hidden constants, so tests pin
the contract instead of the current tuning.

  startup      UI can open, engine exists, health state known within N s
  protection   UI failure never disables the security engine
  freshness    no mandatory collector goes stale without recovery active
  repair       no model-generated patch applies without exact authorization
  evidence     no response counts as successful without verification
  performance  noncritical work yields when the host is pressured
  privacy      precise location / interaction content stays local by default
"""

STARTUP_BUDGET_SECONDS = 30.0


def startup(*, ui_openable, engine_exists, health_known, elapsed_seconds,
            budget=STARTUP_BUDGET_SECONDS):
    if not engine_exists:
        return {"ok": False, "reason": "engine process absent after login"}
    if not health_known:
        return {"ok": False, "reason": "health state unknown; protection "
                "must be represented honestly, never as false green"}
    if not ui_openable:
        return {"ok": False, "reason": "UI cannot open within startup budget"}
    if elapsed_seconds > budget:
        return {"ok": False,
                "reason": f"startup took {elapsed_seconds:.1f}s, budget {budget:.0f}s"}
    return {"ok": True, "reason": "engine present, health known, UI openable"}


def protection(*, ui_failed, engine_active):
    if ui_failed and not engine_active:
        return {"ok": False, "reason": "UI failure disabled the engine; "
                "Defender must continue when the UI crashes"}
    if not engine_active:
        return {"ok": False, "reason": "security engine not active"}
    return {"ok": True, "reason": "engine independent of UI liveness"}


def freshness(*, stale_mandatory, recovery_active):
    if stale_mandatory and not recovery_active:
        return {"ok": False, "reason": "mandatory collector stale with no "
                "recovery active; staleness must page, never look current"}
    return {"ok": True, "reason": "no unstale-mandatory gap without recovery"}


def repair(*, patch_hash, authorized_hash):
    if not patch_hash:
        return {"ok": True, "reason": "no patch proposed; nothing to authorize"}
    if not authorized_hash:
        return {"ok": False, "reason": "patch proposed but no authorization recorded"}
    if patch_hash != authorized_hash:
        return {"ok": False, "reason": "patch hash does not match exact "
                "human authorization; refuse to apply"}
    return {"ok": True, "reason": "exact patch-hash authorization present"}


def evidence(*, response_claimed_success, independently_verified):
    if response_claimed_success and not independently_verified:
        return {"ok": False, "reason": "response claimed success without "
                "independent verification; a vanished finding is not proof"}
    return {"ok": True, "reason": "no unverified success claims"}


def performance(*, host_pressured, noncritical_running):
    if host_pressured and noncritical_running:
        return {"ok": False, "reason": "noncritical work (deep hunt, secret "
                "scan, compaction, model narration) still running under host "
                "pressure; the governor must yield"}
    return {"ok": True, "reason": "noncritical work yields under pressure"}


def privacy(*, precise_location_exfiltrated=False,
            interaction_content_exfiltrated=False):
    if precise_location_exfiltrated:
        return {"ok": False, "reason": "precise coordinates left the machine "
                "by default; request tiles independently of the point overlay"}
    if interaction_content_exfiltrated:
        return {"ok": False, "reason": "raw interaction content (mouse/key "
                "detail) left the machine; observe listener shapes, not content"}
    return {"ok": True, "reason": "precise location and interaction content local"}


def evaluate_all(**kwargs):
    """Evaluate every invariant; kwargs map invariant name -> check kwargs."""
    checks = {"startup": startup, "protection": protection,
              "freshness": freshness, "repair": repair,
              "evidence": evidence, "performance": performance,
              "privacy": privacy}
    out = {}
    for name, fn in checks.items():
        params = kwargs.get(name, {})
        try:
            out[name] = fn(**params)
        except TypeError as exc:
            out[name] = {"ok": False, "reason": f"invariant miswired: {exc}"}
    out["ok"] = all(v["ok"] for v in out.values() if isinstance(v, dict))
    return out

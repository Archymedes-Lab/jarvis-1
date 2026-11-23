"""The response ladder: decide what to do about a finding, and do the safe part.

For every finding a collector produces, this places it on one rung:

  AUTO      a reversible containment action is defined, the evidence is strong,
            and you have enabled it — so JARVIS captures evidence and acts now,
            then tells you what it did and how to undo it.
  PROPOSE   an action is defined but either it is not reversible, or you have
            not enabled automatic response for it, or the evidence is not
            strong enough to act unasked — so it waits for your approval.
  ASK       no action fits, but the finding is one only you can judge — so it
            becomes a question (questions.py), not a silent alert.
  WATCH     nothing to do; it stays on the dashboard and in the advisory.

Everything AUTO does is reversible and logged in the defense ledger, and the
whole autonomous layer is off until `autonomous_defense` is set: the default
posture is PROPOSE, never act.

An action may be time-bounded (Action.ttl): the applied entry then carries an
`expires_at`, and expire() lifts it with the action's own undo. An expiry is not
a human override, so a recurrence may apply it again, longer; a human undo still
turns every recurrence into a proposal.
"""

import hashlib
import json
import time

from jarvis.core.finding import content_origin
from jarvis.response import acknowledge, alert, tools
from jarvis.response.actions import base
from jarvis.response.evidence.case import Case

LEDGER_META = "defense_ledger_v1"
KEEP = 500
FAILED_RETRY_SECONDS = 3600
RECOVERABLE = ("attempting", "uncertain")

AUTO, PROPOSE, ASK, WATCH = "auto", "propose", "ask", "watch"

# A finding must be at least this severe before a reversible action runs
# unasked. Below it, the action is still offered, but only proposed.
AUTO_MIN_SEVERITY = ("critical", "high")


def _entry_id(action_id, finding, job, target=None):
    # Response annotations are presentation state added after the first pass.
    # They must not make the same detector finding look like a new action.
    stable_finding = dict(finding or {})
    stable_finding.pop("defense", None)
    action = base.get(action_id)
    ident = action.identity(stable_finding, target) if action and target else None
    key = f"{action_id}|{job}|{ident or alert.finding_key(stable_finding)}"
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:8]


def load(store, *, strict=False):
    try:
        value = json.loads(store.get_meta(LEDGER_META, "{}"))
        if not isinstance(value, dict) or any(not isinstance(e, dict) for e in value.values()):
            raise ValueError("invalid defense ledger")
        return value
    except (TypeError, ValueError):
        if strict:
            raise ValueError("Defense history is unreadable; response is inhibited.") from None
        return {}


def _save(store, ledger):
    if len(ledger) > KEEP:
        for eid in sorted(ledger, key=lambda k: ledger[k].get("at", 0))[:len(ledger) - KEEP]:
            if ledger[eid].get("status") in ("undone", "expired", "proposed"):
                ledger.pop(eid, None)
    store.set_meta(LEDGER_META, json.dumps(ledger))


def _enabled(conf, action):
    if conf.get("autonomous_defense", False) is not True:
        return False
    if action.autonomy != base.AUTO or not action.enable_flag:
        return False
    return conf.get(action.enable_flag, False) is True


def decide(finding, job, conf, acks):
    """(rung, action|None, target|None) for one finding, without acting."""
    f = finding or {}
    if f.get("severity") in (None, "ok"):
        return WATCH, None, None
    if acks and acknowledge.is_acknowledged(acks, f, job):
        return WATCH, None, None
    for action in base.registry().values():
        target = action.match(f, job)
        if not target or not action.permitted(target, conf)[0]:
            continue
        # A finding raised by signed detection content (core/rulepack.py) is
        # evidence, never authority: it may be proposed, never acted on unasked.
        # Read from the title as well: a stored finding comes back without its `origin` key.
        strong = f.get("severity") in AUTO_MIN_SEVERITY and not content_origin(f)
        if _enabled(conf, action) and strong and action.auto_eligible(f, job, target):
            return AUTO, action, target
        return PROPOSE, action, target
    return WATCH, None, None


def _capture(finding, job, action, target):
    """Open an evidence case before acting. Returns (name, results, complete).

    The finding and exact target are always evidence. If an action names source
    files, every one must be copied successfully before a mutation may run.
    """
    files = action.evidence(target)
    # Nanoseconds keep simultaneous actions and fast tests in separate cases.
    name = f"defense-{action.id}-{time.time_ns()}"
    try:
        case = Case(name)
        case.manifest.meta.update({"reason": finding.get("title", ""), "job": job,
                                   "action": action.id})
        case.add_text("finding.json", {"finding": finding, "job": job,
                                       "action": action.id, "target": target},
                      kind="response-context")
        results = [case.add_file(p, kind="target") for p in files]
        pid = target.get("pid") if isinstance(target, dict) else None
        if isinstance(pid, int):
            case.add_text("process-tree.json", tools.process_tree(pid),
                          kind="process-context")
        case.manifest.save()
        return case.name, results, all(r.get("ok") for r in results)
    except Exception:
        return "", [], False


def _stamp(entry, action, target, prior, now):
    """Count one more application and set its expiry when the action has one."""
    entry["applications"] = int(prior or 0) + 1
    ttl = action.ttl(target, int(prior or 0))
    if ttl:
        entry["expires_at"] = int(now) + int(ttl)
    entry.pop("expire_error", None)
    return entry


def _apply(store, conf, finding, job, action, target, now=None):
    now = time.time() if now is None else now
    case_name, _, captured = _capture(finding, job, action, target)
    if not captured:
        eid = _entry_id(action.id, finding, job, target)
        entry = {"action": action.id, "title": action.title, "target": target,
                 "finding": {"title": finding.get("title"),
                             "severity": finding.get("severity"),
                             "category": finding.get("category"),
                             "where": finding.get("where"),
                             "host": finding.get("host")},
                 "job": job, "preview": action.preview(target), "evidence": case_name,
                 "at": int(time.time()), "detail": "evidence capture failed; no action taken",
                 "status": "failed", "record": {}}
        ledger = load(store)
        ledger[eid] = entry
        _save(store, ledger)
        return eid, entry, False
    case = None
    try:
        if case_name:
            case = Case(case_name, create=False)
    except Exception:
        case = None
    eid, entry, _ = _propose(store, conf, finding, job, action, target, now)
    if entry["status"] in ("attempting", "uncertain"):
        return eid, entry, False
    entry.update(status="attempting", evidence=case_name, approved_by="auto",
                 detail="Action started; outcome requires verification if interrupted.")
    ledger = load(store)
    ledger[eid] = entry
    _save(store, ledger)  # durable intent BEFORE any side effect
    try:
        ok, record, detail = action.apply(target, case)
    except Exception:
        entry.update(status="uncertain", detail="Action interrupted; inspect evidence and target before recovery.")
        _save(store, ledger)
        return eid, entry, False
    eid = _entry_id(action.id, finding, job, target)
    ledger = load(store)
    prior = ledger.get(eid) or {}
    entry = {"action": action.id, "title": action.title, "target": target,
             "finding": {"title": finding.get("title"), "severity": finding.get("severity"),
                         "category": finding.get("category"), "where": finding.get("where"),
                         "host": finding.get("host")},
             "job": job, "preview": action.preview(target), "evidence": case_name,
             "at": int(now), "detail": detail,
             "status": "applied" if ok else "failed", "record": record,
             "applications": int(prior.get("applications") or 0),
             "attempts": (prior.get("attempts") or [])[-9:] + [int(now)]}
    if ok:
        _stamp(entry, action, target, prior.get("applications"), now)
    ledger[eid] = entry
    _save(store, ledger)
    return eid, entry, ok


def _propose(store, conf, finding, job, action, target, now=None):
    eid = _entry_id(action.id, finding, job, target)
    ledger = load(store)
    existing = ledger.get(eid)
    if existing and existing.get("status") in ("applied", "undone", "proposed", "attempting", "uncertain", "not_applied"):
        return eid, existing, False
    entry = {"action": action.id, "title": action.title, "target": target,
             "finding": {"title": finding.get("title"), "severity": finding.get("severity"),
                         "category": finding.get("category"), "where": finding.get("where"),
                         "host": finding.get("host")},
             "job": job, "preview": action.preview(target), "evidence": "",
             "at": int(time.time() if now is None else now), "detail": "",
             "status": "proposed", "record": {},
             # An expired action's history survives, so a repeat escalates.
             "applications": int((existing or {}).get("applications") or 0)}
    ledger[eid] = entry
    _save(store, ledger)
    return eid, entry, True


# Called with (store, eid) for each new proposal. The phone-approval module registers
# itself here when the scheduler loads it (notify/replies.py), so this module never
# imports the notify layer (no import cycle). Listeners must be local and cheap.
PROPOSAL_LISTENERS = []


def _queue_for_phone(store, eid):
    """Tell listeners (phone approvals) about a new proposal. A failure never touches the ladder."""
    for listener in list(PROPOSAL_LISTENERS):
        try:
            listener(store, eid)
        except Exception:
            pass


def _active(ledger, action_id):
    return sum(1 for e in ledger.values()
               if e.get("action") == action_id and e.get("status") in ("applied", "attempting", "uncertain"))


def process(store, conf, job, findings, *, coverage="complete", now=None):
    """Run the ladder over one job's findings. Returns the findings, annotated.

    Each finding that reaches AUTO or PROPOSE gets a `defense` key so the
    score, triage and emails know it is handled or waiting, and can print the
    approve/undo command. Nothing is annotated when the layer is off except
    genuine automatic actions, which run only when enabled.
    """
    load(store, strict=True)  # lost history must never re-authorize an action
    findings = list(findings or [])
    acks = acknowledge.load(store)
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rung, action, target = decide(finding, job, conf, acks)
        if rung == AUTO and coverage != "complete":
            # A partial result can support a proposal, but it must not grant
            # unattended authority. The scheduler supplies the durable receipt.
            rung = PROPOSE
        if rung == AUTO and action.max_active:
            ledger = load(store)
            current = ledger.get(_entry_id(action.id, finding, job, target)) or {}
            if (current.get("status") not in ("applied", "attempting", "uncertain")
                    and _active(ledger, action.id) >= action.max_active):
                # Bounded blast radius: past the cap a person decides.
                rung = PROPOSE
        if rung == AUTO:
            eid = _entry_id(action.id, finding, job, target)
            existing = load(store).get(eid)
            if existing and existing.get("status") in ("applied", "attempting", "uncertain", "not_applied"):
                entry = existing
            elif existing and (existing.get("status") == "undone"
                               or (existing.get("status") == "proposed" and existing.get("override"))):
                # Undo is a human override. Never fight it on a later collector
                # pass: the recurrence becomes a proposal and stays one, marked,
                # until a person approves it (V13; the second recurrence used to
                # re-apply it, found by jarvis/verify/models/response_ladder.py).
                existing.update(status="proposed", at=int(time.time()), override=True,
                                detail="previous automatic action was undone; approval required")
                ledger = load(store)
                ledger[eid] = existing
                _save(store, ledger)
                finding["defense"] = {
                    "rung": PROPOSE, "id": eid, "action": action.id,
                    "preview": existing.get("preview") or action.preview(target),
                    "approve": f"jarvis defend approve {eid}"}
                continue
            elif (existing and existing.get("status") == "failed"
                  and time.time() - int(existing.get("at") or 0) < FAILED_RETRY_SECONDS):
                entry = existing
            else:
                eid, entry, _ok = _apply(store, conf, finding, job, action, target, now)
            finding["defense"] = {"rung": AUTO, "id": eid, "action": action.id,
                                  "status": entry["status"], "detail": entry["detail"],
                                  "undo": f"jarvis defend undo {eid}"}
        elif rung == PROPOSE:
            eid, entry, _new = _propose(store, conf, finding, job, action, target, now)
            if entry.get("status") in ("attempting", "uncertain"):
                finding["defense"] = {
                    "rung": PROPOSE, "id": eid, "action": action.id,
                    "status": entry["status"], "detail": entry["detail"],
                    "reason": "Prior action outcome is uncertain; inspect evidence and target before recovery."}
            if entry.get("status") == "proposed":
                finding["defense"] = {"rung": PROPOSE, "id": eid, "action": action.id,
                                      "preview": entry["preview"],
                                      "approve": f"jarvis defend approve {eid}"}
                if coverage != "complete":
                    finding["defense"]["reason"] = "incomplete collection; automatic response inhibited"
                elif _new:
                    _queue_for_phone(store, eid)
    return findings


# ── acting on a proposal, and undoing ──────────────────────────────────────

def approve(store, eid, now=None, conf=None, by=None):
    """Apply a proposed action now. Returns (ok, detail). `by` names who approved (default: the operator)."""
    ledger = load(store, strict=True)
    entry = ledger.get(eid)
    if not entry:
        return False, f"no proposal with id {eid}"
    if entry["status"] == "applied":
        return True, "already applied"
    action = base.get(entry["action"])
    if not action:
        return False, "that action no longer exists"
    if entry["status"] in ("attempting", "uncertain"):
        return False, "Prior action outcome is uncertain; inspect evidence and target before recovery."
    allowed, why = action.permitted(entry["target"], alert.load_conf() if conf is None else conf)
    if not allowed:
        return False, why
    now = time.time() if now is None else now
    finding = {**entry["finding"]}
    case_name, _, captured = _capture(finding, entry["job"], action, entry["target"])
    if not captured:
        entry.update(status="failed", detail="evidence capture failed; no action taken",
                     evidence=case_name or entry.get("evidence", ""))
        _save(store, ledger)
        return False, entry["detail"]
    case = None
    try:
        case = Case(case_name, create=False) if case_name else None
    except Exception:
        case = None
    entry.update(status="attempting", evidence=case_name, approved_by=by or "operator",
                 detail="Action started; outcome requires verification if interrupted.")
    _save(store, ledger)
    try:
        ok, record, detail = action.apply(entry["target"], case)
    except Exception:
        entry.update(status="uncertain", detail="Action interrupted; inspect evidence and target before recovery.")
        _save(store, ledger)
        return False, entry["detail"]
    entry.update(status="applied" if ok else "failed", record=record, detail=detail,
                 evidence=case_name or entry.get("evidence", ""),
                 applied_at=int(now))
    if ok:
        _stamp(entry, action, entry["target"], entry.get("applications"), now)
        entry.pop("override", None)          # the approval is the person's new decision
    _save(store, ledger)
    return ok, detail


def undo(store, eid):
    ledger = load(store, strict=True)
    entry = ledger.get(eid)
    if not entry:
        return False, f"no action with id {eid}"
    if entry["status"] != "applied":
        return False, f"nothing to undo (status: {entry['status']})"
    action = base.get(entry["action"])
    if not action:
        return False, "that action no longer exists"
    ok, detail = action.undo(entry["target"], entry.get("record") or {})
    if ok:
        entry.update(status="undone", undo_detail=detail, undone_at=int(time.time()))
        _save(store, ledger)
    return ok, detail


def reconcile(store, now=None):
    """Resolve interrupted actions using read-only, action-specific probes.

    This never repeats or rolls back an action.  It promotes an interrupted
    entry only when the probe can establish both the applied state and a safe
    undo record.  All other outcomes remain visibly unresolved.
    """
    ledger = load(store, strict=True)
    changed, results = False, []
    for eid, entry in ledger.items():
        if entry.get("status") not in RECOVERABLE:
            continue
        action = base.get(entry.get("action"))
        if action is None:
            entry.update(status="uncertain", detail="action implementation is unavailable; inspect evidence")
            results.append((eid, "unknown", entry["detail"]))
            changed = True
            continue
        try:
            state, record, detail = action.recover(entry.get("target") or {}, entry.get("record") or {})
        except Exception as exc:
            state, record, detail = "unknown", {}, f"recovery probe failed ({type(exc).__name__})"
        if state == "applied" and isinstance(record, dict) and record:
            entry.update(status="applied", record=record, detail=detail,
                         recovered_at=int(time.time()), recovery="verified")
            # A recovered action is bounded like a fresh one: its clock
            # starts at recovery, since the interrupted start was not recorded.
            _stamp(entry, action, entry.get("target") or {}, entry.get("applications"),
                   time.time() if now is None else now)
        elif state == "not_applied":
            entry.update(status="not_applied", detail=detail,
                         recovered_at=int(time.time()), recovery="verified")
        else:
            entry.update(status="uncertain", detail=detail,
                         recovered_at=int(time.time()), recovery=state)
        results.append((eid, state, detail))
        changed = True
    if changed:
        _save(store, ledger)
    return results


def expire(store, now=None):
    """Lift every time-bounded action whose time is up. Returns [(eid, detail)].

    Only a verified undo marks an entry expired; a failed lift stays applied
    with the reason recorded and is retried on the next sweep. Each entry is
    re-read just before its write so a concurrent apply is not overwritten.
    """
    now = time.time() if now is None else now
    lifted = []
    for eid, entry in load(store, strict=True).items():
        if entry.get("status") != "applied" or not entry.get("expires_at"):
            continue
        if int(entry["expires_at"]) > now:
            continue
        action = base.get(entry.get("action"))
        if action is None:
            ok, detail = False, "action implementation is unavailable"
        else:
            try:
                ok, detail = action.undo(entry.get("target") or {}, entry.get("record") or {})
            except Exception as exc:
                ok, detail = False, f"lift failed ({type(exc).__name__})"
        ledger = load(store, strict=True)
        current = ledger.get(eid)
        if not current or current.get("status") != "applied":
            continue
        if ok:
            current.update(status="expired", expired_at=int(now), undo_detail=detail)
            current.pop("expire_error", None)
            lifted.append((eid, detail))
        else:
            current.update(expire_error=f"could not lift: {detail}",
                           expire_attempts=int(current.get("expire_attempts") or 0) + 1)
        ledger[eid] = current
        _save(store, ledger)
    return lifted


def pending(store):
    return {eid: e for eid, e in load(store).items() if e.get("status") == "proposed"}


def applied(store):
    return {eid: e for eid, e in load(store).items() if e.get("status") == "applied"}

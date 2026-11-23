"""Proactive questions: JARVIS asks about what only you can settle.

A monitor that only lists findings makes you do all the reasoning. This turns
the findings JARVIS cannot judge on its own into direct questions, phrased for
the specific thing it saw, with answers that actually do something:

  * a detection that is either yours or an intruder's becomes
    "Did you do X?"  — yes confirms it (acknowledge), no escalates it;
  * when a reversible containment action fits, "no" is wired straight to it,
    so answering a question can quarantine the file or block the address;
  * otherwise "no" points you at the one command that shows the evidence.

Questions are generated from the latest snapshots, are stable (the same
situation yields the same question id, so an answer sticks), and expire when
the finding they are about stops being observed. They are surfaced in email
and answered with `jarvis answer <id> yes|no`, on the dashboard, or — once the
offline assistant is wired — by voice.
"""

import json
import time

from jarvis.core import egress
from jarvis.response import acknowledge, alert, defense
from jarvis.response.reporting import triage

META = "questions_v1"
KEEP_ANSWERED_DAYS = 30

YES, NO = "yes", "no"


def question_id(finding, job):
    return acknowledge.finding_id(finding, job)


def _phrase(finding, job):
    """The dynamic question and its two answers for one finding."""
    f = finding or {}
    cat = (f.get("category") or "").lower()
    title = f.get("title") or ""
    where = f.get("where") or ""

    program = egress.program_of(title)
    if program:
        return (f"{program} connected to the internet ({(f.get('detail') or '').split(' — ')[0]}). "
                f"Should {program} reach the internet?",
                "Yes, remember it as expected.",
                "No, flag it every time it connects.")
    if cat == "accounts":
        name = title.split(":")[-1].strip() or "this account"
        return (f"An account is hidden from the sign-in screen: {name}. "
                f"Did you (or a tool you use) create it?",
                "Confirm it as expected.",
                "Treat it as a hidden account and investigate.")
    if cat in ("agent", "editor", "vcs", "packages"):
        return (f"A developer-tool configuration runs a command: {title}. "
                f"Is this yours?",
                "Confirm it as expected.",
                "Review it before the tool runs again.")
    if cat == "credential access":
        return (f"A non-browser process is reading your browser password store "
                f"({where or 'the profile'}). Did you start something that would?",
                "Confirm it as expected.",
                "Treat it as credential theft and investigate now.")
    if cat == "staging" or "unsigned executable" in title:
        return (f"A recently written unsigned program is present ({where}). "
                f"Did you put it there?",
                "Confirm it as expected.",
                "Quarantine it.")
    if cat in ("injection", "injected code"):
        return (f"{title}. Code was written into a running process. Is this a "
                f"program you trust (a debugger, an installer, anti-cheat)?",
                "Confirm it as expected.",
                "Capture evidence and investigate.")
    if cat in ("c2 match", "named process", "dropped file"):
        return (f"{title}. This matches threat intelligence. Does it belong to "
                f"something you installed?",
                "Confirm it as expected.",
                "Contain it.")
    # A generic, still-specific fallback.
    return (f"{title}. Is this expected on your machine?",
            "Confirm it as expected.",
            "Investigate it.")


def build(store, snapshots, conf, now=None):
    """Return the list of open questions for the latest snapshots."""
    now = int(time.time() if now is None else now)
    acks = acknowledge.load(store)
    answered = _load(store)
    open_q = []
    seen = set()
    skip = {"visibility", "limits", "telemetry", "intel", "feed", "reporting",
            "daemon", "collectors", "coverage gap", "not observable"}
    for finding, job in triage.current(snapshots, levels=("critical", "high", "medium"),
                                       acks=acks, now=now):
        if (finding.get("category") or "").lower() in skip:
            continue
        t = triage.classify(finding, job)
        if t["owner"] != triage.YOU_CONFIRM:
            continue
        qid = question_id(finding, job)
        if qid in seen:
            continue
        seen.add(qid)
        prior = answered.get(qid)
        if prior and prior.get("answer") and prior.get("finding_key") == alert.finding_key(finding):
            continue    # already answered for this exact finding
        rung, action, target = defense.decide(finding, job, conf, acks)
        prompt, yes_label, no_label = _phrase(finding, job)
        open_q.append({
            "id": qid, "job": job, "prompt": prompt,
            "yes": yes_label, "no": no_label,
            "severity": finding.get("severity"), "title": finding.get("title"),
            "contain": action.id if (rung in (defense.PROPOSE, defense.AUTO) and action) else "",
            "answer_cmd": f"jarvis answer {qid} yes|no",
            # "yes" on this one is refused over the API; it needs the terminal.
            "confirm": acknowledge.TERMINAL if acknowledge.needs_confirmation(finding) else "",
        })
    rank = alert.SEV_RANK
    open_q.sort(key=lambda q: rank.get(q["severity"], 9))
    return open_q


def answer(store, qid, choice, now=None, confirmed_by=None):
    """Record an answer and act on it. Returns (ok, message).

    `confirmed_by` names a confirmation made outside the local API (see
    acknowledge.CONFIRMERS). Without it, a "yes" on a critical finding changes
    nothing: the route this arrives on cannot be allowed to silence one.
    """
    now = int(time.time() if now is None else now)
    choice = (choice or "").strip().lower()
    if choice in ("y", "yes", "mine", "me"):
        choice = YES
    elif choice in ("n", "no", "not me", "notme"):
        choice = NO
    else:
        return False, "answer yes or no"

    hit = acknowledge.resolve(store.get_snapshots(), qid)
    if not hit:
        return False, f"no current finding has question id {qid}"
    finding, job = hit
    if choice == YES and acknowledge.needs_confirmation(finding) and confirmed_by is None:
        return False, ("this is a critical finding, so it stays open until you confirm it at this "
                       f"computer: run  jarvis ack {qid} --reason \"why this is expected\"  in a terminal")
    answered = _load(store)
    answered[qid] = {"answer": choice, "at": now, "title": finding.get("title"),
                     "finding_key": alert.finding_key(finding)}
    _prune(answered, now)
    store.set_meta(META, json.dumps(answered))

    program = egress.program_of(finding.get("title"))
    if program:
        host = finding.get("host") or "wsl"
        egress.decide(store, host, program, egress.EXPECTED if choice == YES else egress.UNEXPECTED, now)
        if choice == YES:
            return True, f"remembered: {program} is expected to reach the internet"
        return True, f"flagged: every connection from {program} will now be a high finding"

    if choice == YES:
        try:
            acknowledge.acknowledge(store, finding, job,
                                    "confirmed via jarvis answer: expected", now=now,
                                    confirmed_by=confirmed_by)
        except ValueError as exc:
            return True, f"noted, but not acknowledged ({exc})"
        return True, "confirmed as expected — it no longer counts against your score"

    # "No, that was not me." Propose containment; never run it from here. An
    # answer arrives over the same unauthenticated local route as any other
    # request, so it may rank a finding but it cannot authorize an action
    # (PROTECTION-REVIEW-2026-10-21 C1). Approval is a separate, deliberate step.
    conf = alert.load_conf()
    rung, action, target = defense.decide(finding, job, conf, acknowledge.load(store))
    if action:
        eid, entry, _new = defense._propose(store, conf, finding, job, action, target)
        return True, (f"proposed {action.title.lower()} (id {eid}): {entry.get('preview', '')} "
                      f"Approve with jarvis defend approve {eid}")
    return True, (f"flagged. Inspect it with: {triage.classify(finding, job).get('command') or 'jarvis status'}")


def _load(store):
    try:
        value = json.loads(store.get_meta(META, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def _prune(answered, now):
    cutoff = now - KEEP_ANSWERED_DAYS * 86400
    for qid in [q for q, e in answered.items() if int(e.get("at", 0)) < cutoff]:
        answered.pop(qid, None)

"""Guided, evidence-bound security advice that works with no language model.

Invariants this module keeps:
  * Every claim comes from stored snapshots, the scoring engine or the triage
    rules. Nothing is "checked" unless the code here read that state, and a
    check that read stored results says so rather than claiming a fresh run.
  * What ARGUS can do is the CAPABILITIES table and nothing else. The router
    and any model text can only *name* a capability; handle_action validates
    the name, target and availability before anything runs.
  * A capability that changes anything (here: queueing one read-only audit)
    needs an explicit proposal, an approval token, and is audited. Success is
    only reported after a later fresh, error-free result, never on queueing.
  * No capability here changes security settings, deletes files, stops
    processes or edits firewall rules. Those are listed as unavailable.
  * Text shown to the user passes through privacy.redact.
"""

import json
import re
import secrets
import time
from dataclasses import dataclass

from jarvis.response import acknowledge, alert, llm
from jarvis.response import report as agent_report
from jarvis.response.privacy import redact
from jarvis.response.reporting import score, triage

CHECK, PREPARE, GUIDE, UNAVAILABLE = "check_now", "prepare", "guide", "unavailable"
PROPOSAL_TTL_S = 600
_PENDING_KEY, _AUDIT_KEY, _USED_KEY = "assistant_pending", "assistant_audit", "assistant_used"
_AUDIT_MAX, _PENDING_MAX, _USED_MAX = 200, 20, 50
# What a proposal can be, in order. "Execution started" is not a separate state here: the scheduler
# does not tell the assistant when a queued audit begins, so the next observable fact is a newer result.
LIFECYCLE = ("awaiting_approval", "approved_queued", "completed", "failed", "cancelled", "expired")
_FID = re.compile(r"^[0-9a-f]{8}$")


@dataclass(frozen=True)
class Capability:
    id: str
    title: str
    purpose: str
    mode: str                  # CHECK, PREPARE (needs approval), GUIDE, UNAVAILABLE
    read_only: bool
    platforms: tuple = ("any",)
    needs_runner: bool = False  # needs a live scheduler to queue work
    permissions: str = "none beyond reading ARGUS's own stored results"
    risks: str = "none"
    rollback: str = "not needed"
    verify: str = ""
    alternative: str = ""


CAPABILITIES = {c.id: c for c in (
    Capability("explain_finding", "Explain this alert", "Describe one current finding in plain language.",
               CHECK, True, verify="Reads the stored finding; nothing to verify."),
    Capability("check_monitor", "Check this problem",
               "Read a monitor's stored last result: age, error, and likely cause.",
               CHECK, True, verify="Reports the stored result's timestamp; it does not re-run the monitor.",
               alternative="Use the dashboard's run button to re-run it."),
    Capability("next_priority", "Show the next priority", "Rank current findings and name the first.",
               CHECK, True),
    Capability("score_plan", "How to raise my score",
               "Split confirmed weaknesses from missing monitoring using the scoring engine.",
               CHECK, True),
    Capability("check_model", "Check local AI", "List local models to see whether the local AI is usable.",
               CHECK, True, verify="Reports what the local endpoint answered just now."),
    Capability("show_fix_steps", "Show me how to fix it",
               "Show the manual steps ARGUS's triage rules give for a finding.",
               GUIDE, True, alternative="ARGUS never runs these steps for you."),
    Capability("verify_finding", "Verify the fix",
               "Check whether a finding is gone from a result newer than when you started.",
               CHECK, True, verify="Requires a monitor result newer than the request."),
    Capability("rerun_monitor", "Re-run this monitor",
               "Queue one extra run of a read-only audit so its stored result is refreshed.",
               PREPARE, False, needs_runner=True,
               permissions="your approval; the scheduler must be running",
               risks="uses some CPU for the length of one audit; changes no setting and no file",
               rollback="not needed; the audit only reads state",
               verify="A stored result newer than the approval with no error.",
               alternative="Press the monitor's run button on the dashboard."),
    Capability("verify_monitor", "Verify the monitor", "Confirm a re-run produced a fresh, valid result.",
               CHECK, True, verify="Compares the stored result's time with the approval time."),
    Capability("system_repair", "Apply a system repair",
               "Change firewall rules, disable security tools, delete files or stop processes.",
               UNAVAILABLE, False,
               alternative="ARGUS shows manual steps; you apply them, then it verifies."),
)}


# ---------------------------------------------------------------- helpers

def _clean(text, limit=220):
    text = " ".join(redact(str(text or "")).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _jobs_label(jobs, job):
    entry = jobs.get(job)
    label = entry[1] if isinstance(entry, (tuple, list)) and len(entry) > 1 else ""
    return _clean(label or job, 60)


def _sev_why(sev):
    return {"critical": "ARGUS rates this critical: it describes something that can seriously harm "
                        "the computer or your data if it is real.",
            "high": "ARGUS rates this high: it deserves attention soon.",
            "medium": "ARGUS rates this medium: worth reviewing, rarely urgent.",
            "low": "ARGUS rates this low: informational."}.get(sev, "ARGUS has not rated this finding.")


def _findings(store, levels=("critical", "high", "medium"), now=None):
    snaps = store.get_snapshots()
    seen, out = set(), []
    for finding, job in triage.current(snaps, levels=levels, acks=acknowledge.load(store), now=now):
        key = (job, finding.get("title"))
        if key not in seen:
            seen.add(key)
            out.append((finding, job))
    out.sort(key=lambda fj: (alert.SEV_RANK.get(fj[0].get("severity"), 9), fj[1]))
    return out


def _blind(result):
    return [b for area in result["areas"] for b in area["blind"]]


_STATE_WORDS = {"missing": "has never reported a result",
                "failing": "its last run failed",
                "stale": "has not reported recently"}


def _cause(error):
    """(plain cause, is_assumption) from a stored error string."""
    e = (error or "").lower()
    if any(k in e for k in ("permission", "access is denied", "denied", "not permitted", "eperm")):
        return "It looks like a permissions problem: the monitor was not allowed to read something it needs.", True
    if any(k in e for k in ("not found", "no such file", "not recognized", "cannot find", "missing module")):
        return "It looks like a required program or file is missing on this computer.", True
    if "timed out" in e or "timeout" in e:
        return "It looks like the monitor took too long to finish and was stopped.", True
    if "not supported" in e or "unsupported" in e:
        return "It looks like this monitor is not supported on this computer.", True
    return "", False


def _section(kind, text):
    return {"kind": kind, "text": text}


def reply(sections, actions=(), offer=None, suggestions=(), extra=None):
    """Uniform response. `sections` kinds: say, verified, recommend, assumption."""
    out = {"answer": "\n\n".join(s["text"] for s in sections), "sections": list(sections),
           "source": "builtin", "actions": list(actions), "offer": offer,
           "suggestions": list(suggestions)}
    out.update(extra or {})
    return out


def _act(action_id, target=None, label=None):
    cap = CAPABILITIES[action_id]
    return {"action": action_id, "label": label or cap.title, "target": target or {}}


# ------------------------------------------------------------- model status

def model_summary(conf=None):
    """Interface-facing model status from the last attempt; makes no network call."""
    state = llm.last_state()
    if state == "unknown":
        return {"state": "unknown", "label": "Local AI has not been checked yet. Basic assistance is working."}
    model = llm.model_name(conf or {})
    return {"state": state, "label": llm.DIAGNOSES.get(state, state).format(model=model)}


# -------------------------------------------------------------- suggestions

def suggestions(store, jobs, now=None):
    out = []
    try:
        result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    except Exception:
        return ["What can you do?", "Am I safe?"]
    if _blind(result):
        out.append("Why is a monitor not working?")
    if _findings(store, now=now):
        out.append("What should I do first?")
    out += ["How do I raise my score?", "Am I safe?"]
    return out[:4]


# ------------------------------------------------------------------ intents

_GREET = re.compile(r"^(hi|hey|hello|yo|hiya|howdy|good (morning|afternoon|evening))\b[\s!.,]*"
                    r"(argus|jarvis|there)?[\s!.?]*$")
_YES = re.compile(r"^(yes|yeah|yep|yup|sure|ok|okay|please|please do|go ahead|do it|y)\b[\s!.]*$")
_NO = re.compile(r"^(no|nope|nah|not now|cancel|stop|never mind|nevermind|n)\b[\s!.]*$")


def classify_intent(q):
    """Deterministic intent for a normalised lowercase question, or None."""
    if _GREET.match(q):
        return "greeting"
    if _YES.match(q):
        return "yes"
    if _NO.match(q):
        return "no"
    has = lambda *ps: any(p in q for p in ps)
    if has("hacked", "compromised", "infected", "am i safe", "is my computer safe", "am i secure",
           "got a virus", "have a virus", "being attacked", "is my computer ok", "is my computer okay",
           "is my system ok", "is my system okay", "is my pc ok", "is everything ok"):
        return "safe"
    if has("what has argus not", "not checked", "hasn't checked", "what didn't you check",
           "what isn't covered", "what is not covered", "what was not checked"):
        return "not_checked"
    if has("what did argus find", "what has argus found", "what did you find", "what did it find",
           "what have you found"):
        return "found"
    if has("should i be worried", "should i worry", "should i be concerned", "is this bad", "am i in danger"):
        return "worry"
    if has("why is this item marked", "marked serious", "why is this serious", "why is it serious",
           "why serious", "why is this item serious"):
        return "why_serious"
    if has("what happens if i approve", "if i approve", "what will approve", "what does approve"):
        return "approve_effect"
    if has("can this damage", "damage my computer", "harm my computer", "break my computer", "will this break"):
        return "damage"
    if has("investigate this safely", "investigate safely", "how do i investigate", "safely investigate"):
        return "investigate_safely"
    if has("explain this finding", "explain this warning", "explain this alert",
           "why is argus", "why am i seeing", "showing this warning", "showing me this"):
        return "warning"
    if has("score mean", "score means", "meaning of my score", "what is the score"):
        return "score_meaning"
    if has("like i'm not technical", "like im not technical", "not technical", "plain english",
           "simple terms", "in simple", "eli5", "explain simply"):
        # A general-knowledge question ("explain what ransomware is in simple words") is for the
        # model; only a question about this computer or ARGUS gets the canned walkthrough.
        about_us = has("argus", "my computer", "my pc", "this finding", "this warning", "this alert",
                       "my score", "the score", "my system", "my security")
        general = re.search(r"\b(what is|what are|what's|explain what|explain how|tell me about|how does|how do)\b", q)
        if about_us or not general:
            return "plain"
    if has("what can you do", "what are you able", "what do you do", "your capabilities",
           "can you help", "what can i ask") or q in ("help", "help me", "?"):
        return "capabilities"
    if has("can you fix", "fix it", "fix this", "fix that", "repair it", "can you repair", "fix my"):
        return "fix"
    if re.search(r"(monitor(?:ing)?|collector|detector|sensor|watcher|check)s?\b.*(not working|stopped|broken|"
                 r"down|offline|fail|blind|why|not reporting)|(not working|stopped|broken|why|which).*"
                 r"(monitor(?:ing)?|collector|detector|sensor|check)s?\b", q):
        return "monitor"
    if has("what does this warning", "what does this alert", "what does that warning",
           "what does this mean", "what does it mean", "what is this warning", "this warning",
           "this alert"):
        return "warning"
    if has("what should i do first", "do first", "most important", "biggest problem", "top priority",
           "what first", "next priority", "attention first", "needs my attention", "safely do next",
           "do next", "what can i safely"):
        return "first"
    if re.search(r"(raise|improve|increase|boost|better|higher|up).{0,20}score|score.{0,20}"
                 r"(better|higher|improve|low|bad)", q):
        return "score"
    if has("retry the model", "retry model", "check the model", "check local ai", "check ollama"):
        return "model"
    return None


def greeting(store, jobs, now=None):
    return reply([_section("say", "Hey! I'm ARGUS, your computer security assistant. I can help you "
                                  "understand your security status, explain alerts, improve your "
                                  "protection, and guide you through fixing problems. What would you "
                                  "like help with?")],
                 suggestions=suggestions(store, jobs, now))


def safe(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    serious = _findings(store, ("critical", "high"), now)
    blind = _blind(result)
    secs = []
    if serious:
        top = serious[0][0]
        secs.append(_section("verified", f"ARGUS currently has {len(serious)} serious finding"
                             f"{'s' if len(serious) != 1 else ''}. The most important is "
                             f"“{_clean(top.get('title'), 120)}”. A finding is evidence to review, not "
                             "proof that someone has broken in."))
        offer = {"action": "next_priority", "target": {}}
        q = "Would you like me to walk you through that one first?"
    else:
        secs.append(_section("verified", f"ARGUS has no critical or high-severity findings in the current "
                             f"results of the monitors that are reporting (coverage {result['coverage']}%)."))
        offer, q = None, ""
    if blind:
        secs.append(_section("verified", f"{len(blind)} monitor{'s are' if len(blind) != 1 else ' is'} not "
                             "reporting, so ARGUS may be missing activity there. That is a gap in visibility, "
                             "not evidence of an attack."))
        if offer is None:
            offer = {"action": "check_monitor", "target": {"job": blind[0]["job"]}}
            q = "Would you like me to check why one of them stopped?"
    secs.append(_section("assumption", "No tool can prove a computer is completely clean, and ARGUS "
                         "can only report what its monitors have seen. " + q))
    return reply(secs, _offer_buttons(offer), offer)


def _offer_buttons(offer):
    return [_act(offer["action"], offer["target"])] if offer else []


def first(store, jobs, now=None):
    items = _findings(store, now=now)
    if items:
        finding, job = items[0]
        return _finding_walkthrough(store, finding, job, len(items), now)
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if blind:
        return monitor(store, jobs, now)
    return reply([_section("verified", "Nothing in ARGUS's current results needs your attention. I'll "
                                       "keep watching.")], suggestions=suggestions(store, jobs, now))


def _finding_walkthrough(store, finding, job, total, now):
    c = triage.classify(finding, job)
    sev = finding.get("severity", "?")
    secs = [_section("verified", f"[{sev.upper()}] {_clean(finding.get('title'), 140)} "
                                 f"(found by {_clean(job, 40)}). {_clean(finding.get('detail'))}"),
            _section("verified", _sev_why(sev))]
    if c.get("action"):
        secs.append(_section("recommend", f"ARGUS recommends: {_clean(c['action'], 240)}"))
    acts = [_act("explain_finding", {"id": c["id"]})]
    if c.get("command"):
        acts.append(_act("show_fix_steps", {"id": c["id"], "job": job}))
        secs.append(_section("say", "I can show you the steps. ARGUS does not make this change for you; "
                                    "you apply it, then I verify the result. Want the steps?"))
        offer = {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
    else:
        secs.append(_section("say", "Want me to explain it in more detail?"))
        offer = {"action": "explain_finding", "target": {"id": c["id"]}}
    if total > 1:
        acts.append(_act("next_priority", label="Show the next priority"))
    return reply(secs, acts, offer)


def monitor(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if not blind:
        return reply([_section("verified", "All of ARGUS's monitors have reported recently. None of them "
                                           "looks stopped right now.")])
    b = blind[0]
    name = _jobs_label(jobs, b["job"])
    more = f" ({len(blind) - 1} more are also not reporting.)" if len(blind) > 1 else ""
    secs = [_section("verified", f"The “{name}” monitor {_STATE_WORDS.get(b['state'], 'is not reporting')}."
                                 f"{more} This does not mean your computer has been attacked, but ARGUS "
                                 "may be missing some activity."),
            _section("say", "Would you like me to check why it stopped working? I'll only read its stored "
                            "result and recent error. I won't run or change anything.")]
    offer = {"action": "check_monitor", "target": {"job": b["job"]}}
    return reply(secs, _offer_buttons(offer), offer)


def capabilities(runner_available):
    groups = {CHECK: [], PREPARE: [], GUIDE: [], UNAVAILABLE: []}
    for cap in CAPABILITIES.values():
        ok, _ = availability(cap, runner_available)
        groups[cap.mode if ok else UNAVAILABLE].append(cap)
    def names(items):
        return ", ".join(c.title.lower() for c in items) or "nothing right now"
    secs = [_section("verified", "Here is what I can actually do:"),
            _section("verified", f"I can check now (read-only): {names(groups[CHECK])}."),
            _section("verified", f"I can prepare for your approval: {names(groups[PREPARE])}."),
            _section("verified", f"I can guide you through manually: {names(groups[GUIDE])}."),
            _section("verified", "Not available: changing firewall rules, disabling security tools, "
                                 "deleting files or stopping processes. I will never do those on my own."
                                 )]
    return reply(secs)


def availability(cap, runner_available):
    if cap.mode == UNAVAILABLE:
        return False, "ARGUS does not change system settings from chat."
    if cap.needs_runner and not runner_available:
        return False, "The ARGUS service is not running, so it cannot queue the audit."
    return True, ""


def plain(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    serious = len(_findings(store, ("critical", "high"), now))
    blind = len(_blind(result))
    secs = [_section("say", "Think of ARGUS as a set of smoke detectors for your computer."),
            _section("verified", f"Right now {serious} thing{'s' if serious != 1 else ''} ARGUS rates as "
                                 f"serious {'need' if serious != 1 else 'needs'} a look, and {blind} "
                                 f"detector{'s are' if blind != 1 else ' is'} not reporting. Your score is "
                                 f"{result['score']}%."),
            _section("say", "Ask “what should I do first?” and I'll explain the most important item "
                            "step by step.")]
    return reply(secs, [_act("next_priority")], {"action": "next_priority", "target": {}})


def fix(store, jobs, runner_available, now=None):
    items = _findings(store, now=now)
    if items:
        finding, job = items[0]
        c = triage.classify(finding, job)
        secs = [_section("verified", "I can't change your system settings, firewall or files from chat, "
                                     "and I won't pretend to. For the top finding, "
                                     f"“{_clean(finding.get('title'), 120)}”, here is what I can do:")]
        if c.get("command"):
            secs.append(_section("say", "I can show you the exact manual steps, then verify the result "
                                        "after you apply them."))
            offer = {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
            return reply(secs, _offer_buttons(offer), offer)
        secs.append(_section("say", "ARGUS has no specific steps for this one yet. I can explain what it "
                                    "found so you can decide."))
        offer = {"action": "explain_finding", "target": {"id": c["id"]}}
        return reply(secs, _offer_buttons(offer), offer)
    return monitor(store, jobs, now)


def score_advice(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    # Same-title findings (e.g. two WMI subscriptions) are one line with a
    # count, so the top three are three different problems, not one repeated.
    grouped = {}
    for step in result.get("next_steps", []):
        key = (step["severity"], step["title"])
        grouped.setdefault(key, dict(step, count=0))["count"] += 1
    steps = list(grouped.values())[:3]
    blind = _blind(result)
    secs = [_section("say", "I can help you improve your security score. Your score is "
                            f"{result['score']}% ({result['grade']}) with {result['coverage']}% monitoring "
                            "coverage. I'll start with the biggest verified weaknesses.")]
    offer = None
    if steps:
        lines = [f"{i}. {s['severity'].upper()}: {_clean(s['title'], 120)}"
                 + (f" ({s['count']} found)" if s["count"] > 1 else "")
                 for i, s in enumerate(steps, 1)]
        secs.append(_section("verified", "Confirmed weaknesses, biggest first:\n" + "\n".join(lines)))
        top = next(((f, j) for f, j in _findings(store, now=now)
                    if f.get("title") == steps[0]["title"]), None)
        if top:
            offer = {"action": "show_fix_steps" if triage.classify(*top).get("command")
                     else "explain_finding",
                     "target": {"id": triage.classify(*top)["id"], "job": top[1]}}
    else:
        secs.append(_section("verified", "ARGUS has no confirmed weaknesses lowering the score right now."))
    if blind:
        secs.append(_section("verified", f"{len(blind)} monitor{'s are' if len(blind) != 1 else ' is'} not "
                             "reporting. That lowers coverage, not proof of infection; restoring "
                             "them only raises the score if their results come back clean."))
        if offer is None:
            offer = {"action": "check_monitor", "target": {"job": blind[0]["job"]}}
    secs.append(_section("say", "I will not hide, downgrade or suppress anything to raise the number. "
                                "The score changes only when a fresh check confirms the underlying issue "
                                "is fixed. Want me to start with the first one?"))
    return reply(secs, _offer_buttons(offer), offer)


def score_meaning(store, jobs, now=None):
    """What the number means, in the engine's own terms (see reporting/score.py)."""
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    secs = [_section("verified", f"Your security score is {result['score']}% ({result['grade']}), with "
                                 f"{result['coverage']}% of ARGUS-INSTINCT's monitoring coverage reporting."),
            _section("say", "How it works: each protection area loses points for its open findings, "
                            "more for critical and high ones. Low-severity items are inventory and do not "
                            "lower it."),
            _section("say", "A check that is failing, stale or has never run is not counted as safe. It "
                            "is shown as unverified and pulls the score down in proportion to how much "
                            "of the computer is unobserved.")]
    if blind:
        secs.append(_section("verified", f"Right now {len(blind)} check{'s are' if len(blind) != 1 else ' is'} "
                                         "not reporting, so part of this score reflects missing "
                                         "visibility rather than known problems."))
    secs.append(_section("assumption", "A low score is not proof of an attack, and a high score is not "
                                       "proof of safety. The score only reflects what ARGUS-INSTINCT could check."))
    offer = {"action": "score_plan", "target": {}}
    secs.append(_section("say", "Want me to show what would raise it?"))
    return reply(secs, [_act("score_plan", label="How do I raise my score?")], offer)


def _tally(store, now=None):
    """(all distinct items, serious ones, ones worth reviewing, count of informational ones)."""
    items = _findings(store, ("critical", "high", "medium", "low"), now)
    serious = [x for x in items if x[0].get("severity") in ("critical", "high")]
    review = [x for x in items if x[0].get("severity") in ("critical", "high", "medium")]
    return items, serious, review, len(items) - len(review)


def changes_summary(store):
    """What ARGUS-INSTINCT has changed on this computer, from the audit trail and the response ledger."""
    executed = sum(1 for e in audit_log(store) if e.get("op") == "approve" and e.get("outcome") == "queued")
    try:
        from jarvis.response import defense
        automatic = len(defense.applied(store))
    except Exception:
        automatic = None
    if executed == 0 and automatic == 0:
        text = "No changes have been made to your computer by ARGUS-INSTINCT."
    elif automatic == 0:
        text = (f"The only thing ARGUS-INSTINCT has done on your approval is {executed} read-only re-run"
                f"{'s' if executed != 1 else ''} of its own checks. It has not changed any setting or file.")
    elif automatic is None:
        text = (f"ARGUS-INSTINCT has queued {executed} approved read-only check{'s' if executed != 1 else ''}. "
                "Whether any automatic response ran could not be read.")
    else:
        text = (f"ARGUS-INSTINCT has applied {automatic} automatic response action{'s' if automatic != 1 else ''}. "
                "They are listed in its response ledger, with undo information.")
    return {"assistant_executed": executed, "automatic_applied": automatic, "text": text}


def _list(items, limit=3):
    return "\n".join(f"- {x[0].get('severity', '?').upper()}: {_clean(x[0].get('title'), 100)}"
                     for x in items[:limit])


def found(store, jobs, now=None):
    items, serious, review, info = _tally(store, now)
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if review:
        simple = (f"ARGUS-INSTINCT found {len(review)} item{'s' if len(review) != 1 else ''} to review, including "
                  f"{len(serious)} marked as serious. Some items may have legitimate explanations.")
    else:
        simple = "ARGUS-INSTINCT found no items to review in the checks that are reporting."
    if info:
        simple += f" It also recorded {info} informational observation{'s' if info != 1 else ''}."
    secs = [_section("simple", simple + " " + changes_summary(store)["text"])]
    if review:
        secs.append(_section("observed", "The most important:\n" + _list(serious or review)))
    secs.append(_section("why", "Serious means ARGUS-INSTINCT rates the possible impact as high if the item is real. "
                                "It does not mean harm has been confirmed."))
    if blind:
        secs.append(_section("why", f"{len(blind)} check{'s are' if len(blind) != 1 else ' is'} not reporting, "
                                    "so this list only covers what the other checks could see."))
    secs.append(_section("next", "Open the first item to see what was observed and why it was flagged."))
    secs.append(_section("technical", f"{len(items)} distinct items in all; {len(serious)} critical or high; "
                                      f"coverage {result['coverage']}%; score {result['score']}%."))
    offer = {"action": "next_priority", "target": {}} if review else None
    return reply(secs, _offer_buttons(offer), offer)


def worry(store, jobs, now=None):
    items, serious, review, info = _tally(store, now)
    blind = _blind(score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store)))
    if serious:
        simple = (f"Take it seriously but calmly. ARGUS-INSTINCT marked {len(serious)} item"
                  f"{'s' if len(serious) != 1 else ''} as serious. That means they deserve a look, not that "
                  "your computer is compromised.")
    elif review:
        simple = "Not urgently. ARGUS-INSTINCT found some items worth reviewing, none marked serious."
    elif blind:
        simple = (f"ARGUS-INSTINCT found nothing to review, but {len(blind)} of its checks are not reporting, so it "
                  "cannot promise everything is fine.")
    else:
        simple = "ARGUS-INSTINCT found nothing serious in the checks it ran. No tool can promise a computer is clean."
    secs = [_section("simple", simple),
            _section("observed", (_list(serious or review) if review else "No items to review right now.")),
            _section("why", "Many flagged items are normal software doing things attackers also do, such as "
                            "starting automatically. ARGUS-INSTINCT does not know your intent, so it reports and explains."),
            _section("next", "Open the first item, read what was observed, and decide whether you expect it. "
                             "You do not need to change anything yet."),
            _section("technical", changes_summary(store)["text"])]
    return reply(secs, _offer_buttons({"action": "next_priority", "target": {}}) if review else [])


def why_serious(store, jobs, now=None):
    items, serious, review, info = _tally(store, now)
    top = (serious or review or [None])[0]
    if top is None:
        return reply([_section("simple", "Nothing is marked serious right now.")])
    f, job = top
    secs = [_section("simple", f"“{_clean(f.get('title'), 100)}” is marked {f.get('severity')} because of what it "
                               "could do if it is real, not because ARGUS-INSTINCT has proof that it is."),
            _section("observed", f"{_clean(f.get('detail') or 'No detail was recorded.', 200)} "
                                 f"(reported by the {_clean(job, 40)} collector)"),
            _section("why", _sev_why(f.get("severity")) + " Severity is about potential impact. ARGUS-INSTINCT does not "
                            "score how likely an item is to be malicious, so a serious item may still be harmless."),
            _section("next", "Compare it with software you know you installed, then ask me to explain it."),
            _section("technical", f"severity={f.get('severity')} category={f.get('category')} job={job}")]
    c = triage.classify(f, job)
    return reply(secs, [_act("explain_finding", {"id": c["id"]})],
                 {"action": "explain_finding", "target": {"id": c["id"]}})


def approve_effect(store, jobs, now=None):
    now = int(now or time.time())
    pend = {t: p for t, p in _load(store, _PENDING_KEY, {}).items() if p.get("expires", 0) > now}
    extra = {}
    if pend:
        token = max(pend, key=lambda t: pend[t]["expires"])
        p = pend[token]
        d = proposal_details(store, jobs, CAPABILITIES[p["action"]], p["target"], now, token)
        d["expires_at"] = p["expires"]
        secs = [_section("simple", f"One proposal is waiting for you: {d['proposes']} Nothing has happened yet."),
                _section("observed", d["why"]),
                _section("why", f"If you approve: {d['expected']} Risk: {d['risks']}. {d['reversible']}"),
                _section("next", d["if_nothing"]),
                _section("technical", d["exact"])]
        extra["details"] = d
    else:
        secs = [_section("simple", "Nothing is waiting for your approval right now.")]
        try:
            from jarvis.response import selffix
            open_fixes = len(selffix.list_open(store))
        except Exception:
            open_fixes = 0
        if open_fixes:
            secs.append(_section("observed", f"{open_fixes} fix proposal{'s are' if open_fixes != 1 else ' is'} in "
                                             "the review queue. Approving one only drafts a patch to ARGUS-INSTINCT's own "
                                             "code. Nothing is applied from this page."))
        secs.append(_section("why", "Before you approve anything, ARGUS-INSTINCT shows what it would do, why, the exact "
                                    "target, the risk, whether it can be undone and what happens if you do nothing."))
        secs.append(_section("next", "You can always decline. Declining, closing the box or letting a proposal "
                                     "expire changes nothing."))
    return reply(secs, extra=extra)


def damage(store, now=None):
    secs = [_section("simple", "Looking at findings cannot damage your computer. Nothing ARGUS-INSTINCT shows here "
                               "changes it."),
            _section("observed", "From this page the assistant can only queue a read-only re-run of one of "
                                 "ARGUS-INSTINCT's own checks, and only after you approve. " + changes_summary(store)["text"]),
            _section("why", "Deleting files, stopping programs and changing settings are not available from "
                            "this page. Any proposal that could change something shows its risk and whether "
                            "it can be undone before you decide."),
            _section("next", "If you are unsure about a finding, leave it alone and ask me to explain it. "
                             "Doing nothing is safe."),
            _section("technical", "Re-runs use the scheduler's normal read-only audit path; the action is "
                                  "recorded in the audit trail.")]
    return reply(secs)


def investigate_safely(store, jobs, now=None):
    secs = [_section("simple", "Look first, change nothing. Everything below is read-only."),
            _section("next", "1. Open the finding and read what ARGUS-INSTINCT observed and where.\n"
                             "2. Ask whether you recognise the program, folder or account, for example because "
                             "you installed or built something recently.\n"
                             "3. Compare the name and location with the software you know.\n"
                             "4. Ask me to explain it, or open Technical details for the raw evidence."),
            _section("why", "Deleting, disabling or stopping something before you understand it can break "
                            "legitimate software and can destroy evidence."),
            _section("next", "If you still cannot explain it, keep a note of the title, location and time, "
                             "and ask someone you trust. Do not run unknown files to see what they do.")]
    return reply(secs, _offer_buttons({"action": "next_priority", "target": {}}),
                 {"action": "next_priority", "target": {}})


def not_checked(store, jobs, now=None):
    result = score.compute(store.get_snapshots(), jobs, now, acknowledge.load(store))
    blind = _blind(result)
    if blind:
        lines = "\n".join(f"- {_jobs_label(jobs, b['job'])}: {_STATE_WORDS.get(b['state'], 'not reporting')}"
                          for b in blind[:12])
        secs = [_section("simple", f"{len(blind)} of ARGUS-INSTINCT's checks are not reporting, so those areas are "
                                   "unchecked right now."),
                _section("observed", lines + (f"\n…and {len(blind) - 12} more." if len(blind) > 12 else ""))]
    else:
        secs = [_section("simple", "Every check ARGUS-INSTINCT counts has reported recently."),
                _section("observed", "That only covers what each check looks at. It is not a promise that "
                                     "nothing else exists.")]
    secs += [_section("why", "A check that is not reporting is not counted as safe, and having no alerts from "
                             "an area that was not checked says nothing about it."),
             _section("next", "Open Monitoring to see why each check is not reporting and what you can do."),
             _section("technical", f"Monitoring coverage {result['coverage']}%. Checks that do not apply to this "
                                   "computer are not counted.")]
    return reply(secs)


def clarify(store, jobs, model_note=True, now=None):
    secs = [_section("say", "I'm not sure I understood that, and I don't want to guess about your "
                            "security. Are you asking about your overall status, a specific warning, "
                            "or how to improve your score? You can also ask about everyday safety, "
                            "such as phishing, passwords, backups or updates.")]
    return reply(secs, suggestions=suggestions(store, jobs, now))


# ------------------------------------------------------------ action handlers

def _snapshot(store, job):
    return store.get_snapshots().get(job)


def _fmt(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"


def _check_monitor(store, jobs, target, runner_available, now):
    job = target.get("job")
    snap = _snapshot(store, job)
    name = _jobs_label(jobs, job)
    secs = [_section("verified", "I read the stored result of its last run. I did not run it again.")]
    if not snap or not snap.get("ts"):
        secs.append(_section("verified", f"The “{name}” monitor has no stored result: it has never "
                                         "completed on this computer."))
    else:
        age = int((now or time.time()) - int(snap["ts"]))
        interval = jobs[job][0]
        state = ("failing" if snap.get("error") else
                 "stale" if age > max(interval * 2, interval + 300) else "current")
        secs.append(_section("verified", f"Last result: {_fmt(snap['ts'])} ({age // 60} min ago; it is "
                                         f"expected about every {max(1, interval // 60)} min). "
                                         f"Status: {state}."))
        if snap.get("error"):
            secs.append(_section("verified", f"Recorded error: {_clean(snap['error'], 200)}"))
            cause, guess = _cause(snap["error"])
            if cause:
                secs.append(_section("assumption", cause))
    actions = []
    cap = CAPABILITIES["rerun_monitor"]
    if availability(cap, runner_available)[0]:
        secs.append(_section("say", "I can re-run it once with your approval. Want me to prepare that?"))
        actions.append(_act("rerun_monitor", {"job": job}))
        offer = {"action": "rerun_monitor", "target": {"job": job}}
    else:
        secs.append(_section("say", "The ARGUS service isn't running, so I can't re-run it from here. "
                                    "Start the service or press the monitor's run button."))
        offer = None
    when = _fmt(snap["ts"]) if snap and snap.get("ts") else "never"
    found = (["The check has never stored a result on this computer."] if not snap or not snap.get("ts") else
             [f"Its last stored result is from {when}."]
             + ([f"That run recorded an error: {_clean(snap['error'], 160)}"] if snap.get("error") else []))
    rep = agent_report.build(
        title=f"Check of the “{name}” monitor", read_only=True,
        checked=[f"The stored result of the “{name}” check and the error it recorded, if any"],
        found=found,
        meaning=[(_cause(snap.get("error"))[0] if snap and snap.get("error") and _cause(snap.get("error"))[0]
                  else "A stored result tells you what the check saw last time, not what it would see now.")],
        certainty="Based only on the stored result. The check was not run again.",
        recommendation=["Re-run the check (it needs your approval) to get a fresh result."
                        if actions else "Start the ARGUS-INSTINCT service, then re-run the check."],
        unchecked=["The check itself was not re-run, so its behaviour right now is unknown"],
        technical=json.dumps({"job": job, "last_result": snap.get("ts") if snap else None,
                              "error": (snap or {}).get("error", "")}, default=str),
        source="assistant")
    return reply(secs, actions, offer, extra={"report": rep})


def _explain_finding(store, target):
    hit = acknowledge.resolve(store.get_snapshots(), target.get("id", ""))
    if not hit:
        return reply([_section("verified", "That finding is no longer in the current results.")])
    finding, job = hit
    c = triage.classify(finding, job)
    secs = [_section("verified", f"[{finding.get('severity', '?').upper()}] "
                                 f"{_clean(finding.get('title'), 140)} (found by {_clean(job, 40)})"),
            _section("verified", _clean(finding.get("detail") or "No detail was recorded.", 400)
                     + f" Observed at: {_clean(finding.get('where') or 'unspecified', 160)}."),
            _section("verified", _sev_why(finding.get("severity"))),
            _section("assumption", "This is evidence to review. It is not proof that your computer is "
                                   "compromised.")]
    acts = [_act("show_fix_steps", {"id": c["id"], "job": job})] if c.get("command") else []
    rep = agent_report.build(
        title=f"Explanation of “{_clean(finding.get('title'), 100)}”", read_only=True,
        checked=["The stored finding and the result of the collector that reported it"],
        found=[_clean(finding.get("detail") or "No detail was recorded.", 200),
               f"Reported by the {_clean(job, 40)} collector at {_clean(finding.get('where') or 'an unspecified place', 120)}."],
        meaning=[_sev_why(finding.get("severity")),
                 "It may have a legitimate explanation. ARGUS-INSTINCT has not confirmed that it is harmful."],
        certainty="Not scored. One collector reported this; ARGUS-INSTINCT does not rate how likely it is to be real.",
        recommendation=["Review the details and decide whether you expect this on your computer."],
        unchecked=["Whether you installed or expect this item", "The item itself was not opened or run"],
        technical=json.dumps({k: finding.get(k) for k in ("category", "severity", "host", "where")}, default=str),
        source="assistant")
    return reply(secs, acts, {"action": "show_fix_steps", "target": {"id": c["id"], "job": job}}
                 if acts else None, extra={"report": rep})


def _show_fix_steps(store, target, now):
    hit = acknowledge.resolve(store.get_snapshots(), target.get("id", ""))
    if not hit:
        return reply([_section("verified", "That finding is no longer in the current results.")])
    finding, job = hit
    c = triage.classify(finding, job)
    if not c.get("command"):
        return reply([_section("verified", "ARGUS has no specific steps for this finding.")])
    secs = [_section("recommend", f"{_clean(c.get('action') or 'Suggested step', 240)}"),
            _section("recommend", f"Command: {_clean(c['command'], 300)}"),
            _section("say", "ARGUS will not run this for you. Side effects depend on the command, so read "
                            "it first. When you've done it, press “Verify the fix” and I'll check a "
                            "fresh result.")]
    since = int(now or time.time())
    return reply(secs, [_act("verify_finding", {"id": c["id"], "job": job, "since": since})])


def _verify_finding(store, jobs, target, now):
    job, fid, since = target.get("job"), target.get("id"), int(target.get("since") or 0)
    snap = _snapshot(store, job)
    if not snap or not snap.get("ts") or int(snap["ts"]) <= since or snap.get("error"):
        why = ("has not produced a result since you started" if snap and not snap.get("error") else
               "has no valid result")
        return reply([_section("verified", f"I can't confirm it yet: the “{_jobs_label(jobs, job)}” monitor "
                                           f"{why}. A fix only counts once a fresh check confirms it.")],
                     [_act("rerun_monitor", {"job": job})] if job in jobs else [],
                     extra={"lifecycle": "approved_queued"})
    still = any(isinstance(f, dict) and acknowledge.finding_id(f, job) == fid
                for f in snap.get("findings") or [])
    if still:
        return reply([_section("verified", f"Checked at {_fmt(snap['ts'])}: the finding is still present, "
                                           "so it is not fixed yet.")], extra={"lifecycle": "failed"})
    return reply([_section("verified", f"Verified: a result from {_fmt(snap['ts'])} (after your "
                                       "request) no longer contains this finding.")],
                 extra={"lifecycle": "completed"})


def _verify_monitor(store, jobs, target):
    job, since = target.get("job"), int(target.get("since") or 0)
    snap = _snapshot(store, job)
    name = _jobs_label(jobs, job)
    if not snap or not snap.get("ts") or int(snap["ts"]) <= since:
        return reply([_section("verified", f"Not confirmed: the “{name}” monitor has not stored a new "
                                           "result since you approved the re-run. It may still be queued. "
                                           "Ask me to verify again shortly.")],
                     [_act("verify_monitor", {"job": job, "since": since})],
                     extra={"lifecycle": "approved_queued"})
    if snap.get("error"):
        cause, _ = _cause(snap["error"])
        secs = [_section("verified", f"The monitor ran at {_fmt(snap['ts'])} but failed: "
                                     f"{_clean(snap['error'], 200)}")]
        if cause:
            secs.append(_section("assumption", cause))
        return reply(secs, extra={"lifecycle": "failed"})
    return reply([_section("verified", f"Recovered: the “{name}” monitor stored a fresh, error-free result "
                                       f"at {_fmt(snap['ts'])}.")], extra={"lifecycle": "completed"})


def _check_model(conf):
    llm.reset_backoff()
    d = llm.diagnose(conf or {})
    return reply([_section("verified", d["label"])],
                 extra={"model": {"state": d["state"], "label": d["label"]}})


# ------------------------------------------------------------ audit/approval

def _load(store, key, default):
    try:
        value = json.loads(store.get_meta(key, "") or "")
        return value if isinstance(value, type(default)) else default
    except ValueError:
        return default


def audit_log(store):
    return _load(store, _AUDIT_KEY, [])


def _audit(store, op, action, target, outcome, detail="", now=None):
    log = audit_log(store)
    entry = {"ts": int(now or time.time()), "op": op, "action": action, "target": target,
             "outcome": outcome, "detail": _clean(detail, 200)}
    last = log[-1] if log else None
    # Polling "verify" while a re-run is still queued would otherwise fill the
    # trail with identical rows. Repeats of the same read-only result collapse
    # into one entry (latest time, repeat count); every state change is kept.
    if (op == "run" and last and last.get("op") == "run" and last.get("action") == action
            and last.get("target") == target and last.get("outcome") == outcome):
        entry["repeats"] = int(last.get("repeats", 1)) + 1
        entry["first_ts"] = last.get("first_ts", last["ts"])
        log.pop()
    log.append(entry)
    store.set_meta(_AUDIT_KEY, json.dumps(log[-_AUDIT_MAX:]))


def _valid_target(cap, target, jobs):
    if not isinstance(target, dict):
        return None
    out = {}
    if "job" in target:
        if target["job"] not in jobs:
            return None
        out["job"] = target["job"]
    if "id" in target:
        if not _FID.match(str(target["id"])):
            return None
        out["id"] = str(target["id"])
    for k in ("since",):
        if k in target:
            try:
                out[k] = int(target[k])
            except (TypeError, ValueError):
                return None
    needs_job = cap.id in ("check_monitor", "rerun_monitor", "verify_monitor", "verify_finding")
    needs_id = cap.id in ("explain_finding", "show_fix_steps", "verify_finding")
    if (needs_job and "job" not in out) or (needs_id and "id" not in out):
        return None
    return out


def _refuse(store, op, action, target, why, now, outcome="denied", lifecycle="denied"):
    _audit(store, op, action, target if isinstance(target, dict) else {}, outcome, why, now)
    return reply([_section("verified", why)], extra={"ok": False, "state": "denied", "lifecycle": lifecycle})


def handle_action(store, jobs, op, action=None, target=None, token=None, runner=None, conf=None,
                  now=None):
    """The only entry point that can cause anything to happen. -> reply dict.

    `runner(job) -> bool` queues one audit; it is injected by the service layer
    and is None when no scheduler is running.
    """
    now = int(now or time.time())
    runner_available = runner is not None
    if op in ("approve", "cancel"):
        return _resolve_proposal(store, jobs, op, token, runner, now)
    cap = CAPABILITIES.get(str(action))
    if cap is None:
        return _refuse(store, op, str(action)[:40], {}, "That is not an action ARGUS supports.", now)
    ok, why = availability(cap, runner_available)
    if not ok:
        return _refuse(store, op, cap.id, {}, why, now)
    clean = _valid_target(cap, target or {}, jobs)
    if clean is None:
        return _refuse(store, op, cap.id, {}, "That request did not name a valid target.", now)
    if op == "propose":
        if cap.mode != PREPARE:
            return _refuse(store, op, cap.id, clean, "That action does not need approval.", now)
        return _propose(store, jobs, cap, clean, now)
    if op != "run" or cap.mode == PREPARE:
        return _refuse(store, op, cap.id, clean,
                       "That action changes something, so it must be proposed and approved first.", now)
    handlers = {
        "explain_finding": lambda: _explain_finding(store, clean),
        "check_monitor": lambda: _check_monitor(store, jobs, clean, runner_available, now),
        "next_priority": lambda: first(store, jobs, now),
        "score_plan": lambda: score_advice(store, jobs, now),
        "check_model": lambda: _check_model(conf),
        "show_fix_steps": lambda: _show_fix_steps(store, clean, now),
        "verify_finding": lambda: _verify_finding(store, jobs, clean, now),
        "verify_monitor": lambda: _verify_monitor(store, jobs, clean),
    }
    result = handlers[cap.id]()
    if cap.id in ("verify_finding", "verify_monitor"):
        _audit(store, op, cap.id, clean, "verified" if result["answer"].startswith(
            ("Verified", "Recovered", "Checked")) and "still present" not in result["answer"]
            else "not_verified", result["answer"], now)
    result.update(ok=True, state="done")
    return result


def proposal_details(store, jobs, cap, target, now, token=""):
    """Everything a person needs before approving, from the capability and the real stored state."""
    job = target["job"]
    label = _jobs_label(jobs, job)
    snap = _snapshot(store, job)
    if not snap or not snap.get("ts"):
        basis = "has never stored a result on this computer"
    else:
        basis = f"last stored a result at {_fmt(snap['ts'])}"
        if snap.get("error"):
            basis += f", and that run recorded an error: {_clean(snap['error'], 120)}"
    return {
        "title": f"Re-run the “{label}” check once",
        "proposes": f"Queue one extra run of the “{label}” audit so its stored result is refreshed.",
        "why": f"The stored result is the evidence ARGUS-INSTINCT has for this area, and the check {basis}.",
        "target": {"kind": "collector", "id": job, "label": label},
        "expected": "A newer stored result for this check. ARGUS-INSTINCT will call it recovered only when that "
                    "result is newer than your approval and has no error.",
        "risks": cap.risks,
        "reversible": "Nothing to undo: the audit only reads state and changes no setting or file.",
        "if_nothing": f"Nothing runs. The proposal expires in {PROPOSAL_TTL_S // 60} minutes and the check "
                      "stays on its normal schedule.",
        "elevated": "No elevated permissions are needed. The ARGUS-INSTINCT service must be running.",
        "exact": f"The scheduler queues one read-only run of the “{job}” audit. Nothing else.",
        "evidence": [f"The “{label}” check {basis}."],
        "confirm_label": f"Approve: run “{label}” once",
        "lifecycle": "awaiting_approval", "expires_at": now + PROPOSAL_TTL_S, "token": token,
    }


def _propose(store, jobs, cap, target, now):
    pending = {t: p for t, p in _load(store, _PENDING_KEY, {}).items() if p.get("expires", 0) > now}
    token = secrets.token_urlsafe(9)
    pending[token] = {"action": cap.id, "target": target, "expires": now + PROPOSAL_TTL_S}
    for old in sorted(pending, key=lambda t: pending[t]["expires"])[:-_PENDING_MAX]:
        del pending[old]
    store.set_meta(_PENDING_KEY, json.dumps(pending))
    _audit(store, "propose", cap.id, target, "proposed", "", now)
    d = proposal_details(store, jobs, cap, target, now, token)
    secs = [_section("recommend", f"Proposed: {cap.purpose} Monitor: “{_jobs_label(jobs, target['job'])}”."),
            _section("verified", f"Needs: {cap.permissions}. Risk: {cap.risks}. Rollback: {cap.rollback}. "
                                 f"I will verify by: {cap.verify}"),
            _section("say", "Nothing has happened yet. Do you approve?")]
    return reply(secs, [{"action": "approve", "label": "Approve", "target": {}, "token": token},
                        {"action": "cancel", "label": "Cancel", "target": {}, "token": token}],
                 extra={"ok": True, "state": "proposed", "lifecycle": "awaiting_approval", "token": token,
                        "details": d})


def pending_proposals(store, jobs, now=None):
    """Unexpired proposals with their full confirmation details, newest expiry first."""
    now = int(now or time.time())
    out = []
    for token, p in _load(store, _PENDING_KEY, {}).items():
        cap = CAPABILITIES.get(p.get("action"))
        if cap is None or p.get("expires", 0) <= now or p.get("target", {}).get("job") not in jobs:
            continue
        d = proposal_details(store, jobs, cap, p["target"], now, token)
        d["expires_at"] = p["expires"]
        out.append(d)
    return sorted(out, key=lambda d: -d["expires_at"])


def _record_used(store, token, state, now):
    used = _load(store, _USED_KEY, {})
    used[str(token)] = {"state": state, "ts": now}
    for old in sorted(used, key=lambda t: used[t]["ts"])[:-_USED_MAX]:
        del used[old]
    store.set_meta(_USED_KEY, json.dumps(used))


def _resolve_proposal(store, jobs, op, token, runner, now):
    token = str(token or "")
    pending = _load(store, _PENDING_KEY, {})
    prop = pending.pop(token, None)
    store.set_meta(_PENDING_KEY, json.dumps(pending))
    if prop is None:
        used = _load(store, _USED_KEY, {}).get(token)
        if used and used.get("state") == "expired":
            return _refuse(store, op, "", {}, "That proposal expired, so nothing was changed. Ask for it again "
                                              "if you still want it.", now, "expired", "expired")
        if used:
            word = {"approved": "approved", "cancelled": "cancelled"}.get(used.get("state"), "used")
            return _refuse(store, op, "", {}, f"That proposal was already {word}. Each proposal works once, "
                                              "so nothing was changed.", now, "already_used", used.get("state", "denied"))
        return _refuse(store, op, "", {}, "ARGUS-INSTINCT has no proposal with that code, so nothing was changed.",
                       now, "unknown_token", "denied")
    if prop.get("expires", 0) <= now:
        _record_used(store, token, "expired", now)
        return _refuse(store, op, prop.get("action", ""), prop.get("target", {}),
                       "That proposal expired, so nothing was changed. Ask for it again if you still want it.",
                       now, "expired", "expired")
    cap, target = CAPABILITIES.get(prop["action"]), prop["target"]
    if op == "cancel":
        _record_used(store, token, "cancelled", now)
        _audit(store, "cancel", prop["action"], target, "cancelled", "", now)
        return reply([_section("verified", "Cancelled. Nothing was changed.")],
                     extra={"ok": True, "state": "cancelled", "lifecycle": "cancelled"})
    ok, why = availability(cap, runner is not None)
    if not ok:
        return _refuse(store, op, cap.id, target, why + " Nothing was changed.", now)
    try:
        queued = bool(runner(target["job"]))
    except Exception:
        queued = False
    _record_used(store, token, "approved" if queued else "failed", now)
    if not queued:
        _audit(store, "approve", cap.id, target, "failed", "runner refused", now)
        return reply([_section("verified", "I could not queue the re-run, so nothing happened.")],
                     extra={"ok": False, "state": "failed", "lifecycle": "failed"})
    _audit(store, "approve", cap.id, target, "queued", "", now)
    return reply([_section("verified", "Approved and queued. It has not finished yet, so I can't tell you "
                                       "whether it worked."),
                  _section("say", "ARGUS runs audits one at a time, so this may wait behind others, "
                                  "sometimes several minutes. Ask me to verify later and I'll check "
                                  "for a fresh result.")],
                 [_act("verify_monitor", {"job": target["job"], "since": now})],
                 extra={"ok": True, "state": "queued", "lifecycle": "approved_queued"})


# ------------------------------------------------------------------ routing

def route(store, jobs, q, offer=None, runner_available=False, now=None, conf=None):
    """Answer a normalised question deterministically, or None if not understood."""
    intent = classify_intent(q)
    if intent is None:
        return None
    if intent == "greeting":
        return greeting(store, jobs, now)
    if intent in ("yes", "no"):
        if intent == "no":
            return reply([_section("say", "No problem. Ask me anything else whenever you like.")],
                         suggestions=suggestions(store, jobs, now))
        if not isinstance(offer, dict):
            return reply([_section("say", "Happy to help. What would you like me to do?")],
                         suggestions=suggestions(store, jobs, now))
        action, target = offer.get("action"), offer.get("target")
        cap = CAPABILITIES.get(str(action))
        if cap is None:
            return None
        # "yes" is consent to the offered step only; a change still gets its
        # own proposal and approval.
        return {"_run": True, "op": "propose" if cap.mode == PREPARE else "run",
                "action": action, "target": target}
    return {"not_checked": lambda: not_checked(store, jobs, now), "found": lambda: found(store, jobs, now),
            "worry": lambda: worry(store, jobs, now), "why_serious": lambda: why_serious(store, jobs, now),
            "approve_effect": lambda: approve_effect(store, jobs, now), "damage": lambda: damage(store, now),
            "investigate_safely": lambda: investigate_safely(store, jobs, now),
            "score_meaning": lambda: score_meaning(store, jobs, now),
            "safe": lambda: safe(store, jobs, now), "plain": lambda: plain(store, jobs, now),
            "capabilities": lambda: capabilities(runner_available), "monitor": lambda: monitor(store, jobs, now),
            "fix": lambda: fix(store, jobs, runner_available, now), "first": lambda: first(store, jobs, now),
            "warning": lambda: first(store, jobs, now), "score": lambda: score_advice(store, jobs, now),
            "model": lambda: _check_model(conf)}[intent]()

"""Spyware / covert-process reasoning workflow: observe -> reason -> advise -> plan.

  1 OBSERVE     read-only sources, each with its own status (intel.spyware_evidence)
  2 NORMALIZE   typed subjects; free text never reaches a verdict
  3 RECONCILE   cross-view contradictions become concealment facts
  4 HYPOTHESIZE deterministic engine: stages, explanations, missing evidence
  5 ADJUDICATE  optional typed advisory model, fixed-vocabulary features only
  6 ESCALATE    a bounded observation-depth plan; nothing is executed here
  7 VERIFY      the fresh observation that must confirm or refute, then re-run
  8 DECIDE      the human; no step above authorizes anything

The advisory model adds a note. Measured on the synthetic corpus it does not
separate spyware from look-alikes well enough to gate anything, so it cannot
change a verdict or a depth, suppress a finding or authorize anything.
Unavailable or malformed advice is stated and ignored.
"""

import time

from jarvis.core.execution import escalate
from jarvis.core.reasoning import corpus, engine, knowledge, vocab
from jarvis.intel import spyware_evidence
from jarvis.response import jev

MAX_ADVISED = 5             # remote calls per run
ADVISE_TIMEOUT_S = 15
ARCHETYPE_MIN_CONFIDENCE = 0.5
# Measured 2026-09-30 on 19 synthetic corpus cases (8 spyware controls, 11 look-alikes):
# no question separated the classes cleanly enough to gate anything, so the advisory
# has no authority over verdict or depth. These constants only decide when a
# disagreement note is printed; they are unvalidated policy, not model truth.
BENIGN_NOTE_AT = 0.6        # explained look-alikes scored 0.30-0.59, controls 0.07-0.40
NO_REASON_NOTE_AT = 0.75
ADVISABLE = ("UNEXPLAINED_CAPABILITY", "SUSPECT_CHAIN", "VISIBILITY_CONTRADICTION",
             "EXPECTED_DUAL_USE")

# -- questions: review these first; everything else follows ---------------------
Q_BENIGN = ("Ordinary, legitimate software of the declared category would plausibly exhibit "
            "exactly these features. If no category is declared, judge whether ordinary "
            "desktop software would")
Q_BENIGN_CRITERIA = {"true": "plausible for ordinary legitimate software",
                     "false": "implausible for ordinary legitimate software"}
Q_NO_REASON = ("The features include a capture capability or a concealment feature that neither "
               "the declared category nor an ordinary application has any reason to have")
Q_NO_REASON_CRITERIA = {"true": "a capability or concealment without an ordinary reason",
                        "false": "every feature has an ordinary reason"}
Q_CONCEALED = ("The concealment features indicate deliberate hiding rather than an "
               "enumeration race or a monitoring artifact")
Q_CONCEALED_CRITERIA = {"true": "consistent with deliberate concealment",
                        "false": "consistent with a benign race or artifact"}
Q_ARCHETYPE = "Which behaviour class best fits the listed features?"
Q_ARCHETYPE_CRITERIA = {**{aid: a["title"] for aid, a in knowledge.ARCHETYPES.items()},
                        "ordinary_software": "ordinary software with these capabilities"}


def _questions(features, verdict):
    q = {"benign": {"type": "noul", "instructions": Q_BENIGN, "criteria": Q_BENIGN_CRITERIA},
         "no_reason": {"type": "noul", "instructions": Q_NO_REASON, "criteria": Q_NO_REASON_CRITERIA},
         "archetype": {"type": "choice", "instructions": Q_ARCHETYPE,
                       "criteria": Q_ARCHETYPE_CRITERIA}}
    if verdict == "VISIBILITY_CONTRADICTION":
        q["concealed"] = {"type": "noul", "instructions": Q_CONCEALED,
                          "criteria": Q_CONCEALED_CRITERIA}
    return q


def compose(row, answers):
    """Pure. Notes only: the advice never changes a verdict or an observation depth."""
    def noul(name):
        v = (answers.get(name) or {}).get("noul")
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None
    arch = answers.get("archetype") or {}
    conf = arch.get("confidence")
    benign, no_reason = noul("benign"), noul("no_reason")
    advice = {"available": True, "advisory_only": True,
              "benign_probability": benign, "no_ordinary_reason_probability": no_reason,
              "concealed_probability": noul("concealed"),
              "archetype": arch.get("choice") if isinstance(conf, (int, float))
              and conf >= ARCHETYPE_MIN_CONFIDENCE else None,
              "archetype_confidence": conf}
    if row["verdict"] in ("SUSPECT_CHAIN", "VISIBILITY_CONTRADICTION") and (
            benign is not None and benign >= BENIGN_NOTE_AT):
        advice["disagreement"] = "advisory finds these features plausible for ordinary software; verdict unchanged"
    elif row["verdict"] == "EXPECTED_DUAL_USE" and (
            no_reason is not None and no_reason >= NO_REASON_NOTE_AT
            and benign is not None and benign <= 0.3):
        advice["disagreement"] = "advisory sees no ordinary reason for capabilities the rules explained; verdict unchanged"
    return advice


def advise(row, subject, call=None):
    """Advice for one assessed subject. Never raises; unavailable is explicit."""
    features = engine.jev_features(row, subject)
    questions = _questions(features, row["verdict"])
    try:
        payload = (call or jev._call)(features, questions, timeout=ADVISE_TIMEOUT_S)
    except jev.JevError as exc:
        return {"available": False, "advisory_only": True, "reason": str(exc)[:160],
                "fallback": "deterministic verdict only"}
    return compose(row, payload["answers"])


def escalation_plan(rows, *, pressured=False):
    """Observation-depth plan via the existing bounded selector. Executes nothing."""
    mapped = []
    for r in rows:
        verdict = ("UNEXPLAINED_PROCESS" if r["observation_depth"] >= 2 else
                   "UNKNOWN" if r["observation_depth"] == 1 else "VERIFIED_PROCESS")
        mapped.append({"key": r["key"], "verdict": verdict})
    plan = escalate.decide(mapped, pressured=pressured)
    plan["awaiting_human_authorization"] = [r["key"] for r in rows if r["depth_needs_human"]]
    plan["executes_nothing"] = True
    return plan


def _verify_steps(rows):
    steps = []
    for r in rows[:10]:
        for a in r["archetypes"][:1]:
            steps.append({"key": r["key"], "confirm_or_refute": a["next_checks"],
                          "then": "re-run this workflow after fresh observation; a repair or a quiet "
                                  "run is not verification"})
    return steps


def run(hosts=("win", "wsl"), *, deep=False, use_jev=True, limit=50, gather=None, call=None,
        clock=time.time):
    """The whole workflow once. Read-only; returns a report dict."""
    subjects, coverage = (gather or spyware_evidence.gather)(hosts, deep=deep)
    rows = engine.assess_all(subjects, limit=max(len(subjects), 1))
    by_key = {s.key: s for s in subjects}
    flagged = [r for r in rows if r["verdict"] in ADVISABLE]
    advised = 0
    for r in flagged:
        if use_jev and advised < MAX_ADVISED:
            r["advice"] = advise(r, by_key[r["key"]], call=call)
            advised += 1
        elif use_jev:
            r["advice"] = {"available": False, "reason": f"advisory budget of {MAX_ADVISED} reached"}
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    focus = [r for r in rows if r["verdict"] not in ("NO_SIGNAL", "EXPECTED_DECLARED")][:limit]
    incomplete = sorted(k for k, v in coverage.items() if v != "current" and v != "complete")
    return {
        "generated_at": int(clock()), "hosts": list(hosts), "deep": deep,
        "subjects_examined": len(subjects), "counts": counts, "coverage": coverage,
        "coverage_incomplete": incomplete,
        "not_connected": list(spyware_evidence.NOT_CONNECTED),
        "focus": focus,
        "plan": escalation_plan(focus),
        "verify": _verify_steps(focus),
        "advisory": {"used": use_jev, "calls": advised, "max_calls": MAX_ADVISED,
                     "authority": "none: a logged second opinion; it cannot change a verdict or a depth"},
        "reading": ("No focus rows means nothing observable matched, not that the machine is clean: "
                    "see coverage and not_connected. Verdicts name observations, never intent."),
    }


def explain(archetype):
    """How one spyware class works, what it must do next, and what JARVIS cannot see."""
    a = knowledge.ARCHETYPES.get(archetype)
    if not a:
        return None
    mechs = sorted({m for kind in a["capture"] for m in vocab.CAPTURE_MECHANISMS.get(kind, ())}
                   | {vocab.STAGE_MECHANISM[s] for s in a["needs"] if s in vocab.STAGE_MECHANISM})
    return {"archetype": archetype, "title": a["title"], "mechanism": a["mechanism"],
            "must_eventually": list(a["needs"]), "next_checks": list(a["next_checks"]),
            "observability": {m: vocab.OBSERVABILITY[m] for m in mechs if m in vocab.OBSERVABILITY},
            "benign_lookalikes": sorted(cid for cid, c in knowledge.CATEGORIES.items()
                                        if set(c["expects"]) & set(a["capture"]))}


def selftest():
    return corpus.selftest()


def calibrate(call=None, limit=64):
    """Measure the advisory on the labelled corpus: per-question scores by class.

    Spyware controls and explained look-alikes are compared separately from the
    look-alikes the rules deliberately leave unexplained, because those should
    look like controls. Costs one remote request per case; nothing leaves the
    machine except fixed-vocabulary features of synthetic subjects.
    """
    cases = [("positive", n, s, e) for n, s, e in corpus.POSITIVES] + \
            [("lookalike", n, s, e) for n, s, e in corpus.LOOKALIKES]
    rows, failures = [], 0
    for kind, name, subject, expect in cases[:limit]:
        row = engine.assess(subject)
        features = engine.jev_features(row, subject)
        try:
            payload = (call or jev._call)(features, _questions(features, row["verdict"]),
                                          timeout=ADVISE_TIMEOUT_S)
        except jev.JevError:
            failures += 1
            continue
        a = payload["answers"]
        group = ("control" if kind == "positive"
                 else "explained_lookalike" if expect.startswith("EXPECTED") or expect == "NO_SIGNAL"
                 else "unexplained_lookalike")
        rows.append({"case": name, "group": group, "verdict": row["verdict"],
                     "benign": a["benign"]["noul"], "no_reason": a["no_reason"]["noul"],
                     "archetype": a["archetype"]["choice"]})
    summary = {}
    for group in ("control", "explained_lookalike", "unexplained_lookalike"):
        vals = [r for r in rows if r["group"] == group]
        for q in ("benign", "no_reason"):
            xs = [r[q] for r in vals]
            summary[f"{group}.{q}"] = ({"n": len(xs), "mean": round(sum(xs) / len(xs), 3),
                                        "min": min(xs), "max": max(xs)} if xs else None)
    ctl = [r["benign"] for r in rows if r["group"] == "control"]
    exp = [r["benign"] for r in rows if r["group"] == "explained_lookalike"]
    return {"cases": len(rows), "failures": failures, "summary": summary,
            "controls_and_explained_separable_on_benign":
                bool(ctl and exp and max(ctl) < min(exp)),
            "rows": rows,
            "reading": "separability on synthetic cases is a gate for giving the advisory any "
                       "authority; it is not evidence about real spyware"}

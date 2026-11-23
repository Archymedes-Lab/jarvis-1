"""Local-first judgment cascade: llama3.2:1b decides when sure, Jev on doubt.

Small local models are cheap, offline and on-loopback — so they may see
full context (llm.chat redacts secrets) — but their confidence is
uncalibrated.
Jev is calibrated but remote, metered and metadata-only. The cascade:

  local 1B vote (rich context, loopback) --confident--> accept
        |
     uncertain / down / busy
        v
  Jev judgment (metadata-only state) --probability--> compose
        |
     unavailable
        v
  deterministic fallback (observe / defer / human review)

Low stakes + high local confidence decides locally. Everything else
escalates; a bare local vote never authorizes high-impact action.
Thresholds live here, in one place. Pure composition over two transports;
tests mock both. Scheduler and HTTP paths never call here; CLI flows do.
"""

import re

from jarvis.core import confidence as confidence_mod
from jarvis.response import jev as jev_mod
from jarvis.response import llm as llm_mod

# A local vote below this self-reported confidence escalates to Jev.
# Deliberately high: small-model confidence is uncalibrated optimism.
LOCAL_ACCEPT = 0.85

_VOTE = re.compile(r"^\s*(YES|NO)\s+(\d{1,3})\b", re.IGNORECASE)


def _parse_vote(text):
    """Strict 'YES|NO <0-100>' parse. Anything else is doubt, not data."""
    match = _VOTE.match(text or "")
    if not match:
        return None
    try:
        score = int(match.group(2)) / 100.0
    except ValueError:
        return None
    if not 0.0 <= score <= 1.0:
        return None
    return {"vote": match.group(1).upper() == "YES", "confidence": score}


def local_noul(conf, question, context):
    """One yes/no judgment from the local 1B model. Rich context allowed.

    Loopback-only transport via llm.chat (which redacts); returns
    {"vote", "confidence"} or {"vote": None} on any doubt or failure.
    """
    system = ("Answer one yes/no question with a calibrated confidence. "
              "Reply with exactly one line: YES <0-100> or NO <0-100>, "
              "then a one-line reason. Never act; you only judge.")
    user = f"Question: {question}\nContext:\n{context[:4000]}"
    try:
        if llm_mod.ping(conf)[0] not in ("model_loaded", "model_ready"):
            return {"vote": None, "reason": "local model not ready"}
        text, err = llm_mod.chat(
            conf, system, user,
            examples=[("Question: Is the sky blue?\nContext:\nIt is daytime.",
                       "YES 95\nClear daytime sky.")],
            temperature=0.0, num_predict=60, timeout=60, wait=10.0)
    except Exception:
        return {"vote": None, "reason": "local model error"}
    if err:
        return {"vote": None, "reason": f"local model: {err}"[:120]}
    parsed = _parse_vote(text)
    if parsed is None:
        return {"vote": None, "reason": "unparseable local vote"}
    return parsed


def ask_yesno(question, full_context, meta_state, conf, criteria=None):
    """Cascade one yes/no question over rich local context + lean Jev state.

    Returns {"route": local|jev|fallback, "vote": bool|None, ...}.
    The Jev leg sees metadata only; the local leg sees full context on
    loopback. That asymmetry is the point: content never leaves the
    machine unless the local model is unsure.
    """
    local = local_noul(conf, question, full_context)
    if local.get("vote") is not None and local.get("confidence", 0) >= LOCAL_ACCEPT:
        return {"route": "local", "vote": local["vote"],
                "confidence": local["confidence"],
                "band": confidence_mod.level(local["confidence"]),
                "advisory_only": True}
    try:
        remote_question = {"type": "noul", "instructions": question}
        if criteria:
            remote_question["criteria"] = criteria
        payload = jev_mod._call(meta_state, {"q": remote_question})
        score = (payload.get("answers", {}).get("q") or {}).get("noul")
        return {"route": "jev", "vote": score >= jev_mod.NOUL_YES,
                "probability": score,
                "model": payload.get("model"), "usage": payload.get("usage"),
                "advisory_only": True}
    except jev_mod.JevError as exc:
        return {"route": "fallback", "vote": None,
                "reason": str(exc)[:200], "advisory_only": True}


def judge_proposal(entry, conf):
    """Worth a bounded investigation? Local-first, Jev on doubt."""
    full = (f"Title: {entry.get('title', '')}\n"
            f"Problem: {entry.get('problem', '')}\n" +
            "\n".join(f"- {line}" for line in (entry.get("evidence") or [])[:6]))
    meta = {"title": jev_mod._text(entry.get("title", "")),
            "problem": jev_mod._text(entry.get("problem", "")),
            "evidence_lines": len(entry.get("evidence") or []),
            "key": str(entry.get("key", ""))[:80]}
    out = ask_yesno(jev_mod.Q_WORTH_INVESTIGATING, full, meta, conf,
                    jev_mod.Q_WORTH_CRITERIA)
    if out["route"] == "fallback":
        out["recommendation"] = "investigate"
        out["reason"] = "no judge available; human approval still required"
    else:
        out["recommendation"] = ("investigate" if out["vote"] else "defer")
    return {"judgment": "proposal", **out}


def validate_patch(entry, conf):
    """Does the draft address the diagnosis? Local-first, Jev on doubt.

    The local leg sees the redacted patch excerpt (loopback only); Jev
    sees file lists and diff stats, never text.
    """
    patch = entry.get("patch_draft") or ""
    if not patch.strip():
        return {"judgment": "validation", "route": "fallback", "vote": None,
                "recommendation": "no patch draft", "advisory_only": True}
    added, removed, files = jev_mod._patch_stats(patch)
    directive = entry.get("directive") or {}
    full = (f"Diagnosis: {directive.get('diagnosis') or entry.get('problem', '')}\n"
            f"Declared scope: {', '.join((directive.get('files') or [])[:20])}\n"
            f"Patch excerpt (redacted):\n{patch[:4000]}")
    meta = {"diagnosis": jev_mod._text(directive.get("diagnosis")
                                       or entry.get("problem", "")),
            "files": files, "lines_added": added, "lines_removed": removed,
            "declared_scope": [str(f)[:200] for f in
                               (directive.get("files") or [])[:20]]}
    out = ask_yesno(jev_mod.Q_PATCH_ADDRESSES, full, meta, conf,
                    jev_mod.Q_PATCH_CRITERIA)
    out["basis"] = ("patch content reviewed locally" if out["route"] == "local"
                    else "metadata scope consistency only"
                    if out["route"] == "jev" else "deterministic fallback")
    if out["route"] == "fallback":
        out["recommendation"] = "human review decides"
    else:
        out["recommendation"] = ("proceed to human review" if out["vote"]
                                 else "rework before human review")
    return {"judgment": "validation", **out}

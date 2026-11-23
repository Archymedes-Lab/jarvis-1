"""Jev judgments for the code-edit pipeline: advise, never authorize.

Every code edit routes through Jev assessment (triage -> proposal review ->
patch validation), but assessment is strictly advisory:

  * Jev cannot approve, authorize, apply, or execute anything. This module
    exposes no such functions, and a test pins that absence.
  * Human gates are unchanged: approve, authorize, apply stay explicit
    terminal commands; tests still gate application; rollback is retained.
  * Low-confidence judgments escalate to the human (the consistency
    pattern), they never silently pass.
  * Request state is counts, severities, file lists, diff stats, and
    best-effort redacted short text (secrets/credentials/URLs scrubbed;
    arbitrary prose is a documented blind spot, so remote questions must
    never need exact content).
  * Tier 2 enrichment: no key, offline, or any failure -> {"unavailable"}
    and the existing deterministic path runs unchanged. The HTTP paths never
    call here. The one scheduler caller is the memory collector's advisory
    note on an unrecognised in-memory image (judge_memory_image): at most
    MEMORY_MAX_CALLS per scan, each bounded by MEMORY_TIMEOUT_S, sending only
    fixed-list features, and never able to change a severity. Everything
    else is CLI-only, bounded by TIMEOUT_S.

Questions and thresholds live in this one file for review.
"""

import json
import math
import os
import re
import time
import urllib.error
import urllib.request

from jarvis.core import confidence as confidence_mod

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"
TIMEOUT_S = 20
KEY_ENV = "TYPESAFE_API_KEY"
KEY_FILE = os.path.expanduser("~/.jarvis/typesafe.env")
MAX_TEXT = 500
MAX_RESPONSE_BYTES = 1024 * 1024

# Composition thresholds. Noul values are yes-probabilities, not confidence.
# These are policy choices to validate on JARVIS examples, never model truth.
NOUL_YES = 0.5
TRIAGE_CHOICE_MIN_CONFIDENCE = 0.5

# -- questions (review these first; everything else follows) -----------------

Q_INTERRUPT = ("This finding needs to interrupt the human now "
               "rather than wait in the timeline. Treat severity as context, "
               "not proof of compromise or permission to act")
Q_INTERRUPT_CRITERIA = {
    "true": "The metadata supports immediate human attention",
    "false": "The metadata supports observation or timeline recording",
}
Q_DISPOSITION_CRITERIA = {
    "page": "Interrupt the human immediately; do not authorize a response",
    "observe": "Increase observation without changing the protected system",
    "log": "Record in the timeline only; no immediate interruption",
}
Q_WORTH_INVESTIGATING = ("This problem warrants a bounded automated "
                         "investigation that produces a patch draft for "
                         "human review")
Q_WORTH_CRITERIA = {
    "true": "A bounded investigation could produce useful review evidence",
    "false": "The metadata does not justify spending automated investigation effort",
}
# The memory collector's advisory note. The features are coarse facts and
# fixed-list hits (assemblies.features); the answer is shown to the human
# beside a deterministic severity it cannot change.
MEMORY_TIMEOUT_S = 10
MEMORY_MAX_CALLS = 3
Q_MEMORY_IMAGE = ("An image copied into a process's memory with these features "
                  "is more consistent with offensive tooling (injection, "
                  "credential theft, keylogging, defence evasion or a "
                  "post-exploitation framework) than with ordinary software "
                  "behaviour. Treat the features as evidence, not proof")
Q_MEMORY_CRITERIA = {
    "true": "The features resemble offensive tooling loaded in memory",
    "false": "The features resemble ordinary software that loads code in memory",
}

Q_PATCH_ADDRESSES = ("The patch draft metadata is consistent with the stated "
                     "diagnosis and declared file scope")
Q_PATCH_CRITERIA = {
    "true": "The changed files and diff size are plausible for the declared scope",
    "false": "The changed files or diff size conflict with the declared scope",
}


class JevError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("TypeSafe redirects are forbidden")


def _open(req, timeout):
    """Use the fixed HTTPS endpoint directly, ignoring environment proxies."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect()).open(
            req, timeout=timeout)


def _key():
    """The API key, or "". Env first, then the user-owned env file.

    The file must be owner-only (no group/other bits) or it is ignored:
    a shared-readable secret is no secret. Never logged, never persisted
    anywhere else.
    """
    key = os.environ.get(KEY_ENV)
    if key:
        return key
    try:
        st = os.stat(KEY_FILE)
        if st.st_mode & 0o077:
            return ""
        with open(KEY_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("export "):
                    line = line[len("export "):]
                name, sep, value = line.partition("=")
                if name.strip() == KEY_ENV and sep:
                    value = value.strip().strip("'\"")
                    return value if value else ""
    except OSError:
        pass
    return ""


def available():
    """A key is configured. No network; a missing key is normal (Tier 2)."""
    return bool(_key())


def _text(value):
    """Best-effort redacted text for remote state. Truncated, scrubbed of
    secrets/credentials/URLs — arbitrary prose remains a documented blind
    spot, so remote questions must never need exact content."""
    from jarvis.response.privacy import redact
    return redact(str(value or ""))[:MAX_TEXT]


def _number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and 0.0 <= value <= 1.0)


def _validate_answer(question_id, question, answer):
    """Reject malformed or type-confused remote answers before composition."""
    if not isinstance(answer, dict) or answer.get("type") != question.get("type"):
        raise JevError(f"malformed {question_id} answer")
    kind = question.get("type")
    if kind == "noul":
        if not _number(answer.get("noul")):
            raise JevError(f"malformed {question_id} noul")
        return
    if kind == "choice":
        criteria = question.get("criteria")
        probabilities = answer.get("probabilities")
        if (not isinstance(criteria, dict) or not criteria
                or answer.get("choice") not in criteria
                or not _number(answer.get("confidence"))
                or not isinstance(probabilities, dict)
                or set(probabilities) != set(criteria)
                or any(not _number(value) for value in probabilities.values())
                or abs(sum(probabilities.values()) - 1.0) > 0.02):
            raise JevError(f"malformed {question_id} choice")
        return
    raise JevError(f"unsupported {question_id} question type")


def _call(state, questions, timeout=TIMEOUT_S):
    """One bounded SystemOne request. Raises JevError on any failure."""
    key = _key()
    if not key:
        raise JevError("no API key configured")
    body = json.dumps({"state": state, "model": MODEL,
                       "questions": questions}).encode()
    req = urllib.request.Request(
        ENDPOINT, data=body,
        headers={"Authorization": "Bearer " + key,
                 "Content-Type": "application/json"})
    try:
        with _open(req, timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except Exception as exc:
        raise JevError(f"request failed: {type(exc).__name__}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise JevError("response too large")
    try:
        payload = json.loads(raw.decode("utf-8", "replace"))
    except (UnicodeError, ValueError) as exc:
        raise JevError("malformed response") from exc
    if not isinstance(payload, dict) or not isinstance(
            payload.get("answers"), dict):
        raise JevError("malformed response")
    for question_id, question in questions.items():
        if not isinstance(question, dict):
            raise JevError(f"malformed {question_id} question")
        _validate_answer(question_id, question,
                         payload["answers"].get(question_id))
    return payload


def _advisory(name, answers, fallback):
    """Compose a judgment with its confidence band. Pure."""
    return {"judgment": name, "answers": answers, "fallback": fallback,
            "advisory_only": True}


def triage_chain(chain):
    """Page / observe / log for one activity chain. Metadata only."""
    fallback = {"disposition": "observe",
                "reason": "Jev unavailable; observe is the safe default"}
    state = {
        "member_count": int(chain.get("count", 0)),
        "worst_severity": str(chain.get("worst_severity", "unknown")),
        "jobs": sorted(str(j) for j in (chain.get("jobs") or [])[:5]),
        "causal_edge": bool(chain.get("causal")),
        "window_s": round(float(chain.get("last", 0))
                          - float(chain.get("first", 0)), 1),
    }
    try:
        payload = _call(state, {
            "interrupt": {"type": "noul", "instructions": Q_INTERRUPT,
                          "criteria": Q_INTERRUPT_CRITERIA},
            "disposition": {"type": "choice",
                            "instructions": "Which advisory disposition best "
                                            "fits the supplied metadata?",
                            "criteria": Q_DISPOSITION_CRITERIA},
        })
        answers = payload["answers"]
        disp = answers.get("disposition") or {}
        conf = disp.get("confidence")
        band = confidence_mod.level(conf)
        interrupt = (answers.get("interrupt") or {}).get("noul")
        # Choice confidence gates whether its relative winner is usable. The
        # separate Noul is an absolute page-eligibility check; it is a
        # probability, not another confidence score.
        choice = disp.get("choice")
        if not _number(conf) or conf < TRIAGE_CHOICE_MIN_CONFIDENCE:
            choice = "observe"
        if choice == "page" and (not _number(interrupt)
                                 or interrupt < NOUL_YES):
            choice = "observe"
        return _advisory("triage", {
            "disposition": choice, "band": band,
            "interrupt_probability": interrupt,
            "model": payload.get("model"),
            "usage": payload.get("usage")}, fallback)
    except JevError as exc:
        return _advisory("triage", {"unavailable": str(exc)[:200]}, fallback)


def judge_proposal(entry):
    """Is this fix proposal worth a bounded investigation? Metadata only."""
    fallback = {"worth_investigating": True,
                "reason": "Jev unavailable; human approval still required"}
    state = {"title": _text(entry.get("title")),
             "problem": _text(entry.get("problem")),
             "evidence_lines": len(entry.get("evidence") or []),
             "key": str(entry.get("key", ""))[:80]}
    try:
        payload = _call(state, {
            "worth": {"type": "noul", "instructions": Q_WORTH_INVESTIGATING,
                      "criteria": Q_WORTH_CRITERIA},
        })
        worth = (payload["answers"].get("worth") or {}).get("noul")
        return _advisory("proposal", {
            "worth_probability": worth,
            "recommendation": ("investigate" if _number(worth)
                               and worth >= NOUL_YES else
                               "defer" if _number(worth) else "human review"),
            "model": payload.get("model"),
            "usage": payload.get("usage")}, fallback)
    except JevError as exc:
        return _advisory("proposal", {"unavailable": str(exc)[:200]}, fallback)


def _patch_stats(patch):
    added = sum(1 for line in patch.splitlines()
                if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in patch.splitlines()
                  if line.startswith("-") and not line.startswith("---"))
    files = sorted({m.group(2) for m in
                    re.finditer(r"^diff --git a/(.+?) b/(.+?)$",
                                patch, flags=re.MULTILINE)})
    return added, removed, files[:20]


def validate_patch(entry):
    """Is draft metadata consistent with declared scope? Advisory only.

    Because Jev receives file lists and diff stats rather than patch text, it
    cannot establish semantic correctness. The returned dict is persisted for
    review; status transitions ignore it by construction.
    """
    fallback = {"scope_consistent": None,
                "reason": "Jev unavailable; tests and human review decide"}
    patch = entry.get("patch_draft") or ""
    if not patch.strip():
        return _advisory("validation", dict(fallback, reason="no patch draft"),
                         fallback)
    added, removed, files = _patch_stats(patch)
    directive = entry.get("directive") or {}
    state = {"diagnosis": _text(directive.get("diagnosis")
                                or entry.get("problem")),
             "files": files, "lines_added": added, "lines_removed": removed,
             "declared_scope": [str(f)[:200] for f in
                                (directive.get("files") or [])[:20]]}
    try:
        payload = _call(state, {
            "addresses": {"type": "noul", "instructions": Q_PATCH_ADDRESSES,
                          "criteria": Q_PATCH_CRITERIA},
        })
        score = (payload["answers"].get("addresses") or {}).get("noul")
        return _advisory("validation", {
            "scope_consistency_probability": score,
            "recommendation": ("metadata supports human review"
                               if _number(score) and score >= NOUL_YES else
                               "review scope mismatch before proceeding"
                               if _number(score) else "human review required"),
            "model": payload.get("model"),
            "usage": payload.get("usage")}, fallback)
    except JevError as exc:
        return _advisory("validation", {"unavailable": str(exc)[:200]},
                         fallback)


def judge_memory_image(features):
    """Advisory: do in-memory image features look like offensive tooling?

    `features` comes from assemblies.features: fixed-list hits and coarse
    facts only. The caller shows the result next to a severity it never
    changes; missing or malformed output is reported as unavailable.
    """
    fallback = {"offensive_probability": None,
                "reason": "Jev unavailable; the severity is deterministic"}
    state = {k: features.get(k) for k in (
        "host_executable", "launch", "parent_executable", "managed",
        "executable_memory", "private_memory", "size_bucket",
        "sensitive_native_apis", "offensive_terms", "identifier_count",
        "unexplained_identifier_count")}
    try:
        payload = _call(state, {
            "offensive": {"type": "noul", "instructions": Q_MEMORY_IMAGE,
                          "criteria": Q_MEMORY_CRITERIA},
        }, timeout=MEMORY_TIMEOUT_S)
        p = (payload["answers"].get("offensive") or {}).get("noul")
        return _advisory("memory_image", {
            "offensive_probability": p,
            "model": payload.get("model")}, fallback)
    except JevError as exc:
        return _advisory("memory_image", {"unavailable": str(exc)[:200]},
                         fallback)


def assess(entry):
    """Run every applicable judgment for a proposal. Best-effort, ordered."""
    started = time.time()
    out = {"at": int(started), "model": MODEL,
           "proposal": judge_proposal(entry)}
    if (entry.get("patch_draft") or "").strip():
        out["validation"] = validate_patch(entry)
    out["latency_s"] = round(time.time() - started, 2)
    return out

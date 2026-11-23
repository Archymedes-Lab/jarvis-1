"""Investigation reports a non-expert can read: what was checked, found, and not done.

One shape for the assistant's checks, JARVIS investigations and the coding
agent's fix proposals, so every one of them says the same seven things in the
same order and none can leave out the uncomfortable ones.

Invariants this module enforces (tests/test_report.py):
  * `not_done` is never empty. It always says whether anything was changed,
    so a report cannot imply an action it did not take or hide one it did.
  * "Nothing was observed" is only ever claimed about the areas listed under
    `checked`, and areas that were not checked are named. Not detected and
    not checked are different statements.
  * A report whose status is not "complete" says it is incomplete, lowers its
    certainty to match, and never carries a recommendation phrased as a result.
  * A read-only report cannot claim a change, and a report that claims a change
    must name what changed.
  * Text from tools or models is evidence to display, never authority: it is
    redacted, bounded, and has no field that could trigger anything.
"""

from jarvis.response.privacy import redact

COMPLETE, INCOMPLETE, FAILED = "complete", "incomplete", "failed"
_STATUSES = (COMPLETE, INCOMPLETE, FAILED)
_LINE = 240
_TECH = 4000

NO_CHANGE = "Nothing on this computer was changed."


def _line(text, limit=_LINE):
    text = " ".join(redact(str(text or "")).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _lines(items, limit=12):
    return [_line(i) for i in (items or ()) if str(i or "").strip()][:limit]


def build(*, title, status=COMPLETE, read_only=True, checked=(), found=(), meaning=(), certainty="",
          recommendation=(), not_done=(), unchecked=(), changed=(), technical="", source=""):
    """-> report dict. Raises ValueError for a combination that would mislead."""
    if status not in _STATUSES:
        raise ValueError(f"unknown status {status!r}")
    changed = _lines(changed)
    if read_only and changed:
        raise ValueError("a read-only report cannot list changes")
    checked, unchecked = _lines(checked), _lines(unchecked)
    found = _lines(found)
    if status == COMPLETE and not checked:
        raise ValueError("a complete report must say what was checked")

    notes = _lines(not_done)
    notes.insert(0, ("Changed: " + "; ".join(changed)) if changed else NO_CHANGE)
    if unchecked:
        notes.append("Not checked: " + "; ".join(unchecked))

    if not found:
        found = ["Nothing was observed in the areas listed under “What I checked”."
                 if checked else "No observations were made."]
        if unchecked:
            found.append("That says nothing about the areas that were not checked.")

    certainty = _line(certainty) or "Not scored. Based only on the evidence listed here."
    if status != COMPLETE:
        head = ("This investigation did not finish." if status == INCOMPLETE
                else "This investigation failed.")
        found.insert(0, head + " Treat what follows as incomplete.")
        certainty = "Low: the investigation did not complete. " + certainty
    return {
        "kind": "report", "title": _line(title, 120), "status": status, "read_only": bool(read_only),
        "mode_label": "Read-only: nothing was changed" if read_only else "Made or proposed changes",
        "checked": checked or ["Nothing was completed."], "found": found, "meaning": _lines(meaning),
        "certainty": certainty, "recommendation": _lines(recommendation), "not_done": notes,
        "technical": redact(str(technical or ""))[:_TECH], "changed": bool(changed), "source": _line(source, 60),
    }


SECTIONS = (("checked", "What I checked"), ("found", "What I found"), ("meaning", "What this might mean"),
            ("certainty", "How certain I am"), ("recommendation", "What I recommend"),
            ("not_done", "What I have not done"))


def as_text(report):
    """Plain-text form (CLI, logs, assistant answers). Same order, same wording."""
    out = [f"{report['title']} ({report['mode_label']}; {report['status']})"]
    for key, heading in SECTIONS:
        value = report.get(key)
        if not value:
            continue
        out.append(heading + ":")
        out.extend(f"  - {v}" for v in (value if isinstance(value, list) else [value]))
    return "\n".join(out)


# ---- coding-agent fix proposals (response/selffix.py entries) --------------

_FIX_NEXT = {
    "proposed": "Read the problem below. Approving starts a draft only; nothing is applied.",
    "approved": "A draft is being generated. Nothing is applied.",
    "review": "Read the drafted patch. Authorizing records your intent only; applying is a separate terminal step.",
    "draft_failed": "The draft failed. Retry it, or reject the proposal.",
    "apply_approved": "Authorized. Applying needs the terminal command and its tests.",
    "applied": "A patch was applied from the terminal. Check the result before relying on it.",
    "rejected": "This proposal was rejected. Nothing was applied.",
    "expired": "This proposal expired. Nothing was applied.",
}


def fix_report(entry):
    """Report for one fix proposal, built only from fields the entry actually has."""
    status = str(entry.get("status") or "")
    state = str(entry.get("generation_state") or "")
    failed = status == "draft_failed" or bool(entry.get("generation_error"))
    applied = status == "applied"
    checked = []
    if entry.get("problem"):
        checked.append("The collector result that raised this proposal: " + str(entry["problem"]))
    if state:
        checked.append("Draft generation state: " + state)
    directive = (entry.get("directive") or {}).get("objective") or entry.get("directive_objective")
    found = [str(entry["problem"])] if entry.get("problem") else []
    jev = entry.get("jev") or {}
    advisory = ("An advisory review (Jev) was recorded for this proposal. It cannot approve or apply anything."
                if jev else "No advisory review is recorded for this proposal.")
    patch = int(entry.get("patch_chars") or len(entry.get("patch_draft") or "") or 0)
    return build(
        title=str(entry.get("title") or entry.get("id") or "Fix proposal"),
        status=FAILED if failed else (COMPLETE if checked else INCOMPLETE),
        read_only=not applied,
        checked=checked,
        found=found,
        meaning=["A drafted patch is a suggestion written by a model. It may be wrong, and it has not been "
                 "tried on your system by this page."] + ([f"The drafted change is {patch} characters long."]
                                                          if patch else []),
        certainty="Draft only. " + advisory,
        recommendation=[_FIX_NEXT.get(status, "Review the proposal before deciding.")],
        not_done=["No patch is applied from the dashboard." if not applied else
                  "Applying happened through the terminal, not this page.",
                  "Your approval here is a record of intent; it is not execution."],
        changed=(["a patch was applied through the terminal"] if applied else []),
        technical="\n".join(x for x in (
            f"proposal: {entry.get('id', '')}", f"status: {status}", f"model directive: {directive or '-'}",
            f"generation error: {entry.get('generation_error')}" if entry.get("generation_error") else "") if x),
        source="fix proposal",
    )

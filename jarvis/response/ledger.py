"""What JARVIS has already told you, and what became of it.

Every other collector answers "what is true right now?". This one answers a
question none of them can: **what did this system report to me that I never
actually resolved?**

That question had no answer before. `alert.py` keeps a live state map so it can
decide what to mail next, and it deletes an entry the moment the finding stops
being reported. Useful for sending; useless for accountability. A HIGH finding
could be mailed, ignored for three weeks, and then quietly clear itself — say,
because the collector that raised it started failing — and leave behind no
record that it had ever existed. Worse, a finding that was genuinely fixed and
then came back was indistinguishable from one seen for the first time, which
throws away the single most diagnostic fact available: *it came back*.

So the ledger is append-and-update, never delete, and it sorts what it holds
into four states:

  outstanding  mailed, still being reported, never cleared. The backlog.
  recurring    cleared at least once and reported again since. Remediation did
               not hold, or the persistence re-established itself. This is the
               worst state in the table, and it is deliberately ranked above a
               plain outstanding finding of the same severity.
  stale        mailed, and the job that raised it has not run since. Not
               resolved — unobserved. Silence from a dead collector is not a
               clean result, and this is where that distinction is made.
  resolved     cleared, and stayed cleared.

Ageing is reported in days rather than as a boolean, because "unresolved" is
not a state that means the same thing after one hour and after one month.
"""

import json
import time

from jarvis.core.finding import LOCAL_HOST
from jarvis.core.finding import finding as _finding
from jarvis.response import alert

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"recurring": 0, "outstanding": 1, "stale": 2, "resolved": 3}

DAY = 86400

# How long an unresolved finding of each severity is allowed to sit before the
# ledger raises it as a finding in its own right. A critical nobody touched for
# two days is its own emergency; a low is a housekeeping note for a month.
OVERDUE_DAYS = {"critical": 2, "high": 7, "medium": 21, "low": 45}


def _age_days(ts, now_ts):
    return max(0.0, (now_ts - int(ts or 0)) / DAY)


def _phrase_age(days):
    if days < 1:
        hours = int(days * 24)
        return f"{hours}h" if hours else "under an hour"
    if days < 60:
        return f"{int(days)}d"
    return f"{int(days // 30)} months"


def classify(rows, job_ts=None, now_ts=None):
    """Sort ledger rows into the four states, newest activity first.

    `job_ts` maps job name -> the timestamp of that job's last successful run,
    which is what separates "still being reported" from "nobody has looked".
    Without it every open row is simply outstanding, which is the safe reading.
    """
    now_ts = int(now_ts if now_ts is not None else time.time())
    job_ts = job_ts or {}
    out = {"recurring": [], "outstanding": [], "stale": [], "resolved": []}

    for row in rows:
        row = dict(row)
        row["age_days"] = _age_days(row.get("first_sent"), now_ts)
        row["quiet_days"] = _age_days(row.get("last_sent"), now_ts)
        if row.get("cleared_at"):
            row["state"] = "resolved"
        else:
            last_run = int(job_ts.get(row.get("job") or "", 0) or 0)
            # An open row whose job has not run since the alert was sent has
            # not survived a re-check; it has merely not been contradicted.
            if last_run and last_run < int(row.get("last_sent") or 0):
                row["state"] = "stale"
            elif int(row.get("reopened") or 0) > 0:
                row["state"] = "recurring"
            else:
                row["state"] = "outstanding"
        out[row["state"]].append(row)

    for state in out:
        out[state].sort(key=lambda r: (SEV_ORDER.get(r.get("severity"), 9),
                                       -r["age_days"]))
    return out


def overdue(row, now_ts=None):
    """True when an open row has sat longer than its severity allows."""
    if row.get("cleared_at"):
        return False
    limit = OVERDUE_DAYS.get(row.get("severity") or "low")
    if limit is None:
        return False
    return _age_days(row.get("first_sent"),
                     int(now_ts if now_ts is not None else time.time())) > limit


_M_BACKFILLED = "ledger_backfilled"


def backfill(store):
    """Seed the ledger from alert.py's live state, once.

    The ledger was added after alerting had been running for weeks, so on the
    day it shipped it knew about nothing while a real backlog already existed —
    41 open alerts on the machine it was written on. `alert_state` is the only
    surviving record of those, so it is read once and imported.

    What it can recover is limited and the import says so: the state map stores
    the dedupe key, the timestamps, the count, the severity and the job, but
    never the finding's `detail`, because it never needed it. Imported rows
    therefore carry the key's own three fields and an explicit note, rather than
    a fabricated description.

    Entries still inside the persistence gate (`count` 0, never actually
    mailed) are skipped: the ledger records what was *sent*, and claiming
    otherwise would make the backlog look worse than it is.
    """
    if store.get_meta(_M_BACKFILLED):
        return 0
    try:
        state = json.loads(store.get_meta("alert_state", "{}") or "{}")
    except (ValueError, TypeError):
        state = {}

    imported = 0
    existing = {r["key"] for r in store.ledger_rows(limit=100000)}
    for key, st in state.items():
        if key in existing or int(st.get("count", 0) or 0) < 1:
            continue
        parts = key.split("|")
        category = parts[0] if parts else ""
        title = parts[1] if len(parts) > 1 else key
        locus = parts[2] if len(parts) > 2 else ""
        first = int(st.get("first") or 0)
        last = int(st.get("last_sent") or first)
        store.ledger_sent(
            key,
            {"category": category, "title": title, "where": locus,
             # The state map never stored the host, and the key cannot be
             # made to yield it -- a hunt finding's `where` is the intel URL,
             # not the path. Guessing produced confident nonsense (Windows
             # paths labelled wsl), so imported rows carry no host until the
             # next real send fills it in.
             "host": "",
             "severity": st.get("sev") or "high",
             "detail": "imported from the live alert state when the ledger was "
                       "added; the original detail text was not retained there"},
            st.get("job") or "", "", first or None)
        # ledger_sent counts one send; restore the real total and the real
        # last-sent time, which is what the ageing is measured from.
        store.db.execute(
            "UPDATE alert_ledger SET sent_count=?, last_sent=? WHERE key=?",
            (int(st.get("count", 1) or 1), last, key))
        imported += 1

    store.set_meta(_M_BACKFILLED, str(int(time.time())))
    store.commit()
    return imported


def _listed_keys(snapshots):
    """job -> {dedupe key} of every non-ok finding its current snapshot lists.

    A failing snapshot lists nothing here: its findings are not a current
    observation, so a ledger row about it must keep standing on its own."""
    out = {}
    for job, snap in (snapshots or {}).items():
        if job == "ledger" or not isinstance(snap, dict) or snap.get("error"):
            continue
        keys = set()
        for f in snap.get("findings") or ():
            if isinstance(f, dict) and f.get("severity") not in (None, "ok"):
                keys.add(alert.finding_key(f))
        out[job] = keys
    return out


def _restated(row, listed):
    """True when the row's original finding is listed right now by its own job
    (or a job in the same clearing domain), under the same dedupe key."""
    job, key = row.get("job") or "", row.get("key") or ""
    if not key:
        return False
    return any(key in keys for j, keys in listed.items() if alert.same_domain(j, job))


def annotation(row, now_ts=None):
    """The ageing/recurrence facts a ledger row adds to its original finding."""
    now_ts = int(now_ts if now_ts is not None else time.time())
    age = _age_days(row.get("first_sent"), now_ts)
    reopened = int(row.get("reopened") or 0)
    state = "recurring" if reopened > 0 else "overdue" if overdue(row, now_ts) else "open"
    return {"state": state, "age_days": round(age, 1), "age": _phrase_age(age),
            "deadline_days": OVERDUE_DAYS.get(row.get("severity") or "low"),
            "sent_count": int(row.get("sent_count") or 0),
            "cleared": int(row.get("clear_count") or 0), "reopened": reopened,
            "worst_severity": row.get("worst_sev") or row.get("severity") or ""}


def annotate(findings, job, rows, now_ts=None):
    """Copies of `findings` with a `ledger` field on each one the ledger holds
    open: how long it has been unresolved, whether it is past its deadline,
    and whether it came back after a clear. This is where the ageing signal
    lives now that the ledger no longer restates the finding as a second one
    (ALERT-QUALITY-2026-11-08). `rows` maps dedupe key -> open ledger row."""
    out = []
    for f in findings or ():
        row = rows.get(alert.finding_key(f)) if isinstance(f, dict) else None
        if (row and not row.get("cleared_at")
                and alert.same_domain(job, row.get("job") or "")
                and f.get("severity") not in (None, "ok")):
            f = {**f, "ledger": annotation(row, now_ts)}
        out.append(f)
    return out


def open_rows(store, limit=2000):
    """dedupe key -> open ledger row, for annotate()."""
    return {r["key"]: dict(r) for r in store.ledger_rows(open_only=True, limit=limit)}


def audit(store, job_ts=None, now_ts=None, snapshots=None):
    """Findings about the backlog itself, for the scheduler and the dashboard.

    One underlying problem is one finding. When `snapshots` is given and a
    recurring or overdue row's original finding is still listed by its own
    job, the ledger does not restate it at the original's severity (that
    double-counted every unresolved secret on 2026-10-27): it records it as a
    low `restates` note, and the original carries the age and recurrence via
    annotate(). A row whose original is *not* listed -- the collector is
    failing, or the title drifted -- keeps its full severity, so nothing the
    ledger knows about can disappear from view. Without `snapshots` every row
    stands on its own, as before."""
    now_ts = int(now_ts if now_ts is not None else time.time())
    try:
        backfill(store)
        rows = store.ledger_rows(limit=2000)
    except Exception as exc:
        return [_finding("ledger", "medium", "the alert ledger is unreadable",
                         f"{type(exc).__name__}: {exc} — there is no record of "
                         f"what has already been reported", "alert_ledger")]
    if not rows:
        return [_finding(
            "ledger", "ok", "no alerts have been sent yet",
            "the ledger is empty, so there is no backlog — this is only "
            "meaningful once alerting is configured and has run",
            "alert_ledger")]

    states = classify(rows, job_ts=job_ts, now_ts=now_ts)
    listed = _listed_keys(snapshots) if snapshots is not None else {}
    out = []

    def emit(row, severity, title, detail):
        attached = snapshots is not None and _restated(row, listed)
        f = _finding("ledger", "low" if attached else severity, title,
                     detail + (f" Shown on the original {row.get('job')} finding, "
                               f"which keeps its own {severity} severity; this "
                               f"note does not count it twice." if attached else ""),
                     row.get("locus") or "alert_ledger", row.get("host") or LOCAL_HOST)
        # restates: the dedupe key of the finding this note is about, when that
        # finding is listed now. orphan: the original is not listed, so this is
        # the only place the problem is visible and it keeps full severity.
        f["restates"] = row.get("key") if attached else ""
        f["orphan"] = not attached
        out.append(f)

    # Recurring first, and each one individually: a finding that came back is a
    # statement about the fix, not about the finding.
    for row in states["recurring"]:
        emit(row, row.get("worst_sev") or row.get("severity") or "medium",
             f"a resolved alert has come back: {row.get('title')}",
             f"cleared {row.get('clear_count')}× and reported again "
             f"{row.get('reopened')}× since — first seen "
             f"{_phrase_age(row['age_days'])} ago, {row.get('sent_count')} "
             f"emails total. Something is re-establishing this, or the fix did "
             f"not hold. That is a different problem from the original finding."
             + (f" Suggested fix on record: {row.get('fix')}"
                if row.get("fix") else ""))

    for row in states["outstanding"]:
        if not overdue(row, now_ts):
            continue
        limit = OVERDUE_DAYS.get(row.get("severity") or "low")
        emit(row, row.get("severity") or "medium",
             f"unresolved for {_phrase_age(row['age_days'])}: {row.get('title')}",
             f"first mailed {_phrase_age(row['age_days'])} ago and still "
             f"reported; {row.get('sent_count')} emails sent about it. A "
             f"{row.get('severity')} finding is expected to be dealt with "
             f"within {limit} days."
             + (f" Fix on record: {row.get('fix')}" if row.get("fix") else
                " No automatic remediation is on record for it."))

    for row in states["stale"]:
        f = _finding(
            "ledger", "medium",
            f"unverified since it was reported: {row.get('title')}",
            f"the '{row.get('job')}' collector has not produced a result since "
            f"this was mailed {_phrase_age(row['quiet_days'])} ago, so it is "
            f"neither confirmed nor cleared — nobody has looked. Treat it as "
            f"open, not as fixed.",
            row.get("locus") or "alert_ledger", row.get("host") or LOCAL_HOST)
        f["restates"], f["orphan"] = "", True
        out.append(f)

    open_rows_ = states["recurring"] + states["outstanding"] + states["stale"]
    attached = sum(1 for f in out if f.get("restates"))
    if not out:
        out.append(_finding(
            "ledger", "ok", "no overdue alerts",
            f"{len(rows)} alerts on record: {len(states['resolved'])} resolved, "
            f"{len(open_rows_)} still open but none past its severity's "
            f"deadline, none recurring",
            "alert_ledger"))
    else:
        out.append(_finding(
            "ledger", "ok", "alert backlog summary",
            f"{len(rows)} alerts on record — {len(states['outstanding'])} "
            f"outstanding, {len(states['recurring'])} recurring, "
            f"{len(states['stale'])} unverified, {len(states['resolved'])} "
            f"resolved; {attached} overdue or recurring shown on their original "
            f"finding", "alert_ledger"))
    return sort_findings(out)


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["title"]))

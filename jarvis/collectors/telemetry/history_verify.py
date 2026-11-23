"""Daily whole-chain verification of the recorded event history.

Its own bulk-lane job (`history_verify`, interval one day, 300 s budget) and
its own module: bulk jobs must never reach PowerShell, and the ingestion
collector this used to live in (native.py) is a 45 s fast-lane job whose
budget a 75 s verification of 1.5 GiB of history could never meet. The
ingestion collector only reports when verification is overdue.
"""

import time

from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.core.finding import win_finding as _finding

VERIFY_META = "eventlog_verified_at"
VERIFY_EVERY = 86400
VERIFY_ATTEMPT_META = "eventlog_verify_attempt_at"
VERIFY_RETRY = 3600          # an attempt that did not finish waits this long
VERIFY_OVERDUE = 2 * VERIFY_EVERY


def verify_history(store, hosts=("win",), root=None):
    """Re-verify the whole event history. Daily, bulk lane, bounded.

    Records the attempt before reading so a run that the worker deadline
    kills is visible and is not retried every minute: a second attempt waits
    VERIFY_RETRY and is reported meanwhile. History damage is the loudest
    finding here; it is never softened by a timeout."""
    if "win" not in hosts:
        return []
    now = time.time()
    verified = float(store.get_meta(VERIFY_META, 0) or 0)
    attempted = float(store.get_meta(VERIFY_ATTEMPT_META, 0) or 0)
    if attempted > verified and now - attempted < VERIFY_RETRY:
        return [_finding(
            "visibility", "medium", "Event history verification did not finish",
            f"An attempt {int((now - attempted) / 60)} min ago was cut off by its "
            f"time budget; the next one waits {VERIFY_RETRY // 60} min. If this "
            "repeats, the history has outgrown the budget: raise the job's budget "
            "or prune by retention, never by hand.", str(root or DEFAULT_ROOT))]
    store.set_meta(VERIFY_ATTEMPT_META, now)
    store.commit()
    try:
        log = EventLog(root or DEFAULT_ROOT, writer=False)
    except LogError as exc:
        return [_finding("visibility", "medium", "Event history could not be opened for verification",
                         str(exc)[:300], str(root or DEFAULT_ROOT))]
    try:
        result = log.verify()
    finally:
        close = getattr(log, "close", None)
        if callable(close):
            close()
    store.set_meta(VERIFY_META, time.time())
    store.commit()
    if result["ok"]:
        return [_finding(
            "visibility", "ok", "Recorded event history verifies",
            f"{result.get('segments', 0)} sealed segments re-hashed and chained; "
            f"{result.get('unsealed_events', 0)} events not yet sealed.", str(log.root))]
    return [_finding(
        "tampering", "critical", "Recorded event history does not verify",
        "; ".join(result["problems"][:5]) + ". Segments were changed, removed or "
        "reordered outside retention. Preserve the event log directory before "
        "anything else writes to it.", str(log.root))]

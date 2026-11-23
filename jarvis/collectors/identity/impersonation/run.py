"""Running the identity audit, correlated with what the input hook saw."""

from jarvis.core.util import now

from . import rules
from .collect import sample

# How far back to count real input when deciding whether anything typed while
# the workstation was locked. The lock state is a point-in-time reading, so a
# wide window would attribute old, legitimate input to the current lock.
LOCK_WINDOW = 300


def _real_input_since(store, seconds=LOCK_WINDOW):
    """(keys, clicks) of un-flagged input in the recent beats.

    Beats carry the helper's lifetime counters, not per-interval deltas, so
    rows are differenced in time order: each step contributes its increase,
    and a counter reset (helper restart) contributes the post-reset value.
    Summing raw rows would multiply one idle total into a phantom burst —
    e.g. five frozen rows of 3174 keys read as 15870 keystrokes.
    """
    if store is None:
        return 0, 0, "the last sample"
    try:
        rows = store.db.execute(
            "SELECT real_keys, real_clicks FROM input_beats WHERE ts >= ? ORDER BY ts",
            (now() - seconds,)).fetchall()
    except Exception:
        return 0, 0, "the last sample"
    keys = clicks = 0
    prev_k = prev_c = None
    for r in rows:
        try:
            k, c = int(r["real_keys"] or 0), int(r["real_clicks"] or 0)
        except (TypeError, ValueError):
            continue
        if prev_k is None:
            prev_k, prev_c = k, c
            continue
        keys += k - prev_k if k >= prev_k else k
        clicks += c - prev_c if c >= prev_c else c
        prev_k, prev_c = k, c
    return max(0, keys), max(0, clicks), "the last %d minutes" % (seconds // 60)


def audit(store=None, hosts=("wsl", "win")):
    if "win" not in hosts:
        return []
    keys, clicks, label = _real_input_since(store)
    data = sample()
    out = rules.audit_data(data, keys, clicks, label)
    return sort_findings(out)


def sort_findings(findings):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
    return sorted(findings, key=lambda f: (order.get(f["severity"], 9),
                                           f["title"]))

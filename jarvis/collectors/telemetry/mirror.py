"""Mirror the authoritative event history into the independent Rust store.

The Python event log stays the one source of truth. The Rust store is a
second, separately verified copy: if the two ever disagree, or the copy stops
verifying, that is evidence about the history itself. This job advances the
copy in bounded batches and records a health-safe summary for /api/health,
so HTTP requests never pay for store verification.
"""

import json

from jarvis.core import runtime
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.core.finding import finding

META = "rust_mirror_v1"
# Rust verification failures that mean stored bytes or links changed, as
# opposed to an operational failure (missing binary, timeout, lock).
_INTEGRITY_MARKERS = ("altered", "does not link", "not contiguous",
                      "disagrees", "pruning marker", "does not match",
                      "no header", "invalid chain header",
                      "invalid segment header", "unreadable segment")


def _integrity_failure(state):
    detail = str(state.get("detail") or "").lower()
    return any(marker in detail for marker in _INTEGRITY_MARKERS)


def findings(state):
    """Findings for one mirror summary. Pure."""
    if state.get("ok"):
        if state.get("gap_events"):
            return [finding(
                "visibility", "medium",
                "Evidence mirror skipped events removed by retention",
                f"{state['gap_events']} events left the authoritative history "
                "before the Rust mirror copied them; that range exists in "
                "neither store.", state.get("root", ""))]
        return []
    if state.get("error") == "binary_absent":
        return [finding(
            "visibility", "low", "Rust evidence mirror is not built",
            "The independent event-history copy is inactive. Build it with "
            "`cargo build --release` in rust-runtime/.", "rust-runtime")]
    if state.get("error") == "cursor_regressed":
        return [finding(
            "tampering", "high", "Rust evidence mirror lost history",
            f"{state.get('detail')}. The store was deleted, replaced or rolled "
            "back since the last run; mirroring is paused so nothing overwrites "
            "it. Preserve the directory. To start a new mirror afterwards, move "
            "it aside and delete the rust_mirror_v1 meta row.",
            state.get("root", ""))]
    if _integrity_failure(state):
        return [finding(
            "tampering", "high", "Rust evidence mirror does not verify",
            f"{state.get('detail')}. The independent copy of the event history "
            "changed outside its writer. Preserve the store directory before "
            "anything else writes to it.", state.get("root", ""))]
    return [finding(
        "visibility", "medium", "Rust evidence mirror is not advancing",
        f"{state.get('error')}: {state.get('detail') or 'no detail'}",
        state.get("root", ""))]


def audit(store, hosts=None, root=DEFAULT_ROOT, mirror_root=None):
    previous = summary(store) or {}
    # The highest cursor ever recorded survives failed runs, so one failure
    # cannot erase the reference a regression is measured against.
    expected = max((c for c in (previous.get("cursor"),
                                previous.get("expected_cursor"))
                    if type(c) is int), default=None)
    try:
        with EventLog(root) as log:
            state = runtime.mirror(log, root=mirror_root,
                                   expected_cursor=expected)
    except (LogError, OSError) as exc:
        state = {"ok": False, "runtime": "rust", "error": "source_unreadable",
                 "detail": type(exc).__name__}
    if expected is not None and not (type(state.get("cursor")) is int
                                     and state["cursor"] >= expected):
        state["expected_cursor"] = expected
    store.set_meta(META, json.dumps(state, sort_keys=True))
    store.commit()
    return findings(state)


def summary(store):
    """Last recorded mirror state for health, or None."""
    try:
        state = json.loads(store.get_meta(META) or "null")
    except (TypeError, ValueError):
        return None
    return state if isinstance(state, dict) else None

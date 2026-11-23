"""JARVIS Runtime bridge: hot-path prototype in Rust, intelligence in Python.

Phase 4: the Python engine calls the optional binary for live metrics,
governance, and durable append/verification of an independent Rust segment
store. The established Python event log remains authoritative; there is no
unsafe claim that two separately committed stores form one atomic journal.
Python also owns policies, incidents, reasoning and models.

The binary is optional: when absent (dev checkout, unbuilt tree) every
helper falls back to the pure-Python path and reports
`{"runtime": "python"}` so no caller can mistake the fallback for the
measured Rust path.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import time
from pathlib import Path

_RUNTIME_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "rust-runtime" / "target" / "release" / "jarvis-runtime",
    Path(__file__).resolve().parents[2] / "rust-runtime" / "target" / "debug" / "jarvis-runtime",
)
DEFAULT_STORE = Path(os.path.expanduser("~/.jarvis/rust-eventlog"))
# Store work is O(retained store): ingest fully re-verifies every retained
# segment first. Measured 0.3s per 5,000 real events (1.8 MB compressed), so
# the budget keeps one ingest well inside STORE_TIMEOUT_S and the job's
# 120s reliability budget.
STORE_TIMEOUT_S = 90
MIRROR_BATCH_EVENTS = 20_000
MIRROR_BATCH_BYTES = 24 * 1024 * 1024
MIRROR_BUDGET_BYTES = 128 * 1024 * 1024


def binary():
    for path in _RUNTIME_CANDIDATES:
        try:
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)
        except OSError:
            continue
    return None


def available():
    return binary() is not None


def _invoke(*args):
    """Run one bounded CLI probe and return (stdout, failure_kind)."""
    path = binary()
    if path is None:
        return None, "binary_absent"
    try:
        out = subprocess.run(
            [path, *args], capture_output=True, text=True, errors="replace",
            timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, "execution_failed"
    if out.returncode != 0:
        return None, "nonzero_exit"
    stdout = out.stdout or ""
    if len(stdout) > 64 * 1024:
        return None, "oversized_output"
    return stdout, None


def metrics():
    """Live host-pressure metrics. Prefers the Rust probe; falls back pure."""
    stdout, rust_error = _invoke("metrics")
    if stdout is not None:
        try:
            data = json.loads(stdout)
            cpu = data.get("cpu_pct")
            mem = data.get("mem_available_pct")
            reason = data.get("reason")
            valid_numbers = (
                isinstance(cpu, (int, float)) and not isinstance(cpu, bool)
                and math.isfinite(cpu) and cpu >= 0
                and isinstance(mem, (int, float)) and not isinstance(mem, bool)
                and math.isfinite(mem) and 0 <= mem <= 100
            )
            if (isinstance(data, dict)
                    and type(data.get("pressured")) is bool
                    and isinstance(reason, str) and reason
                    and valid_numbers):
                return {"runtime": "rust", "cpu_pct": cpu,
                        "mem_available_pct": mem,
                        "pressured": data["pressured"], "reason": reason}
            rust_error = "invalid_output"
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
            rust_error = "invalid_output"
    try:
        from jarvis.core import governor as governor_mod
        pressured, reason = governor_mod.live_pressure()
        return {"runtime": "python", "pressured": pressured,
                "reason": reason, "rust_status": rust_error}
    except Exception:
        return {"runtime": "python", "pressured": False,
                "reason": "metrics unavailable; all tiers permitted",
                "rust_status": rust_error}


def should_defer(job_name, pressured):
    """Governance decision; identical contract in Rust and Python."""
    stdout, rust_error = _invoke(
        "defer", str(job_name), "true" if pressured else "false")
    if stdout is not None:
        value = stdout.strip().lower()
        if value in ("true", "false"):
            return {"runtime": "rust", "defer": value == "true"}
        rust_error = "invalid_output"
    try:
        from jarvis.core import governor as governor_mod
        return {"runtime": "python",
                "defer": governor_mod.should_defer(job_name, pressured),
                "rust_status": rust_error}
    except Exception:
        return {"runtime": "python", "defer": False,
                "rust_status": rust_error}


def persist(events, root=None):
    """Durably append canonical events to the verified Rust segment store."""
    path = binary()
    if path is None:
        return {"ok": False, "runtime": "python", "error": "binary_absent"}
    events = list(events)
    if len(events) > 20_000 or any(not isinstance(event, dict)
                                   for event in events):
        return {"ok": False, "runtime": "rust", "error": "invalid_events"}
    try:
        body = "".join(json.dumps(event, separators=(",", ":")) + "\n"
                       for event in events)
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_events"}
    store = Path(root or DEFAULT_STORE)
    try:
        out = subprocess.run(
            [path, "ingest", str(store)], input=body, capture_output=True,
            text=True, errors="replace", timeout=STORE_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "runtime": "rust", "error": "execution_failed"}
    if len(out.stdout or "") > 4 * 1024 * 1024:
        return {"ok": False, "runtime": "rust", "error": "oversized_output"}
    try:
        rows = [json.loads(line) for line in (out.stdout or "").splitlines()]
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    if out.returncode != 0:
        # Ingest is all-or-nothing: a rejected event leaves the store as it
        # was. Surface the reason; never treat a partial reply as progress.
        last = rows[-1] if rows and isinstance(rows[-1], dict) else {}
        if last.get("ok") is False:
            return {"ok": False, "runtime": "rust", "error": "rejected",
                    "detail": str(last.get("error") or "")[:200],
                    "rejected_index": len(rows) - 1}
        return {"ok": False, "runtime": "rust", "error": "ingest_failed",
                "detail": (out.stderr or "").strip()[:200]}
    if len(rows) != len(events) + 1 \
            or any(row.get("ok") is not True for row in rows) \
            or rows[-1].get("persisted") is not True:
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    return {"runtime": "rust", **rows[-1], "events": len(events),
            "root": str(store)}


def verify_store(root=None):
    """Verify every durable Rust segment and return its measured chain head."""
    path = binary()
    if path is None:
        return {"ok": False, "runtime": "python", "error": "binary_absent"}
    store = Path(root or DEFAULT_STORE)
    if not store.is_dir():
        return {"ok": False, "runtime": "rust", "error": "store_absent",
                "root": str(store)}
    try:
        out = subprocess.run(
            [path, "verify", str(store)], capture_output=True, text=True,
            errors="replace", timeout=STORE_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "runtime": "rust", "error": "execution_failed"}
    if out.returncode != 0 or len(out.stdout or "") > 64 * 1024:
        return {"ok": False, "runtime": "rust", "error": "verify_failed",
                "detail": (out.stderr or "").strip()[:200]}
    try:
        result = json.loads(out.stdout)
    except (TypeError, ValueError):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    if (not isinstance(result, dict) or result.get("ok") is not True
            or not isinstance(result.get("segments"), int)
            or not isinstance(result.get("last_seq"), int)):
        return {"ok": False, "runtime": "rust", "error": "invalid_output"}
    return {"runtime": "rust", **result, "root": str(store)}


def _store_call(*args):
    """Run one bounded store subcommand whose reply is a JSON object."""
    path = binary()
    if path is None:
        return None, "binary_absent"
    try:
        out = subprocess.run(
            [path, *args], capture_output=True, text=True, errors="replace",
            timeout=STORE_TIMEOUT_S, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, "execution_failed"
    if out.returncode != 0 or len(out.stdout or "") > 64 * 1024:
        return None, (out.stderr or "").strip()[:200] or "nonzero_exit"
    try:
        data = json.loads(out.stdout)
    except (TypeError, ValueError):
        return None, "invalid_output"
    if not isinstance(data, dict) or data.get("ok") is not True:
        return None, "invalid_output"
    return data, None


def _cursor_value(value):
    return value if type(value) is int and value >= 0 else None


def store_bytes(root=None):
    """Bytes the Rust store occupies on disk (0 when absent)."""
    total = 0
    for directory, _dirs, files in os.walk(Path(root or DEFAULT_STORE)):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(directory, name))
            except OSError:
                continue
    return total


def mirror(log, root=None, max_events=MIRROR_BATCH_EVENTS,
           max_bytes=MIRROR_BATCH_BYTES, budget=MIRROR_BUDGET_BYTES,
           expected_cursor=None):
    """Copy the next authoritative events into the independent Rust store.

    The Python event log stays authoritative. Each mirrored event carries its
    log sequence as `source_seq`; the Rust store rejects any batch that does
    not advance it, so the durable store is its own cursor and a crash can
    neither skip nor duplicate events. Events that retention removed from
    the authoritative log before they were mirrored are counted as a gap,
    never silently bridged. `expected_cursor` is the last cursor this
    machine recorded: a store behind it lost history (deleted, replaced or
    rolled back), and rebuilding over it would erase that evidence, so
    nothing is written. Returns a health-safe summary; never raises.
    """
    started = time.time()
    store = Path(root or DEFAULT_STORE)
    summary = {"runtime": "rust", "at": int(started), "root": str(store),
               "mirrored": 0, "gap_events": 0}
    if binary() is None:
        return dict(summary, ok=False, runtime="python", error="binary_absent")
    peek, why = _store_call("cursor", str(store))
    if peek is None:
        return dict(summary, ok=False, error="cursor_failed", detail=why)
    cursor = _cursor_value(peek.get("last_source_seq"))
    if peek.get("last_source_seq") is not None and cursor is None:
        return dict(summary, ok=False, error="invalid_output")
    if type(expected_cursor) is int and (cursor or 0) < expected_cursor:
        return dict(summary, ok=False, error="cursor_regressed",
                    detail=f"store cursor {cursor} is behind recorded "
                           f"cursor {expected_cursor}",
                    cursor=cursor, expected_cursor=expected_cursor)
    batch, size = [], 0
    try:
        for event in log.iter_events(after=cursor or 0):
            line = len(json.dumps(event, separators=(",", ":")))
            if batch and (len(batch) >= max_events or size + line > max_bytes):
                break
            batch.append(dict(event, source_seq=event["seq"]))
            size += line
    except Exception as exc:     # a corrupt authoritative log is not ours to mask
        return dict(summary, ok=False, error="source_unreadable",
                    detail=type(exc).__name__)
    if cursor is not None and batch and batch[0]["source_seq"] > cursor + 1:
        summary["gap_events"] = batch[0]["source_seq"] - cursor - 1
    if batch:
        written = persist(batch, root=store)
        if written.get("ok") is False:
            return dict(summary, ok=False,
                        error=written.get("error", "ingest_failed"),
                        detail=written.get("detail", ""),
                        cursor=cursor)
        summary["mirrored"] = len(batch)
        cursor = batch[-1]["source_seq"]
    else:
        # Nothing to append, so no ingest re-verified the store this run.
        verified = verify_store(root=store)
        if verified.get("ok") is False and verified.get("error") != "store_absent":
            return dict(summary, ok=False,
                        error=verified.get("error", "verify_failed"),
                        detail=verified.get("detail", ""), cursor=cursor)
    summary["cursor"] = cursor
    try:
        summary["behind"] = max(0, int(log.stats()["last_seq"]) - int(cursor or 0))
    except Exception:
        summary["behind"] = None
    occupied = store_bytes(store)
    if occupied > budget:
        pruned, why = _store_call("prune", str(store), str(int(budget)))
        if pruned is None:
            return dict(summary, ok=False, error="prune_failed", detail=why)
        summary["pruned_segments"] = pruned.get("removed_segments")
        occupied = store_bytes(store)
    summary.update(ok=True, store_bytes=occupied, budget_bytes=budget,
                   elapsed_s=round(time.time() - started, 2))
    return summary


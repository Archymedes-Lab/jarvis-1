"""Reconcile point-in-time process state with the native temporal history.

The event stream and snapshots fail differently. Sysmon can miss records when
its log wraps or its sensor is stopped; a snapshot can miss a process that
starts and exits between scans. Comparing them turns those blind spots into
evidence about JARVIS's own perception.

This module is deliberately conservative. It only judges Windows process
instances with an exact creation time, after the stream's last continuous
coverage boundary, and only when a fresh complete Sysmon cursor has already
advanced past that creation. Processes that predate coverage or are still in
the ingestion settling window are unknown, not discrepancies.
"""

import re
from datetime import datetime, timezone

from jarvis.core import perception as perception_mod
from jarvis.core.eventlog import DEFAULT_ROOT, EventLog, LogError
from jarvis.platform.native.normalize import SYSMON

FRESH_SECONDS = 180
SETTLE_SECONDS = 10
START_TOLERANCE_SECONDS = 2
_BOOT_EVIDENCE = {}
_BOOT_CACHE_LIMIT = 16
# Kernel-created processes that never pass through a process-create
# notification, so Sysmon cannot log their start. Measured on this host:
# 54,218 ProcessCreate events over six boots and 25 WSL VM launches, none of
# them for these names (smss.exe does appear and so stays judged). Minimal
# processes have no image file; a user-mode process always has one, so the
# empty-image requirement keeps a same-named impostor judged.
KERNEL_IMAGELESS = frozenset({"system", "secure system", "registry",
                              "memory compression", "vmmem", "vmmemwsl"})
# Created during kernel initialisation and alive until shutdown: no process
# of this boot can have started before the earliest of them.
KERNEL_LIFETIME = frozenset({"system", "secure system", "registry"})


def _stamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (ValueError, OverflowError):
        return None


def _same_start(left, right):
    a, b = _stamp(left), _stamp(right)
    return a is not None and b is not None and abs(a - b) <= START_TOLERANCE_SECONDS


def _kernel_imageless(proc):
    name = str(proc.get("name") or "").strip().lower()
    return name in KERNEL_IMAGELESS and not proc.get("exe")


def boot_floor(snapshot):
    """Earliest creation time of this boot's kernel-lifetime processes.

    The sensor labels records with the boot current when it reads them, so
    the unread tail of the previous boot's shutdown arrives labelled as the
    new boot. Nothing from this boot predates its kernel processes, so
    records older than this floor belong to the previous boot. None when the
    snapshot does not show those processes; continuity is then unchanged.
    """
    stamps = [_stamp(p.get("started")) for p in snapshot or ()
              if p.get("host") == "win" and not p.get("exe")
              and str(p.get("name") or "").strip().lower() in KERNEL_LIFETIME]
    stamps = [s for s in stamps if s is not None]
    return min(stamps) if stamps else None


def _boot_key(log, cursor, floor):
    return (str(log.root), cursor.get("host"), cursor.get("boot"),
            cursor.get("generation"), floor)


def _boot_boundary(log, cursor, continuous, floor=None):
    """Clamp legacy continuity to the first retained event in this boot.

    Older cursors carried continuity across reboot, and a new boot's first
    batch carries the previous boot's unread shutdown tail; `floor` drops
    that tail. It can only move the boundary later, so processes it affects
    become unknown, never verified. Cache the one-time replay by
    store/host/boot/generation so the 30-second process scan does not turn
    into repeated event-log IO.
    """
    boot = cursor.get("boot")
    if not boot:
        return continuous
    key = _boot_key(log, cursor, floor)
    if key in _BOOT_EVIDENCE:
        return max(continuous, _BOOT_EVIDENCE[key]["boundary"])
    boundary = None
    dropped_process_create = 0
    for event in log.iter_events(since=cursor.get("continuous_since")):
        if (event.get("host") != cursor.get("host")
                or event.get("boot") != boot
                or event.get("channel") != SYSMON):
            continue
        stamp = _stamp(event.get("time"))
        if floor is not None and stamp is not None and stamp < floor:
            continue
        if event.get("category") == "process" and event.get("action") == "start":
            if stamp is not None and (boundary is None or stamp < boundary):
                boundary = stamp
        if event.get("source_event") == 255:
            description = str((event.get("attrs") or {}).get("Description") or "")
            dropped = re.search(r"(?i)\bProcessCreate:(\d+)\b", description)
            if dropped:
                dropped_process_create += int(dropped.group(1))
    if boundary is not None:
        if len(_BOOT_EVIDENCE) >= _BOOT_CACHE_LIMIT:
            _BOOT_EVIDENCE.pop(next(iter(_BOOT_EVIDENCE)))
        _BOOT_EVIDENCE[key] = {
            "boundary": boundary,
            "dropped_process_create": dropped_process_create,
        }
        return max(continuous, boundary)
    return continuous


def _boot_dropped_process_create(log, cursor, floor=None):
    continuous = _stamp(cursor.get("continuous_since")) or 0.0
    _boot_boundary(log, cursor, continuous, floor)
    key = _boot_key(log, cursor, floor)
    return int((_BOOT_EVIDENCE.get(key) or {}).get("dropped_process_create") or 0)


def coverage_evidence(observed_at, root=DEFAULT_ROOT, snapshot=None):
    """Return health-safe process-stream coverage evidence for this boot.

    This deliberately exposes counts and boundaries, never raw events. An
    unavailable or stale cursor remains explicit rather than looking like
    zero loss.
    """
    observed_at = _stamp(observed_at)
    if observed_at is None:
        return {"status": "unknown"}
    try:
        with EventLog(root) as log:
            floor = boot_floor(snapshot)
            stream = _cursor(log, observed_at, floor)
            if stream is None:
                return {"status": "unknown"}
            cursor, cursor_at, continuous_since = stream
            return {
                "status": "observed",
                "boot": cursor.get("boot"),
                "cursor_at": cursor_at,
                "continuous_since": continuous_since,
                "dropped_process_create": _boot_dropped_process_create(
                    log, cursor, floor),
            }
    except (LogError, OSError):
        return {"status": "unknown"}


def _cursor(log, observed_at, floor=None):
    candidates = [c for c in log.cursors.values()
                  if c.get("channel") == SYSMON and c.get("status") == "complete"
                  and not c.get("gap") and c.get("host")]
    if not candidates:
        return None
    cursor = max(candidates, key=lambda c: float(c.get("at") or 0))
    created = _stamp(cursor.get("created_at"))
    continuous = _stamp(cursor.get("continuous_since"))
    if created is None or continuous is None:
        return None
    # A stale stream cannot contradict a current snapshot. The native health
    # collector owns the outage finding; avoiding a second one here also keeps
    # existing incidents unobserved rather than spuriously replaced.
    if observed_at - created > FRESH_SECONDS or created - observed_at > FRESH_SECONDS:
        return None
    if floor is not None and floor > created:
        floor = None    # a boot that starts after the cursor is a bad clock
    return cursor, created, _boot_boundary(log, cursor, continuous, floor)


def classify_snapshot(snapshot, observed_at, root=DEFAULT_ROOT):
    """Per-process perception verdicts: OBSERVED/INFERRED/RECONCILED/UNOBSERVED.

    Pure read path shared by findings and UX. Every snapshot row gets one
    verdict with confidence, source, freshness and corroboration; only
    RECONCILED rows may be presented as VERIFIED. Rows the stream cannot
    judge (pre-coverage, settling, stale/gapped) are UNOBSERVED/UNKNOWN,
    never false discrepancies.
    """
    observed_at = _stamp(observed_at)
    if observed_at is None:
        return []
    try:
        with EventLog(root) as log:
            stream = _cursor(log, observed_at, boot_floor(snapshot))
            if stream is None:
                return [
                    {"pid": p.get("pid"), "name": p.get("name"),
                     **perception_mod.classify(
                         event_present=False, snapshot_present=True,
                         coverage_valid=False)}
                    for p in snapshot if p.get("host") == "win" and p.get("pid")
                ]
            cursor, cursor_at, continuous_since = stream
            verdicts = []
            for proc in snapshot:
                if proc.get("host") != "win" or not proc.get("pid"):
                    continue
                started = _stamp(proc.get("started"))
                if (started is None or started < continuous_since
                        or _kernel_imageless(proc)):
                    verdicts.append({
                        "pid": proc.get("pid"), "name": proc.get("name"),
                        **perception_mod.classify(
                            event_present=False, snapshot_present=True,
                            coverage_valid=False)})
                    continue
                if started > cursor_at - SETTLE_SECONDS:
                    verdicts.append({
                        "pid": proc.get("pid"), "name": proc.get("name"),
                        **perception_mod.classify(
                            event_present=False, snapshot_present=True,
                            coverage_valid=False)})
                    continue
                rows = log.process_instances(cursor["host"], proc["pid"])
                instance = next(
                    (r for r in rows
                     if _same_start(r.get("started"), proc["started"])), None)
                if instance is None:
                    verdicts.append({
                        "pid": proc.get("pid"), "name": proc.get("name"),
                        **perception_mod.classify(
                            event_present=False, snapshot_present=True,
                            coverage_valid=True)})
                    continue
                ended = _stamp(instance.get("ended"))
                snapshot_at = _stamp(proc.get("observed_at")) or observed_at
                if ended is not None and ended <= snapshot_at - SETTLE_SECONDS:
                    verdicts.append({
                        "pid": proc.get("pid"), "name": proc.get("name"),
                        **perception_mod.classify(
                            event_present=True, snapshot_present=True,
                            identity_match=False, coverage_valid=True)})
                    continue
                verdicts.append({
                    "pid": proc.get("pid"), "name": proc.get("name"),
                    **perception_mod.classify(
                        event_present=True, snapshot_present=True,
                        identity_match=True, coverage_valid=True)})
            return verdicts
    except (LogError, OSError):
        return []


def processes(snapshot, observed_at, root=DEFAULT_ROOT, policy=None,
              dropped_process_create=False):
    """Return visibility findings for snapshot/event-state contradictions."""
    observed_at = _stamp(observed_at)
    if observed_at is None:
        return []
    try:
        with EventLog(root) as log:
            stream = _cursor(log, observed_at, boot_floor(snapshot))
            if stream is None:
                return []
            cursor, cursor_at, continuous_since = stream
            dropped_in_boot = _boot_dropped_process_create(log, cursor)
            findings = []
            for proc in snapshot:
                if proc.get("host") != "win" or not proc.get("pid"):
                    continue
                started = _stamp(proc.get("started"))
                snapshot_at = _stamp(proc.get("observed_at")) or observed_at
                if (started is None or started < continuous_since
                        or _kernel_imageless(proc)):
                    continue
                # The committed native cursor must be newer than the start by
                # enough for Event Log publication and ingestion to settle.
                if started > cursor_at - SETTLE_SECONDS:
                    continue
                rows = log.process_instances(cursor["host"], proc["pid"])
                instance = next((r for r in rows if _same_start(r.get("started"), proc["started"])), None)
                subject = (f"{cursor.get('device') or cursor['host']}:"
                           f"{cursor.get('boot') or 'unknown'}:{proc['pid']}:{proc['started']}")
                if instance is None:
                    from jarvis.collectors.telemetry import sysmon_policy
                    drops = dropped_process_create or dropped_in_boot
                    cause = sysmon_policy.gap_cause(
                        policy, dropped_process_create=drops, process=proc)
                    findings.append({
                        "category": "visibility", "severity": "high", "host": "win",
                        "rule_id": "temporal-process-start-missing", "subject_id": subject,
                        "title": f"{proc.get('name') or 'process'} exists without a start event",
                        "detail": ("The current process snapshot contains this exact execution, but the "
                                   "continuous native Sysmon stream has no matching ProcessGuid start. "
                                   "This can indicate an event-log gap, excluded telemetry, sensor "
                                   "tampering, or a process hidden from the event path. "
                                   f"Policy attribution: {cause}."),
                        "where": proc.get("exe") or f"pid {proc['pid']}",
                    })
                    continue
                ended = _stamp(instance.get("ended"))
                if ended is not None and ended <= snapshot_at - SETTLE_SECONDS:
                    findings.append({
                        "category": "visibility", "severity": "high", "host": "win",
                        "rule_id": "temporal-process-exit-conflict", "subject_id": subject,
                        "title": f"{proc.get('name') or 'process'} exists after its recorded exit",
                        "detail": ("The snapshot still contains this exact process instance after the "
                                   "temporal stream recorded its termination. The snapshot or event "
                                   "state is inconsistent and must not be treated as verified reality."),
                        "where": proc.get("exe") or f"pid {proc['pid']}",
                    })
            return findings
    except (LogError, OSError):
        return []

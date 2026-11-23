"""Cross-view process presence: confidence, not a boolean.

No single user-mode enumeration API is trusted as absolute truth. JARVIS
maintains independent views and reconciles them per process instance:

  VIEW A  native process-creation callbacks (future JarvisKernel.sys)
  VIEW B  ETW process/thread events (native sensor channel)
  VIEW C  Sysmon ProcessCreate history (event log, policy-aware)
  VIEW D  current process snapshot (one authoritative read, many consumers)
  VIEW E  thread / module observations (hidden.ps1 threadOwners, memscan)
  VIEW F  resource activity attribution (cpu / network owners)

Identity is (boot_id, pid, start event or guid); a bare pid is never an
instance key because Windows reuses pids. Missing evidence stays unknown:
when coverage cannot contradict the snapshot, absence proves nothing.

Pure, bounded, no IO, no clocks, no model calls.
"""

from dataclasses import dataclass, field

VIEWS = ("kernel_create", "kernel_exit", "etw_start", "etw_stop",
         "sysmon_create", "snapshot", "thread_activity", "image_activity",
         "cpu_activity", "network_activity")


@dataclass
class ProcessPresence:
    """One process instance across independent views. Booleans only."""
    boot_id: str = ""
    pid: int = 0
    guid: str = ""
    started: str = ""
    kernel_create_seen: bool = False
    kernel_exit_seen: bool = False
    etw_start_seen: bool = False
    etw_stop_seen: bool = False
    sysmon_create_seen: bool = False
    snapshot_seen: bool = False
    thread_activity_seen: bool = False
    image_activity_seen: bool = False
    cpu_activity_seen: bool = False
    network_activity_seen: bool = False
    first_seen: str = ""
    last_seen: str = ""
    extra: dict = field(default_factory=dict)

    def key(self):
        """Instance key that survives pid reuse. Never a bare pid."""
        if self.guid:
            return f"guid:{self.guid}"
        stamp = self.started or "unknown-start"
        return f"boot:{self.boot_id}:pid:{self.pid}:{stamp}"

    def corroboration(self):
        """How many independent creation/snapshot/activity sources agree."""
        return sum((
            self.kernel_create_seen, self.etw_start_seen,
            self.sysmon_create_seen, self.snapshot_seen,
            self.thread_activity_seen, self.image_activity_seen,
        ))


def visibility_confidence(presence):
    """0.0-1.0 visibility confidence. Proportional, conservative at edges.

    Only complete independent observations earn credit; a mapping gap
    (source not reporting at all) scores like blindness for that source.
    Exit observations reduce liveness confidence but do not erase history.
    """
    present = sum((
        presence.kernel_create_seen, presence.etw_start_seen,
        presence.sysmon_create_seen, presence.snapshot_seen,
        presence.thread_activity_seen, presence.image_activity_seen,
    ))
    score = present / 6.0
    if presence.kernel_exit_seen or presence.etw_stop_seen:
        # An exit record means "was running", not "is running".
        score = min(score, 0.6)
        if not presence.snapshot_seen and not presence.thread_activity_seen \
                and not presence.cpu_activity_seen \
                and not presence.network_activity_seen:
            score = min(score, 0.3)
    return round(score, 3)


def reconcile(presence, coverage_valid=True, sysmon_policy="full"):
    """Reconcile one instance into a verdict. Pure.

    `coverage_valid` means the event stream was in a position to
    contradict the snapshot (fresh, continuous coverage predates the
    start, settling window passed). When False, absence proves nothing.
    `sysmon_policy` is one of full/filtered/missing/unknown from
    collectors.telemetry.sysmon_policy; it explains gaps, never hides them.

    Returns {verdict, label, severity, confidence, reasons, sources}.
    Verdicts: VERIFIED_PROCESS, VERIFIED_EXIT, CROSS_VIEW_MISMATCH,
    UNEXPLAINED_PROCESS, EXITED, UNKNOWN.
    """
    p = presence
    confidence = visibility_confidence(p)
    exited = bool(p.kernel_exit_seen or p.etw_stop_seen)
    created = bool(p.kernel_create_seen or p.etw_start_seen
                   or p.sysmon_create_seen)
    active = bool(p.thread_activity_seen or p.image_activity_seen
                  or p.cpu_activity_seen or p.network_activity_seen)

    # An exit observation and a later-looking active view cannot establish
    # either a live process or a clean exit without a continuous, settled
    # window. Keep the contradiction factual; source ordering may be delayed.
    if exited and (p.snapshot_seen or active):
        if not coverage_valid:
            return {
                "verdict": "UNKNOWN", "label": "UNKNOWN",
                "severity": "low", "confidence": 0.2,
                "reasons": ["exit and active views disagree, but coverage is "
                            "stale, gapped or unsettled"],
                "sources": _sources(p), "key": p.key(),
            }
        return {
            "verdict": "CROSS_VIEW_MISMATCH", "label": "UNRECONCILED",
            "severity": "high", "confidence": confidence,
            "reasons": ["exit recorded while snapshot or execution activity "
                        "still resolves to this instance; verify event ordering"],
            "sources": _sources(p), "key": p.key(),
        }

    # -- verified live process -------------------------------------------
    if created and p.snapshot_seen and active:
        return {
            "verdict": "VERIFIED_PROCESS",
            "label": "VERIFIED",
            "severity": "ok",
            "confidence": max(confidence, 0.85),
            "reasons": ["creation record, snapshot and activity agree"],
            "sources": _sources(p),
            "key": p.key(),
        }
    if created and p.snapshot_seen and not active:
        return {
            "verdict": "VERIFIED_PROCESS",
            "label": "VERIFIED",
            "severity": "ok",
            "confidence": max(confidence, 0.75),
            "reasons": ["creation record and snapshot agree; "
                        "no thread/cpu/network activity sampled"],
            "sources": _sources(p),
            "key": p.key(),
        }
    # -- clean exit -------------------------------------------------------
    if exited and not p.snapshot_seen and not active:
        return {
            "verdict": "VERIFIED_EXIT",
            "label": "VERIFIED",
            "severity": "ok",
            "confidence": 0.8,
            "reasons": ["exit recorded and no snapshot or activity remains"],
            "sources": _sources(p),
            "key": p.key(),
        }
    # -- the interesting mismatches --------------------------------------
    if created and not p.snapshot_seen and active:
        if not coverage_valid:
            return {
                "verdict": "UNKNOWN", "label": "UNKNOWN",
                "severity": "low", "confidence": 0.2,
                "reasons": ["creation and activity observed without snapshot, "
                            "but coverage is stale, gapped or unsettled"],
                "sources": _sources(p), "key": p.key(),
            }
        return {
            "verdict": "CROSS_VIEW_MISMATCH",
            "label": "UNRECONCILED",
            "severity": "high",
            "confidence": 0.8,
            "reasons": ["creation recorded but process absent from "
                        "snapshot while threads/images/cpu/network "
                        "still attribute activity to it"],
            "sources": _sources(p),
            "key": p.key(),
        }
    if created and not p.snapshot_seen and not active:
        if not coverage_valid:
            return {
                "verdict": "UNKNOWN",
                "label": "UNKNOWN",
                "severity": "low",
                "confidence": 0.2,
                "reasons": ["creation recorded without snapshot but the "
                            "stream cannot contradict the snapshot "
                            "(stale, gapped, pre-coverage or settling)"],
                "sources": _sources(p),
                "key": p.key(),
            }
        return {
            "verdict": "EXITED",
            "label": "UNRECONCILED",
            "severity": "low",
            "confidence": 0.5,
            "reasons": ["creation recorded, snapshot absent, no residual "
                        "activity: exited between scans or snapshot missed it"],
            "sources": _sources(p),
            "key": p.key(),
        }
    if p.snapshot_seen and not created:
        if not coverage_valid:
            return {
                "verdict": "UNKNOWN",
                "label": "UNKNOWN",
                "severity": "low",
                "confidence": 0.2,
                "reasons": ["snapshot present but stream cannot contradict it"],
                "sources": _sources(p),
                "key": p.key(),
            }
        cause = _gap_cause(sysmon_policy)
        return {
            "verdict": "UNEXPLAINED_PROCESS",
            "label": "UNRECONCILED",
            "severity": "high" if p.image_activity_seen else "medium",
            "confidence": 0.75,
            "reasons": ["snapshot present with no matching creation record "
                        f"under continuous coverage: {cause}"],
            "sources": _sources(p),
            "key": p.key(),
        }
    return {
        "verdict": "UNKNOWN",
        "label": "UNKNOWN",
        "severity": "low",
        "confidence": 0.0,
        "reasons": ["no evidence from any source"],
        "sources": _sources(p),
        "key": p.key(),
    }


def _sources(presence):
    out = []
    for name in ("kernel_create", "kernel_exit", "etw_start", "etw_stop",
                 "sysmon_create", "snapshot", "thread_activity",
                 "image_activity", "cpu_activity", "network_activity"):
        attr = {"kernel_create": "kernel_create_seen",
                "kernel_exit": "kernel_exit_seen",
                "etw_start": "etw_start_seen",
                "etw_stop": "etw_stop_seen",
                "sysmon_create": "sysmon_create_seen",
                "snapshot": "snapshot_seen",
                "thread_activity": "thread_activity_seen",
                "image_activity": "image_activity_seen",
                "cpu_activity": "cpu_activity_seen",
                "network_activity": "network_activity_seen"}[name]
        if getattr(presence, attr):
            out.append(name)
    return out


def _gap_cause(sysmon_policy):
    return {
        "full": "policy records all ProcessCreate; suspect log wrap, "
                "sensor stop, or tampering rather than filtering",
        "filtered": "likely Sysmon ProcessCreate filtering; inspect the "
                    "persisted elevated policy evidence",
        "missing": "Sysmon ProcessCreate absent from the active configuration",
        "unknown": "policy unknown; preserve evidence and re-validate",
    }.get(sysmon_policy, "policy unknown; preserve evidence and re-validate")

"""Adapter: existing JARVIS sources -> ProcessPresence. Pure, metadata-only.

Feeds the reconciliation engine without new privileged reads:

  kernel_create/exit  future JarvisKernel.sys ring buffer (absent today;
                      recorded as unknown, never fabricated)
  etw_start/stop      native sensor process start/exit events (by guid/pid)
  sysmon_create       Sysmon Event 1 ProcessCreate (policy-aware)
  snapshot            authoritative process snapshot (state_mod provider)
  thread_activity     hidden.ps1 threadOwners / ghostThreads pids
  image_activity      memscan foreign-image pids / Sysmon image-load pids
  cpu_activity        resource samples attributed to a pid
  network_activity    Get-NetTCPConnection owners / socket table owners

Pid reuse is guarded by (boot_id, pid, started/guid) keys. Sysmon policy
explains gaps (filtered vs full) but never clears a mismatch. No cmdlines,
paths, or raw telemetry leave this module: keys, pids, and booleans only.
"""

from .presence import ProcessPresence


def instance_key(*, boot_id="", pid=0, guid="", started=""):
    if guid:
        return f"guid:{guid}"
    return f"boot:{boot_id or '?'}:pid:{pid}:{started or 'unknown-start'}"


def build_presence(*, boot_id="", pid=0, guid="", started="",
                   kernel_events=(), etw_events=(), sysmon_creates=(),
                   snapshot_pids=(), thread_pids=(), image_pids=(),
                   cpu_pids=(), network_pids=(), first_seen="",
                   last_seen=""):
    """Fold boolean source membership into one ProcessPresence. Pure."""
    kernel_events = set(kernel_events or ())
    etw_events = set(etw_events or ())
    sysmon_creates = set(sysmon_creates or ())
    snapshot_pids = set(snapshot_pids or ())
    thread_pids = set(thread_pids or ())
    image_pids = set(image_pids or ())
    cpu_pids = set(cpu_pids or ())
    network_pids = set(network_pids or ())
    return ProcessPresence(
        boot_id=str(boot_id or ""), pid=int(pid or 0),
        guid=str(guid or ""), started=str(started or ""),
        kernel_create_seen="create" in kernel_events,
        kernel_exit_seen="exit" in kernel_events,
        etw_start_seen="start" in etw_events,
        etw_stop_seen="stop" in etw_events,
        sysmon_create_seen=pid in sysmon_creates,
        snapshot_seen=pid in snapshot_pids,
        thread_activity_seen=pid in thread_pids,
        image_activity_seen=pid in image_pids,
        cpu_activity_seen=pid in cpu_pids,
        network_activity_seen=pid in network_pids,
        first_seen=str(first_seen or ""), last_seen=str(last_seen or ""),
        extra={"kernel_ring": "absent" if not kernel_events else "present"},
    )


def to_finding(verdict, *, host="win"):
    """Verdict dict -> collector finding shape (stable category/title/where)."""
    from jarvis.core.finding import finding as _finding
    severity = verdict.get("severity", "low")
    if severity == "ok":
        return None
    title = {"CROSS_VIEW_MISMATCH": "cross-view process mismatch",
             "UNEXPLAINED_PROCESS": "unexplained process"}.get(
                 verdict.get("verdict"), "process visibility anomaly")
    detail = "; ".join(verdict.get("reasons", ["disagreement"]))
    detail += f" [{', '.join(verdict.get('sources', [])) or 'no sources'}]"
    return _finding("execution", severity, title, detail,
                    verdict.get("key", ""), host=host)

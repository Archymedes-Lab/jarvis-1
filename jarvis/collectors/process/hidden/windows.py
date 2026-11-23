"""The Windows half of the hidden-process audit."""

from jarvis.core.paths import load_win_script
from jarvis.platform.windows import aslist, ps_json

from .common import _finding

PS_HIDDEN = load_win_script("hidden.ps1")


def audit_windows():
    data = ps_json(PS_HIDDEN, timeout=120)
    if data is None:
        return [_finding("medium", "Windows cross-view unavailable",
                         "powershell.exe returned no data", "interop")]
    out = []

    wmi = {p["pid"]: p for p in aslist(data.get("wmi")) if p.get("pid") is not None}
    api = {p["pid"]: p for p in aslist(data.get("api")) if p.get("pid") is not None}
    tl = {p["pid"]: p for p in aslist(data.get("tasklist")) if p.get("pid") is not None}
    netpids = {p for p in aslist(data.get("netpids")) if isinstance(p, int) and p > 4}
    # Only owners still running and absent from the fresh verification listing;
    # a process that exits mid-scan otherwise reads as invisible.
    netpids &= {g.get("pid") for g in aslist(data.get("ghostNet")) if isinstance(g, dict)}

    def label(pid):
        for src in (wmi, api, tl):
            if pid in src:
                return src[pid].get("name") or "?"
        return "unknown"

    # WMI and the process API disagreeing is the classic userland-hook tell.
    # Only disagreements that survived a per-pid re-query count (see
    # PS_HIDDEN); the raw listings were taken moments apart.
    wmi_only = {p for p in aslist(data.get("wmiOnly")) if isinstance(p, int)}
    api_only = {p for p in aslist(data.get("apiOnly")) if isinstance(p, int)}
    for pid in sorted(wmi_only & (set(wmi) - set(api))):
        out.append(_finding("high", "process visible to WMI but not to the process API",
                            f"pid {pid} ({label(pid)}) — {wmi[pid].get('path') or 'no path'}",
                            "Win32_Process vs Get-Process"))
    for pid in sorted(api_only & (set(api) - set(wmi))):
        out.append(_finding("high", "process visible to the process API but not to WMI",
                            f"pid {pid} ({label(pid)}) — WMI provider may be tampered with",
                            "Get-Process vs Win32_Process"))
    for pid in sorted((set(wmi) | set(api)) - set(tl) - {0, 4}):
        out.append(_finding("medium", "process missing from tasklist",
                            f"pid {pid} ({label(pid)})", "tasklist.exe"))

    for pid in sorted(netpids - set(wmi) - set(api) - set(tl)):
        out.append(_finding("critical", "network connection owned by an invisible process",
                            f"pid {pid} holds an open TCP connection but appears in no "
                            f"process listing",
                            "Get-NetTCPConnection vs process views"))

    # -- the DKOM cross-view ----------------------------------------------
    # Everything above walks ActiveProcessLinks, one kernel list. These three
    # reach process objects by other routes, so a pid they can see while the
    # enumerations cannot is the signature of a process unlinked from that list.
    threads = {p for p in aslist(data.get("threadOwners")) if isinstance(p, int)}
    perf = {p for p in aslist(data.get("perfpids")) if isinstance(p, int)}
    svc = {p for p in aslist(data.get("svcpids")) if isinstance(p, int)}

    # pid 0 and 4 are the System process and have no ordinary listing entry.
    IGNORE = {0, 4}

    # The handle-table suspects are already triple-verified inside PowerShell
    # (see PS_HIDDEN), so anything still here survived two bracketing
    # enumerations, a third fresh listing and a re-opened handle.
    for s in aslist(data.get("openable")):
        pid = s.get("pid") if isinstance(s, dict) else None
        if pid is None or pid in IGNORE:
            continue
        image = (s.get("image") or "").strip()
        out.append(_finding(
            "critical", "process visible only to the handle table",
            f"pid {pid} ({image or 'no image name'}) is running — not merely a "
            f"handle held open on a dead object — yet appears in no enumeration. "
            f"The handle table (PspCidTable) still holds it, which is what "
            f"unlinking an EPROCESS from ActiveProcessLinks (DKOM) leaves behind",
            image or "OpenProcess vs WMI/Get-Process/tasklist"))

    opaque = {p for p in aslist(data.get("opaque")) if isinstance(p, int)} - IGNORE
    if opaque:
        out.append(_finding(
            "low", "some pids could not be qualified",
            f"{len(opaque)} pid(s) return ERROR_ACCESS_DENIED to a limited-info "
            f"open, so this scan cannot tell a protected process from an already "
            f"exited one and does not guess: {', '.join(str(p) for p in sorted(opaque)[:10])}"
            + (" …" if len(opaque) > 10 else "")
            + ". Running the audit elevated resolves them.",
            "OpenProcess"))

    for src_name, src, ghost_key, note in (
        ("the thread list", threads, "ghostThreads",
         "owns running threads while appearing in no process listing"),
        ("the performance counters", perf, "ghostPerf",
         "is reported by the performance subsystem but by no enumeration API"),
        ("the service controller", svc, "ghostSvc",
         "is registered as a running service's process but appears in no listing"),
    ):
        if not src:
            out.append(_finding("low", f"{src_name} view unavailable",
                                "this cross-check was skipped", "Windows"))
            continue
        # Already re-verified against a fourth enumeration inside PowerShell.
        ghosts = [g for g in aslist(data.get(ghost_key))
                  if isinstance(g, dict) and g.get("pid") not in IGNORE]
        for g in ghosts:
            image = (g.get("image") or "").strip()
            out.append(_finding(
                "critical", f"process visible only to {src_name}",
                f"pid {g.get('pid')} ({image or 'no image name'}) {note}, and is "
                f"still running when re-checked",
                image or f"{src_name} vs WMI/Get-Process/tasklist"))
        if not ghosts:
            out.append(_finding("ok", f"{src_name} agrees with the process listings",
                                f"{len(src)} pids, none of them concealed", ""))

    out.append(_finding("low", "handle-table sweep has a finite PID range",
                        "OpenProcess probes PIDs 4–65535. A process with a higher "
                        "PID may appear in the other views but is not checked "
                        "through this independent handle-table path; no claim "
                        "of complete hidden-process coverage follows.",
                        "OpenProcess sweep"))
    out.append(_finding("ok", "sampled cross-view scan complete",
                        f"{len(wmi)} via WMI, {len(api)} via process API, "
                        f"{len(tl)} via tasklist, "
                        f"{data.get('openableTotal', 0)} via OpenProcess sweep, "
                        f"{len(threads)} via threads, {len(perf)} via perf counters",
                        ""))
    for f in out:
        f["host"] = "win"
    return out, data

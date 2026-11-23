"""Sysmon: the interception layer this design could not otherwise have.

Every other collector here samples state on an interval, and `coverage.py`
reports the consequence honestly: anything that starts and exits between two
passes is never seen. That ceiling is why `T1003` — OS credential dumping, the
most-raised technique in the entire intelligence corpus — was marked
unclosable. Catching a process opening LSASS requires being told when it
happens, not asking afterwards whether it did.

Sysmon is a kernel driver that does exactly that, writing to an event log this
module reads. It changes what jarvis is capable of rather than adding another
thing to poll:

  event 10  a process opened another process's memory — the LSASS case is
            credential theft, and the access mask says whether it was a read
  event 8   a thread created inside another process
  event 25  process image tampering: hollowing and herpaderping
  event 7   an image loaded that is unsigned or signed by nobody expected
  event 22  every DNS query, by process
  event 1   every process start, with a SHA-256 and its parent

The last two matter beyond their own findings. A DNS query is a name to check
against the 53,000 domains the intel corpus holds, and a process start carries
a hash to check against 252,000 sample digests — so Sysmon turns the knowledge
base from something matched against *current* state into something matched
against everything that has happened since the last pass.

Reading the channel needs membership in `Event Log Readers` or elevation. When
that is missing the module says so and says how to fix it, because a log that
cannot be read produces exactly the same silence as a machine with nothing
wrong.
"""

import json
import os
import re
from datetime import datetime, timezone

from jarvis.collectors.telemetry import community, regwatch, techniques
from jarvis.core import collection, sigma, warninglist
from jarvis.core.eventlog import EventLog, LogError
from jarvis.core.finding import win_finding as _finding
from jarvis.core.util import iso, now
from jarvis.platform.windows import aslist, ps_json

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "ok": 4}
CAT_ORDER = {"impact": 0, "credential access": 1, "injection": 2,
             "tampering": 3, "intel match": 4, "telemetry loss": 5, "telemetry": 6,
             "visibility": 7}

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
REGISTRY_RECORDED_META = "sysmon_registry_recorded_v1"      # {registry rule title: last seen}
REGISTRY_RECORDED_FOR_S = 30 * 86400
VOLUMES_META = "windows_volumes_v1"     # {"at": epoch, "volumes": {letter: [drive type, bus]}}
VOLUMES_FOR_S = 6 * 3600                # how long a drive known to be internal is not asked about again
# Drive type alone calls a USB hard disk "Fixed"; the bus of the disk under the
# letter tells it apart. Read-only, unelevated, about two seconds.
PS_VOLUMES = r"""
$ErrorActionPreference = 'SilentlyContinue'
$bus = @{}
Get-Partition | Where-Object { $_.DriveLetter } | ForEach-Object {
  $bus[[string]$_.DriveLetter] = [string](Get-Disk -Number $_.DiskNumber).BusType }
$o = @{ volumes = @([IO.DriveInfo]::GetDrives() | ForEach-Object {
  $l = $_.Name.Substring(0,1)
  [pscustomobject]@{ letter=$l; type=[string]$_.DriveType; bus=[string]$bus[$l] } }) }
"""

# Access masks that include reading another process's memory. 0x0010 is
# PROCESS_VM_READ and 0x0400 is PROCESS_QUERY_INFORMATION; the classic
# credential-dumping combination is 0x1010 or 0x1410.
VM_READ = 0x0010
# Rights that cannot touch LSASS memory, threads or handles:
# PROCESS_QUERY_LIMITED_INFORMATION (0x1000), PROCESS_QUERY_INFORMATION
# (0x0400) and SYNCHRONIZE (0x100000). Windows components ask for these
# constantly. They still allow OpenProcessToken, the first step of
# SYSTEM-token theft, so a query-only open stays reportable at medium.
QUERY_ONLY = 0x1000 | 0x0400 | 0x100000

# Processes that legitimately open LSASS. Windows' own protection stack and
# a few management agents do this by design.
LSASS_EXPECTED = {
    "msmpeng.exe", "mssense.exe", "sensecncproxy.exe", "wmiprvse.exe",
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "taskmgr.exe", "procexp64.exe", "procexp.exe", "perfmon.exe",
    "securityhealthservice.exe", "mpcmdrun.exe", "vgk.exe", "vgc.exe",
}

# Named pipes the Sysmon baseline records: each belongs to one attack tool,
# so a single event is the tool running, not a heuristic.
ATTACK_PIPES = (
    ("\\paexec", "PAExec remote execution", ("T1559", "T1021")),
    ("\\remcom", "RemCom remote execution", ("T1559", "T1021")),
    ("\\csexec", "CsExec remote execution", ("T1559", "T1021")),
    ("\\lsadump", "LSA secrets dumper", ("T1559", "T1003")),
    ("\\cachedump", "cached-credential dumper", ("T1559", "T1003")),
    ("\\wceservicepipe", "Windows Credential Editor", ("T1559", "T1003")),
    ("\\postex_", "Cobalt Strike post-exploitation", ("T1559", "T1071")),
)
# Where a Startup-folder drop lands: anything written there runs at the next
# logon of that user (or every user, under ProgramData).
STARTUP_FOLDER = "\\start menu\\programs\\startup\\"
DRIVERS_FOLDER = "\\windows\\system32\\drivers\\"
# Programs that write drivers and Startup entries as part of their job.
INSTALLER_IMAGES = {"msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "drvinst.exe",
                    "dism.exe", "wuauclt.exe", "mousocoreworker.exe", "svchost.exe",
                    "poqexec.exe", "setup.exe", "windowsupdatebox.exe"}

# Browser processes whose memory holds decrypted cookies and session tokens.
# The Sysmon baseline records every open of these by a process that is not
# the same browser (its sandbox opens its own processes constantly). Reading
# that memory is how ChromeKatz-style theft gets session cookies without ever
# touching the cookie database on disk.
BROWSER_IMAGES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}
# Opens of a browser that carry no signal: the same browser (its sandbox),
# Windows' own protection stack, the crash handler and the desktop shell
# probing windows. Another browser is not expected: Edge has no business in
# Firefox's memory.
BROWSER_ACCESS_EXPECTED = {
    "msmpeng.exe", "mssense.exe", "csrss.exe", "svchost.exe", "explorer.exe",
    "werfault.exe", "werfaultsecure.exe", "taskmgr.exe", "procexp64.exe",
    "procexp.exe", "sihost.exe", "dwm.exe", "searchhost.exe", "runtimebroker.exe",
    "applicationframehost.exe", "textinputhost.exe", "ctfmon.exe", "msedgewebview2.exe",
    "lsass.exe", "wmiprvse.exe", "vgk.exe", "vgc.exe",
}

# Commands used to destroy Windows recovery paths before encryption. The
# command and destructive argument must occur together; merely running one of
# these administration tools is inventory, not ransomware behaviour.
RANSOM_RECOVERY = re.compile(
    r"(?i)(vssadmin(?:\.exe)?\s+delete\s+shadows|"
    r"wmic(?:\.exe)?\s+shadowcopy\s+delete|"
    r"wbadmin(?:\.exe)?\s+delete\s+(catalog|systemstatebackup)|"
    r"bcdedit(?:\.exe)?.*?/(set|deletevalue).*?(recoveryenabled\s+no|"
    r"bootstatuspolicy\s+ignoreallfailures)|"
    r"reagentc(?:\.exe)?\s+/disable)")

WRITABLE_DLL_DIRS = ("/users/", "/programdata/", "/windows/temp/", "/temp/", "/public/")
# Under ProgramData but not writable by users: Defender's platform tree, where it
# installs its own kernel drivers on every platform update (measured 2026-10-23:
# BUILTIN\Users read/execute only; ksld.sys and WdNisDrv.sys signed "Microsoft
# Windows", Valid). A driver there counts as staged only if its signature fails.
PROTECTED_DRIVER_DIRS = ("c:/programdata/microsoft/windows defender/platform/",)


# Windows creates threads across its own processes as normal operation — the
# desktop compositor into the client-server subsystem, the crash handler into
# whatever crashed. Reporting those as injection is the CreateRemoteThread
# equivalent of flagging every browser sandbox hook.
SYSTEM_INJECTORS = {
    "dwm.exe", "csrss.exe", "wininit.exe", "services.exe", "smss.exe",
    "lsass.exe", "svchost.exe", "werfault.exe", "werfaultsecure.exe",
    "explorer.exe", "audiodg.exe", "taskmgr.exe", "system", "ntoskrnl.exe",
    "sihost.exe", "runtimebroker.exe", "dllhost.exe", "conhost.exe",
    "searchindexer.exe", "wmiprvse.exe", "msmpeng.exe", "mssense.exe",
}


def _ps(script, timeout=240):
    return ps_json(
        script + "\n$json = [pscustomobject]$o | ConvertTo-Json -Depth 6 -Compress\n"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))",
        timeout=timeout)


def _known_volumes(store):
    """The last volume inventory this collector stored: ({letter: (type, bus)}, taken at)."""
    try:
        saved = json.loads(store.get_meta(VOLUMES_META, "") or "{}")
        return ({str(k).upper(): tuple(v) for k, v in saved["volumes"].items()},
                float(saved["at"]))
    except (AttributeError, KeyError, TypeError, ValueError):
        return {}, 0.0


def _read_volumes():
    """Ask Windows which drives are attached. None when it cannot be asked: an
    empty answer is a failure too, since the system drive is always there."""
    data = _ps(PS_VOLUMES, timeout=60)
    rows = aslist((data or {}).get("volumes")) if isinstance(data, dict) else []
    found = {str(r.get("letter") or "").upper(): (str(r.get("type") or ""), str(r.get("bus") or ""))
             for r in rows if isinstance(r, dict) and r.get("letter")}
    return found or None


def status():
    """Is Sysmon installed, and can this account actually read its log?"""
    d = _ps(r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$svc = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' or Name='Sysmon'"
$o.installed = [bool]$svc
$o.state = [string]$svc.State
$k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
$o.channel = [bool](Test-Path $k)
$o.enabled = [string](Get-ItemProperty $k).Enabled
# The only honest test of readability is a read.
$probe = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -EA SilentlyContinue
$o.readable = [bool]$probe
$o.reader = [bool]((whoami /groups) -match 'Event Log Readers')
""", timeout=180)
    return d or {}


def _fetch(hours=24, max_events=1200, minutes=None, rare_hours=None, since_epoch=None):
    """Pull the event types worth reasoning about, already reduced to fields.

    Cost here is almost entirely `Get-WinEvent`, and it scales with how many
    events come back: 2354 events took 23s and 800 took 11s, while the XML
    parsing everyone blames was 4s of that. So the lever is the window, not
    the parsing — and re-reading a full day of log every ten minutes was
    paying for the same events over and over.
    """
    script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$since = __SINCE__
$rareSince = __RARE_SINCE__
# Event 3 (network connect) was being fetched and never read — on a busy
# desktop it is most of the log by volume, and dropping it is most of the cost.
# The remaining types split by frequency: 8/10/25 are rare and each one
# matters, while 1/7/22 are continuous and only need a representative sample.
function Read-Events($filter, $limit) {
  try { @(Get-WinEvent -FilterHashtable $filter -MaxEvents $limit -Oldest -ErrorAction Stop) }
  catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $script:readFailed=$true }
    @()
  }
}
$readFailed=$false
$rare  = @(Read-Events @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=8,10,25,255
        StartTime=$rareSince } 801)
$bulk  = @(Read-Events @{
        LogName='Microsoft-Windows-Sysmon/Operational'
        Id=1,7,22
        StartTime=$since } (__MAX__ + 1))
$o.complete = (-not $readFailed -and $rare.Count -le 800 -and $bulk.Count -le __MAX__)
$o.readFailed = $readFailed
$o.rareComplete = (-not $readFailed -and $rare.Count -le 800)
$o.capped = ($rare.Count -gt 800 -or $bulk.Count -gt __MAX__)
# Oldest-first pages: drop the probe event and name the last one kept, so the
# caller can advance its cursor to the end of what was actually read.
$o.rareLast = $null; $o.bulkLast = $null
if ($rare.Count -gt 800) { $rare = @($rare | Select-Object -First 800); $o.rareLast = $rare[-1].TimeCreated.ToUniversalTime().ToString('o') }
if ($bulk.Count -gt __MAX__) { $bulk = @($bulk | Select-Object -First __MAX__); $o.bulkLast = $bulk[-1].TimeCreated.ToUniversalTime().ToString('o') }
$ev = @($rare) + @($bulk)

$rows = foreach ($e in $ev) {
  $d = @{}
  foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  [pscustomobject]@{
    id      = $e.Id
    record_id = $e.RecordId
    process_guid = [string]$d['ProcessGuid']
    parent_guid = [string]$d['ParentProcessGuid']
    process_id = [string]$d['ProcessId']
    parent_cmdline = [string]$d['ParentCommandLine']
    time    = $e.TimeCreated.ToString('o')
    # ProcessAccess (10) and CreateRemoteThread (8) name the actor
    # SourceImage, not Image — reading the wrong field left every injection
    # finding with a blank process name.
    image   = [string]$(if ($d['SourceImage']) { $d['SourceImage'] } else { $d['Image'] })
    target  = [string]$d['TargetImage']
    granted = [string]$d['GrantedAccess']
    parent  = [string]$d['ParentImage']
    hashes  = [string]$d['Hashes']
    query   = [string]$d['QueryName']
    loaded  = [string]$d['ImageLoaded']
    signed  = [string]$d['Signed']
    sigstat = [string]$d['SignatureStatus']
    dest    = [string]$d['DestinationIp']
    dport   = [string]$d['DestinationPort']
    cmdline = [string]$d['CommandLine']
    type    = [string]$d['Type']
    start_module = [string]$d['StartModule']
    start_function = [string]$d['StartFunction']
    start_address = [string]$d['StartAddress']
    description = [string]$d['Description']
  }
}
$o.events = @($rows)
$o.count = @($rows).Count
"""
    since = (f"[DateTimeOffset]::FromUnixTimeMilliseconds({int(since_epoch * 1000)}).LocalDateTime"
             if since_epoch else f"(Get-Date).AddMinutes(-{int(minutes)})" if minutes
             else f"(Get-Date).AddHours(-{int(hours)})")
    # rare_hours: re-read the rare events (8, 10, 25) over a longer window
    # than the bulk ones, for a one-time re-judge that must not trip the
    # bulk cap and leave the whole collector partial.
    rare_since = f"(Get-Date).AddHours(-{int(rare_hours)})" if rare_hours else since
    script = (script.replace("__RARE_SINCE__", rare_since).replace("__SINCE__", since)
                    .replace("__MAX__", str(int(max_events))))
    return _ps(script, timeout=420) or {}


# Sysmon reports its own losses as event 255. `ID=QUEUE` means the driver's
# queue overflowed and events were discarded before reaching the log — the
# counts name which kinds were lost.
DROPPED = re.compile(r"(\w+):(\d+)")
# A consumer that has not seen a sensor batch for this long is reading history,
# not the present; the PowerShell query takes over until delivery resumes.
NATIVE_FRESH = 600


def rows_from_events(events):
    """Canonical Sysmon events -> the reduced rows the detections below read.

    The same shape `_fetch` produces from PowerShell, so every detection runs
    unchanged on either source.
    """
    rows = []
    for e in events:
        p, par, t = e.get("process") or {}, e.get("parent") or {}, e.get("target") or {}
        eid = int(e.get("source_event") or 0)
        rows.append({
            "id": eid, "record_id": e.get("record"), "seq": e.get("seq"),
            "process_guid": p.get("guid") or "", "parent_guid": par.get("guid") or "",
            "process_id": str(p.get("pid") or ""), "parent_cmdline": par.get("cmdline") or "",
            "time": e.get("time"), "image": p.get("image") or "",
            "target": t.get("image") or "", "granted": t.get("access") or "",
            "parent": par.get("image") or "",
            "hashes": (p.get("hashes") if eid == 1 else t.get("hashes")) or "",
            "query": t.get("query") or "", "loaded": t.get("path") or "",
            "signed": t.get("signed") or "", "sigstat": t.get("signature_status") or "",
            "dest": t.get("ip") or "", "dport": str(t.get("port") or ""),
            "initiated": t.get("initiated"), "dns_status": str(t.get("status") or ""),
            "reg_key": t.get("key") or "", "reg_details": str(t.get("details") or ""),
            "cmdline": p.get("cmdline") or "", "type": t.get("tamper") or "",
            "original_name": p.get("original_name") or "",
            "start_module": t.get("start_module") or "",
            "start_function": t.get("start_function") or "",
            "start_address": t.get("start_address") or "",
            "description": (e.get("attrs") or {}).get("Description") or "",
            "error_id": (e.get("attrs") or {}).get("ID") or "",
            "state": (e.get("attrs") or {}).get("State") or "",
            # File creation (11), named pipes (17/18) and WMI subscriptions
            # (19-21) were logged but never judged before 2026-10-23.
            "file": t.get("path") if eid == 11 else "",
            "pipe": t.get("name") or "",
            "wmi_operation": (e.get("attrs") or {}).get("Operation") or "",
            "wmi_name": (e.get("attrs") or {}).get("Name") or "",
            "wmi_type": (e.get("attrs") or {}).get("Type") or "",
            "wmi_consumer": (e.get("attrs") or {}).get("Consumer") or "",
            "wmi_destination": (e.get("attrs") or {}).get("Destination") or "",
            "wmi_user": (e.get("attrs") or {}).get("User") or "",
        })
    return rows


# Most event-log records one incremental native read may load. About 1-2 KB
# each once parsed, so a page stays under about 200 MB (50 000 measured 463 MB peak); the cursor advances to
# the page end and the rest is read on later runs, never skipped.
NATIVE_PAGE = 20_000


def _native(store, root=None, since=None, event_ids=None, page=None):
    """Read Sysmon events from the event log, if the sensor is delivering.

    New events since this consumer's offset, or with `since` (epoch seconds)
    everything the source timestamped from then on. -> (data, through) shaped
    like `_fetch`, or None to fall back. Only the consumer offset moves here;
    the log itself is written by the ingest job.
    """
    try:
        log = EventLog(root) if root else EventLog()
    except (LogError, OSError):
        return None
    try:
        fresh = [c for c in log.cursors.values()
                 if c.get("channel") == CHANNEL and now() - float(c.get("at") or 0) < NATIVE_FRESH]
        if not fresh:
            return None
        offset = int(store.get_meta("sysmon_eventlog_seq", 0) or 0)
        if offset > log.last_seq:
            offset = 0              # the log was rebuilt or replaced; re-read it
        start = None
        if since is not None:
            offset = 0
            start = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        page = NATIVE_PAGE if page is None else page
        until = None
        if start is None and page and log.last_seq - offset > page:
            until = offset + page
        events = [e for e in log.iter_events(after=offset, until=until, since=start)
                  if e.get("channel") == CHANNEL
                  and (start is None or (e.get("time") or "") >= start)
                  and (event_ids is None or e.get("source_event") in event_ids)]
        through = log.last_seq if until is None else until
        backlog = log.last_seq - through
        lost = [a for a, b in log.missing() if b > offset and a <= through]
    finally:
        log.close()
    return ({"events": rows_from_events(events), "complete": not lost,
             "rareComplete": not lost, "source": "native sensor",
             "pruned": bool(lost), "backlog": backlog}, through)


# A driver-queue drop reported within this many seconds after the service's
# own "Started" event is the boot backlog, not loss while running.
BOOT_DROP_WINDOW_S = 5
BOOT_DROP_TITLE = "Sysmon lost events while starting at boot"


def _epoch(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _boot_backlog(when, eventlog=None):
    """True when the native log holds a Sysmon "Started" event up to
    BOOT_DROP_WINDOW_S before `when` (UTC "YYYY-MM-DD HH:MM:SS")."""
    at = _epoch(when.replace(" ", "T") + "Z")
    if at is None:
        return False
    since = datetime.fromtimestamp(at - BOOT_DROP_WINDOW_S - 1, timezone.utc)
    try:
        log = EventLog(eventlog) if eventlog else EventLog()
    except (LogError, OSError):
        return False
    try:
        for e in log.iter_events(since=since.strftime("%Y-%m-%dT%H:%M:%S")):
            t = _epoch(e.get("time"))
            if t is not None and t > at + 1:
                break
            if (e.get("channel") == CHANNEL and e.get("source_event") == 4
                    and str((e.get("attrs") or {}).get("State")).lower() == "started"
                    and t is not None and 0 <= at - int(t) <= BOOT_DROP_WINDOW_S + 1):
                return True
    except (LogError, OSError):
        return False
    finally:
        log.close()
    return False


def drop_verdict(description):
    """-> (severity, events lost, "Kind n, ...") for a Sysmon 255 report, or None."""
    counts = {k: int(v) for k, v in DROPPED.findall(description or "") if k != "DriverQueueSize"}
    counts = {k: v for k, v in counts.items() if v}
    if not counts:
        return None
    total = sum(counts.values())
    worst = ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
    # Losing process starts means an execution can have happened unrecorded.
    severity = "high" if counts.get("ProcessCreate") or counts.get("ProcessAccess") \
        or counts.get("CreateRemoteThread") else "medium"
    return severity, total, worst


# Categories that describe a run rather than something that happened.
RUN_STATE = ("visibility", "telemetry")

THREAD_RULES = "start-module-v2"
# A changed rule must replay every remote-thread event in the retained window
# before replacing persisted injection findings. A partial or oversized replay
# keeps the prior warning rather than silently erasing it.
REJUDGE_REMOTE_MAX = 5000
KERNEL_SPACE = 0xFFFF800000000000
LOADLIBRARY = {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
               "ldrloaddll"}


def thread_verdict(image, target, module, function, address, ctrl_addresses=()):
    """-> None for routine, or (severity, why) for a remote thread (Sysmon 8).

    Where the new thread starts decides it, as mature rules do. Measured here
    (2026-09-17) before this existed, every injection finding was one of three
    benign shapes: DWM or csrss starting a thread at a kernel address, csrss
    delivering Ctrl+C through KERNELBASE!CtrlRoutine, and VSCodium's Chromium
    sandbox starting a thread in its own executable in a child process.
    """
    src, dst = _base(image), _base(target)
    module = "" if (module or "").strip() in ("", "-") else module.strip()
    func = (function or "").strip().lower()
    try:
        start = int(str(address or "0"), 16)
    except ValueError:
        start = 0
    if start >= KERNEL_SPACE:
        return None                     # user-mode code cannot start a thread here
    if func == "ctrlroutine" and _base(module) in ("kernelbase.dll", "kernel32.dll"):
        return None                     # console control (Ctrl+C) delivery
    if (not module and _base(image) == "csrss.exe" and start
            and start in ctrl_addresses):
        # Measured 2026-09-23: at shutdown csrss delivers console close to
        # llama-server; Sysmon, racing the teardown, left the module blank
        # but the address was exactly KERNELBASE!CtrlRoutine as resolved for
        # ollama.exe in the same boot. System DLLs share one base per boot,
        # so an equal address is that routine, not unbacked memory.
        return None
    if src in SYSTEM_INJECTORS and dst in SYSTEM_INJECTORS:
        return None
    if func in LOADLIBRARY:
        return ("critical", f"the thread starts at {function} — the classic way to "
                            f"force a DLL into another process")
    if not module and start:
        return ("critical", "the thread starts in memory that no file backs — code "
                            "written into the target, the shape of shellcode injection")
    if module and src and src == dst and _base(module) == src:
        return ("low", f"the thread starts inside {src} itself, in a child process of "
                       f"the same application — how Chromium and Electron sandboxes "
                       f"and crash handlers work")
    if module:
        return ("medium", f"the thread starts in {module}"
                          + (f"!{function}" if func and func != "-" else "")
                          + ", a file-backed start in another process")
    return ("high", "a thread starting in another process's address space; Sysmon "
                    "recorded no start module to judge it by")


CTRL_ROUTINE_WINDOW_S = 30


def _ctrl_routine_addresses(remote_threads):
    """Resolved CtrlRoutine starts in this batch, with source timestamps.

    A bare address saved across boots is not proof: ASLR addresses can be
    reused. Require a resolved system-DLL event in the same short burst.
    """
    known = {}
    for _img, _tgt, when, module, function, address in remote_threads:
        if (str(function or "").strip().lower() != "ctrlroutine"
                or _base(module) not in ("kernelbase.dll", "kernel32.dll")):
            continue
        at = _epoch(when)
        try:
            value = int(str(address), 16)
        except ValueError:
            continue
        if at is not None and value:
            known.setdefault(value, []).append(at)
    return known


def _near_ctrl_routine(address, when, known):
    try:
        value = int(str(address), 16)
    except ValueError:
        return False
    at = _epoch(when)
    return at is not None and any(
        abs(at - ref) <= CTRL_ROUTINE_WINDOW_S for ref in known.get(value, ()))


def _sha256_of(hashes):
    """Sysmon packs hashes as 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..'."""
    for part in (hashes or "").split(","):
        k, _, v = part.partition("=")
        if k.strip().upper() == "SHA256":
            return v.strip().lower()
    return ""


def _base(path):
    """Basename of a Sysmon image path, or "" when Sysmon could not resolve it.

    Sysmon writes the literal string `<unknown process>` rather than leaving
    the field empty, so testing for emptiness silently never fires.
    """
    p = (path or "").strip()
    if not p or p.startswith("<"):
        return ""
    return p.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _service_findings(st):
    """A stopped Sysmon or a disabled channel, from a status() answer. Pure.

    status() always read the service state and channel switch, but nothing
    judged them: a stopped Sysmon whose old log was still readable passed as
    healthy, and on the native-sensor path status() was never asked at all
    (2026-10-27 coverage audit). An empty answer judges nothing either way."""
    if not st or not st.get("installed"):
        return []
    out = []
    state = str(st.get("state") or "")
    if state and state.lower() != "running":
        collection.failed("sysmon-service", f"service {state}")
        out.append(_finding(
            "visibility", "high", "Sysmon is installed but not running",
            f"the Sysmon service is {state}. Process, network and registry events "
            f"stop being recorded, which looks exactly like a quiet machine; "
            f"stopping it is a known first step before an attack (T1562.001). "
            f"Start it with `sc start Sysmon64` in an elevated shell and find who "
            f"stopped it in the System log (event 7036/7040).", "Sysmon64"))
    if str(st.get("enabled") or "").lower() == "false":
        collection.failed("sysmon-channel", "event channel disabled")
        out.append(_finding(
            "visibility", "high", "Sysmon's event log channel is disabled",
            "the driver may still run, but nothing it sees is written anywhere. "
            "Re-enable it with `wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true` "
            "(elevated).", CHANNEL))
    return out


def _query_blocked(st=None):
    """Findings that stop the PowerShell fallback before it queries, or []."""
    st = status() if st is None else st
    if not st:
        collection.failed('sysmon', 'status unavailable')
        return [_finding("visibility", "medium", "Sysmon status unavailable",
                         "powershell.exe returned no data")]
    if not st.get("installed"):
        collection.failed('sysmon', 'not installed')
        return [_finding(
            "visibility", "medium", "Sysmon is not installed",
            "without an interception layer, anything that starts and exits "
            "between two sampling passes is invisible — which is why "
            "credential dumping cannot be detected by polling",
            "Sysmon64.exe -i")]
    if not st.get("readable"):
        collection.failed('sysmon', 'log unreadable')
        return [_finding(
            "visibility", "high",
            "Sysmon is running but its log cannot be read by this account",
            "the driver is recording and nothing here can see it, which "
            "produces the same silence as a clean machine. Add this account to "
            "the Event Log Readers group (one-time, needs admin): "
            "net localgroup \"Event Log Readers\" %USERNAME% /add — then log "
            "out and back in. Running jarvis elevated also works.",
            CHANNEL)]
    return []


def audit(store=None, hours=24, hosts=("win",), incremental=False, eventlog=None,
          events=None, volumes=None, community_rules=None):
    """`events` replays the given reduced rows (the shape rows_from_events
    returns) through every rule below instead of reading the machine. A replay
    never touches the store: it cannot record a hit or move a cursor. The
    coverage map's probes use it so they test this function, not a copy.

    `community_rules`: whether community (Sigma) rules run after the built-in
    ones. Default: on for the machine, off for a replay, so a replay exercises
    the built-in rule table (the coverage map's probes and look-alike controls
    depend on that) unless it asks for community rules too.

    `volumes` is a drive inventory {letter: (type, bus)} to judge drives
    against. A replay never asks Windows for one, so without it a replay leaves
    drives unjudged."""
    if "win" not in hosts:
        return []
    probing = events is not None
    if probing:
        store = None

    # The native sensor, when it is delivering, replaces the PowerShell query:
    # every record in order, no cap, no window arithmetic. The query below is
    # the fallback for machines without the sensor, or while it is down.
    rejudge = store is not None and store.get_meta("sysmon_thread_rules", "") != THREAD_RULES
    native = None
    replay_data = None
    if store is not None:
        # Incremental runs start from the consumer offset — on first use, the
        # whole retained history, not just the last day. A one-off CLI read
        # asks for its window by source time instead.
        native = _native(store, eventlog,
                         since=None if incremental else now() - hours * 3600)
        if native is not None and rejudge and incremental:
            # Keep the ordinary offset stream intact. Rule changes need only
            # the rare Event 8 history, not every event from a busy full day.
            replay = _native(store, eventlog, since=now() - hours * 3600,
                             event_ids={8})
            if replay is not None:
                replay_data = replay[0]
    query_started = now()
    minutes = None
    service = []
    if probing:
        through = None
        data = {"events": list(events), "complete": True, "rareComplete": True}
    elif native is not None:
        data, through = native
        # The native sensor reads the log, not the service: a stopped Sysmon
        # leaves an intact, quiet log behind. Ask Windows directly.
        service = _service_findings(status())
    else:
        through = None
        st = status()
        failed = _query_blocked(st)
        if failed:
            return failed
        # Stopped is not unreadable: the events already in the log still need
        # reading, so this reports alongside the query instead of blocking it.
        service = _service_findings(st)
        since_epoch = None
        if incremental and store is not None:
            last = int(float(store.get_meta("sysmon_last_run", 0) or 0))
            if last and now() - last < hours * 3600:
                since_epoch = last - 60
            if last:
                # A minute of overlap, so an event landing between the query and
                # the timestamp write is seen twice rather than never.
                minutes = max(2, min(int((now() - last) / 60) + 1, hours * 60))
        data = _fetch(hours=hours, minutes=minutes, rare_hours=hours if rejudge else None,
                      since_epoch=None if rejudge else since_epoch)
    if 'events' not in data or data.get('readFailed'):
        collection.failed('sysmon', 'event query incomplete; cursor retained')
        return [_finding('visibility', 'high', 'Sysmon event query failed',
                         'Previous cursor retained; missing events are not a clean result.', CHANNEL)]
    if replay_data is not None and replay_data.get('complete') and replay_data.get('rareComplete'):
        seen_seq = {e.get('seq') for e in data['events'] if e.get('seq') is not None}
        data['events'] = list(data['events']) + [
            e for e in replay_data.get('events', ())
            if e.get('seq') is not None and e.get('seq') not in seen_seq
            and (through is None or e['seq'] <= through)]
        data['rareComplete'] = True
    elif rejudge and native is not None and incremental:
        # A failed historical replay cannot erase stored injection verdicts,
        # but it must not obstruct the complete live incremental stream.
        data['rareComplete'] = False
    # Oldest-first paging (2026-10-11): a capped fallback query used to keep
    # its cursor and fail on every run, and the reviver re-forced it every
    # ~30 s, starving the other collectors for hours. The cursor now moves to
    # the end of the page actually read; the rest is read on later runs.
    paged_to = None
    if (native is None and not probing and incremental and not rejudge
            and store is not None and data.get('capped')
            and not data.get('complete', False) and not data.get('readFailed')):
        ends = [_epoch(data[k]) if data.get(k) else query_started
                for k in ('rareLast', 'bulkLast')]
        prior = float(store.get_meta('sysmon_last_run', 0) or 0)
        if None not in ends and min(ends) > prior:
            paged_to = min(ends)
    events = aslist(data.get("events"))
    replay_complete = (rejudge and data.get('complete') and data.get('rareComplete')
                       and sum(int(e.get('id') or 0) == 8 for e in events)
                       <= REJUDGE_REMOTE_MAX)
    out = list(service)
    if not data.get('complete', False):
        if native is not None:
            collection.failed('sysmon', 'event log retention removed unread events')
            out.append(_finding('visibility', 'high', 'Sysmon events were removed before analysis',
                                'Event log retention pruned segments this detector had not '
                                'read yet; raise the event log budget.', CHANNEL))
        elif paged_to is not None:
            collection.succeeded('sysmon')
            out.append(_finding('visibility', 'medium', 'Sysmon is catching up a backlog',
                                'The query cap was reached. This run read the oldest '
                                f'unread events through {datetime.fromtimestamp(paged_to).isoformat(timespec="seconds")}'
                                ' and advanced the cursor; newer events are read on the '
                                'next runs, so recent activity is delayed, not skipped.', CHANNEL))
        else:
            collection.failed('sysmon', 'event query capped or completeness unverified; cursor retained')
            out.append(_finding('visibility', 'high', 'Sysmon event coverage is partial',
                                'The query cap was reached or completeness was not established. '
                                'The cursor is retained; install the native sensor '
                                '(windows-sensor/install.ps1) to drain the backlog.', CHANNEL))
    if native is not None and (data.get('backlog') or 0) > 0:
        out.append(_finding('visibility', 'medium', 'Sysmon is catching up a backlog',
                            f"{data['backlog']} newer event-log records are still unread; "
                            f"each run reads up to {NATIVE_PAGE} and advances the cursor, so "
                            'recent activity is delayed, not skipped.', CHANNEL))
    window = ("a replay" if probing
              else "the native sensor's full review window" if native is not None and replay_complete
              else "the native sensor since the last run" if native is not None and incremental
              else f"the last {minutes} minutes" if minutes else f"the last {hours}h")

    lsass_hits, remote_threads, tampering = [], [], []
    browser_hits = {}
    driver_loads, startup_drops, driver_drops, pipe_hits, wmi_events = [], [], [], [], []
    unsigned, dns_names, proc_hashes = {}, {}, {}
    recovery_tamper, sideloads = [], []
    technique_hits, discovery_seen = {}, []
    renamed = {}                    # (image, original) -> [count, first time]
    off_runs, off_copies = [], []       # process starts naming a drive not known to be internal
    judge_drives = volumes is not None or not probing
    known_volumes, known_at = ((volumes, now()) if volumes is not None
                               else _known_volumes(store) if judge_drives else ({}, 0.0))
    internal = {letter for letter in known_volumes
                if now() - known_at < VOLUMES_FOR_S
                and techniques.volume_kind(letter, known_volumes) == techniques.INTERNAL}
    smb_out, failed_lookups, registry_hits, registry_seen, odd_ports = {}, [], {}, set(), {}
    family_hits = {}                # (key family, writer image) -> [count, key, time, tids, what, kind]
    dropped, drop_times = {}, []
    boot_dropped, boot_drop_times, service_starts, drop_reports = {}, [], [], []

    for e in events:
        eid = int(e.get("id") or 0)
        image = e.get("image") or ""
        base = _base(image)

        if eid == 10:
            target_base = _base(e.get("target"))
            if target_base in BROWSER_IMAGES:
                if base == target_base or base in BROWSER_ACCESS_EXPECTED:
                    continue
                try:
                    mask = int(str(e.get("granted") or ""), 16)
                except ValueError:
                    mask = None
                # Query-only opens cannot read memory; they are inventory.
                if mask is not None and not mask & ~QUERY_ONLY:
                    continue
                hit = browser_hits.setdefault((image, target_base), [0, e.get("granted"), e.get("time"), False])
                hit[0] += 1
                hit[2] = e.get("time") or hit[2]
                hit[3] = hit[3] or bool(mask and mask & VM_READ) or mask is None
                continue
            if target_base != "lsass.exe":
                continue
            if base in LSASS_EXPECTED:
                continue
            try:
                mask = int(str(e.get("granted") or ""), 16)
            except ValueError:
                mask = None     # unreadable rights are judged as memory access
            lsass_hits.append((image, e.get("granted"), e.get("time"),
                               bool(mask and mask & VM_READ),
                               bool(mask) and not mask & ~QUERY_ONLY,
                               e.get("process_guid") or ""))
        elif eid == 8:
            remote_threads.append((image, e.get("target"), e.get("time"),
                                   e.get("start_module") or "", e.get("start_function") or "",
                                   e.get("start_address") or ""))
        elif eid == 25:
            tampering.append((image, e.get("type"), e.get("time")))
        elif eid == 7:
            if str(e.get("signed") or "").lower() == "false":
                loaded = e.get("loaded") or ""
                unsigned.setdefault(_base(loaded), [0, image])
                unsigned[_base(loaded)][0] += 1
                loader_dir = os.path.dirname(image.replace("\\", "/").lower())
                loaded_dir = os.path.dirname(loaded.replace("\\", "/").lower())
                if (loaded.lower().endswith(".dll") and loader_dir and loader_dir == loaded_dir
                        and any(part in loaded_dir + "/" for part in WRITABLE_DLL_DIRS)):
                    sideloads.append((image, loaded, e.get("time")))
        elif eid == 6:
            loaded = e.get("loaded") or ""
            low = loaded.replace("\\", "/").lower()
            unsigned_drv = str(e.get("signed") or "").lower() == "false"
            valid = (e.get("sigstat") or "Valid") == "Valid"
            staged = any(part in low + "/" for part in WRITABLE_DLL_DIRS) and not (
                valid and not unsigned_drv and low.startswith(PROTECTED_DRIVER_DIRS))
            if unsigned_drv or staged or not valid:
                driver_loads.append((loaded, e.get("signed"), e.get("sigstat"), e.get("time"), staged))
        elif eid == 11:
            path = e.get("file") or ""
            low = path.replace("\\", "/").lower().replace("/", "\\")
            if STARTUP_FOLDER in low and base not in INSTALLER_IMAGES:
                startup_drops.append((image, path, e.get("time")))
            elif DRIVERS_FOLDER in low and base not in INSTALLER_IMAGES \
                    and not image.lower().startswith("c:\\windows\\"):
                driver_drops.append((image, path, e.get("time")))
        elif eid in (17, 18):
            pipe = (e.get("pipe") or "").lower()
            for needle, tool, tids in ATTACK_PIPES:
                if needle in pipe:
                    pipe_hits.append((image, pipe, tool, tids, eid, e.get("time")))
                    break
        elif eid in (19, 20, 21):
            wmi_events.append((eid, image, e.get("wmi_operation") or "", e.get("wmi_name") or "",
                               e.get("wmi_type") or "", e.get("wmi_consumer") or "",
                               e.get("wmi_destination") or "", e.get("wmi_user") or "",
                               e.get("time")))
        elif eid == 22:
            q = (e.get("query") or "").lower().rstrip(".")
            if q:
                dns_names.setdefault(q, set()).add(base)
                failed_lookups.append((e.get("process_guid") or image, base, _epoch(e.get("time")),
                                       q, e.get("dns_status") or ""))
        elif eid == 13:
            registry_seen.update(techniques.registry_families(e.get("reg_key")))
            specific = techniques.registry(e.get("reg_key"), e.get("reg_details"))
            for rule in specific:
                hit = registry_hits.setdefault((rule, image), [0, e.get("reg_key") or "", e.get("time")])
                hit[0] += 1
                hit[2] = e.get("time") or hit[2]
            # A family write nobody's specific rule covers, judged by its writer.
            watched = None if specific else regwatch.judge(image, e.get("reg_key"))
            if watched:
                fid, tids, what, kind = watched
                hit = family_hits.setdefault((fid, image), [0, e.get("reg_key") or "", e.get("time"),
                                                            tids, what, kind])
                hit[0] += 1
                hit[2] = e.get("time") or hit[2]
        elif eid == 3:
            if techniques.outbound_smb(e.get("dest"), e.get("dport"), e.get("initiated")):
                seen = smb_out.setdefault(image, [set(), e.get("time")])
                seen[0].add(e.get("dest"))
                seen[1] = e.get("time") or seen[1]
            elif techniques.odd_port(image, e.get("dest"), e.get("dport"), e.get("initiated")):
                seen = odd_ports.setdefault(image, [set(), e.get("time")])
                seen[0].add(f"{e.get('dest')}:{e.get('dport')}")
                seen[1] = e.get("time") or seen[1]
        elif eid == 1:
            h = _sha256_of(e.get("hashes"))
            if h:
                proc_hashes.setdefault(h, (image, e.get("time")))
            cmdline = e.get("cmdline") or ""
            if RANSOM_RECOVERY.search(cmdline):
                recovery_tamper.append((image, cmdline, e.get("time")))
            # A renamed system utility is judged under its real name too: every
            # rule matches on the image name, so a renamed copy slipped past all.
            original = techniques.original_base(e.get("original_name"))
            as_images = [image]
            if original in techniques.RENAMED_WATCH and original != techniques.image_base(image):
                seen_r = renamed.setdefault((image, original), [0, e.get("time")])
                seen_r[0] += 1
                as_images.append(original + ".exe")
            matched = set()
            for as_image in as_images:
                for rule, span in techniques.match(as_image, cmdline, techniques.WIN,
                                                   e.get("parent") or ""):
                    if rule in matched:
                        continue
                    matched.add(rule)
                    hit = technique_hits.setdefault((rule, image), [0, span, e.get("time")])
                    hit[0] += 1
                    hit[2] = e.get("time") or hit[2]
            if judge_drives:
                if techniques.drive_letter(image) not in internal | {""}:
                    off_runs.append((image, e.get("time")))
                sources, dest = techniques.copy_drives(image, cmdline)
                if (sources | {dest}) - internal - {""}:
                    off_copies.append((image, sources, dest, e.get("time")))
            for tid in techniques.discovery(image, cmdline, techniques.WIN):
                discovery_seen.append((e.get("parent_guid") or "", _base(e.get("parent")) or "?",
                                       _epoch(e.get("time")), tid, base))
        elif eid == 4:
            if str(e.get("state") or "").lower() == "started":
                service_starts.append(_epoch(e.get("time")))
        elif eid == 255:
            desc = e.get("description") or ""
            if "dropped" in desc.lower():
                drop_reports.append((e.get("time") or "", desc))

    # -- the sensor's queue: boot backlog vs loss while running ---------------
    # Classified after the loop: the service's "Started" and its drop report
    # are milliseconds apart and may arrive in either order.
    for when, desc in drop_reports:
        at = _epoch(when)
        boot = at is not None and any(
            s is not None and 0 <= at - s <= BOOT_DROP_WINDOW_S for s in service_starts)
        into, times = (boot_dropped, boot_drop_times) if boot else (dropped, drop_times)
        for kind, n in DROPPED.findall(desc):
            if kind != "DriverQueueSize" and int(n):
                into[kind] = into.get(kind, 0) + int(n)
        times.append(when)

    # -- credential access -------------------------------------------------
    for (image, target), (count, granted, when, read) in sorted(
            browser_hits.items(), key=lambda kv: -kv[1][0])[:10]:
        # A memory read by a program running from a staging path (a user
        # profile, Temp, ProgramData) is the theft shape; an installed program
        # under Program Files or Windows doing the same is more often a
        # password manager or an accessibility tool, so it is medium until
        # the owner says otherwise.
        staged = any(part in image.replace("\\", "/").lower() + "/" for part in WRITABLE_DLL_DIRS)
        out.append(_finding(
            "credential access", "high" if read and staged else "medium",
            f"{_base(image)} opened {target} memory",
            f"{count}× with access {granted}, most recently {iso_of(when)}"
            + (", including PROCESS_VM_READ: the browser's decrypted cookies and "
               "session tokens live in that memory, and reading them there is how "
               "they are stolen without touching the cookie database" if read else
               ", without memory-read rights")
            + ". Password managers, accessibility tools and debuggers do this "
              "legitimately; confirm you recognise the program.", image))
    for image, granted, when, read, query_only, guid in lsass_hits:
        if query_only:
            script = _broker_script(guid, eventlog)
            if script:
                out.append(_finding(
                    "credential access", "low",
                    f"{_base(image)} queried LSASS (JARVIS broker)",
                    _lsass_query_detail(granted, iso_of(when)) + f" This process ran "
                    f"JARVIS's reviewed broker script {script} from the "
                    f"administrator-only broker folder.", image))
                continue
            out.append(_finding(
                "credential access", "medium", f"{_base(image)} queried LSASS",
                _lsass_query_detail(granted, iso_of(when)), image))
            continue
        out.append(_finding(
            "credential access", "critical" if read else "high",
            f"{_base(image)} opened LSASS memory",
            f"granted access {granted}"
            + (" including PROCESS_VM_READ, which is what reading credentials "
               "out of LSASS requires" if read else "")
            + f" — {iso_of(when)}. This is the detection that polling cannot "
              f"make, and the technique current intel raises more than any "
              f"other.", image))

    # -- injection ---------------------------------------------------------
    routine = 0
    replayed_injections = set()
    ctrl_addresses = _ctrl_routine_addresses(remote_threads)
    for image, target, when, module, function, address in (
            remote_threads if replay_complete else remote_threads[:40]):
        src, dst = _base(image), _base(target)
        if replay_complete:
            replayed_injections.add((
                f"{src or '<unknown process>'} created a thread inside "
                f"{dst or '<exited process>'}", image))
        nearby = {int(str(address), 16)} if _near_ctrl_routine(
            address, when, ctrl_addresses) else set()
        verdict = thread_verdict(image, target, module, function, address, nearby)
        if verdict is None:
            routine += 1
            continue
        severity, why = verdict
        out.append(_finding(
            "injection", severity,
            f"{src or '<unknown process>'} created a thread inside {dst or '<exited process>'}",
            f"{iso_of(when)} — {why}", image))
    if routine:
        out.append(_finding(
            "injection", "ok",
            f"{routine} remote threads between Windows system processes",
            "the compositor, subsystem and crash handler create threads in "
            "each other as normal operation", "SYSTEM_INJECTORS"))

    for image, kind, when in tampering[:20]:
        out.append(_finding(
            "tampering", "critical",
            f"process image tampering by {_base(image)}",
            f"{kind or 'image replaced'} at {iso_of(when)} — the process on "
            f"disk is not the code that is running, which is hollowing",
            image))

    for name, (count, loader) in sorted(
            unsigned.items(), key=lambda kv: -kv[1][0])[:10]:
        out.append(_finding(
            "tampering", "medium", f"unsigned image loaded: {name}",
            f"loaded {count}×, most recently by {_base(loader)} — an unsigned "
            f"module runs with the full trust of whatever loaded it", loader))

    for loader, loaded, when in sideloads[:20]:
        out.append(_finding(
            "tampering", "high", f"possible DLL side-loading by {_base(loader)}",
            f"unsigned {_base(loaded)} was loaded beside its host executable in a "
            f"user-writable directory at {iso_of(when)}. Portable applications can "
            f"look the same; verify both signatures and origin before containment.", loaded))

    # -- drivers, startup drops, attack-tool pipes, WMI subscriptions ----------
    # Sysmon 6, 11, 17/18 and 19-21 reached the event log for a month with no
    # detector reading them (BLIND-SPOTS-2026-10-22 S15).
    for loaded, signed, sigstat, when, staged in driver_loads[:20]:
        f = _finding(
            "tampering", "critical" if (str(signed).lower() == "false" or staged) else "high",
            f"driver loaded that is unsigned or from a writable path: {_base(loaded)}",
            f"{loaded} at {iso_of(when)}; signed={signed or '?'}, signature status "
            f"{sigstat or '?'}. A kernel driver runs with full control of the machine "
            f"and can hide from every userland check JARVIS makes.", loaded)
        f["techniques"] = ["T1014", "T1068"]
        out.append(f)
    for image, path, when in startup_drops[:20]:
        f = _finding(
            "persistence", "high", f"{_base(image) or 'a process'} wrote to a Startup folder",
            f"{path} at {iso_of(when)}; it runs at the next logon. Installers do this "
            f"for their own tray helpers; confirm you asked for it.", path)
        f["techniques"] = ["T1547"]
        out.append(f)
    for image, path, when in driver_drops[:20]:
        f = _finding(
            "persistence", "high", f"{_base(image) or 'a process'} wrote into the drivers folder",
            f"{path} at {iso_of(when)} by a program outside Windows; a driver file "
            f"written here is loaded at the next boot or service start.", path)
        f["techniques"] = ["T1014", "T1543"]
        out.append(f)
    for image, pipe, tool, tids, eid, when in pipe_hits[:20]:
        # A pipe name is evidence of the tool that normally creates it, not
        # proof: a decoy, a honeypot or an administrator's own PAExec session
        # produce the same event. Credential-dump pipes have no routine use.
        lateral = "T1021" in tids
        f = _finding(
            "lateral movement" if lateral else "credential access",
            "high" if lateral else "critical",
            f"named pipe of {tool} {'created' if eid == 17 else 'connected'} by {_base(image) or '?'}",
            f"{pipe} at {iso_of(when)}. This name is the one {tool} uses; confirm whether "
            f"you or an administrator ran that tool at this time, because a decoy or a "
            f"renamed binary with the same pipe name looks identical here.", image)
        f["techniques"] = list(tids)
        out.append(f)
    for eid, image, operation, name, kind, consumer, destination, user, when in wmi_events[:20]:
        what = {19: "filter", 20: "consumer", 21: "filter-to-consumer binding"}[eid]
        deleted = operation.lower() == "deleted"
        f = _finding(
            "persistence", "medium" if deleted else "critical",
            f"WMI event {what} {operation.lower() or 'changed'}: {name or consumer or '?'}",
            f"{iso_of(when)}; type {kind or '?'}"
            + (f"; consumer {consumer}" if consumer else "")
            + (f"; runs {destination[:200]}" if destination else "")
            + (f"; by {user}" if user else "")
            + f"; process {_base(image) or '?'}. A WMI subscription runs its consumer "
              f"whenever its filter fires, with no file on disk and no autostart key; "
              f"it is the quietest persistence Windows offers. Nothing JARVIS installs "
              f"creates one.", image)
        f["techniques"] = ["T1546"]
        out.append(f)

    for image, cmdline, when in recovery_tamper[:20]:
        out.append(_finding(
            "impact", "critical", f"{_base(image)} attempted to disable Windows recovery",
            f"{iso_of(when)} — {cmdline[:240]}. Destroying shadow copies or recovery "
            f"configuration commonly precedes ransomware encryption; confirm whether an "
            f"administrator or backup tool initiated it.", image))

    # -- renamed system utilities (T1036.003) --------------------------------
    for (image, original), (count, when) in sorted(renamed.items()):
        f = _finding(
            "technique", "high", f"a renamed copy of {original}.exe ran",
            f"{image} is {original}.exe under another name (Sysmon's original file name) "
            f"at {iso_of(when)}" + (f", {count} times" if count > 1 else "")
            + ". Renaming a system tool is done to slip past rules that match on its "
              "name; its command line was also judged as the real tool.", image)
        f["techniques"] = ["T1036"]
        out.append(f)

    # -- techniques recognisable from one process start ----------------------
    for (rule, image), (count, span, when) in technique_hits.items():
        f = _finding(
            "technique", rule.severity, techniques.finding_title(rule),
            f"{_base(image)} at {iso_of(when)}"
            + (f", {count} times" if count > 1 else "")
            + (f": {span}" if span else " (command line withheld: it may carry a secret)")
            + ". The action is what is reported; whether it was authorised is for "
              "you to confirm.", image)
        f["techniques"] = list(rule.tids)
        if rule.origin:
            f["origin"] = "rulepack"     # content, not authority: never acted on unasked
        out.append(f)
    for parent, tids, commands in techniques.bursts(discovery_seen):
        f = _finding("technique", "medium", techniques.burst_title(parent),
                     techniques.burst_detail(tids, commands), parent)
        f["techniques"] = sorted(tids)
        out.append(f)
    for (rule, image), (count, key, when) in registry_hits.items():
        f = _finding(
            "technique", rule.severity, f"{rule.title} ({', '.join(rule.tids)})",
            f"{_base(image) or 'a process'} at {iso_of(when)}"
            + (f", {count} times" if count > 1 else "")
            + f": {key[-120:]}. Seen as the registry write itself, whatever tool made it.", image)
        f["techniques"] = list(rule.tids)
        out.append(f)
    for image, (dests, when) in smb_out.items():
        f = _finding(
            "technique", "high", f"{_base(image)} opened a file-share connection to the internet (T1187)",
            f"SMB to {', '.join(sorted(dests)[:4])} at {iso_of(when)}. Windows offers the "
            f"signed-in account's NTLM credentials to a file share it connects to, which is "
            f"how a link or document is used to capture them.", image)
        f["techniques"] = ["T1187"]
        out.append(f)
    for image, (dests, when) in odd_ports.items():
        f = _finding(
            "technique", "medium", f"{_base(image)} connected out on an unusual port (T1571)",
            f"to {', '.join(sorted(dests)[:4])} at {iso_of(when)}. A script host or system "
            f"utility seldom opens a connection of its own, and this one is not on a web, mail, "
            f"name or remote-shell port. Only the port is judged; what was sent is not seen.", image)
        f["techniques"] = ["T1571"]
        out.append(f)
    if off_runs or off_copies:
        # Asked once a run, and only because a process named a drive that is not
        # known to be an internal disk. A failed read never replaces the last
        # good inventory, and what it leaves unjudged is said, not dropped.
        inventory = volumes if volumes is not None else _read_volumes()
        if inventory is not None and volumes is None and store is not None:
            store.set_meta(VOLUMES_META, json.dumps({"at": now(), "volumes": inventory}))
        if inventory is None:
            was_internal = {letter for letter in known_volumes
                            if techniques.volume_kind(letter, known_volumes) == techniques.INTERNAL}
            off_runs = [r for r in off_runs if techniques.drive_letter(r[0]) not in was_internal]
            off_copies = [(i, s - was_internal, "" if d in was_internal else d, w)
                          for i, s, d, w in off_copies]
        hits, unread = techniques.off_disk(off_runs, off_copies, inventory)
        for tid, kind, letter, image, count, when in hits:
            severity, title, why = techniques.OFF_DISK[tid]
            f = _finding(
                "technique", severity, f"{title.format(kind=techniques.KIND_TEXT[kind])} ({tid})",
                f"{_base(image)}, drive {letter}:, at {iso_of(when)}"
                + (f", {count} times" if count > 1 else "") + f". {why}"
                + (" The drive was gone before its type could be asked for, so it may also "
                   "have been a network drive or a mounted disk image."
                   if kind == techniques.DETACHED else ""), image)
            f["techniques"] = [tid]
            out.append(f)
        if unread:
            out.append(_finding(
                "visibility", "low", "drive types could not be read",
                f"{unread} process events named a drive that is not known to be an internal "
                f"disk, and Windows did not answer when asked what kind of drive it is. They "
                f"were not judged as removable-media use; this is not a clean result.", CHANNEL))
    for label, names in techniques.dga_bursts(failed_lookups):
        f = _finding(
            "technique", "medium", f"{label} looked up many names that do not exist (T1568)",
            f"{len(names)} distinct non-existent names in ten minutes, for example "
            f"{', '.join(sorted(names)[:3])}. Software that generates its contact domains "
            f"tries many before one answers; a misconfigured program can look the same.",
            label)
        f["techniques"] = ["T1568"]
        out.append(f)

    # -- the sensor's own losses ---------------------------------------------
    verdict = drop_verdict(" ".join(f"{k}:{v}" for k, v in dropped.items()))
    if verdict:
        severity, total, worst = verdict
        out.append(_finding(
            "telemetry loss", severity, "Sysmon dropped events before logging them",
            f"{total} events lost from the driver queue ({worst}), most recently "
            f"{iso_of(max(drop_times))}. Nothing that reads the log can detect what "
            f"never reached it. The usual cause is one rule matching a flood of "
            f"events — narrow the noisiest event type in the Sysmon configuration.",
            CHANNEL))

    if boot_dropped:
        total = sum(boot_dropped.values())
        worst = ", ".join(f"{k} {v}" for k, v in sorted(boot_dropped.items(), key=lambda kv: -kv[1]))
        out.append(_finding(
            "telemetry loss", "medium", BOOT_DROP_TITLE,
            f"{total} events queued by the driver before the Sysmon service started "
            f"did not fit its queue ({worst}), last at {iso_of(max(boot_drop_times))}. "
            f"The window is bounded: from boot until the service starts, when "
            f"configuration filtering begins, so most of these are event types the "
            f"policy would discard. Process starts in that window are treated as "
            f"unknown, never as verified.", CHANNEL))

    # -- correlation with the intelligence corpus --------------------------
    if store is not None:
        out += _correlate(store, dns_names, proc_hashes)

    # Which registry key families this machine's policy has been seen to record:
    # the coverage map counts a registry rule as proof only for those.
    if store is not None and registry_seen:
        try:
            known = json.loads(store.get_meta(REGISTRY_RECORDED_META, "") or "{}")
        except (TypeError, ValueError):
            known = {}
        known.update(dict.fromkeys(registry_seen, now()))
        store.set_meta(REGISTRY_RECORDED_META, json.dumps(known))

    # -- security-relevant registry families written by an unexpected kind of program
    for (_fid, image), (count, key, when, tids, what, kind) in family_hits.items():
        title, detail = regwatch.describe(image, what, kind, key, count, iso_of(when))
        f = _finding("technique", regwatch.SEVERITY, title, detail, image)
        f["techniques"] = list(tids)
        out.append(f)

    # -- community rules (Sigma), judged per install --------------------------
    # After the built-in rules and never instead of them. A replay (no store)
    # learns nothing and returns every match.
    def _community(severity, title, detail, image):
        return _finding("technique", severity, title, detail, image or CHANNEL)

    if community_rules is None:
        community_rules = not probing
    if community_rules:
        out += community.findings(
            sigma.WIN_PROC, [e for e in events if int(e.get("id") or 0) == 1],
            lambda e: (e.get("image") or "", e.get("parent") or "", iso_of(e.get("time")),
                       e.get("cmdline") or ""),
            _community, store=store, now=now())
        out += community.findings(
            sigma.WIN_REG, [dict(e, event_type="SetValue") for e in events if int(e.get("id") or 0) == 13],
            lambda e: (e.get("image") or "", "", iso_of(e.get("time")), e.get("reg_key") or ""),
            _community, store=store, now=now())

    # Persist and re-surface. Reading incrementally means each run sees only
    # new events, so anything worth reporting has to outlive its own snapshot.
    if store is not None:
        if replay_complete:
            # Only replace a verdict when its underlying event was actually
            # replayed. A formerly observed event absent from retained source
            # evidence is uncertainty, not proof that the alert was false.
            for title, image in replayed_injections:
                store.db.execute(
                    "DELETE FROM sysmon_hits WHERE category='injection' "
                    "AND title=? AND where_=?", (title[:300], image[:400]))
        out = _remember(store, out, hours, eventlog)
        if native is not None and incremental and data.get('complete'):
            store.set_meta('sysmon_eventlog_seq', through)
            store.set_meta('sysmon_last_run', query_started)
            store.commit()
        elif native is None and incremental and paged_to is not None:
            # Floored: a cursor that re-reads a second is safe, one that skips is not.
            store.set_meta('sysmon_last_run', int(paged_to))
            store.commit()
        elif native is None and incremental and data.get('complete'):
            # Findings are durable first. A crash here replays evidence instead
            # of skipping unseen records. The native store makes this atomic.
            store.set_meta('sysmon_last_run', query_started)
            store.commit()
        if replay_complete:
            store.set_meta('sysmon_thread_rules', THREAD_RULES)
            store.commit()

    out.append(_finding(
        "telemetry", "ok" if data.get('complete') else "medium",
        f"Sysmon delivered {len(events)} events from {window}",
        f"{len(dns_names)} distinct DNS names and {len(proc_hashes)} process "
        f"hashes were checked against the indicator corpus; "
        f"{len(lsass_hits)} unexpected LSASS opens, "
        f"{len(remote_threads)} remote threads", CHANNEL))
    return sort_findings(out)


_BROKER_FILE = re.compile(
    r'-File\s+"?C:\\ProgramData\\Jarvis\\Broker\\([A-Za-z0-9_.-]+\.ps1)"?(\s|$)', re.I)


def _broker_script(guid, eventlog=None):
    """The broker script a process ran, when its recorded start shows JARVIS's
    elevated broker running a staged script that still matches the reviewed
    checkout; "" otherwise. The broker folder is administrator-only."""
    if not guid:
        return ""
    try:
        from jarvis.platform import broker
        log = EventLog(eventlog) if eventlog else EventLog()
    except (LogError, OSError):
        return ""
    try:
        if log.db is None:
            return ""
        row = log.db.execute("SELECT cmdline FROM processes WHERE guid=?", (guid,)).fetchone()
    except Exception:
        return ""
    finally:
        log.close()
    m = _BROKER_FILE.search(str(row[0] if row else ""))
    if not m or m.group(1) not in broker.SCRIPTS.values() or m.group(1) in broker.drifted():
        return ""
    return m.group(1)


def _lsass_query_detail(granted, when):
    return (f"granted access {granted} — {when}. Query-only rights cannot read "
            f"LSASS memory; they can open its token, so an unfamiliar process "
            f"doing this is still worth a look.")


def iso_of(t):
    """Sysmon timestamps arrive as ISO strings already; keep them readable."""
    return (t or "")[:19].replace("T", " ")


def _remember(store, findings, hours, eventlog=None):
    """Store this run's real findings, and return everything still in window.

    The `ok` rows are per-run status and are not kept — only things that
    happened. A repeat of the same detection updates its timestamp rather than
    accumulating duplicates.
    """
    ts = now()
    # Only detections are remembered. A visibility or telemetry finding
    # describes one run: remembered, a single capped query kept Sysmon
    # "partial" — and the whole Active threats area blind — for a day after
    # the reads were complete again.
    keep = [f for f in findings if f["severity"] != "ok" and f["category"] not in RUN_STATE]
    for f in keep:
        store.db.execute(
            """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
               VALUES(?,?,?,?,?,?)
               ON CONFLICT(category,title,where_) DO UPDATE SET
                   ts=excluded.ts, severity=excluded.severity,
                   detail=excluded.detail""",
            (ts, f["category"], f["severity"], f["title"][:300],
             f["detail"][:600], f["where"][:400]))
    # sysmon_linux writes into the same table under its own 'sysmon-linux'
    # category and manages its own retention; this Windows collector must not
    # touch those rows or it re-emits Linux findings under host=win.
    store.db.execute(
        "DELETE FROM sysmon_hits WHERE ts < ? AND category != 'sysmon-linux'",
        (ts - 30 * 86400,))
    store.commit()

    store.db.execute("DELETE FROM sysmon_hits WHERE category IN (%s)"
                     % ",".join("?" * len(RUN_STATE)), tuple(RUN_STATE))
    since = ts - hours * 3600
    out = [f for f in findings if f["severity"] == "ok" or f["category"] in RUN_STATE]
    for r in store.db.execute(
            "SELECT * FROM sysmon_hits WHERE ts >= ? AND category != 'sysmon-linux' "
            "ORDER BY ts DESC", (since,)).fetchall():
        detail = r["detail"]
        # A stored domain match is re-judged every run, like the corpus is at
        # match time: a vetting or popularity fix must clear yesterday's false
        # "attacker domain" now, not when it ages out of the window.
        if r["category"] == "intel match" and " domain: " in r["title"]:
            m = warninglist.match_domain(store, r["title"].rsplit(" domain: ", 1)[1])
            if not m:
                continue
            if m["severity"] != r["severity"]:
                continue   # re-emitted at its new strength if it recurs
        severity, title = r["severity"], r["title"]
        # LSASS rows stored before query-only rights were told apart claimed
        # a memory read. Re-judge them from their recorded mask and migrate
        # the row, so a later repeat updates it instead of duplicating it.
        if r["category"] == "credential access" and title.endswith(" opened LSASS memory"):
            m = re.match(r"granted access (0x[0-9a-fA-F]+) — ([^.]*)", detail)
            mask = int(m.group(1), 16) if m else 0
            if mask and not mask & ~QUERY_ONLY:
                severity = "medium"
                title = title[:-len(" opened LSASS memory")] + " queried LSASS"
                detail = _lsass_query_detail(m.group(1), m.group(2))
                store.db.execute(
                    """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(category,title,where_) DO UPDATE SET
                           ts=MAX(ts, excluded.ts)""",
                    (r["ts"], r["category"], severity, title, detail[:600], r["where_"]))
                store.db.execute(
                    "DELETE FROM sysmon_hits WHERE category=? AND title=? AND where_=?",
                    (r["category"], r["title"], r["where_"]))
                store.commit()
        if r["category"] == "telemetry loss" and title == "Sysmon dropped events before logging them":
            m = re.search(r"most recently (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", detail)
            if m and _boot_backlog(m.group(1), eventlog):
                # Stored before boot backlog was told apart from runtime loss.
                severity, title = "medium", BOOT_DROP_TITLE
                detail = detail.split(". Nothing that reads")[0] + (
                    ". Reported with the service's own start at boot: the driver's "
                    "backlog before filtering began, a bounded window.")
                store.db.execute(
                    """INSERT INTO sysmon_hits(ts,category,severity,title,detail,where_)
                       VALUES(?,?,?,?,?,?) ON CONFLICT(category,title,where_)
                       DO UPDATE SET ts=MAX(ts, excluded.ts)""",
                    (r["ts"], r["category"], severity, title, detail[:600], r["where_"]))
                store.db.execute(
                    "DELETE FROM sysmon_hits WHERE category=? AND title=? AND where_=?",
                    (r["category"], r["title"], r["where_"]))
                store.commit()
        if ts - r["ts"] > 900:
            detail += f"  [last seen {iso(r['ts'])}]"
        out.append(_finding(r["category"], severity, title, detail, r["where_"]))
    return out


def _correlate(store, dns_names, proc_hashes):
    """Match observed names and hashes against stored indicators.

    This is the payoff of having both halves: the corpus stops being a thing
    checked against current state and becomes a thing checked against
    everything that happened while nobody was looking.
    """
    out = []
    for name, procs in dns_names.items():
        m = warninglist.match_domain(store, name)
        if m:
            hit = m["hit"]
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            weak = (" — the host is shared by many sites, so resolving it is weak evidence"
                    if m["severity"] == "low" else "")
            out.append(_finding(
                "intel match", m["severity"],
                f"a process resolved a {m['qualifier']} domain: {name}",
                f"queried by {', '.join(sorted(procs))} — {label} "
                f"(via {hit['source']}){weak}", hit["source_url"]))

    for digest, (image, when) in proc_hashes.items():
        hit = store.db.execute(
            "SELECT context, source_url, malware, source FROM indicators "
            "WHERE kind='sha256' AND norm=? AND status='active'",
            (digest,)).fetchone()
        if hit:
            label = hit["malware"] or hit["context"] or "listed in threat intelligence"
            out.append(_finding(
                "intel match", "critical",
                f"a process matching a known sample ran: {_base(image)}",
                f"SHA-256 {digest} at {iso_of(when)} — {label} "
                f"(via {hit['source']})", image))
    return out


def sort_findings(f):
    return sorted(f, key=lambda x: (SEV_ORDER.get(x["severity"], 9),
                                    CAT_ORDER.get(x["category"], 9), x["title"]))

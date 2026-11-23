"""Sustained process consumption and whole-system capacity pressure."""

import json
import math
import os
import shutil
import time

from jarvis.core.finding import LOCAL_HOST
from jarvis.platform import host as machine

from . import monitor

_META = "resourcewatch_sample_v1"
PROFILE_META = "resource_profile_v1"
# Where this engine runs from, so its processes are named wherever it is installed.
_ENGINE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))).lower() + "/"


def _owner(proc):
    """Stable resource bucket; classification only, never a threat verdict."""
    name = str(proc.get("name") or "").lower()
    text = " ".join(str(proc.get(k) or "") for k in ("name", "exe", "cmdline")).lower()
    if "ollama" in text:
        return "ollama"
    if name in ("chrome.exe", "msedge.exe", "brave.exe", "chromium", "chrome"):
        return "browser"
    if "jarvis.service.collector_worker" in text:
        return "collector workers"
    if "-m jarvis" in text or _ENGINE_ROOT in text or "/opt/jarvis/" in text:
        return "jarvis engine"
    if "powershell" in name and "jarvis" in text:
        return "collector interop"
    return "other"


# The per-table breakdown walks every page of the database (dbstat). On an
# 882 MB store that cost 6.8 s of CPU and pulled ~330 MB into the process
# through the memory map, every five minutes (measured 2026-11-02). The total
# size stays fresh each run; the breakdown is rebuilt daily, or sooner when
# the file has grown or shrunk by a tenth, and says when it was taken.
TABLES_MAX_AGE_S = 86400
TABLES_CHANGE = 0.10


def _database_profile(store, previous=None, now_ts=None):
    """{bytes, tables, tables_at, tables_bytes}: size now, breakdown as of tables_at."""
    now_ts = time.time() if now_ts is None else now_ts
    size = 0
    try:
        size = os.path.getsize(store.path)
    except OSError:
        pass
    prev = previous if isinstance(previous, dict) else {}
    tables, at, at_bytes = prev.get("tables") or [], prev.get("tables_at"), prev.get("tables_bytes") or 0
    fresh = (tables and isinstance(at, (int, float)) and now_ts - at < TABLES_MAX_AGE_S
             and at_bytes and abs(size - at_bytes) / at_bytes < TABLES_CHANGE)
    if not fresh:
        try:
            rows = store.db.execute(
                "SELECT name, SUM(pgsize) AS bytes FROM dbstat "
                "GROUP BY name ORDER BY bytes DESC LIMIT 8").fetchall()
            tables = [{"name": row[0], "bytes": int(row[1] or 0)} for row in rows]
            at, at_bytes = now_ts, size
        except Exception:
            tables, at, at_bytes = [], None, 0
    return {"bytes": size, "tables": tables, "tables_at": at, "tables_bytes": at_bytes}


def _previous_database_profile(store):
    try:
        return (json.loads(store.get_meta(PROFILE_META, "") or "{}") or {}).get("database")
    except (ValueError, TypeError, AttributeError):
        return None


def _finding(severity, title, detail, where="", host=LOCAL_HOST):
    return {"category": "resource", "severity": severity, "title": title,
            "detail": detail, "where": where, "host": host}


CGROUP_META = "resourcewatch_cgroup_v1"
CGROUP_ROOT = "/sys/fs/cgroup"
# memory.high throttle events per sample that mean the daemon is living at its
# ceiling rather than brushing it: one per five seconds over a five-minute
# sample. Measured 2026-10-22: 20 per minute at 1.47 GiB against a 1.5 GiB
# MemoryHigh, with the service's own RSS at 0.3 GiB and the rest page cache
# of its 0.77 GiB database.
CGROUP_THROTTLE_EVENTS = 60
CGROUP_CEILING_SHARE = 0.9


def service_cgroup(root=CGROUP_ROOT, procfile="/proc/self/cgroup"):
    """Memory accounting of the cgroup this process runs in (cgroup v2), or
    None when there is none to read. Never raises."""
    try:
        with open(procfile, encoding="ascii", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return None
    path = ""
    for line in lines:
        if line.startswith("0::"):
            path = line[3:]
    if not path or path == "/":
        return None
    base = os.path.join(root, path.lstrip("/"))

    def number(name):
        try:
            with open(os.path.join(base, name), encoding="ascii", errors="replace") as fh:
                text = fh.read().strip()
        except OSError:
            return None
        if text == "max":
            return None
        try:
            return int(text)
        except ValueError:
            return None

    events = {}
    try:
        with open(os.path.join(base, "memory.events"), encoding="ascii", errors="replace") as fh:
            for line in fh:
                key, _, value = line.partition(" ")
                events[key] = int(value)
    except (OSError, ValueError):
        pass
    stat = {}
    try:
        with open(os.path.join(base, "memory.stat"), encoding="ascii", errors="replace") as fh:
            for line in fh:
                key, _, value = line.partition(" ")
                if key in ("anon", "file", "swapcached"):
                    stat[key] = int(value)
    except (OSError, ValueError):
        pass
    pressure = None
    try:
        with open(os.path.join(base, "memory.pressure"), encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("full "):
                    for field in line.split():
                        if field.startswith("avg60="):
                            pressure = float(field[6:])
    except (OSError, ValueError):
        pass
    return {"path": path, "current": number("memory.current"),
            "high": number("memory.high"), "max": number("memory.max"),
            "events": events, "stat": stat, "pressure_full_avg60": pressure}


def _cgroup_findings(store, data, now):
    """The daemon's own memory ceiling, judged on throttle events between two
    samples. The first sample only records counters."""
    if not data:
        return []
    try:
        previous = json.loads(store.get_meta(CGROUP_META, "{}") or "{}")
    except (TypeError, ValueError):
        previous = {}
    if not isinstance(previous, dict) or previous.get("path") != data.get("path"):
        previous = {}
    events = data.get("events") or {}
    before = previous.get("events") or {}
    store.set_meta(CGROUP_META, json.dumps(
        {"at": now, "path": data.get("path"), "events": events,
         "current": data.get("current"), "high": data.get("high")}))
    if not previous:
        return []
    out = []
    where = os.path.join(CGROUP_ROOT, str(data.get("path", "")).lstrip("/"))
    killed = int(events.get("oom_kill", 0)) - int(before.get("oom_kill", 0))
    if killed > 0:
        out.append(_finding(
            "high", "JARVIS was OOM-killed inside its own memory limit",
            f"{killed} process(es) of the service were killed since the last "
            "sample because the unit's MemoryMax was exhausted; collection "
            "restarted from scratch each time. Raise MemoryMax in the unit "
            "drop-in or shrink the database.", where))
    high = data.get("high")
    current = data.get("current")
    throttled = int(events.get("high", 0)) - int(before.get("high", 0))
    if (high and current is not None and current >= high * CGROUP_CEILING_SHARE
            and throttled >= CGROUP_THROTTLE_EVENTS):
        stat = data.get("stat") or {}
        pressure = data.get("pressure_full_avg60")
        out.append(_finding(
            "medium", "JARVIS is being throttled at its memory ceiling",
            f"the service cgroup holds {current / 1024**2:.0f} MiB against a "
            f"MemoryHigh of {high / 1024**2:.0f} MiB and crossed it {throttled} "
            "times since the last sample"
            + (f" ({stat.get('anon', 0) / 1024**2:.0f} MiB process memory, "
               f"{stat.get('file', 0) / 1024**2:.0f} MiB database page cache)"
               if stat else "")
            + (f"; {pressure:.1f}% of the last minute fully stalled on memory"
               if pressure is not None else "")
            + ". Every collector pays reclaim latency at this ceiling, which "
            "is how the scheduler comes to look stalled to the watchdogs. "
            "Raise MemoryHigh/MemoryMax in the jarvis.service drop-in "
            "(systemctl edit jarvis.service) or reduce database retention.",
            where))
    return out


def _memory_pressure():
    try:
        values = {}
        with open("/proc/meminfo", errors="replace") as fh:
            for line in fh:
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
        return values["MemTotal"], values["MemAvailable"]
    except (OSError, ValueError, KeyError, IndexError):
        return 0, 0


def _guest_cache():
    """Bytes of guest memory that are reclaimable file cache, or None.

    Inside WSL, Linux page cache is free memory to the guest but committed
    memory to Windows (vmmemWSL), so it is the part of the VM that grows
    under "normal apps" without any program asking for it.
    """
    try:
        values = {}
        with open("/proc/meminfo", errors="replace") as fh:
            for line in fh:
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
        return max(0, values["Cached"] + values.get("SReclaimable", 0)
                   - values.get("Shmem", 0))
    except (OSError, ValueError, KeyError, IndexError):
        return None


# Commit, not free RAM, is what runs out: when committed bytes reach the
# commit limit Windows cannot back the WSL VM's pages and the guest dies with
# a fake "Fatal machine check" (measured 2026-10-11 at 98-100% commit; see
# microsoft/WSL#41649). Starting points, not a validated predictor.
COMMIT_MEDIUM_PCT = 85
COMMIT_HIGH_PCT = 95
# Free space on the Windows system drive below which the WSL disk image and
# the page file can no longer grow. Measured 2026-10-11 and 2026-10-23: both
# times the drive hit 0.1 GB free, guest writes failed, the VM hung and WSL
# relaunched it (journal "corrupted or uncleanly shut down"). A fixed-size
# 8 GB swap file survives this; the dynamically growing ext4.vhdx does not.
SYS_DRIVE_CRITICAL_BYTES = 2 * 1024 ** 3
SYS_DRIVE_HIGH_BYTES = 8 * 1024 ** 3
PANIC_WINDOW_S = 24 * 3600
HOST_MEMORY_PS = r"""
$o=[ordered]@{}
try {
  $m=Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory -ErrorAction Stop
  $o.committed=[double]$m.CommittedBytes; $o.limit=[double]$m.CommitLimit
} catch { $o.error=[string]$_.Exception.Message }
$o.vm=[double](Get-Process -Name vmmemWSL,vmmem -ErrorAction SilentlyContinue | Measure-Object PrivateMemorySize64 -Sum).Sum
$sw=$null
try { $line=(Get-Content (Join-Path $env:USERPROFILE '.wslconfig') -ErrorAction Stop | Where-Object { $_ -match '^\s*swapFile\s*=' } | Select-Object -First 1)
  if ($line) { $sw=($line -split '=',2)[1].Trim().Replace('\\','\') } } catch {}
if (-not $sw) { $sw=(Get-ChildItem $env:TEMP -Directory -ErrorAction SilentlyContinue | Where-Object Name -match '^[0-9A-F]{8}-' | Sort-Object LastWriteTime -Descending |
  ForEach-Object { Join-Path $_.FullName 'swap.vhdx' } | Where-Object { Test-Path $_ } | Select-Object -First 1) }
if ($sw -and (Test-Path $sw)) { try { $o.swap_file=[double](Get-Item $sw).Length
  $o.swap_drive_free=[double](Get-PSDrive ((Split-Path $sw -Qualifier).TrimEnd(':')) -ErrorAction Stop).Free } catch {} }
# The Windows system drive holds the WSL disk image, the page file and (by
# default) the WSL swap file; when it fills, none of them can grow.
try { $o.sys_drive_free=[double](Get-PSDrive $env:SystemDrive.TrimEnd(':') -ErrorAction Stop).Free } catch {}
try { $o.host_free=[double](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).FreePhysicalMemory*1024 } catch {}
$o.apps=@(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -notmatch '^vmmem' } |
  Group-Object ProcessName | ForEach-Object { [pscustomobject]@{name=$_.Name; bytes=[double]($_.Group | Measure-Object PrivateMemorySize64 -Sum).Sum} } |
  Sort-Object bytes -Descending | Select-Object -First 4)
$o.panics=@(Get-ChildItem (Join-Path $env:TEMP 'wsl-crashes') -Filter 'kernel-panic-*.txt' -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddSeconds(-86400) } | Sort-Object LastWriteTime -Descending | Select-Object -First 5 |
  ForEach-Object { [pscustomobject]@{at=[double]([DateTimeOffset]$_.LastWriteTime).ToUnixTimeSeconds(); mce=[bool](Select-String -Path $_.FullName -Pattern 'Fatal machine check' -SimpleMatch -Quiet)} })
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 4 -Compress)))
"""


def _host_memory():
    """One bounded Windows read; None when the bridge or counters failed."""
    try:
        from jarvis.platform.windows import ps_json
        data = ps_json(HOST_MEMORY_PS, timeout=25)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


# 2026-10-11 14:18: C: reached 0 bytes free, WSL's swap disk could not grow,
# the kernel logged 110 "Write-error on swap-device" lines in 20 minutes, and
# the daemon died with SIGBUS (a JARVIS and a Claude Code process had died the
# same way at 01:35). Linux sees plenty of free swap and never warns.
SWAP_ERROR_MARKS = ("Write-error on swap-device", "Read-error on swap-device")
KERNEL_IO_SINCE_META = "resourcewatch_kernel_io_since_v1"


def _guest_swap():
    """(SwapTotal, SwapUsed) bytes from /proc/meminfo, or (None, None)."""
    try:
        values = {}
        with open("/proc/meminfo", errors="replace") as fh:
            for line in fh:
                name, value = line.split(":", 1)
                values[name] = int(value.split()[0]) * 1024
        total = values["SwapTotal"]
        return total, max(0, total - values["SwapFree"])
    except (OSError, ValueError, KeyError, IndexError):
        return None, None


def _kernel_io_errors(since):
    """(swap errors, other block I/O errors) logged since `since`, or None.

    One bounded journalctl read of kernel messages; None when the journal
    cannot be read, so an unreadable log is never reported as clean."""
    import subprocess
    try:
        r = subprocess.run(["journalctl", "-k", "--since", f"@{int(since)}", "-o", "cat",
                            "--no-pager", "-q"], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    text = r.stdout[-4_000_000:].decode("utf-8", "replace")
    swap_devs = set()
    try:
        with open("/proc/swaps", errors="replace") as fh:
            swap_devs = {line.split()[0].rsplit("/", 1)[-1] for line in fh.readlines()[1:]
                         if line.split()}
    except OSError:
        pass
    swap = other = 0
    for line in text.splitlines():
        if any(m in line for m in SWAP_ERROR_MARKS):
            swap += 1
        elif "I/O error, dev " in line or "Buffer I/O error on dev" in line:
            dev = line.split(" dev ", 1)[1].split(",")[0].split()[0] if " dev " in line else ""
            if dev not in swap_devs:
                other += 1
    return swap, other


def _offline_swap_devices():
    """Swap block devices the SCSI layer has taken offline; [] when none or unreadable."""
    out = []
    try:
        with open("/proc/swaps", errors="replace") as fh:
            devs = [line.split()[0].rsplit("/", 1)[-1] for line in fh.readlines()[1:] if line.split()]
    except OSError:
        return out
    for dev in devs:
        try:
            with open(f"/sys/block/{dev}/device/state", errors="replace") as fh:
                if fh.read().strip() not in ("running", ""):
                    out.append(dev)
        except OSError:
            continue
    return out


def _swap_findings(store, data, now, errors=None, swap=None, offline=None):
    """Swap failing now, or unable to grow when it is needed. Metadata only."""
    findings = []
    offline = _offline_swap_devices() if offline is None else offline
    if offline:
        findings.append(_finding(
            "high", "WSL swap device is offline",
            f"swap device {', '.join(offline)} was taken offline after I/O errors; every "
            "swapped-out page is unreadable and processes that touch one crash with "
            "SIGBUS. It does not recover by itself: as root, write 'running' to "
            "/sys/block/<dev>/device/state, or restart WSL with wsl --shutdown",
            "WSL swap device"))
    since = None
    try:
        since = float(store.get_meta(KERNEL_IO_SINCE_META, "") or 0) or None
    except (TypeError, ValueError):
        since = None
    if errors is None:
        errors = _kernel_io_errors(since or now - 600)
    if errors is not None:
        store.set_meta(KERNEL_IO_SINCE_META, str(now))
        swap_errors, io_errors = errors
        if swap_errors:
            findings.append(_finding(
                "high", "WSL swap device is failing",
                f"{swap_errors} swap write/read errors in the kernel log since the last "
                "check; Linux processes with swapped-out memory can be killed with SIGBUS "
                "(the JARVIS daemon crashed this way on 2026-10-11). The swap file usually "
                "fails because its Windows drive is full", "WSL swap device"))
        if io_errors:
            findings.append(_finding(
                "high", "WSL disk I/O errors",
                f"{io_errors} block I/O errors in the kernel log since the last check; "
                "the WSL disk image or a mounted disk could not be written", "WSL block devices"))
    if isinstance(data, dict):
        try:
            sys_free = float(data.get("sys_drive_free"))
        except (TypeError, ValueError):
            sys_free = None
        if sys_free is not None and math.isfinite(sys_free) and sys_free < SYS_DRIVE_HIGH_BYTES:
            critical = sys_free < SYS_DRIVE_CRITICAL_BYTES
            findings.append(_finding(
                "critical" if critical else "high",
                "Windows system drive nearly full: WSL can crash",
                f"only {_gib(sys_free)} free. The WSL disk image (ext4.vhdx) grows with "
                "every write inside Linux and the Windows page file grows under memory "
                "pressure; when the drive is full both fail, Linux processes crash on "
                "I/O errors and WSL relaunches the VM (measured 2026-10-11 and "
                "2026-10-23 at 0.1 GB free). Free space on this drive first, then "
                "reclaim the image: inside WSL clear package caches (uv, go, docker), "
                "then from Windows `wsl --shutdown` and `wsl --manage Ubuntu "
                "--set-sparse true` or Optimize-VHD so freed blocks return to Windows."
                + (" This is the state in which the VM died before." if critical else ""),
                "Windows system drive", host="win"))
    total, used = swap if swap is not None else _guest_swap()
    if isinstance(data, dict) and total:
        try:
            swap_file = float(data.get("swap_file"))
            free = float(data.get("swap_drive_free"))
        except (TypeError, ValueError):
            swap_file = free = None
        if swap_file is not None and free is not None and math.isfinite(free):
            growth = max(0.0, total - swap_file)
            if growth > free:
                findings.append(_finding(
                    "high", "WSL swap cannot grow",
                    f"the WSL swap file can still grow by {_gib(growth)} but its drive has "
                    f"only {_gib(free)} free ({_gib(used or 0)} of {_gib(total)} swap in use); "
                    "once it hits the full drive, swap writes fail and processes crash",
                    "WSL swap file", host="win"))
    return findings


def _gib(n):
    return f"{n / 1024**3:.1f} GiB"


def _host_memory_findings(data, guest_cache, now):
    """Findings plus a metadata-only profile for the Windows commit budget."""
    if not data:
        return [_finding(
            "medium", "host memory commit unmeasured",
            "the Windows commit counters could not be read this run; host memory "
            "headroom is unknown, not healthy", host="win")], {"status": "unmeasured"}
    findings = []
    try:
        committed, limit = float(data.get("committed")), float(data.get("limit"))
    except (TypeError, ValueError):
        committed = limit = float("nan")
    if not (math.isfinite(committed) and math.isfinite(limit)) or limit <= 0 \
            or committed < 0 or committed > limit * 1.02:
        findings.append(_finding(
            "medium", "host memory commit unmeasured",
            "Windows returned missing or inconsistent commit counters; host memory "
            "headroom is unknown, not healthy", host="win"))
        profile = {"status": "unmeasured"}
    else:
        pct = committed / limit * 100
        vm = max(0.0, float(data.get("vm") or 0))
        apps = [a for a in (data.get("apps") or []) if isinstance(a, dict)]
        profile = {"status": "measured", "at": now, "committed": committed,
                   "limit": limit, "pct": round(pct, 1), "wsl_vm": vm,
                   "guest_cache": guest_cache,
                   "apps": [{"name": str(a.get("name") or "?")[:64],
                             "bytes": float(a.get("bytes") or 0)} for a in apps]}
        if pct >= COMMIT_MEDIUM_PCT:
            parts = [f"Windows has committed {_gib(committed)} of its {_gib(limit)} "
                     f"limit ({pct:.0f}%)"]
            if vm:
                share = f"the WSL VM holds {_gib(vm)}"
                if guest_cache:
                    share += (f", of which about {_gib(min(guest_cache, vm))} is Linux "
                              "file cache, which WSL only hands back to Windows when the guest goes idle")
                parts.append(share)
            if profile["apps"]:
                parts.append("largest Windows apps: " + ", ".join(
                    f"{a['name']} {_gib(a['bytes'])}" for a in profile["apps"][:3]))
            parts.append("at the limit Windows cannot back the VM's memory and WSL crashes")
            findings.append(_finding(
                "high" if pct >= COMMIT_HIGH_PCT else "medium",
                "host memory commit pressure", "; ".join(parts), "Windows commit charge",
                host="win"))

    panics = []
    for item in data.get("panics") or []:
        try:
            at = float(item.get("at"))
        except (TypeError, ValueError, AttributeError):
            continue
        if 0 <= now - at <= PANIC_WINDOW_S:
            panics.append({"at": at, "mce": bool(item.get("mce"))})
    profile["guest_panics_24h"] = len(panics)
    if panics:
        latest = max(panics, key=lambda p: p["at"])
        cause = ("its report shows the \"Fatal machine check\" signature that Hyper-V "
                 "raises when the host cannot back guest memory"
                 if latest["mce"] else "its report does not name a memory cause")
        findings.append(_finding(
            "medium", "WSL VM crashed",
            f"{len(panics)} WSL kernel panic report(s) in the last 24 h, latest "
            f"{_duration(max(0.0, now - latest['at']))} ago; {cause}",
            "%TEMP%\\wsl-crashes", host="win"))
    return findings, profile


def audit(store, hosts=("wsl", "win")):
    """Compare cumulative CPU counters with the prior five-minute sample."""
    sampled_at = time.time()
    processes = monitor.collect_all(hosts=hosts, with_sockets=False)
    try:
        previous = json.loads(store.get_meta(_META, "{}") or "{}")
    except (TypeError, ValueError):
        previous = {}
    if not isinstance(previous, dict):
        previous = {}
    elapsed = sampled_at - float(previous.get("ts", sampled_at))
    cpu_count = max(1, os.cpu_count() or 1)
    old = previous.get("processes", {}) if isinstance(previous, dict) else {}
    current = {}
    findings = []
    cpu_gaps = set()
    owners = {}

    for proc in processes:
        # Windows PID 0 is the idle-time counter. Its socket attribution label
        # must not turn unused CPU capacity into a resource-pressure alert.
        if proc.get("pid") in (None, 0, "0"):
            continue
        host = proc.get("host") or "wsl"
        key = f"{proc.get('host')}:{proc.get('pid')}:{proc.get('fp')}"
        cpu_seconds = max(0.0, float(proc.get("cpu_seconds") or 0))
        rss = max(0, int(proc.get("rss_bytes") or 0))
        current[key] = {"cpu": cpu_seconds}
        prior = old.get(key) if isinstance(old, dict) else None
        # WSL can have fewer virtual CPUs than the Windows host. Never divide
        # Windows CPU counters by the Linux VM's processor count.
        capacity = proc.get("logical_cpus", 0) if host == "win" else cpu_count
        cpu_pct = None
        if not capacity:
            cpu_gaps.add(host)
        elif prior is not None and elapsed > 0:
            delta = cpu_seconds - float(prior.get("cpu", 0))
            measured = delta / elapsed / capacity * 100
            if math.isfinite(measured) and 0 <= measured <= 100:
                cpu_pct = measured
            else:
                # Counter resets, PID reuse, or clock discontinuities cannot
                # establish sustained consumption. Rebaseline, don't clamp an
                # impossible measurement into a HIGH process alert.
                cpu_gaps.add(host)
        elif prior is not None:
            cpu_gaps.add(host)
        owner = _owner(proc)
        bucket = owners.setdefault(owner, {"rss_bytes": 0, "cpu_pct": 0.0,
                                           "processes": 0})
        bucket["rss_bytes"] += rss
        bucket["processes"] += 1
        if cpu_pct is not None:
            bucket["cpu_pct"] += cpu_pct
        severe = rss >= 4 * 1024**3 or (cpu_pct is not None and cpu_pct >= 50)
        notable = rss >= 1536 * 1024**2 or (cpu_pct is not None and cpu_pct >= 20)
        if severe or notable:
            cpu_detail = (f"{cpu_pct:.1f}% of total CPU over the last {_duration(elapsed)}"
                          if cpu_pct is not None else "CPU usage unavailable for this sample")
            findings.append(_finding(
                "high" if severe else "medium", "resource-intensive process",
                f"{proc.get('name') or '?'} [pid {proc.get('pid')}] uses "
                f"{rss / 1024**3:.1f} GiB resident memory and {cpu_detail}",
                proc.get("exe") or "", proc.get("host") or "wsl"))

    for host in sorted(cpu_gaps):
        findings.append(_finding(
            "medium", "process CPU measurement unavailable",
            "Missing host CPU capacity or inconsistent counters/timestamps; "
            "affected samples were rebaselined, memory checks remain active", host=host))

    total, available = _memory_pressure()
    if total:
        pct = available / total * 100
        if pct < 10:
            findings.append(_finding(
                "high" if pct < 5 else "medium", "system memory pressure",
                f"only {available / 1024**3:.1f} GiB ({pct:.1f}%) remains available",
                "/proc/meminfo"))

    if machine.has_linux():
        try:
            findings.extend(_cgroup_findings(store, service_cgroup(), sampled_at))
        except Exception:
            pass

    host_memory = None
    if "win" in hosts and machine.has_windows():
        raw_host = _host_memory()
        commit_findings, host_memory = _host_memory_findings(
            raw_host, _guest_cache() if machine.on_wsl() else None, sampled_at)
        findings.extend(commit_findings)
        findings.extend(_swap_findings(store, raw_host, sampled_at))

    for path in dict.fromkeys(p for p in (
            "/" if machine.has_linux() else "", machine.windows_root()) if p):
        if not os.path.exists(path):
            continue
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        used = (usage.total - usage.free) / usage.total * 100 if usage.total else 0
        if used >= 85:
            findings.append(_finding(
                "high" if used >= 95 else "medium", "disk capacity pressure",
                f"{path} is {used:.1f}% full; low free space can stop logs, "
                "updates, quarantine, and collector snapshots", path))

    store.set_meta(_META, json.dumps({"ts": sampled_at, "processes": current}))
    store.set_meta(PROFILE_META, json.dumps({
        "at": sampled_at,
        "owners": dict(sorted(owners.items(),
                              key=lambda item: item[1]["rss_bytes"], reverse=True)),
        "database": _database_profile(store, _previous_database_profile(store), sampled_at),
        "attribution": _attribution(owners),
        "governor": _governor_advice(owners, processes),
        "host_memory": host_memory,
    }))
    findings.sort(key=lambda f: ({"high": 0, "medium": 1}.get(f["severity"], 9),
                                 f["title"], f["detail"]))
    if not findings:
        findings.append(_finding(
            "ok", "system resource headroom is healthy",
            f"{len(processes)} processes sampled; no sustained CPU, memory, or "
            "disk pressure crossed the reporting threshold"))
    return findings[:20]


def _duration(seconds):
    return f"{int(seconds)}s" if seconds < 120 else f"{int(seconds // 60)}m"


def _attribution(owners):
    """JARVIS self-cost shares; always sums to ~1 so the UI can render it.

    RAM-first and cheap: shares of already-measured owner buckets, never a
    new scan. Tells which part of JARVIS costs what instead of one number.
    """
    try:
        from jarvis.core import governor as governor_mod
        cpu = {k: float(v.get("cpu_pct") or 0.0) for k, v in owners.items()}
        rss = {k: int(v.get("rss_bytes") or 0) for k, v in owners.items()}
        return governor_mod.attribution(cpu, rss)
    except Exception:
        return {}


def _governor_advice(owners, processes):
    """Advisory-only governor input snapshot; enforcement lives elsewhere."""
    try:
        from jarvis.core import governor as governor_mod
        jarvis_rss = sum(int(v.get("rss_bytes") or 0)
                         for k, v in owners.items() if "jarvis" in k or "collector" in k)
        total_rss = sum(int(v.get("rss_bytes") or 0) for v in owners.values()) or 1
        jarvis_cpu = sum(float(v.get("cpu_pct") or 0.0)
                         for k, v in owners.items() if "jarvis" in k or "collector" in k)
        decision = governor_mod.decide(cpu_pct=jarvis_cpu,
                                       memory_pressure=False,
                                       disk_pressure=False,
                                       queue_depth=0, telemetry_backlog=0)
        return {"jarvis_cpu_pct": round(jarvis_cpu, 2),
                "jarvis_rss_share": round(jarvis_rss / total_rss, 4),
                "processes": len(processes),
                "decision": decision["reason"],
                "pause": decision["pause"]}
    except Exception:
        return {}

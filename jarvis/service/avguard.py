"""What Windows' own antivirus is doing, and a bounded way to ask it to scan.

ARGUS-INSTINCT is a monitor: it notices and explains, it does not replace an
antivirus. Blocking and removing malware as it arrives is what Microsoft
Defender does, so this module reads Defender's state (read-only) and, when
the owner asks, starts one Defender *quick scan* with fixed arguments. No
text from the caller reaches the command, a scan is allowed at most once
every SCAN_COOLDOWN_S, and ARGUS-INSTINCT never claims the computer is clean
because a scan was started.
"""

import json
import subprocess
import sys
import time

SCAN_COOLDOWN_S = 600
CACHE_S = 60
_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_STATUS_SCRIPT = (
    "$s=Get-MpComputerStatus -ErrorAction Stop;"
    "@{rt=[bool]$s.RealTimeProtectionEnabled;av=[bool]$s.AntivirusEnabled;"
    "age=[int]$s.AntivirusSignatureAge;"
    "scan=if($s.QuickScanEndTime){$s.QuickScanEndTime.ToUniversalTime().ToString('o')}else{''}}"
    "|ConvertTo-Json -Compress"
)
_SCAN_SCRIPT = "Start-MpScan -ScanType QuickScan"
_BASE = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]

_state = {"at": 0.0, "value": None, "scan_at": 0.0}


def _powershell(script, timeout):
    return subprocess.run(_BASE + [script], capture_output=True, text=True, errors="replace",
                          timeout=timeout, creationflags=_FLAGS)


def summarize(raw):
    """-> the dict the app shows, from Defender's raw fields (None when unreadable)."""
    if not isinstance(raw, dict):
        return {"available": False, "level": "unknown",
                "summary": "ARGUS-INSTINCT cannot read Windows' antivirus right now, so it cannot say whether you are protected."}
    rt, av = bool(raw.get("rt")), bool(raw.get("av"))
    age = raw.get("age") if isinstance(raw.get("age"), int) else None
    if not (rt and av):
        level, text = "off", "Windows' real-time virus protection is off. Turn it on in Windows Security."
    elif age is not None and age > 7:
        level, text = "stale", f"Windows' virus protection is on, but its virus list is {age} days old. Run Windows Update."
    else:
        level, text = "on", "Windows' virus protection is on and up to date. It blocks known viruses as they arrive."
    return {"available": True, "level": level, "realtime": rt, "antivirus": av,
            "signature_age_days": age, "last_quick_scan": raw.get("scan") or "", "summary": text}


def status(now=None, run=_powershell, platform=None):
    now = time.time() if now is None else now
    if (platform or sys.platform) != "win32":
        return summarize(None)
    if _state["value"] is not None and now - _state["at"] < CACHE_S:
        return _state["value"]
    raw = None
    try:
        out = run(_STATUS_SCRIPT, 25)
        raw = json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None
    except (OSError, ValueError, subprocess.SubprocessError):
        raw = None
    _state.update(at=now, value=summarize(raw))
    return _state["value"]


def _start_scan():
    subprocess.Popen(_BASE + [_SCAN_SCRIPT], creationflags=_FLAGS,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def scan(now=None, start=None, platform=None):
    """Start one Defender quick scan. -> {started, message}. Never waits for the scan."""
    now = time.time() if now is None else now
    if (platform or sys.platform) != "win32":
        return {"started": False, "message": "Scanning is only available on Windows."}
    wait = SCAN_COOLDOWN_S - (now - _state["scan_at"])
    if wait > 0:
        return {"started": False, "message": f"A scan was just started. Try again in {int(wait // 60) + 1} minute(s)."}
    try:
        (start or _start_scan)()
    except OSError:
        return {"started": False, "message": "Could not start Windows' scan."}
    _state["scan_at"] = now
    _state["value"] = None
    return {"started": True, "message": "Windows' quick scan has started in the background. "
                                        "Starting a scan does not mean the computer is clean; Windows will report what it finds."}

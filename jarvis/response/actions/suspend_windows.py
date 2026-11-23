"""Pause a Windows process that has the shape of a keylogger, reversibly.

The input-watcher audit names a process that holds a global keyboard watcher
(low-level hook, background raw-input sink, or fast key-state polling) from an
unsigned image or a script host. Until now JARVIS could only say so. This
action freezes that process with NtSuspendProcess: nothing is killed, memory
and handles stay for a dump, and NtResumeProcess undoes it exactly.

Identity before action: the target is (pid, image path, process start time)
captured when the finding was made; apply() refuses if the pid now belongs to
a different image or start time, so a reused pid is never frozen. Never
suspends a process whose image lives under Windows or Program Files, a JARVIS
component, or a protected system process. Approval-only (APPROVE): the owner
runs `jarvis defend approve <id>`; there is no automatic rung until an
isolated positive control has shown the end-to-end path (SPYWARE-DEFENSE §6).
"""

import ntpath
import re

from jarvis.platform.windows import ps_json

from .base import APPROVE, Action, register

PROTECTED = {"csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe",
             "smss.exe", "svchost.exe", "explorer.exe", "dwm.exe", "system",
             "msmpeng.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "wsl.exe",
             "wslhost.exe", "wslservice.exe", "jarvissensor.exe", "sysmon64.exe"}
SYSTEM_DIRS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
TITLE = re.compile(r"^(?P<name>\S+) is watching every (?P<device>keyboard|mouse) event$")
PID = re.compile(r"\(pid (?P<pid>\d+)\)")

# Both scripts read their arguments from a JSON object on stdin; nothing from a
# finding is interpolated into a command line.
PS_IDENTITY = r"""
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$p = Get-Process -Id ([int]$in.pid) -ErrorAction SilentlyContinue
$o = if ($p) { @{ alive = $true; path = [string]$p.Path; start = [string]$p.StartTime.ToUniversalTime().ToString('o') } } else { @{ alive = $false } }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress)))
"""

PS_TOGGLE = r"""
$in = [Console]::In.ReadToEnd() | ConvertFrom-Json
$p = Get-Process -Id ([int]$in.pid) -ErrorAction SilentlyContinue
if (-not $p -or [string]$p.Path -ne [string]$in.path -or [string]$p.StartTime.ToUniversalTime().ToString('o') -ne [string]$in.start) {
  $o = @{ ok = $false; reason = 'pid no longer names the same process' }
} else {
  Add-Type -Namespace J -Name Nt -MemberDefinition '[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h); [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);'
  $rc = if ($in.resume) { [J.Nt]::NtResumeProcess($p.Handle) } else { [J.Nt]::NtSuspendProcess($p.Handle) }
  $o = @{ ok = ($rc -eq 0); status = $rc }
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress)))
"""


def _basename(path):
    return ntpath.basename(path or "").lower()


@register
class SuspendWindowsProcess(Action):
    id = "suspend_windows_process"
    title = "Pause a Windows process watching the keyboard"
    autonomy = APPROVE
    reversible = True
    host = "win"
    enable_flag = "auto_suspend_windows"      # unused while APPROVE; kept for the ladder's shape

    def match(self, finding, job):
        f = finding or {}
        if job != "input" or f.get("severity") != "high":
            return None
        m = TITLE.match(f.get("title") or "")
        p = PID.search(f.get("detail") or "")
        if not m or not p or m.group("device") != "keyboard":
            return None
        path = f.get("where") or ""
        name = _basename(path) or m.group("name").lower()
        if name in PROTECTED or path.lower().startswith(SYSTEM_DIRS):
            return None
        return {"pid": int(p.group("pid")), "path": path, "name": name}

    def preview(self, target):
        return (f"Freeze {target['name']} (pid {target['pid']}) with NtSuspendProcess; "
                f"it stays in memory for a dump. Undo resumes it.")

    def auto_eligible(self, finding, job, target):
        return False

    def _run(self, script, payload):
        return ps_json(script, timeout=30, payload=payload)

    def evidence(self, target):
        return self._run(PS_IDENTITY, _json({"pid": target["pid"]}))

    def apply(self, target, case):
        ident = self.evidence(target)
        if not isinstance(ident, dict) or not ident.get("alive"):
            return False, {}, "the process is no longer running"
        if target.get("path") and _basename(ident.get("path")) != _basename(target["path"]):
            return False, {}, "pid now belongs to a different image; nothing done"
        record = {"pid": target["pid"], "path": ident.get("path"), "start": ident.get("start")}
        result = self._run(PS_TOGGLE, _json(dict(record, resume=False)))
        if isinstance(result, dict) and result.get("ok"):
            return True, record, f"suspended {target['name']} (pid {target['pid']})"
        reason = (result or {}).get("reason") if isinstance(result, dict) else None
        return False, {}, reason or "suspend failed (needs the Windows bridge)"

    def undo(self, target, record):
        if not record or not record.get("pid"):
            return False, "no process recorded"
        result = self._run(PS_TOGGLE, _json(dict(record, resume=True)))
        if isinstance(result, dict) and result.get("ok"):
            return True, f"resumed pid {record['pid']}"
        reason = (result or {}).get("reason") if isinstance(result, dict) else None
        return False, reason or "resume failed; the process may have exited"

    def recover(self, target, record):
        ident = self.evidence({"pid": (record or target or {}).get("pid")})
        if not isinstance(ident, dict):
            return "unknown", {}, "identity could not be read"
        if not ident.get("alive"):
            return "not_applied", {}, "the process is gone"
        return "uncertain", {}, "the process exists; suspension state is not readable from here"


def _json(obj):
    import json
    return json.dumps(obj)

"""End-to-end smoke run of the input-hook host, beside the live hook.

Runs the checkout's inputhook.ps1 as a second, temporary helper writing to its
own folder, samples its memory, reads its heartbeats, then stops it. It does
install a real low-level hook for the run, so the input-watcher audit will
list a short-lived powershell.exe hook: that is this script.

The copy is named so it does NOT match `*inputhook.ps1*`: on 2026-10-31 a test
copy named *_inputhook.ps1 was counted as a duplicate helper, and the live
hook was stopped with it.

    python3 scripts/dev/inputhook_smoke.py [seconds]
"""

import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PS = shutil.which("powershell.exe") or "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
NAME = "jvhost-smoke.ps1"     # must not contain "inputhook.ps1"


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 75
    assert "inputhook.ps1" not in NAME
    local = subprocess.run([PS, "-NoProfile", "-NonInteractive", "-Command", "$env:LOCALAPPDATA"],
                           capture_output=True, text=True, cwd="/", timeout=60).stdout.strip()
    wsl_local = subprocess.run(["wslpath", "-u", local], capture_output=True, text=True).stdout.strip()
    shutil.copyfile(ROOT / "jarvis/platform/win/inputhook.ps1", Path(wsl_local) / "Temp" / NAME)
    body = f"""
$d=Join-Path $env:LOCALAPPDATA 'Temp\\jvhost-smoke'; Remove-Item $d -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force $d | Out-Null; $out=Join-Path $d 'out.jsonl'
$p=Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $env:LOCALAPPDATA 'Temp\\{NAME}'),'-OutFile',$out,'-HeartbeatSeconds','10'
$samples=@(); $t=0
while($t -lt {seconds}){{ Start-Sleep 5; $t+=5; $p.Refresh(); if($p.HasExited){{ break }}
  $samples+=[pscustomobject]@{{t=$t;priv=[int]($p.PrivateMemorySize64/1MB);ws=[int]($p.WorkingSet64/1MB);threads=$p.Threads.Count}} }}
$exited=$p.HasExited; if(-not $exited){{ Stop-Process -Id $p.Id -Force }}
$beats=@([string[]]@(Get-Content $out -EA SilentlyContinue) | Where-Object {{ $_ -like '*"heartbeat"*' }})
[pscustomobject]@{{exited=$exited;samples=$samples;beats=$beats.Count;last=$(if($beats){{$beats[-1]}}else{{''}})}}|ConvertTo-Json -Compress -Depth 4
"""
    enc = base64.b64encode(body.encode("utf-16le")).decode()
    r = subprocess.run([PS, "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
                       capture_output=True, text=True, cwd="/", timeout=seconds + 120)
    res = json.loads(r.stdout.strip().splitlines()[-1])
    last = json.loads(res["last"]) if res["last"] else {}
    privs = [s["priv"] for s in res["samples"]]
    print(json.dumps({
        "exited_early": res["exited"], "heartbeats": res["beats"],
        "private_mb": {"min": min(privs, default=0), "max": max(privs, default=0), "last": privs[-1] if privs else 0},
        "threads_last": res["samples"][-1]["threads"] if res["samples"] else 0,
        "lat_max_ms": (last.get("counters") or {}).get("lat_max_ms"),
        "sound": (last.get("sound") or {}).get("state"),
        "hook": last.get("hook"),
    }, indent=1))
    ok = not res["exited"] and res["beats"] >= 2 and (last.get("hook") or {}).get("task_faults", 1) == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

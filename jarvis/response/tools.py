"""On-demand tools an investigation or a response action can call.

These are the things you would reach for by hand the moment something looks
wrong — ask Defender what it thinks of a file, take the process tree around a
pid, hash a file — wrapped so an action can call them and store the answer with
the evidence. Each one degrades to a plain "unavailable" result rather than
raising: a tool that is missing must never stop a containment action that does
not depend on it.
"""

import hashlib
import os
import re
import subprocess

from jarvis.platform import host
from jarvis.platform.windows import ps_json, stdin_text

# Defender's scanner, in the versioned platform directory it ships in.
_MPCMDRUN = (r"$d=(Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform' "
             r"-Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | "
             r"Select-Object -First 1);if($d){$exe=Join-Path $d.FullName 'MpCmdRun.exe'}"
             r"else{$exe='C:\Program Files\Windows Defender\MpCmdRun.exe'};")


def defender_scan(win_path, timeout=180):
    """Ask Microsoft Defender to scan one Windows file. Returns a dict:

    {"available": bool, "clean": bool|None, "threat": str, "output": str}

    `clean` is None when Defender could not be asked, which is not the same as
    a clean verdict and is reported as such.
    """
    if not isinstance(win_path, str) or not re.match(r"^[A-Za-z]:\\", win_path):
        return {"available": False, "clean": None, "threat": "",
                "output": "not a Windows path"}
    # The path travels over stdin so nothing from a finding is interpolated
    # into (or visible on) the command line.
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        + stdin_text("p") +
        f"{_MPCMDRUN}"
        "$out='';$code=-1;"
        "if(Test-Path -LiteralPath $exe){"
        "$out=(& $exe -Scan -ScanType 3 -File $p -DisableRemediation 2>&1|Out-String);"
        "$code=$LASTEXITCODE};"
        "$threat='';"
        "try{$t=Get-MpThreatDetection|Where-Object{$_.Resources -match [regex]::Escape($p)}|"
        "Select-Object -First 1;if($t){$threat=[string]$t.ThreatName}}catch{}"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "(@{exe=$exe;code=$code;out=$out;threat=$threat}|ConvertTo-Json -Compress)))")
    result = ps_json(script, timeout=timeout, payload=win_path)
    if not isinstance(result, dict) or int(result.get("code", -1)) < 0:
        return {"available": False, "clean": None, "threat": "",
                "output": "Defender could not be run (no Windows bridge, or MpCmdRun missing)"}
    out = str(result.get("output") or result.get("out") or "")
    threat = str(result.get("threat") or "")
    # MpCmdRun: 0 = no threat found, 2 = threat found.
    code = int(result.get("code", -1))
    clean = True if code == 0 and not threat else (False if (code == 2 or threat) else None)
    return {"available": True, "clean": clean, "threat": threat, "output": out[-2000:]}


def authenticode(win_path):
    """Read a Windows file's signature without trusting its filename."""
    if not isinstance(win_path, str) or not re.match(r"^[A-Za-z]:\\", win_path):
        return {"available": False, "status": "", "signer": "",
                "output": "not a Windows path"}
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        + stdin_text("p") +
        "$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "$o=@{exists=[bool](Test-Path -LiteralPath $p);status=[string]$s.Status;"
        "signer=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''};"
        "error=[string]$s.StatusMessage};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "($o|ConvertTo-Json -Compress)))")
    result = ps_json(script, timeout=30, payload=win_path)
    if not isinstance(result, dict):
        return {"available": False, "status": "", "signer": "",
                "output": "Windows signature query unavailable"}
    return {"available": bool(result.get("exists")),
            "status": str(result.get("status") or ""),
            "signer": str(result.get("signer") or ""),
            "output": str(result.get("error") or "")}


def yara_scan(path, rules, timeout=120):
    """Scan one local path with an installed YARA binary and explicit rules."""
    exe = which("yara")
    if not exe:
        return {"available": False, "matches": [], "output": "yara is not installed"}
    if not os.path.isfile(path):
        return {"available": True, "matches": [], "output": "target is not a file"}
    if not rules or not os.path.exists(rules):
        return {"available": True, "matches": [], "output": "rules path is unavailable"}
    try:
        result = subprocess.run([exe, "-w", rules, path], capture_output=True, text=True,
                                errors="replace", timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "matches": [], "output": str(exc)}
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    matches = [line.split(None, 1)[0] for line in lines]
    output = (result.stdout + result.stderr)[-4000:]
    # YARA uses 0 both for no match and successful matches. Operational errors
    # are non-zero and must not be represented as a clean scan.
    return {"available": True, "matches": matches,
            "error": result.returncode != 0, "output": output}


def sysinternals_status():
    """Report which read-only Sysinternals investigation tools are installed."""
    script = (
        "$root=Join-Path $env:LOCALAPPDATA 'Jarvis\\Tools\\Sysinternals';"
        "$o=@{};foreach($n in @('sigcheck64.exe','sigcheck.exe','autorunsc64.exe',"
        "'autorunsc.exe','handle64.exe','handle.exe','procdump64.exe','procdump.exe')){"
        "$c=Get-Command $n -ErrorAction SilentlyContinue;"
        "if($c){$o[$n]=$c.Source}elseif(Test-Path (Join-Path $root $n)){"
        "$o[$n]=(Join-Path $root $n)}};"
        "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("
        "($o|ConvertTo-Json -Compress)))")
    result = ps_json(script, timeout=30)
    return result if isinstance(result, dict) else {}


def sha256(path, cap=512 * 1024 * 1024):
    """Hash a local file. Returns "" when it cannot be read or is too large."""
    try:
        if os.path.getsize(path) > cap:
            return ""
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _proc_field(pid, name):
    try:
        with open(f"/proc/{pid}/{name}", "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def process_tree(pid, up=4, down=2):
    """Ancestors and children of a Linux pid: who started this, and what it started.

    A pid on its own says nothing; the chain that produced it usually says
    everything ("a shell, under the web server, under systemd").
    """
    def info(p):
        stat = _proc_field(p, "stat")
        ppid = ""
        try:
            ppid = stat.rsplit(")", 1)[1].split()[1]
        except IndexError:
            pass
        return {"pid": p, "ppid": int(ppid) if ppid.isdigit() else None,
                "name": _proc_field(p, "comm").strip(),
                "cmdline": _proc_field(p, "cmdline").replace("\x00", " ").strip()[:300],
                "exe": os.path.realpath(f"/proc/{p}/exe") if os.path.exists(f"/proc/{p}/exe") else ""}

    if not os.path.isdir(f"/proc/{pid}"):
        return {"pid": pid, "available": False, "ancestors": [], "self": {}, "children": []}
    me = info(pid)
    ancestors, cur, seen = [], me.get("ppid"), {pid}
    while cur and cur > 0 and cur not in seen and len(ancestors) < up:
        seen.add(cur)
        if not os.path.isdir(f"/proc/{cur}"):
            break
        parent = info(cur)
        ancestors.append(parent)
        cur = parent.get("ppid")
    children = []
    if down:
        for entry in os.listdir("/proc"):
            if entry.isdigit() and info(int(entry)).get("ppid") == pid:
                children.append(info(int(entry)))
                if len(children) >= 25:
                    break
    return {"pid": pid, "available": True, "self": me,
            "ancestors": ancestors, "children": children}


def which(name):
    """Path of an external tool, or "" — used to report what is installed."""
    try:
        out = subprocess.run(["which", name], capture_output=True, text=True,
                             errors="replace", timeout=5)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def inspect(path="", pid=None, yara_rules=""):
    """One bounded, read-only investigation report for a file or Linux PID."""
    report = {"path": path or "", "pid": pid, "sha256": "", "process_tree": {},
              "defender": {}, "authenticode": {}, "yara": {},
              "sysinternals": sysinternals_status()}
    local = path
    win_path = path if isinstance(path, str) and re.match(r"^[A-Za-z]:\\", path) else ""
    if win_path:
        local = host.local_path(win_path)
        report["defender"] = defender_scan(win_path)
        report["authenticode"] = authenticode(win_path)
    if local:
        report["sha256"] = sha256(local)
        if yara_rules:
            report["yara"] = yara_scan(local, yara_rules)
    if isinstance(pid, int) and pid > 0:
        report["process_tree"] = process_tree(pid)
    return report

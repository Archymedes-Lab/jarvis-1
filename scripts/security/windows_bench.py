#!/usr/bin/env python3
"""Controlled Windows state/telemetry measurement, hosted disposable VMs only.

Never execute on a protected user's machine. Fixture preparation is the separate
reviewed windows_bench_setup.ps1; no logging, security policy or sensor changes
occur here. No secrets, credential reads, memory dumping or external connections.
"""
import argparse
import ctypes
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARK = 'argus-win-' + uuid.uuid4().hex[:10]
JOBS = ('sysmon', 'psscript', 'asep', 'backdoor', 'control', 'intrusion', 'implant', 'firewall', 'scan',
        'evasion', 'winblocks')
MAX_OUTPUT = 8 * 1024 * 1024
CHILD = ("import sys,json; sys.path.insert(0,%r)\n"
         "from jarvis.service.jobs import run_job\n"
         "out=run_job(sys.argv[1],('win',),sys.argv[2])\n"
         "print(json.dumps([{k:str(f.get(k) or '')[:2000] for k in "
         "('category','severity','title','detail','where')} for f in (out or [])]))\n") % str(ROOT)


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def refusal(env=None, platform=None, admin=None, home=None, exists=None):
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = Path.home() if home is None else Path(home)
    exists = (lambda p: Path(p).exists()) if exists is None else exists
    if platform != 'win32':
        return 'not Windows'
    if env.get('GITHUB_ACTIONS') != 'true' or env.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        return 'not a disposable GitHub-hosted runner'
    if env.get('JARVIS_ARENA_SANDBOX') != '1' or not env.get('RUNNER_TEMP'):
        return 'missing explicit sandbox mark or scratch root'
    for path in (home / '.jarvis/jarvis.db', home / '.argus/argus.db',
                 Path(env.get('ProgramData', r'C:\ProgramData')) / 'Jarvis',
                 Path(env.get('ProgramFiles', r'C:\Program Files')) / 'Jarvis'):
        if exists(path):
            return 'protected installation/data exists; never a benchmark target'
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin()) if admin is None else admin
    if not admin:
        return 'not an administrator in the disposable VM'
    return ''


def powershell(script, timeout=45, as_json=False):
    result = subprocess.run(['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                             '-Command', "$ErrorActionPreference='Stop'; " + script],
                            capture_output=True, text=True, errors='replace', timeout=timeout)
    if result.returncode:
        # The last error line says why (runner-only fixture text; no secrets exist here).
        last = [ln.strip() for ln in (result.stderr or '').splitlines() if ln.strip()][-1:] or ['']
        raise RuntimeError('PowerShell returned failure: ' + last[0][:160])
    if len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
        raise RuntimeError('PowerShell output exceeded budget')
    if as_json:
        return json.loads(result.stdout.strip().splitlines()[-1])
    return None


def verify_network(group):
    script = (f"$r=@(Get-NetFirewallRule -Group {quote(group)} -PolicyStore ActiveStore); "
              "$bad=@($r | Where-Object { $_.Enabled -ne 'True' -or $_.Action -ne 'Block' -or $_.Direction -ne 'Outbound' }); "
              "$profiles=@(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -ne 'True' }); "
              "@{ rules=$r.Count; invalid=$bad.Count; inactive_profiles=$profiles.Count } | ConvertTo-Json -Compress")
    state = powershell(script, as_json=True)
    if state != {'rules': 3, 'invalid': 0, 'inactive_profiles': 0}:
        raise RuntimeError('active scoped network rules did not verify')
    # No payload: a reserved documentation address must fail specifically due to policy.
    with socket.socket() as probe:
        probe.settimeout(2)
        try:
            probe.connect(('203.0.113.1', 9))
        except OSError as exc:
            if getattr(exc, 'winerror', None) != 10013:
                raise RuntimeError('outbound denial not established') from None
        else:
            raise RuntimeError('outbound connection was permitted')
    return state


def cases(scratch):
    cmd = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/cmd.exe')
    run = r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    ifeo = r'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' + '\\' + MARK + '-02.exe'
    script = scratch / (MARK + '-05.ps1')
    proof = scratch / (MARK + '-05.proof')
    script.write_text("Get-Process -Name lsass | Select-Object -ExpandProperty Id | Out-Null\n"
                      + f"[IO.File]::WriteAllText({quote(proof)},'observed')\n", encoding='utf-8')
    # (id, technique, description, apply script or argv, undo script, absence check)
    return (
        ('01', 'T1547.001', 'unique Run value with an inert command',
         f"if (-not (Test-Path -LiteralPath {quote(run)})) {{ New-Item -Path {quote(run)} -Force | Out-Null }}; New-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-01' -Value {quote(cmd+' /c exit 0')} -PropertyType String | Out-Null; "
         f"if (-not (Get-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-01')) {{ throw 'Run verification failed' }}",
         f"Remove-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-01' -ErrorAction SilentlyContinue",
         f"if (Get-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-01' -ErrorAction SilentlyContinue) {{ throw 'Run value remains' }}"),
        ('02', 'T1546.012', 'IFEO debugger for a unique nonexistent program',
         f"if (Test-Path -LiteralPath {quote(ifeo)}) {{ throw 'IFEO collision' }}; New-Item -Path {quote(ifeo)} -Force | Out-Null; "
         f"New-ItemProperty -LiteralPath {quote(ifeo)} -Name Debugger -Value {quote(cmd+' /c exit 0')} -PropertyType String | Out-Null; "
         f"if (-not (Get-ItemProperty -LiteralPath {quote(ifeo)} -Name Debugger)) {{ throw 'IFEO verification failed' }}",
         f"Remove-Item -LiteralPath {quote(ifeo)} -Recurse -Force -ErrorAction SilentlyContinue",
         f"if (Test-Path -LiteralPath {quote(ifeo)}) {{ throw 'IFEO remains' }}"),
        ('03', 'T1053.005', 'inert logon scheduled task',
         f"$a=New-ScheduledTaskAction -Execute {quote(cmd)} -Argument '/c exit 0'; $t=New-ScheduledTaskTrigger -AtLogOn; "
         f"Register-ScheduledTask -TaskName '{MARK}-03' -Action $a -Trigger $t | Out-Null; "
         f"if (-not (Get-ScheduledTask -TaskName '{MARK}-03')) {{ throw 'task verification failed' }}",
         f"Unregister-ScheduledTask -TaskName '{MARK}-03' -Confirm:$false -ErrorAction SilentlyContinue",
         f"if (Get-ScheduledTask -TaskName '{MARK}-03' -ErrorAction SilentlyContinue) {{ throw 'task remains' }}"),
        ('04', 'T1543.003', 'inert auto-service registration, never started',
         f"New-Service -Name '{MARK}-04' -BinaryPathName {quote(cmd+' /c exit 0')} -StartupType Automatic | Out-Null; "
         f"if (-not (Get-Service -Name '{MARK}-04')) {{ throw 'service verification failed' }}",
         f"& sc.exe delete '{MARK}-04' | Out-Null; if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1060) {{ throw 'service deletion failed' }}",
         f"if (Get-Service -Name '{MARK}-04' -ErrorAction SilentlyContinue) {{ throw 'service remains' }}"),
        ('05', 'T1057', 'LSASS process-id discovery from a script file, no memory access',
         ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
         f"Remove-Item -LiteralPath {quote(script)},{quote(proof)} -Force -ErrorAction SilentlyContinue",
         f"if ((Test-Path -LiteralPath {quote(script)}) -or (Test-Path -LiteralPath {quote(proof)})) {{ throw 'script fixture remains' }}"),
    ), script, proof


# Attack-shaped but harmless: every program is a renamed copy of a Windows tool given an
# argument that exits at once, every object carries MARK, and every one is removed after.
# (id, technique, description, apply, undo, absence check)
EXTRA = {'17': ('44417',)}       # strings that identify a case where MARK cannot appear


def more_cases(scratch):
    sysdir = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
    cmd = str(sysdir / 'cmd.exe')
    temp = Path(os.environ.get('TEMP', str(scratch)))
    stage = temp / (MARK + '-stage')

    def staged(sid):
        # One copy per case, named with the case id, so a finding that names the
        # program can be matched to the case that planted it.
        return stage / f'{MARK}-{sid}.exe'
    run = r'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    lsa = r'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    winlogon = r'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    clsid = r'HKCU:\Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}'
    startup = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / r'Microsoft\Windows\Start Menu\Programs\StartUp'
    encoded = 'ZQB4AGkAdAAgADAA'   # "exit 0" in UTF-16LE base64
    def prep(sid):
        return (f"New-Item -ItemType Directory -Force -Path {quote(stage)} | Out-Null; "
                f"Copy-Item -LiteralPath {quote(cmd)} -Destination {quote(staged(sid))} -Force; ")
    return (
        ('06', 'T1547.001', 'Run value starting a program from the temporary folder',
         prep('06') + f"New-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-06' -Value {quote(str(staged('06')) + ' /c exit 0')} -PropertyType String | Out-Null",
         f"Remove-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-06' -ErrorAction SilentlyContinue",
         f"if (Get-ItemProperty -LiteralPath {quote(run)} -Name '{MARK}-06' -ErrorAction SilentlyContinue) {{ throw 'remains' }}"),
        ('07', 'T1053.005', 'scheduled task running hidden encoded PowerShell',
         f"$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -EncodedCommand {encoded}'; "
         f"$t=New-ScheduledTaskTrigger -Daily -At 03:00; Register-ScheduledTask -TaskName '{MARK}-07' -Action $a -Trigger $t | Out-Null",
         f"Unregister-ScheduledTask -TaskName '{MARK}-07' -Confirm:$false -ErrorAction SilentlyContinue",
         f"if (Get-ScheduledTask -TaskName '{MARK}-07' -ErrorAction SilentlyContinue) {{ throw 'remains' }}"),
        ('08', 'T1543.003', 'automatic service whose program is in the temporary folder',
         prep('08') + f"New-Service -Name '{MARK}-08' -BinaryPathName {quote(str(staged('08')) + ' /c exit 0')} -StartupType Automatic | Out-Null",
         f"& sc.exe delete '{MARK}-08' | Out-Null",
         f"if (Get-Service -Name '{MARK}-08' -ErrorAction SilentlyContinue) {{ throw 'remains' }}"),
        ('09', 'T1546.003', 'WMI event subscription running a command',
         f"$ns='root\\subscription'; "
         f"$f=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{{Name='{MARK}-09';EventNamespace='root\\cimv2';QueryLanguage='WQL';"
         f"Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}}; "
         f"$c=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{{Name='{MARK}-09';CommandLineTemplate={quote(cmd + ' /c exit 0')}}}; "
         f"Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{{Filter=$f;Consumer=$c}} | Out-Null",
         f"$ns='root\\subscription'; "
         f"Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding | Where-Object {{ $_.Filter -like '*{MARK}-09*' }} | Remove-WmiObject; "
         f"Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter \"Name='{MARK}-09'\" | Remove-WmiObject; "
         f"Get-WmiObject -Namespace $ns -Class __EventFilter -Filter \"Name='{MARK}-09'\" | Remove-WmiObject",
         f"if (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='{MARK}-09'\") {{ throw 'remains' }}"),
        ('10', 'T1562.001', 'Microsoft Defender exclusion for a folder',
         f"Add-MpPreference -ExclusionPath {quote(str(temp / (MARK + '-10')))}",
         f"Remove-MpPreference -ExclusionPath {quote(str(temp / (MARK + '-10')))} -ErrorAction SilentlyContinue",
         f"if ((Get-MpPreference).ExclusionPath -contains {quote(str(temp / (MARK + '-10')))}) {{ throw 'remains' }}"),
        ('11', 'T1136.001', 'new local account added to Administrators',
         f"$p=New-Object Security.SecureString; foreach($ch in ([guid]::NewGuid().ToString() + 'aA1!').ToCharArray()){{ $p.AppendChar($ch) }}; "
         f"New-LocalUser -Name '{MARK[-10:]}11' -Password $p -Description '{MARK}-11' | Out-Null; "
         f"Add-LocalGroupMember -SID 'S-1-5-32-544' -Member '{MARK[-10:]}11'",
         f"Remove-LocalUser -Name '{MARK[-10:]}11' -ErrorAction SilentlyContinue",
         f"if (Get-LocalUser -Name '{MARK[-10:]}11' -ErrorAction SilentlyContinue) {{ throw 'remains' }}"),
        ('12', 'T1546.015', 'per-user COM class registration pointing at a temporary-folder library',
         f"if (Test-Path -LiteralPath {quote(clsid)}) {{ throw 'collision' }}; "
         f"New-Item -Path {quote(clsid + chr(92) + 'InprocServer32')} -Force | Out-Null; "
         f"Set-ItemProperty -LiteralPath {quote(clsid + chr(92) + 'InprocServer32')} -Name '(default)' -Value {quote(str(stage / (MARK + '-12.dll')))}",
         f"Remove-Item -LiteralPath {quote(clsid)} -Recurse -Force -ErrorAction SilentlyContinue",
         f"if (Test-Path -LiteralPath {quote(clsid)}) {{ throw 'remains' }}"),
        ('13', 'T1547.004', 'Winlogon Userinit extended with a second program',
         prep('13') + f"$v=(Get-ItemProperty -LiteralPath {quote(winlogon)} -Name Userinit).Userinit; "
         f"Set-Content -LiteralPath {quote(str(scratch / (MARK + '-13.bak')))} -Value $v -Encoding UTF8; "
         f"Set-ItemProperty -LiteralPath {quote(winlogon)} -Name Userinit -Value ($v.TrimEnd(',') + ',' + {quote(str(staged('13')))} + ',')",
         f"$b={quote(str(scratch / (MARK + '-13.bak')))}; if (Test-Path -LiteralPath $b) {{ "
         f"Set-ItemProperty -LiteralPath {quote(winlogon)} -Name Userinit -Value (Get-Content -LiteralPath $b -Raw).Trim(); Remove-Item -LiteralPath $b }}",
         f"if ((Get-ItemProperty -LiteralPath {quote(winlogon)} -Name Userinit).Userinit -like '*{MARK}*') {{ throw 'remains' }}"),
        ('14', 'T1547.005', 'extra LSA security package registered',
         f"$v=@((Get-ItemProperty -LiteralPath {quote(lsa)} -Name 'Security Packages').'Security Packages'); "
         f"Set-Content -LiteralPath {quote(str(scratch / (MARK + '-14.bak')))} -Value ($v -join \"`n\") -Encoding UTF8; "
         f"Set-ItemProperty -LiteralPath {quote(lsa)} -Name 'Security Packages' -Type MultiString -Value ($v + '{MARK}-14')",
         f"$b={quote(str(scratch / (MARK + '-14.bak')))}; if (Test-Path -LiteralPath $b) {{ "
         f"$v=@((Get-Content -LiteralPath $b) | Where-Object {{ $_ -ne '' }}); "
         f"Set-ItemProperty -LiteralPath {quote(lsa)} -Name 'Security Packages' -Type MultiString -Value $v; Remove-Item -LiteralPath $b }}",
         f"if (@((Get-ItemProperty -LiteralPath {quote(lsa)} -Name 'Security Packages').'Security Packages') -contains '{MARK}-14') {{ throw 'remains' }}"),
        ('15', 'T1547.001', 'script in the machine-wide startup folder',
         f"Set-Content -LiteralPath {quote(str(startup / (MARK + '-15.cmd')))} -Value '@exit /b 0' -Encoding ASCII",
         f"Remove-Item -LiteralPath {quote(str(startup / (MARK + '-15.cmd')))} -Force -ErrorAction SilentlyContinue",
         f"if (Test-Path -LiteralPath {quote(str(startup / (MARK + '-15.cmd')))}) {{ throw 'remains' }}"),
        ('16', 'T1197', 'BITS job that runs a command when it completes',
         f"& bitsadmin.exe /create '{MARK}-16' | Out-Null; "
         f"& bitsadmin.exe /SetNotifyCmdLine '{MARK}-16' {quote(cmd)} '/c exit 0' | Out-Null; "
         f"if ($LASTEXITCODE -ne 0) {{ throw 'bits' }}",
         f"& bitsadmin.exe /cancel '{MARK}-16' | Out-Null",
         f"if ((& bitsadmin.exe /list /allusers) -match '{MARK}-16') {{ throw 'remains' }}"),
        ('17', 'T1090.001', 'port proxy forwarding a local port',
         "& netsh.exe interface portproxy add v4tov4 listenport=44417 listenaddress=127.0.0.1 connectport=9 connectaddress=127.0.0.1 | Out-Null; "
         "if ($LASTEXITCODE -ne 0) { throw 'portproxy' }",
         "& netsh.exe interface portproxy delete v4tov4 listenport=44417 listenaddress=127.0.0.1 | Out-Null",
         "if ((& netsh.exe interface portproxy show v4tov4) -match '44417') { throw 'remains' }"),
        ('18', 'T1036.005', 'program named svchost.exe running from the temporary folder',
         f"New-Item -ItemType Directory -Force -Path {quote(str(stage / (MARK + '-18')))} | Out-Null; "
         f"Copy-Item -LiteralPath {quote(str(sysdir / 'PING.EXE'))} -Destination {quote(str(stage / (MARK + '-18') / 'svchost.exe'))} -Force; "
         f"$p=Start-Process -FilePath {quote(str(stage / (MARK + '-18') / 'svchost.exe'))} -ArgumentList '-n','3600','127.0.0.1' -WindowStyle Hidden -PassThru; "
         f"Start-Sleep -Seconds 1; if ($p.HasExited) {{ throw 'not running' }}",
         f"Get-Process -Name svchost -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -like '*{MARK}*' }} | Stop-Process -Force; "
         f"Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath {quote(str(stage))} -Recurse -Force -ErrorAction SilentlyContinue",
         f"if (Get-Process -Name svchost -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -like '*{MARK}*' }}) {{ throw 'remains' }}"),
        # An inbound firewall rule (T1562.004) could not be created on the hosted runner in
        # four attempts (2026-11-11); not measured here. The firewall collector reads rules.
    )


def telemetry(script_file):
    # Query errors remain errors; no payload or script text is returned.
    request = f"$fixture={quote(script_file)}; $prefix={quote(MARK)}; "
    request += r'''
$o=@{sysmon_process=0;sysmon_registry=0;fixture_script_blocks=0;sysmon_last=0;ps_last=0}
foreach($name in @('Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')) {
  $errors=@(); $all=@(Get-WinEvent -LogName $name -MaxEvents 3000 -ErrorAction SilentlyContinue -ErrorVariable errors)
  foreach($e in $errors) { if ($e.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw 'event channel read failed' } }
  foreach($e in $all) {
    if($name -like '*Sysmon*') {
      if([long]$e.RecordId -gt $o.sysmon_last){$o.sysmon_last=[long]$e.RecordId}
      if($e.Id -eq 1){$o.sysmon_process++}
      if($e.Id -eq 13){
        $x=[xml]$e.ToXml()
        foreach($v in $x.Event.EventData.Data){if($v.Name -eq 'TargetObject' -and $v.'#text' -like "*$prefix*"){$o.sysmon_registry++}}
      }
    } else {
      if([long]$e.RecordId -gt $o.ps_last){$o.ps_last=[long]$e.RecordId}
      if($e.Id -eq 4104 -and $e.Properties.Count -ge 5 -and [string]$e.Properties[4].Value -eq $fixture){$o.fixture_script_blocks++}
    }
  }
}
$o | ConvertTo-Json -Compress
'''
    return powershell(request, timeout=60, as_json=True)


def worker_env(home):
    names = ('SystemRoot', 'WINDIR', 'SystemDrive', 'COMSPEC', 'PATH', 'PATHEXT', 'TEMP', 'TMP',
             'PROCESSOR_ARCHITECTURE', 'PSModulePath', 'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)')
    env = {name: os.environ[name] for name in names if name in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / 'AppData/Roaming'),
               LOCALAPPDATA=str(home / 'AppData/Local'), JARVIS_NO_ALERTS='1')
    return env


def sweep(db, home):
    findings, failures = {}, {}
    for job in JOBS:
        try:
            result = subprocess.run([sys.executable, '-I', '-c', CHILD, job, str(db)],
                                    env=worker_env(home), capture_output=True, text=True, errors='replace', timeout=180)
            if result.returncode or len(result.stdout) + len(result.stderr) > MAX_OUTPUT:
                raise RuntimeError('worker failed or exceeded output budget')
            rows = json.loads(result.stdout.strip().splitlines()[-1])
            for row in rows:
                if row.get('severity') not in ('', 'ok'):
                    key = job + '|' + hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
                    findings[key] = (job, row)
        except Exception as exc:
            failures[job] = type(exc).__name__
    return findings, failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--json', type=Path)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args(argv)
    if args.list:
        print('Run value; IFEO; logon task; inert service; LSASS process-id query; and attack-shaped cases '
              '06-19 (Temp Run key, encoded task, Temp service, WMI subscription, Defender exclusion, new admin, '
              'COM hijack, Userinit, LSA package, startup script, BITS, port proxy, svchost look-alike). '
              'Hosted Windows only.')
        return 0
    why = refusal()
    if why:
        print('refused, nothing executed: ' + why, file=sys.stderr)
        return 2
    setup_path = Path(os.environ['RUNNER_TEMP']) / 'argus-windows-bench/setup.json'
    setup = json.loads(setup_path.read_text(encoding='utf-8-sig'))
    network = verify_network(setup['group'])
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='argus-win-', dir=os.environ['RUNNER_TEMP']) as directory:
        scratch = Path(directory)
        home = scratch / 'home'
        home.mkdir()
        # Create the isolated encrypted store without modifying the runner profile.
        env = worker_env(home)
        init = ("import sys,json;sys.path.insert(0,%r);from jarvis.core.store import Store; "
                "from jarvis.collectors.telemetry import community; s=Store(sys.argv[1]); "
                "s.set_meta(community.META,json.dumps({'since':0,'shapes':{}}));s.commit();s.close()") % str(ROOT)
        db = home / '.jarvis/test.db'
        subprocess.run([sys.executable, '-I', '-c', init, str(db)], env=env, check=True, capture_output=True, timeout=30)
        scenarios, script_file, proof = cases(scratch)
        scenarios = scenarios + more_cases(scratch)
        before, failed_before = sweep(db, home)
        baseline = telemetry(script_file)
        applied, attempted, not_applied, cleanup = [], [], {}, {}
        after, failed_after, observed, execution_error = {}, {}, {}, ''
        try:
            for row in scenarios:
                if row[0] != '05':
                    try:
                        powershell(row[5])  # absence before creation; never undo a pre-existing object
                    except Exception as exc:
                        not_applied[row[0]] = 'precondition: ' + type(exc).__name__
                        continue
                attempted.append(row)
                try:
                    if isinstance(row[3], list):
                        result = subprocess.run(row[3], capture_output=True, text=True, errors='replace', timeout=45)
                        if result.returncode or not proof.is_file():
                            raise RuntimeError('script was prevented or did not complete')
                    else:
                        powershell(row[3])
                    applied.append(row[0])
                except Exception as exc:
                    not_applied[row[0]] = f'{type(exc).__name__}: {str(exc)[:200]}'
            # Event providers can publish asynchronously. Bound retries; never fabricate rows.
            for _attempt in range(10):
                observed = telemetry(script_file)
                if observed['sysmon_registry'] >= 2 and observed['fixture_script_blocks'] > 0:
                    break
                time.sleep(1)
            after, failed_after = sweep(db, home)
        except (Exception, KeyboardInterrupt) as exc:
            execution_error = type(exc).__name__
        finally:
            for row in reversed(attempted):
                try:
                    powershell(row[4] + '; ' + row[5])
                except Exception as exc:
                    cleanup[row[0]] = type(exc).__name__
        new = [value for key, value in after.items() if key not in before]
        rows = []
        for sid, tid, description, _do, _undo, _verify in scenarios:
            marks = (MARK + '-' + sid,) + EXTRA.get(sid, ()) + ((MARK[-10:] + sid,) if sid == '11' else ())
            findings = [(job, f['severity'], f['title']) for job, f in new
                        if any(m in ' '.join(f.values()) for m in marks)]
            state = 'not applied' if sid not in applied else ('caught' if findings else 'missed')
            rows.append({'id': sid, 'technique': tid, 'what': description, 'state': state,
                         'why': not_applied.get(sid, ''), 'findings': findings})
        delivered = (observed.get('sysmon_last', 0) > baseline['sysmon_last']
                     and observed.get('ps_last', 0) > baseline['ps_last']
                     and observed.get('sysmon_registry', 0) >= 2
                     and observed.get('fixture_script_blocks', 0) > 0)
        report = {'platform': 'windows', 'applied': len(applied),
                  'caught': sum(r['state'] == 'caught' for r in rows), 'scenarios': rows,
                  'jobs': list(JOBS), 'jobs_failed_before': failed_before, 'jobs_failed_after': failed_after,
                  'cleanup_failed': cleanup, 'execution_error': execution_error,
                  'network': network, 'telemetry_delivered': delivered,
                  'telemetry_before': baseline, 'telemetry_after': observed,
                  'seconds': round(time.monotonic() - started, 1)}
        if args.json:
            args.json.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f"Windows: {report['caught']}/{len(applied)} applied scenarios named; real telemetry: {delivered}; {report['seconds']} s")
        for row in rows:
            print(row['id'], row['state'], row['what'])
        return 1 if (not delivered or failed_before or failed_after or cleanup or execution_error or not_applied) else 0


if __name__ == '__main__':
    sys.exit(main())

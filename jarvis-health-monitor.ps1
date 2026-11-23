# Independent Windows health monitor: all runtime files live in LocalAppData.
# -Loop: one process checks every IntervalSeconds for LoopMinutes, then exits;
# the task (every 5 minutes, IgnoreNew) starts the next one. Starting PowerShell
# every minute cost ~50 process starts an hour and their Sysmon image-load
# events (measured 2026-11-02). Without -Loop it runs one check, as before.
param([switch]$Install, [switch]$ProbeOnly, [switch]$TestNotification,
      [switch]$Loop, [int]$LoopMinutes = 10, [int]$IntervalSeconds = 60,
      [string]$StateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\HealthMonitor'),
      # Where monitors installed before the rename kept their state. -Install
      # copies it forward once; the old folder stays as the rollback copy.
      [string]$LegacyStateRoot = (Join-Path $env:LOCALAPPDATA 'Jarvis\Deadman'))
$ErrorActionPreference='Stop'
# .NET cuts a non-200 reply at 64 KB; /api/health answers 503 when degraded and is ~90 KB, so the probe
# misread a live daemon as silent and restarted it (measured 2026-11-04). Read up to 4 MB.
[Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
$taskName='JARVIS independent health monitor'
$appId='JARVIS.Monitor'

function Save-State($state) {
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $StateRoot 'state.json.new') -Encoding UTF8
    Move-Item -LiteralPath (Join-Path $StateRoot 'state.json.new') -Destination (Join-Path $StateRoot 'state.json') -Force
}
# The product is ARGUS-INSTINCT (jarvis/core/brand.py has the same rule): the word
# JARVIS is shown as ARGUS-INSTINCT except in the names of real Windows objects.
function Format-Brand([string]$s) {
    return [regex]::Replace($s, '\bJARVIS\b(?!-(?:1|INSTINCT)\b)(?! (input hook|independent health monitor|connectivity guard|native sensor|Jarvis))', 'ARGUS-INSTINCT')
}
function Show-JarvisToast([string]$title,[string]$body) {
    $title=Format-Brand $title; $body=Format-Brand $body
    [void][Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]
    $xml=New-Object Windows.Data.Xml.Dom.XmlDocument
    $t=[Security.SecurityElement]::Escape($title);$b=[Security.SecurityElement]::Escape($body)
    $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$t</text><text>$b</text></binding></visual></toast>")
    $toast=[Windows.UI.Notifications.ToastNotification]::new($xml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
}
function Send-JarvisMail([string]$title,[string]$body) {
    $title=Format-Brand $title; $body=Format-Brand $body
    # Raw HttpWebRequest for the same reason as the health probe below:
    # Invoke-RestMethod can block on proxy and first-run state under Task
    # Scheduler. TLS 1.2 is required by the mail API and is not guaranteed to
    # be enabled for Windows PowerShell 5.1 by default.
    [Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $mailPath=Join-Path $StateRoot 'mail.json'
    if (-not (Test-Path -LiteralPath $mailPath)) { throw [System.InvalidOperationException]::new('mail paused: mail.json is not present') }
    $cfg=Get-Content -LiteralPath $mailPath -Raw | ConvertFrom-Json
    $secure=ConvertTo-SecureString $cfg.key
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $key=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        $json=@{from=$cfg.from;to=@($cfg.to);subject=$title;text=$body}|ConvertTo-Json -Compress
        $bytes=[Text.Encoding]::UTF8.GetBytes($json)
        $req=[Net.HttpWebRequest]::Create('https://api.resend.com/emails')
        $req.Method='POST'; $req.Proxy=$null; $req.Timeout=20000; $req.ReadWriteTimeout=20000
        $req.ContentType='application/json'; $req.Headers['Authorization']='Bearer '+$key
        $stream=$req.GetRequestStream()
        try {$stream.Write($bytes,0,$bytes.Length)} finally {$stream.Dispose()}
        $req.GetResponse().Dispose()
    } finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr);$key=$null}
}
function Get-MailFailure($err) {
    # Why delivery failed, without anything from the request or the key: the
    # HTTP status when the API answered, otherwise the network failure kind.
    $e=$err.Exception
    while ($e.InnerException -and -not ($e -is [Net.WebException])) {$e=$e.InnerException}
    if ($e -is [Net.WebException]) {
        if ($e.Response) {return 'mail API answered HTTP '+[int]$e.Response.StatusCode}
        return 'network: '+$e.Status
    }
    return $e.GetType().Name
}
function Get-Reviver {
    # What the instant reviver (jarvis-reviver.ps1) is doing about it, if anything.
    try {
        $r=Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'Jarvis\Reviver\state.json') -Raw | ConvertFrom-Json
        $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        return @{present=$true;active=($now-[long]$r.checkedAt -lt 30);gaveUp=($r.gaveUp -eq $true);
                 paused=($r.paused -eq $true);action=[string]$r.lastAction;actionAt=[long]$r.lastActionAt}
    } catch {return @{present=$false;active=$false;gaveUp=$false;paused=$false;action='';actionAt=0}}
}
function Get-DegradedSources($h) {
    # Required sources (jarvis/service/protection.py `required`) that are not
    # complete, as "name status (reason)". A source the daemon did not report
    # is named too: absence is not coverage.
    $out=@()
    foreach ($name in @('scan','bridge','sysmon','native')) {
        $s=$null
        if ($h -and $h.sources) {$s=$h.sources.$name}
        if ($null -eq $s) {
            if ($name -eq 'scan') {$out+="$name not reported"}   # scan is required on every host
            continue
        }
        if ([string]$s.status -ne 'complete') {$out+=("{0} {1} ({2})" -f $name,[string]$s.status,[string]$s.reason)}
    }
    return $out
}
function Get-JarvisClientToken {
    # A paired client token (`jarvis desktop pair --name supervisor`, saved on its own
    # line). Every API route but liveness needs one; without it this script sees
    # liveness only. Keep the file readable by this account alone.
    $path = if ($env:JARVIS_CLIENT_TOKEN_FILE) { $env:JARVIS_CLIENT_TOKEN_FILE } else { Join-Path $env:LOCALAPPDATA 'Jarvis\client.token' }
    try { $t = ([IO.File]::ReadAllText($path)).Trim() } catch { return $null }
    if ($t -cmatch '^jc1_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$') { return $t }
    return $null
}
function Add-JarvisToken($req) {
    $tok = Get-JarvisClientToken
    if ($tok) { $req.Headers.Add('X-JARVIS-Token', $tok) }
}
function Get-JarvisHealth {
    # Raw HttpWebRequest, not Invoke-RestMethod. Under Task Scheduler the
    # cmdlet consults the system proxy and Internet Explorer first-run state,
    # and in a hidden non-interactive session that can block past any
    # -TimeoutSec, leaving the task stuck 'Running'. With MultipleInstances
    # IgnoreNew every later trigger is then refused (0x800710E0) and the
    # health monitor silently stops checking -- the exact failure it exists
    # to catch. Proxy is disabled explicitly: this call never leaves the host.
    try {
        # A non-200 reply is cut at DefaultMaximumErrorResponseLength (64 KB) and the
        # health body is 72-76 KB: a live 503 parsed as silence (2026-10-31). Bounded
        # at 4 MB (the unit is KB).
        [Net.HttpWebRequest]::DefaultMaximumErrorResponseLength = 4096
        $req=[Net.HttpWebRequest]::Create('http://127.0.0.1:8787/api/health')
        $req.Proxy=$null; $req.Timeout=8000; $req.ReadWriteTimeout=8000
        $req.Method='GET'; $req.KeepAlive=$false; Add-JarvisToken $req
        $resp=$req.GetResponse()
        try {
            $reader=New-Object IO.StreamReader($resp.GetResponseStream())
            try {$h=$reader.ReadToEnd()|ConvertFrom-Json} finally {$reader.Dispose()}
        } finally {$resp.Dispose()}
        $now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($h.service -ne 'JARVIS' -or $h.healthy -ne $true -or $h.protection_healthy -ne $true -or
            $null -eq $h.time -or [math]::Abs($now-[double]$h.time) -gt 120 -or
            $null -eq $h.progress_age -or [double]$h.progress_age -ge 900) {
            return @{healthy=$false;reason='JARVIS reports stale or invalid scheduler health'}
        }
        return @{healthy=$true;reason='scheduler progress and required protection coverage verified';progress_age=$h.progress_age}
    } catch [Net.WebException] {
        # 503 can mean lost coverage while the scheduler is still alive.
        $r=$_.Exception.Response
        if ($r -and [int]$r.StatusCode -eq 503) {
            try {
                $reader=New-Object IO.StreamReader($r.GetResponseStream())
                try {$h=$reader.ReadToEnd()|ConvertFrom-Json} finally {$reader.Dispose();$r.Dispose()}
                if ($h.live -eq $true) {
                    # Running and making progress, with a source blind or late: a
                    # coverage fault, reported as such -- not as JARVIS being down.
                    $why=@(Get-DegradedSources $h)
                    $list=if ($why.Count) {$why -join '; '} else {'no source named'}
                    return @{healthy=$false;degraded=$true;reason="JARVIS is running but required coverage is degraded: $list"}
                }
            } catch {}
            return @{healthy=$false;reason='JARVIS reports unavailable service or protection coverage'}
        }
        return @{healthy=$false;reason='JARVIS local health endpoint is unreachable'}
    } catch {return @{healthy=$false;reason='JARVIS health probe failed: '+$_.Exception.GetType().Name}}
}

function Copy-LegacyState {
    # Carry the outage-escalation state and the DPAPI-protected mail config
    # over from the pre-rename folder. Copy, never move: the old folder is what
    # the previous task registration still runs from, so it stays intact as
    # the rollback. Files already present in the new folder are never
    # overwritten. DPAPI is scoped to this Windows user, who owns both folders.
    if (-not $LegacyStateRoot -or -not (Test-Path -LiteralPath $LegacyStateRoot)) {return}
    if ((Resolve-Path -LiteralPath $LegacyStateRoot).Path -eq (Resolve-Path -LiteralPath $StateRoot).Path) {return}
    foreach ($name in @('mail.json','state.json')) {
        $from=Join-Path $LegacyStateRoot $name; $to=Join-Path $StateRoot $name
        if ((Test-Path -LiteralPath $from) -and -not (Test-Path -LiteralPath $to)) {
            Copy-Item -LiteralPath $from -Destination $to
            Write-Output "Carried $name over from $LegacyStateRoot"
        }
    }
}

if ($Install) {
    [void](New-Item -ItemType Directory -Path $StateRoot -Force)
    Copy-LegacyState
    $registry="HKCU:\Software\Classes\AppUserModelId\$appId"
    [void](New-Item -Path $registry -Force)
    [void](New-ItemProperty -Path $registry -Name DisplayName -Value 'ARGUS-INSTINCT' -PropertyType String -Force)
    [void](New-ItemProperty -Path $registry -Name ShowInSettings -Value 1 -PropertyType DWord -Force)
    $script=Join-Path $StateRoot 'jarvis-health-monitor.ps1'
    if ($MyInvocation.MyCommand.Path -ne $script) {Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $script -Force}
    # conhost --headless: -WindowStyle Hidden alone still flashes a console window each run.
    $action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\conhost.exe" -Argument ('--headless "'+"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"+'" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$script+'" -Loop')
    # The loop lives 10 minutes and is killed at 15 (a hung loop while WSL is down
    # cannot be restarted from WSL); the 5-minute repeat (IgnoreNew) starts a new
    # one when none is running, so a crashed loop is replaced within minutes.
    $triggers=@((New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)))
    $principal=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
    # The limit must exceed the one-minute repeat, not equal it. At PT1M a
    # run that is merely slow -- PowerShell start-up plus a WinRT load on a
    # loaded machine -- is killed at the boundary and every run records
    # SCHED_S_TASK_TERMINATED (0x41306), which hides a genuine failure
    # behind a result code that is always the same. IgnoreNew already stops
    # slow runs from piling up.
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    [void](Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force)
    Write-Output 'Independent Windows health monitor installed. Stage mail credentials with DPAPI if none were carried over.'
    return
}
if ($ProbeOnly) {Get-JarvisHealth | ConvertTo-Json -Compress;return}
if ($TestNotification) {
    Show-JarvisToast 'JARVIS notification test' 'The independent Windows notification path is working. This is a test.'
    Write-Output 'Test toast submitted to Windows.';return
}

$loopUntil=(Get-Date).AddMinutes([Math]::Max(1,$LoopMinutes))
while ($true) {
try {
[void](New-Item -ItemType Directory -Path $StateRoot -Force)
$state=@{failures=0;firstFailure=0;emailLevel=-1;toastLevel=-1;lastMailAttempt=0;lastToastAttempt=0;lastHealthy=0}
$saved=Join-Path $StateRoot 'state.json'
if (Test-Path -LiteralPath $saved) {
    try {
        $old=Get-Content -LiteralPath $saved -Raw | ConvertFrom-Json
        foreach ($p in $old.PSObject.Properties) {$state[$p.Name]=$p.Value}
        # A note about an earlier unreadable file is history once one reads cleanly.
        $state.Remove('stateError')
    } catch {$state.stateError='Previous state was unreadable; outage confirmation restarted'}
}
$now=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$health=Get-JarvisHealth
$state.checkedAt=$now;$state.healthy=$health.healthy;$state.reason=$health.reason
if ($health.healthy) {
    $state.lastHealthy=$now
    if ($state.emailLevel -ge 0 -or $state.toastLevel -ge 0) {
        if ($state.toastLevel -ge 0) {
            try {Show-JarvisToast 'JARVIS recovered' 'The independent Windows monitor verified scheduler progress.';$state.toastLevel=-1}
            catch {$state.toastError=$_.Exception.Message}
        }
        if ($state.emailLevel -ge 0 -and $now-$state.lastMailAttempt -ge 300) {
            $state.lastMailAttempt=$now
            try {Send-JarvisMail '[JARVIS] monitor recovered' 'The independent Windows monitor verified that JARVIS is reachable and its scheduler is progressing.';$state.emailLevel=-1;$state.mailError=''}
            catch {$state.mailError='Recovery email failed ('+(Get-MailFailure $_)+'); queued for retry'}
        }
    } elseif ($state.mailError -and $now-[long]$state.lastMailAttempt -ge 3600) {
        # An outage mail that failed leaves emailLevel at -1, so nothing above
        # would ever retry and the error would stay stale. Only a delivered
        # message proves the path again; retry at most hourly while healthy.
        $state.lastMailAttempt=$now
        try {Send-JarvisMail '[JARVIS] alert email path restored' 'The independent Windows monitor failed to send an earlier email. Delivery is working again and JARVIS is healthy.';$state.mailError=''}
        catch {$state.mailError='Email delivery still failing ('+(Get-MailFailure $_)+'); retrying hourly. No credential data logged.'}
    }
    $state.failures=0;$state.firstFailure=0;$state.alertKind=''
} else {
    if (-not $state.firstFailure) {$state.firstFailure=$now}
    $state.failures=[int]$state.failures+1
    $age=$now-[long]$state.firstFailure
    # A live reviver gets three minutes to fix it before anyone is told: most
    # outages are a stale source or a restart it clears in seconds. One that
    # has given up, is paused, or is not running gets no such grace.
    $rev=Get-Reviver
    $state.reviver=if (-not $rev.present) {'not installed'} elseif (-not $rev.active) {'not running'} elseif ($rev.paused) {'paused'} elseif ($rev.gaveUp) {'gave up'} else {'working'}
    $holding=$rev.active -and -not $rev.gaveUp -and -not $rev.paused -and $age -lt 180
    if ($state.failures -ge 2 -and $age -ge 60 -and -not $holding) {
        $level=0
        foreach ($threshold in @(3600,21600,86400)) {if ($age -ge $threshold) {$level++}}
        $kind=if ($health.degraded) {'degraded'} else {'unavailable'}
        if ($kind -eq 'unavailable' -and $state.alertKind -eq 'degraded') {
            # It got worse inside the same outage: JARVIS itself is now
            # unreachable or stalled. Tell the owner now, whatever was sent.
            $state.toastLevel=-1;$state.emailLevel=-1;$state.lastToastAttempt=0;$state.lastMailAttempt=0
        }
        $state.alertKind=$kind
        $title=if ($kind -eq 'degraded') {'[JARVIS] coverage degraded'} else {'[JARVIS] monitoring unavailable'}
        $toastTitle=if ($kind -eq 'degraded') {'JARVIS coverage degraded'} else {'JARVIS monitoring unavailable'}
        $tried=if (-not $rev.present) {'The instant reviver is not installed.'}
               elseif (-not $rev.active) {'The instant reviver is not running, so nothing has tried to fix this.'}
               elseif ($rev.paused) {'The instant reviver is paused for maintenance.'}
               elseif ($rev.action) {"The instant reviver tried: $($rev.action) ($([int](($now-$rev.actionAt)/60)) min ago)$(if ($rev.gaveUp) {', and has stopped after its restart budget'})."}
               else {'The instant reviver has not found anything it can safely restart.'}
        $lead=if ($kind -eq 'degraded') {'The independent Windows monitor verified JARVIS is running, but required protection coverage is degraded.'}
              else {'The independent Windows monitor cannot verify JARVIS.'}
        $body="$lead Failure duration: $([int]($age/60)) minutes. $($health.reason). $tried If this persists, open Ubuntu and run: jarvis selfcheck. Escalation level: $level."
        if ($level -gt $state.toastLevel -and $now-$state.lastToastAttempt -ge 300) {
            $state.lastToastAttempt=$now
            try {Show-JarvisToast $toastTitle $body;$state.toastLevel=$level;$state.toastError=''}
            catch {$state.toastError=$_.Exception.Message}
        }
        if ($level -gt $state.emailLevel -and $now-$state.lastMailAttempt -ge 300) {
            $state.lastMailAttempt=$now
            try {Send-JarvisMail $title $body;$state.emailLevel=$level;$state.mailError=''}
            catch {$state.mailError='Outage email failed ('+(Get-MailFailure $_)+'); queued for retry. No credential data logged.'}
        }
    }
}
Save-State $state
} catch {
    # One failed check must not end the loop; a single run still fails loudly.
    if (-not $Loop) { throw }
}
if (-not $Loop -or (Get-Date) -ge $loopUntil) { break }
Start-Sleep -Seconds ([Math]::Max(15,$IntervalSeconds))
}

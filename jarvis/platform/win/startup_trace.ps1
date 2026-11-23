# Read-only startup/periodic-console evidence. Does not enable logs or edit tasks.
# Raw command lines are sensitive: the caller stores this locally with mode 0600.
$ErrorActionPreference = 'Stop'
$o = [ordered]@{ schema=1; collectedAt=(Get-Date).ToUniversalTime().ToString('o'); errors=@(); tasks=@(); windows=@() }
try {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $o.bootTime = $boot.ToUniversalTime().ToString('o')
} catch { $o.errors += 'boot: ' + $_.Exception.Message; $boot = $null }

try {
    $o.tasks = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
        $t = $_
        $actions = @($t.Actions | ForEach-Object { [pscustomobject]@{
            execute=$_.Execute; arguments=$_.Arguments; workingDirectory=$_.WorkingDirectory
        } })
        $info = $null
        try { $info = $t | Get-ScheduledTaskInfo } catch {}
        [pscustomobject]@{
            name=$t.TaskName; path=$t.TaskPath; state=[string]$t.State
            user=$t.Principal.UserId; logonType=[string]$t.Principal.LogonType
            runLevel=[string]$t.Principal.RunLevel; hidden=$t.Settings.Hidden
            actions=$actions
            triggers=@($t.Triggers | ForEach-Object { [pscustomobject]@{
                type=$_.CimClass.CimClassName; start=$_.StartBoundary; delay=$_.Delay
                interval=$_.Repetition.Interval; enabled=$_.Enabled
            } })
            lastRun=$(if ($info -and $info.LastRunTime) { $info.LastRunTime.ToUniversalTime().ToString('o') })
            nextRun=$(if ($info -and $info.NextRunTime) { $info.NextRunTime.ToUniversalTime().ToString('o') })
            lastResult=$(if ($info) { $info.LastTaskResult })
        }
    })
} catch { $o.errors += 'tasks: ' + $_.Exception.Message }

function Read-TraceWindow([string]$label, [string]$channel, [int[]]$ids, [datetime]$start, [datetime]$end, [int]$limit) {
    $r = [ordered]@{ label=$label; channel=$channel; start=$start.ToUniversalTime().ToString('o'); end=$end.ToUniversalTime().ToString('o'); limit=$limit; capped=$false; status='unknown'; events=@() }
    try {
        $log = Get-WinEvent -ListLog $channel
        $r.enabled = $log.IsEnabled
        $r.recordCount = $log.RecordCount
        $r.maximumSizeBytes = $log.MaximumSizeInBytes
        if (-not $log.IsEnabled) { $r.status='disabled'; return [pscustomobject]$r }
        $oldest = Get-WinEvent -LogName $channel -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($oldest) { $r.oldestTime=$oldest.TimeCreated.ToUniversalTime().ToString('o'); $r.oldestRecordId=$oldest.RecordId }
        try {
            $events = @(Get-WinEvent -FilterHashtable @{LogName=$channel; Id=$ids; StartTime=$start; EndTime=$end} -MaxEvents ($limit+1))
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events=@() }
            else { throw }
        }
        $r.status='ok'; $r.capped=($events.Count -gt $limit)
        $r.events = @($events | Select-Object -First $limit | ForEach-Object {
            $e=$_; $d=[ordered]@{}
            foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) {
                if ($n.Name) { $d[[string]$n.Name]=[string]$n.'#text' }
            }
            [pscustomobject]@{ id=$e.Id; recordId=$e.RecordId; time=$e.TimeCreated.ToUniversalTime().ToString('o'); data=$d }
        })
    } catch { $r.status='unavailable'; $r.error=$_.Exception.Message }
    return [pscustomobject]$r
}

$now = Get-Date
$ranges = @(@{name='recent'; start=$now.AddMinutes(-15); end=$now})
if ($boot) { $ranges += @{name='startup'; start=$boot; end=$(if ($boot.AddMinutes(15) -lt $now) {$boot.AddMinutes(15)} else {$now})} }
foreach ($range in $ranges) {
    $o.windows += Read-TraceWindow $range.name 'Microsoft-Windows-TaskScheduler/Operational' @(100,102,129,200,201) $range.start $range.end 2000
    $o.windows += Read-TraceWindow $range.name 'Microsoft-Windows-Sysmon/Operational' @(1,5) $range.start $range.end 4000
}
$json = [pscustomobject]$o | ConvertTo-Json -Depth 12 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

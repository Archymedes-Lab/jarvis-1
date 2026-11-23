$ErrorActionPreference = 'SilentlyContinue'
# Read-only spyware evidence: identity, capture-consent history, autostart, egress.
# Nothing is executed, injected or changed. Paths stay in this process's output
# for local reasoning and are never sent anywhere by this script.
$now = [DateTime]::UtcNow
$sigCache = @{}
function Get-Sig($p) {
    if (-not $p) { return @{ st = 'unknown'; sub = ''; age = $null } }
    if ($sigCache.ContainsKey($p)) { return $sigCache[$p] }
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $age = $null
    $item = Get-Item -LiteralPath $p
    if ($item) { $age = [int]($now - $item.CreationTimeUtc).TotalDays }
    $st = switch ([string]$s.Status) { 'Valid' { 'valid' } 'NotSigned' { 'none' } 'UnknownError' { 'unknown' } default { 'invalid' } }
    $r = @{ st = $st; sub = [string]$s.SignerCertificate.GetNameInfo('SimpleName', $false); age = $age }
    $sigCache[$p] = $r
    return $r
}
$hasWindow = @{}
Get-Process | Where-Object { $_.MainWindowHandle -ne 0 } | ForEach-Object { $hasWindow[[int]$_.Id] = $true }
$ext = @{}
Get-NetTCPConnection -State Established | Where-Object {
    $_.RemoteAddress -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|::1|fe80|fc|fd|0\.0\.0\.0)'
} | ForEach-Object { $ext[[int]$_.OwningProcess] = 1 + [int]$ext[[int]$_.OwningProcess] }
$procs = @(Get-CimInstance Win32_Process | ForEach-Object {
    $sig = Get-Sig $_.ExecutablePath
    [pscustomobject]@{
        pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = $_.Name
        path = $_.ExecutablePath; session = [int]$_.SessionId
        started = if ($_.CreationDate) { $_.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        window = [bool]$hasWindow[[int]$_.ProcessId]; ext = [int]$ext[[int]$_.ProcessId]
        sig = $sig.st; signer = $sig.sub; age = $sig.age
    } })
$base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore'
function Get-ConsentRow($key, $np) {
    $stop = [int64](Get-ItemProperty -LiteralPath $key.PSPath).LastUsedTimeStop
    $start = [int64](Get-ItemProperty -LiteralPath $key.PSPath).LastUsedTimeStart
    $hrs = $null
    if ($start -gt 0 -and $stop -eq 0) { $hrs = 0 }
    elseif ($stop -gt 0) { $hrs = [math]::Round(($now - [DateTime]::FromFileTimeUtc($stop)).TotalHours, 1) }
    [pscustomobject]@{ who = $key.PSChildName; np = $np; hrs = $hrs }
}
$consent = [ordered]@{}
foreach ($cap in 'microphone', 'webcam', 'graphicsCaptureProgrammatic', 'graphicsCaptureWithoutBorder') {
    $rows = @()
    Get-ChildItem "$base\$cap" | ForEach-Object {
        if ($_.PSChildName -eq 'NonPackaged') { Get-ChildItem $_.PSPath | ForEach-Object { $rows += Get-ConsentRow $_ $true } }
        else { $rows += Get-ConsentRow $_ $false }
    }
    $consent[$cap] = @($rows | Where-Object { $_.hrs -ne $null })
}
$auto = @()
foreach ($r in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run') {
    (Get-ItemProperty $r).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $auto += [string]$_.Value }
}
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { foreach ($a in $_.Actions) { if ($a.Execute) { $auto += [string]$a.Execute } } }
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object { $auto += [string]$_.PathName }
$out = [pscustomobject]@{ procs = $procs; consent = $consent; autostart = @($auto | Select-Object -Unique); observed_at = $now.ToString('o') }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Depth 5 -Compress)))

# Run as administrator. Collect evidence, update Defender, scan the reported
# file without remediation, then run a full scan under existing Defender policy.
# No exclusions, protections, policies, or scheduled tasks are changed.
# No reboot or automatic public sample submission is requested by this script.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this reviewed script in an elevated Windows PowerShell session.'
}

$caseName = 'alert-review-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
$caseDir = Join-Path $env:LOCALAPPDATA ('Jarvis\Evidence\' + $caseName)
[void](New-Item -ItemType Directory -Path $caseDir)
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($identity.User.Value, 'S-1-5-18', 'S-1-5-32-544')) {
    $rule = New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)),
        'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $caseDir -AclObject $acl
$state = [ordered]@{ startedUtc=(Get-Date).ToUniversalTime().ToString('o'); stage='collecting'; errors=@() }
function Save-State {
    $state.updatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $caseDir 'status.json') -Encoding UTF8
}
function Save-Json($name, $value) {
    ConvertTo-Json -InputObject $value -Depth 8 |
        Set-Content -LiteralPath (Join-Path $caseDir $name) -Encoding UTF8
}
Write-Host "JARVIS investigation results: $caseDir"
Save-State
try {
    Save-Json 'defender-before.json' (Get-MpComputerStatus)
    $pref = Get-MpPreference
    Save-Json 'defender-preferences.json' ($pref | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress,DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,MAPSReporting,SubmitSamplesConsent)
    Save-Json 'threats-before.json' @(Get-MpThreat)
    $file = Join-Path $env:LOCALAPPDATA 'Temp\cc9c3fe9-50a0-4302-90ab-6f2f13b5914a.tmp.js'
    $state.flaggedFilePresent = Test-Path -LiteralPath $file
    if ($state.flaggedFilePresent) {
        $state.flaggedFileSha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $file -Destination (Join-Path $caseDir 'flagged-script.txt')
        Save-Json 'flagged-file.json' (Get-Item -LiteralPath $file | Select-Object FullName,Length,CreationTimeUtc,LastWriteTimeUtc)
    }
    $history = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path -LiteralPath $history) {
        Copy-Item -LiteralPath $history -Destination (Join-Path $caseDir 'history.txt')
    }
    $state.stage = 'updating-signatures'; Save-State
    try { Update-MpSignature; $state.signatureUpdateSucceeded=$true }
    catch { $state.signatureUpdateSucceeded=$false; $state.errors += $_.Exception.Message }

    if ($state.flaggedFilePresent) {
        $state.stage = 'scanning-flagged-file'; Save-State
        $mp = Get-ChildItem -Path (Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform\*\MpCmdRun.exe') |
            Sort-Object { [version]($_.Directory.Name -replace '-.*$','') } -Descending | Select-Object -First 1
        if (-not $mp) { throw 'Defender MpCmdRun.exe was not found.' }
        & $mp.FullName -Scan -ScanType 3 -File $file -DisableRemediation 2>&1 |
            Out-File -LiteralPath (Join-Path $caseDir 'flagged-file-scan.txt') -Encoding UTF8
        $state.flaggedFileScanExitCode = $LASTEXITCODE
    }
    $state.stage = 'full-scan-running'; Save-State
    $fullScanRequested = Get-Date
    Start-MpScan -ScanType FullScan
    $after = Get-MpComputerStatus
    Save-Json 'defender-after.json' $after
    Save-Json 'threats-after.json' @(Get-MpThreat)
    Save-Json 'detections-after.json' @(Get-MpThreatDetection)
    $state.fullScanCompleted = ($null -ne $after.FullScanEndTime -and $after.FullScanEndTime -ge $fullScanRequested)
    $state.stage = if ($state.fullScanCompleted) { 'completed' } else { 'scan-returned-without-completion-proof' }
} catch {
    $state.errors += $_.Exception.Message
    $state.stage = 'failed'
} finally {
    Save-State
    Write-Host "Stage: $($state.stage). Results: $caseDir"
}

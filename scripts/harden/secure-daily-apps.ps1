# Learns which Windows applications are actually used, audits their trust, and
# applies a small reversible browser-security baseline to daily essentials.
#
# Privacy boundary: this records executable name/path and launch time only. It
# never records command lines, window titles, URLs, documents, or input.
#
#   .\secure-daily-apps.ps1 -Install
#   .\secure-daily-apps.ps1 -Install -AutoHarden
#   .\secure-daily-apps.ps1 -Report
#   .\secure-daily-apps.ps1 -Harden
#   .\secure-daily-apps.ps1 -Undo
#   .\secure-daily-apps.ps1 -Remove

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$Watch,
    [switch]$Report,
    [switch]$Harden,
    [switch]$Undo,
    [switch]$AutoHarden,
    [ValidateRange(1, 365)][int]$Days = 30,
    [ValidateRange(1, 90)][int]$LearningDays = 7,
    [ValidateRange(1, 1000)][int]$MinLaunches = 3,
    [ValidateRange(1, 90)][int]$MinActiveDays = 2
)

$ErrorActionPreference = 'Stop'
$TaskName = 'jarvis daily app guard'
$DataDir = Join-Path $env:LOCALAPPDATA 'Jarvis\AppGuard'
$InstalledScript = Join-Path $DataDir 'secure-daily-apps.ps1'
$EventsFile = Join-Path $DataDir 'launches.jsonl'
$ConfigFile = Join-Path $DataDir 'config.json'
$BackupFile = Join-Path $DataDir 'policy-backup.json'
$ReportFile = Join-Path $DataDir 'essential-apps.json'
$ProtectionFile = Join-Path $DataDir 'browser-protection.json'

function Ensure-DataDir {
    if (-not (Test-Path -LiteralPath $DataDir)) {
        New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    }
}

function Read-Config {
    if (-not (Test-Path -LiteralPath $ConfigFile)) {
        return [pscustomobject]@{
            LearningDays = $LearningDays
            MinLaunches = $MinLaunches
            MinActiveDays = $MinActiveDays
            AutoHarden = $false
        }
    }
    try { return Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json }
    catch { throw "AppGuard config is unreadable: $ConfigFile" }
}

function Write-JsonAtomic([string]$Path, $Value, [int]$Depth = 6) {
    Ensure-DataDir
    $temp = "$Path.tmp"
    $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Read-Launches([int]$WithinDays = 30) {
    if (-not (Test-Path -LiteralPath $EventsFile)) { return @() }
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-$WithinDays)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($line in Get-Content -LiteralPath $EventsFile) {
        if (-not $line.Trim()) { continue }
        try {
            $row = $line | ConvertFrom-Json
            if ([datetime]$row.ts -ge $cutoff) { $rows.Add($row) }
        } catch { }
    }
    return @($rows)
}

function Get-AppReport([int]$WithinDays = 30) {
    $cfg = Read-Config
    $rows = @(Read-Launches -WithinDays $WithinDays)
    $out = foreach ($group in ($rows | Group-Object name)) {
        $ordered = @($group.Group | Sort-Object { [datetime]$_.ts })
        $paths = @($ordered | Where-Object path | Group-Object path |
                   Sort-Object Count -Descending)
        $path = if ($paths.Count) { $paths[0].Name } else { '' }
        $daysUsed = @($ordered | ForEach-Object {
            ([datetime]$_.ts).ToLocalTime().ToString('yyyy-MM-dd')
        } | Sort-Object -Unique).Count
        $signature = 'unknown'
        $publisher = ''
        if ($path -and (Test-Path -LiteralPath $path)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $path
                $signature = [string]$sig.Status
                if ($sig.SignerCertificate) {
                    $publisher = [string]$sig.SignerCertificate.Subject
                }
            } catch { $signature = 'check-failed' }
        }
        [pscustomobject]@{
            name = $group.Name
            launches = $group.Count
            activeDays = $daysUsed
            firstSeen = $ordered[0].ts
            lastSeen = $ordered[-1].ts
            path = $path
            signature = $signature
            publisher = $publisher
            essential = ($group.Count -ge [int]$cfg.MinLaunches -and
                         $daysUsed -ge [int]$cfg.MinActiveDays)
        }
    }
    return @($out | Sort-Object essential, activeDays, launches -Descending)
}

function Show-Report {
    $apps = @(Get-AppReport -WithinDays $Days)
    Write-JsonAtomic -Path $ReportFile -Value $apps
    if (-not $apps.Count) {
        Write-Host "No launches recorded yet. Install the watcher and use Windows normally."
        return
    }
    $apps | Select-Object essential, name, launches, activeDays, signature, path |
        Format-Table -AutoSize
    $protection = @(Get-BrowserProtection)
    Write-JsonAtomic -Path $ProtectionFile -Value $protection
    Write-Host "`nBrowser policy configuration (configured is not proof of enforcement):"
    $protection | Select-Object browser, configured, policyPath |
        Format-Table -AutoSize
    Write-Host "`nMachine-readable report: $ReportFile"
    Write-Host "Protection report: $ProtectionFile"
    Write-Host 'Confirm enforcement inside chrome://policy, edge://policy, brave://policy, or about:policies.'
}

function Save-PreviousPolicy([string]$Path, [string]$Name) {
    $entries = @()
    if (Test-Path -LiteralPath $BackupFile) {
        try { $entries = @(Get-Content $BackupFile -Raw | ConvertFrom-Json) }
        catch { $entries = @() }
    }
    if ($entries | Where-Object { $_.path -eq $Path -and $_.name -eq $Name }) {
        return
    }
    $exists = $false
    $value = $null
    $kind = ''
    if (Test-Path -LiteralPath $Path) {
        $key = Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            $exists = $true
            $value = $key.GetValue($Name)
            $kind = [string]$key.GetValueKind($Name)
        }
    }
    $entries += [pscustomobject]@{
        path = $Path; name = $Name; existed = $exists; value = $value; kind = $kind
    }
    Write-JsonAtomic -Path $BackupFile -Value $entries
}

function Set-SafePolicy([string]$Path, [string]$Name, $Value,
                        [Microsoft.Win32.RegistryValueKind]$Kind) {
    Save-PreviousPolicy -Path $Path -Name $Name
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    $type = if ($Kind -eq [Microsoft.Win32.RegistryValueKind]::DWord) {
        'DWord'
    } else { 'String' }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $type `
        -Force | Out-Null
}

function Protect-Chromium([string]$PolicyPath) {
    # Recommended policies establish safe defaults while remaining user
    # overridable. Standard Safe Browsing avoids Enhanced mode's additional
    # browsing-data sharing.
    Set-SafePolicy $PolicyPath 'SafeBrowsingProtectionLevel' 1 DWord
    Set-SafePolicy $PolicyPath 'HttpsOnlyMode' 'force_balanced_enabled' String
    Set-SafePolicy $PolicyPath 'PasswordLeakDetectionEnabled' 1 DWord
}

function Protect-Edge {
    $path = 'HKCU:\Software\Policies\Microsoft\Edge\Recommended'
    Set-SafePolicy $path 'SmartScreenEnabled' 1 DWord
    Set-SafePolicy $path 'SmartScreenPuaEnabled' 1 DWord
    Set-SafePolicy $path 'HttpsOnlyMode' 'force_balanced_enabled' String
    Set-SafePolicy $path 'PasswordMonitorAllowed' 1 DWord
}

function Protect-Firefox {
    # `enabled` turns HTTPS-Only on by default but still lets the user turn it
    # off for a site that genuinely needs HTTP.
    $path = 'HKCU:\Software\Policies\Mozilla\Firefox'
    Set-SafePolicy $path 'HttpsOnlyMode' 'enabled' String
}

function Get-BrowserProtection {
    $specs = @(
        [pscustomobject]@{ browser='Google Chrome'; path='HKCU:\Software\Policies\Google\Chrome\Recommended'; values=[ordered]@{ SafeBrowsingProtectionLevel=1; HttpsOnlyMode='force_balanced_enabled'; PasswordLeakDetectionEnabled=1 } },
        [pscustomobject]@{ browser='Brave'; path='HKCU:\Software\Policies\BraveSoftware\Brave\Recommended'; values=[ordered]@{ SafeBrowsingProtectionLevel=1; HttpsOnlyMode='force_balanced_enabled'; PasswordLeakDetectionEnabled=1 } },
        [pscustomobject]@{ browser='Microsoft Edge'; path='HKCU:\Software\Policies\Microsoft\Edge\Recommended'; values=[ordered]@{ SmartScreenEnabled=1; SmartScreenPuaEnabled=1; HttpsOnlyMode='force_balanced_enabled'; PasswordMonitorAllowed=1 } },
        [pscustomobject]@{ browser='Firefox'; path='HKCU:\Software\Policies\Mozilla\Firefox'; values=[ordered]@{ HttpsOnlyMode='enabled' } }
    )
    foreach ($spec in $specs) {
        $configured = 0
        $actual = [ordered]@{}
        foreach ($name in $spec.values.Keys) {
            $value = $null
            if (Test-Path -LiteralPath $spec.path) {
                try { $value = (Get-ItemProperty -LiteralPath $spec.path -Name $name).$name }
                catch { $value = $null }
            }
            $actual[$name] = $value
            if ([string]$value -eq [string]$spec.values[$name]) { $configured++ }
        }
        [pscustomobject]@{
            browser = $spec.browser
            configured = "$configured/$($spec.values.Count)"
            expected = $spec.values
            actual = $actual
            policyPath = $spec.path
        }
    }
}

function Get-TrustedEssentialBrowser($Apps, [string]$Name,
                                     [string]$PublisherPattern) {
    return @($Apps | Where-Object {
        $_.name -eq $Name -and $_.signature -eq 'Valid' -and
        $_.publisher -match $PublisherPattern
    })
}

function Invoke-Hardening {
    $apps = @(Get-AppReport -WithinDays $Days | Where-Object essential)
    $changed = [System.Collections.Generic.List[string]]::new()

    if ((Get-TrustedEssentialBrowser $apps 'chrome.exe' '(^|,\s*)CN=Google LLC(,|$)').Count) {
        Protect-Chromium 'HKCU:\Software\Policies\Google\Chrome\Recommended'
        $changed.Add('Google Chrome')
    }
    if ((Get-TrustedEssentialBrowser $apps 'brave.exe' '(^|,\s*)CN=Brave Software').Count) {
        Protect-Chromium 'HKCU:\Software\Policies\BraveSoftware\Brave\Recommended'
        $changed.Add('Brave')
    }
    if ((Get-TrustedEssentialBrowser $apps 'msedge.exe' '(^|,\s*)CN=Microsoft Corporation(,|$)').Count) {
        Protect-Edge
        $changed.Add('Microsoft Edge')
    }
    if ((Get-TrustedEssentialBrowser $apps 'firefox.exe' '(^|,\s*)CN=Mozilla Corporation(,|$)').Count) {
        Protect-Firefox
        $changed.Add('Firefox')
    }

    Write-JsonAtomic -Path $ReportFile -Value $apps
    if ($changed.Count) {
        Write-Host "Applied reversible browser protections: $($changed -join ', ')"
        Write-Host "Previous policy values are backed up at $BackupFile"
    } else {
        Write-Host 'No recognized, validly signed browser has met the essential-app threshold yet.'
    }

    $untrusted = @($apps | Where-Object { $_.signature -notin @('Valid', 'NotSupported') })
    if ($untrusted.Count) {
        Write-Warning "$($untrusted.Count) essential app(s) lack a valid publisher signature. Review $ReportFile."
    }
    Write-JsonAtomic -Path $ProtectionFile -Value @(Get-BrowserProtection)
    Write-Host "Configured-policy report: $ProtectionFile"
    Write-Host 'Confirm browser enforcement at chrome://policy, edge://policy, brave://policy, or about:policies.'
}

function Restore-Policies {
    if (-not (Test-Path -LiteralPath $BackupFile)) {
        Write-Host 'No AppGuard policy backup exists.'
        return
    }
    $entries = @(Get-Content $BackupFile -Raw | ConvertFrom-Json)
    foreach ($entry in $entries) {
        if ($entry.existed) {
            if (-not (Test-Path -LiteralPath $entry.path)) {
                New-Item -Path $entry.path -Force | Out-Null
            }
            $kind = if ($entry.kind -eq 'DWord') { 'DWord' } else { 'String' }
            New-ItemProperty -Path $entry.path -Name $entry.name -Value $entry.value `
                -PropertyType $kind -Force | Out-Null
        } elseif (Test-Path -LiteralPath $entry.path) {
            Remove-ItemProperty -Path $entry.path -Name $entry.name `
                -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $BackupFile -Force
    Write-Host 'Restored the browser policies that existed before AppGuard.'
}

function Install-Watcher {
    Ensure-DataDir
    Copy-Item -LiteralPath $PSCommandPath -Destination $InstalledScript -Force
    Write-JsonAtomic -Path $ConfigFile -Value ([pscustomobject]@{
        LearningDays = $LearningDays
        MinLaunches = $MinLaunches
        MinActiveDays = $MinActiveDays
        AutoHarden = [bool]$AutoHarden
    })
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    $arg = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass ' +
           '-File "' + $InstalledScript + '" -Watch'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
        -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings `
        -Description 'Counts app launches without commands/titles and audits daily essentials' |
        Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Installed and started '$TaskName'. Data stays local at $DataDir"
}

function Remove-Watcher {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false `
        -ErrorAction SilentlyContinue
    Write-Host "Removed '$TaskName'. Usage data was preserved at $DataDir"
}

function Start-Watcher {
    Ensure-DataDir
    $source = 'Jarvis.AppGuard.ProcessStart'
    Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
    Register-CimIndicationEvent `
        -Query 'SELECT ProcessID, ParentProcessID, ProcessName FROM Win32_ProcessStartTrace' `
        -SourceIdentifier $source | Out-Null
    $last = @{}
    $lastHardenDay = ''
    try {
        while ($true) {
            $event = Wait-Event -SourceIdentifier $source -Timeout 30
            if ($event) {
                $e = $event.SourceEventArgs.NewEvent
                Remove-Event -EventIdentifier $event.EventIdentifier
                $name = ([string]$e.ProcessName).ToLowerInvariant()
                if (-not $name -or $name -in @(
                    'conhost.exe', 'dllhost.exe', 'runtimebroker.exe',
                    'backgroundtaskhost.exe', 'taskhostw.exe', 'werfault.exe',
                    'audiodg.exe', 'fontdrvhost.exe', 'wermgr.exe'
                )) { continue }

                # Count an app once per launch session, not once per Chromium
                # renderer/helper process.
                try {
                    $parent = Get-Process -Id ([int]$e.ParentProcessID) -ErrorAction Stop
                    if (("$($parent.ProcessName).exe").ToLowerInvariant() -eq $name) {
                        continue
                    }
                } catch { }
                $now = (Get-Date).ToUniversalTime()
                if ($last.ContainsKey($name) -and
                    ($now - $last[$name]).TotalSeconds -lt 30) { continue }
                $last[$name] = $now

                $path = ''
                try {
                    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$e.ProcessID)"
                    $path = [string]$proc.ExecutablePath
                } catch { }
                $row = [pscustomobject]@{
                    ts = $now.ToString('o'); name = $name; path = $path
                }
                $json = $row | ConvertTo-Json -Compress
                [IO.File]::AppendAllText($EventsFile, $json + [Environment]::NewLine,
                    [Text.UTF8Encoding]::new($false))
            }

            $cfg = Read-Config
            $today = (Get-Date).ToString('yyyy-MM-dd')
            if ($cfg.AutoHarden -and $today -ne $lastHardenDay) {
                $rows = @(Read-Launches -WithinDays ([int]$cfg.LearningDays + 1))
                if ($rows.Count) {
                    $first = ($rows | Sort-Object { [datetime]$_.ts } | Select-Object -First 1)
                    if (((Get-Date) - ([datetime]$first.ts).ToLocalTime()).TotalDays -ge
                        [int]$cfg.LearningDays) {
                        Invoke-Hardening
                        $lastHardenDay = $today
                    }
                }
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier $source -ErrorAction SilentlyContinue
    }
}

if ($Install) { Install-Watcher; exit 0 }
if ($Remove) { Remove-Watcher; exit 0 }
if ($Undo) { Restore-Policies; exit 0 }
if ($Harden) { Invoke-Hardening; exit 0 }
if ($Watch) { Start-Watcher; exit 0 }
Show-Report

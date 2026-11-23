<#
.SYNOPSIS
  Install (or remove) the ARGUS-INSTINCT desktop app for the current Windows user.

.DESCRIPTION
  No administrator rights, no network, no installer framework: every change is listed here
  and -Uninstall reverses all of them.

    %LOCALAPPDATA%\Programs\ARGUS-INSTINCT Desktop\jarvis-desktop.exe   the binary (hash-checked copy)
    %LOCALAPPDATA%\Programs\ARGUS-INSTINCT Desktop\jarvis.png           notification icon
    %LOCALAPPDATA%\Programs\ARGUS-INSTINCT Desktop\install-receipt.json what was installed, from which build
    HKCU\Software\Classes\AppUserModelId\local.jarvis.desktop
                                                         lets Windows show the app's toasts
    Start menu\Programs\ARGUS-INSTINCT.lnk                launcher
    Scheduled task "ARGUS-INSTINCT desktop"               at logon, current user, limited,
                                                         runs the binary with --hidden (tray)

  The app is a client: quitting or removing it never stops monitoring (`jarvis serve` and
  its tasks are untouched). WebView2 keeps its own profile in
  %LOCALAPPDATA%\local.jarvis.desktop; -Uninstall leaves it unless -Purge is given.

  ARGUS-INSTINCT's own control audit will list the "ARGUS-INSTINCT desktop" task (an undeclared scheduled
  task, low) and the new unsigned binary. That is the correct report for a binary built
  here; it is not suppressed.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoAutostart
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
#>
param(
    [string]$BuildRoot = (Join-Path $env:LOCALAPPDATA 'JarvisDesktopBuild'),
    [switch]$NoAutostart,
    [switch]$NoLaunch,
    [switch]$Uninstall,
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$AppId = 'local.jarvis.desktop'           # tauri.conf.json "identifier": the toast AUMID
$TaskName = 'ARGUS-INSTINCT desktop'
$Dest = Join-Path $env:LOCALAPPDATA 'Programs\ARGUS-INSTINCT Desktop'
$Exe = Join-Path $Dest 'jarvis-desktop.exe'
$Icon = Join-Path $Dest 'jarvis.png'
$AumidKey = "HKCU:\Software\Classes\AppUserModelId\$AppId"
$Shortcut = Join-Path ([Environment]::GetFolderPath('Programs')) 'ARGUS-INSTINCT.lnk'
$Me = "$env:USERDOMAIN\$env:USERNAME"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # The task must belong to the desktop user at a limited run level; an elevated shell
    # would also make the copy administrator-owned.
    throw 'Run this from a normal (not elevated) PowerShell.'
}

function Stop-InstalledApp {
    # Only the copy installed here; a build being tested from target\ is left alone.
    Get-Process -Name 'jarvis-desktop' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and ($_.Path -ieq $Exe) } |
        ForEach-Object { Stop-Process -Id $_.Id -Force; $_.WaitForExit(5000) | Out-Null }
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Stop-InstalledApp
    Remove-Item -LiteralPath $Shortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $AumidKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Dest -Recurse -Force -ErrorAction SilentlyContinue
    if ($Purge) {
        Remove-Item -LiteralPath (Join-Path $env:LOCALAPPDATA $AppId) -Recurse -Force -ErrorAction SilentlyContinue
    }
    $left = @($Dest, $Shortcut) | Where-Object { Test-Path -LiteralPath $_ }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $left += "task $TaskName" }
    if (Test-Path -LiteralPath $AumidKey) { $left += $AumidKey }
    if ($left.Count) { throw "Not fully removed: $($left -join ', ')" }
    Write-Host 'ARGUS-INSTINCT desktop removed. Monitoring is unaffected.' -ForegroundColor Green
    exit 0
}

# The binary, as desktop/scripts/build-windows.sh handed it over.
$built = Join-Path $BuildRoot 'jarvis-desktop.exe'
$receiptPath = Join-Path $BuildRoot 'build-receipt.json'
if (-not (Test-Path -LiteralPath $built)) { throw "No build at $built. Run desktop/scripts/build-windows.sh in WSL first." }
if (-not (Test-Path -LiteralPath $receiptPath)) { throw "No build receipt beside $built. Run desktop/scripts/build-windows.sh (it writes one)." }
$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$hash = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -ne $receipt.sha256) {
    throw "The binary changed after it was built (receipt $($receipt.sha256), file $hash). Rebuild."
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Stop-InstalledApp
Copy-Item -LiteralPath $built -Destination $Exe -Force
if ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash) {
    throw "Copy to $Exe does not match the build."
}
Copy-Item -LiteralPath (Join-Path $BuildRoot 'jarvis.png') -Destination $Icon -Force

# Toasts from an unpackaged app show only for a registered AppUserModelID.
New-Item -Path $AumidKey -Force | Out-Null
New-ItemProperty -Path $AumidKey -Name 'DisplayName' -Value 'ARGUS-INSTINCT' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $AumidKey -Name 'IconUri' -Value $Icon -PropertyType String -Force | Out-Null

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($Shortcut)
$lnk.TargetPath = $Exe
$lnk.WorkingDirectory = $Dest
$lnk.Description = 'ARGUS-INSTINCT security monitor (window, tray and notifications)'
$lnk.Save()

if ($NoAutostart) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} else {
    $action = New-ScheduledTaskAction -Execute $Exe -Argument '--hidden' -WorkingDirectory $Dest
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $Me
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $Me -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $taskPrincipal -Settings $settings -Description 'ARGUS-INSTINCT desktop window and tray (a client; monitoring runs without it).' -Force | Out-Null
}

# Read back what was installed rather than trusting the calls above.
$t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
$autostart = 'MISMATCH'
if ($NoAutostart) {
    $autostart = if ($t) { 'MISMATCH' } else { 'off' }
} elseif ($t -and @($t.Actions).Count -eq 1) {
    $owner = ([string]$t.Principal.UserId -split '\\')[-1]
    if ($t.Actions[0].Execute -eq $Exe -and $t.Actions[0].Arguments -eq '--hidden' -and
        [string]$t.Principal.RunLevel -eq 'Limited' -and $owner -ieq $env:USERNAME) {
        $autostart = 'verified'
    }
}
$check = [ordered]@{
    binary_matches_build = ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant() -eq $hash)
    aumid_registered     = ((Get-ItemProperty -LiteralPath $AumidKey -ErrorAction SilentlyContinue).DisplayName -eq 'ARGUS-INSTINCT')
    shortcut             = (Test-Path -LiteralPath $Shortcut)
    autostart            = $autostart
}
$install = [ordered]@{
    installed_utc = (Get-Date).ToUniversalTime().ToString('o')
    sha256        = $hash
    built_utc     = $receipt.built_utc
    path          = $Exe
    readback      = $check
}
$install | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Dest 'install-receipt.json') -Encoding UTF8
$check.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Key, $_.Value) }
if (-not $check.binary_matches_build -or -not $check.aumid_registered -or -not $check.shortcut -or $check.autostart -eq 'MISMATCH') {
    throw 'Install read-back failed; see above.'
}

if (-not $NoLaunch) {
    $launched = Get-Date
    Start-Process -FilePath $Exe -WorkingDirectory $Dest
    Start-Sleep -Seconds 5
    # Defender's ASR prevalence rule blocks some freshly built executables; say so plainly
    # instead of reporting an install that cannot start.
    $blocked = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1121; StartTime = $launched } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match [regex]::Escape($Exe) })
    if ($blocked.Count) {
        throw "Defender blocked $Exe (ASR event 1121). See docs/architecture/DESKTOP-APP.md, Windows readiness."
    }
    if (-not (Get-Process -Name 'jarvis-desktop' -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $Exe })) {
        throw "Installed, but $Exe is not running 5 s after launch."
    }
}
Write-Host "ARGUS-INSTINCT desktop installed ($hash)." -ForegroundColor Green

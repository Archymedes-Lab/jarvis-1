# Stops JARVIS's hidden scheduled monitors flashing terminal windows.
# With "Default terminal application = Let Windows decide", Windows 11 hosts
# every console process in Windows Terminal (OpenConsole.exe -Embedding), and
# Terminal ignores the hidden show-state that powershell -WindowStyle Hidden
# requests -- so each one-minute task opens a visible window. Classic Console
# Host honours it. Per-user (HKCU), no elevation, reversible with -Revert.
param([switch]$Revert, [switch]$Status)
$ErrorActionPreference = 'Stop'
$key = 'HKCU:\Console\%%Startup'
$conhost = '{B23D10C0-E52E-411E-9D5B-C09FDF709C7D}'
$backup = Join-Path $env:LOCALAPPDATA 'Jarvis\console-host-backup.json'

function Get-Delegation {
    $p = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
    [pscustomobject]@{ DelegationConsole = $p.DelegationConsole; DelegationTerminal = $p.DelegationTerminal }
}

if ($Status) { Get-Delegation | ConvertTo-Json -Compress; return }

if ($Revert) {
    if (-not (Test-Path -LiteralPath $backup)) { throw "No backup at $backup; nothing to revert." }
    $old = Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
    foreach ($name in 'DelegationConsole', 'DelegationTerminal') {
        if ($old.$name) { Set-ItemProperty -LiteralPath $key -Name $name -Value $old.$name }
        else { Remove-ItemProperty -LiteralPath $key -Name $name -ErrorAction SilentlyContinue }
    }
    Write-Output ('Restored: ' + (Get-Delegation | ConvertTo-Json -Compress))
    return
}

if (-not (Test-Path -LiteralPath $key)) { [void](New-Item -Path $key -Force) }
$current = Get-Delegation
if ($current.DelegationConsole -eq $conhost -and $current.DelegationTerminal -eq $conhost) {
    Write-Output 'Already using Windows Console Host; no change.'
    return
}
# Never overwrite the first backup: a second run must still revert to the original.
if (-not (Test-Path -LiteralPath $backup)) {
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $backup))
    $current | ConvertTo-Json | Set-Content -LiteralPath $backup -Encoding UTF8
}
Set-ItemProperty -LiteralPath $key -Name DelegationConsole -Value $conhost -Type String
Set-ItemProperty -LiteralPath $key -Name DelegationTerminal -Value $conhost -Type String
$after = Get-Delegation
if ($after.DelegationConsole -ne $conhost -or $after.DelegationTerminal -ne $conhost) { throw 'Setting did not persist.' }
Write-Output "Default terminal set to Windows Console Host. Backup: $backup. Undo: .\fix-console-host.ps1 -Revert"

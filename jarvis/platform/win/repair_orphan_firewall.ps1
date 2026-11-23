# Fixed operation: disable local inbound allow rules for missing executables.
# No elevation prompts, arbitrary commands, deletion, or policy-store edits.
$ErrorActionPreference = 'Stop'
$result = @{ ok = $false; changed = 0 }
try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Administrator permission is unavailable'
    }
    $targets = @(
        foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore)) {
            if ($rule.Enabled -ne 'True' -or $rule.Direction -ne 'Inbound' -or
                $rule.Action -ne 'Allow' -or $rule.PolicyStoreSourceType -ne 'Local') { continue }
            $apps = @($rule | Get-NetFirewallApplicationFilter)
            if ($apps.Count -ne 1) { continue }
            $program = [Environment]::ExpandEnvironmentVariables([string]$apps[0].Program)
            if ($program -notmatch '^[A-Za-z]:\\.+\.exe$') { continue }
            if (Test-Path -LiteralPath $program) { continue }
            # Prove absence from the nearest existing ancestor: updaters remove
            # whole version directories, while an unmounted drive or a
            # directory this token cannot list is not absence.
            $ancestor = Split-Path -Parent $program
            $child = Split-Path -Leaf $program
            while ($ancestor -and -not (Test-Path -LiteralPath $ancestor -PathType Container)) {
                $child = Split-Path -Leaf $ancestor
                $ancestor = Split-Path -Parent $ancestor
            }
            if (-not $ancestor) { continue }
            try { $names = @(Get-ChildItem -LiteralPath $ancestor -Force -Name -ErrorAction Stop) }
            catch { continue }
            if ($names -contains $child) { continue }
            [pscustomobject]@{ Name = $rule.Name; Program = $program; Enabled = $rule.Enabled }
        }
    )
    if ($targets.Count) {
        $dir = Join-Path $env:LOCALAPPDATA 'Jarvis\repairs'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $backup = Join-Path $dir ('orphan-firewall-' + [guid]::NewGuid().ToString() + '.clixml')
        $targets | Export-Clixml -LiteralPath $backup
        foreach ($target in $targets) {
            if (Test-Path -LiteralPath $target.Program) { throw 'Program reappeared' }
            Disable-NetFirewallRule -PolicyStore PersistentStore -Name $target.Name | Out-Null
            $live = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $target.Name)
            if (-not $live.Count -or @($live | Where-Object Enabled -ne 'False').Count) {
                throw 'Rule disable could not be verified'
            }
            $result.changed++
        }
    }
    $result.ok = $true
} catch { $result.ok = $false }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Compress)))

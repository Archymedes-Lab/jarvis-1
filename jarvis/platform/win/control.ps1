
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.currentUser = "$env:USERDOMAIN\$env:USERNAME"
$o.localAppData = $env:LOCALAPPDATA

function Get-NormalizedTextHash([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").TrimEnd()
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } catch { return $null }
}

# --- persistence: scheduled tasks not shipped by Microsoft
$o.tasks = @(Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*'
} | ForEach-Object {
    $task = $_
    $principal = $task.Principal
    $actions = @($task.Actions | ForEach-Object {
        $target = $null
        if ($_.Arguments -match '(?i)(?:^|\s)-File\s+(?:"([^"]+)"|([^\s]+))') {
            $target = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
        }
        # A COM-handler action runs the DLL registered for its class id.
        $handler = $null
        if ($_.ClassId) {
            $handler = (Get-ItemProperty -LiteralPath "Registry::HKEY_CLASSES_ROOT\CLSID\$($_.ClassId)\InprocServer32" `
                -ErrorAction SilentlyContinue).'(default)'
        }
        [pscustomobject]@{
            execute=$_.Execute
            arguments=$_.Arguments
            target=$target
            targetHash=(Get-NormalizedTextHash $target)
            handler=$handler
        }
    })
    [pscustomobject]@{
        name=$task.TaskName
        path=$task.TaskPath
        author=$task.Author
        user=$principal.UserId
        logonType=[string]$principal.LogonType
        runLevel=[string]$principal.RunLevel
        actions=$actions
    }
})

# --- persistence: Run / RunOnce registry keys
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$o.runkeys = @(foreach ($k in $runKeys) {
    $p = Get-ItemProperty -Path $k
    if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } |
        ForEach-Object { [pscustomobject]@{ key=$k; name=$_.Name; value=[string]$_.Value } } }
})

# --- persistence: startup folders
$o.startup = @(Get-ChildItem -Path @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") -File |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; path=$_.FullName } })

# --- persistence: auto-start services outside system32
$o.services = @(Get-CimInstance Win32_Service |
    Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and
                   $_.PathName -notlike '*\System32\*' } |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; disp=$_.DisplayName;
                                        path=$_.PathName; state=$_.State } })

# --- persistence: WMI event subscriptions (a quiet, classic foothold)
$o.wmi = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    ForEach-Object { [pscustomobject]@{ filter=[string]$_.Filter; consumer=[string]$_.Consumer } })

# --- remote: inbound control channels
$rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$winrm   = (Get-Service WinRM).Status
$sshd    = (Get-Service sshd).Status
$o.remote = [pscustomobject]@{
    rdpEnabled = ($rdpDeny -eq 0)
    winrm      = [string]$winrm
    sshd       = [string]$sshd
    sessions   = @(query user 2>$null)
}

# --- remote: interactive logon sessions other than the console
$o.logons = @(Get-CimInstance Win32_LogonSession |
    Where-Object { $_.LogonType -in 3,10 } |
    Select-Object -First 20 LogonId, LogonType, StartTime)

# --- defense: Defender + tamper protection
$mp = Get-MpComputerStatus
$pref = Get-MpPreference
$o.defender = [pscustomobject]@{
    present          = [bool]$mp
    realtime         = $mp.RealTimeProtectionEnabled
    tamperProtection = $mp.IsTamperProtected
    antivirus        = $mp.AntivirusEnabled
    sigAgeDays       = $mp.AntivirusSignatureAge
    exclusionPaths   = @($pref.ExclusionPath)
    exclusionProcs   = @($pref.ExclusionProcess)
}

# --- defense: firewall profile state
$o.firewall = @(Get-NetFirewallProfile |
    ForEach-Object { [pscustomobject]@{ name=$_.Name; enabled=$_.Enabled } })

# --- defense: inbound Allow rules opened for specific programs
$o.fwrules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.Group -eq $null -or $_.Group -eq '' } |
    Select-Object -First 40 DisplayName, Profile)

# --- privilege: who is a local administrator
$o.admins = @((Get-LocalGroupMember -Group 'Administrators').Name)

# --- privilege: UAC posture
$o.uac = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

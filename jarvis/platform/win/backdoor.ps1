
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.authkeys = @()
foreach ($p in @("$env:ProgramData\ssh\administrators_authorized_keys") +
                @(Get-ChildItem C:\Users -Directory |
                  ForEach-Object { Join-Path $_.FullName '.ssh\authorized_keys' })) {
  if (Test-Path $p) {
    $o.authkeys += [pscustomobject]@{ path=$p; body=(Get-Content $p -Raw) }
  }
}

# Accessibility backdoor: a debugger on sethc/utilman gives a SYSTEM shell
# from the logon screen without any credential.
$o.ifeo = @('sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe',
            'displayswitch.exe','atbroker.exe') | ForEach-Object {
  $k = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
  $d = (Get-ItemProperty -Path $k -Name Debugger).Debugger
  if ($d) { [pscustomobject]@{ exe=$_; debugger=[string]$d } }
}

# Accounts hidden from the sign-in screen.
$o.hidden = @()
$ul = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
if (Test-Path $ul) {
  # Privilege decides what a hidden account can do. Groups are looked up by
  # well-known SID (Administrators, Remote Desktop Users) so a localized
  # group name cannot hide membership; a failed lookup reports $null.
  $groups = @{}
  foreach ($sid in 'S-1-5-32-544','S-1-5-32-555') {
    try { $groups[$sid] = @(Get-LocalGroupMember -SID $sid -ErrorAction Stop |
                            ForEach-Object { ([string]$_.Name).Split('\')[-1] }) }
    catch { $groups[$sid] = $null }
  }
  (Get-Item $ul).Property | ForEach-Object {
    $name = $_
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    $o.hidden += [pscustomobject]@{
      name=$name; val=[int](Get-ItemProperty $ul $name).$name
      exists=[bool]$user; enabled=($user -and [bool]$user.Enabled)
      admin=$(if ($null -eq $groups['S-1-5-32-544']) { $null } else { $groups['S-1-5-32-544'] -contains $name })
      rdp=$(if ($null -eq $groups['S-1-5-32-555']) { $null } else { $groups['S-1-5-32-555'] -contains $name })
    }
  }
}

$o.sshsvc = [string](Get-Service sshd).Status
$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))


# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'Stop'
# The user the broker was installed for, recorded by SID at install in this
# administrator-only folder. The broker runs as SYSTEM, so per-user state is
# read from HKEY_USERS\<SID>, read-only, never from this process's environment.
$UserSid = ''
try { $UserSid = [string](Get-Content -LiteralPath (Join-Path $PSScriptRoot 'user.json') -Raw | ConvertFrom-Json).sid } catch { }
if ($UserSid -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { $UserSid = '' }
$o = @{errors=@(); connections=@(); apps=@(); profiles=@(); logs=@(); browserPolicies=@()}
# Per-user policies are unknown, not absent, when the recorded user's hive
# is not loaded (that user is signed out) or no user was recorded.
$o.user_hive = if (-not $UserSid) { 'no recorded user' } elseif (Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid") { 'loaded' } else { 'not loaded' }
try {
  $o.connections = @(Get-NetTCPConnection | Where-Object { $_.State -in 'Listen','Established' } |
    ForEach-Object { @{pid=[int]$_.OwningProcess; proto='tcp'; local_ip=[string]$_.LocalAddress;
      local_port=[int]$_.LocalPort; remote_ip=[string]$_.RemoteAddress;
      remote_port=[int]$_.RemotePort; state=([string]$_.State).ToUpperInvariant()} })
} catch { $o.errors += 'TCP socket inventory unavailable' }
try {
  $o.connections += @(Get-NetUDPEndpoint | ForEach-Object {
    @{pid=[int]$_.OwningProcess; proto='udp'; local_ip=[string]$_.LocalAddress;
      local_port=[int]$_.LocalPort; remote_ip=''; remote_port=0; state='BOUND'} })
} catch { $o.errors += 'UDP endpoint inventory unavailable' }
try {
  $ids = @($o.connections | ForEach-Object { $_.pid } | Sort-Object -Unique)
  $o.apps = @(Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -in $ids } |
    ForEach-Object {
      $flags = @([regex]::Matches([string]$_.CommandLine,
        '(?i)(?:^|\s)(--(?:no-sandbox|disable-web-security|ignore-certificate-errors|remote-debugging-port)(?:=\S+)?)') |
        ForEach-Object { ($_.Groups[1].Value -split '=')[0] } | Sort-Object -Unique)
      @{pid=[int]$_.ProcessId; name=[string]$_.Name; exe=[string]$_.ExecutablePath; flags=$flags}
    })
} catch { $o.errors += 'Application attribution unavailable' }
$specs = @(
  @{app='chrome.exe'; path='Software\Policies\Google\Chrome'; keys=@('SafeBrowsingProtectionLevel','PasswordLeakDetectionEnabled')},
  @{app='brave.exe'; path='Software\Policies\BraveSoftware\Brave'; keys=@('SafeBrowsingProtectionLevel','PasswordLeakDetectionEnabled')},
  @{app='msedge.exe'; path='Software\Policies\Microsoft\Edge'; keys=@('SmartScreenEnabled','SmartScreenPuaEnabled')}
)
foreach ($spec in $specs) {
  if (@($o.apps | Where-Object { $_.name -eq $spec.app }).Count -eq 0) { continue }
  $hives = @('HKLM:')
  if ($UserSid) { $hives += "Registry::HKEY_USERS\$UserSid" }
  foreach ($hive in $hives) {
    foreach ($suffix in @('', '\Recommended')) {
      $path = $hive + '\' + $spec.path + $suffix
      foreach ($key in $spec.keys) {
        $value = Get-ItemProperty -LiteralPath $path -Name $key -ErrorAction SilentlyContinue
        if ($null -ne $value) {
          # Reported under the HKCU: name the consumers already use.
          $o.browserPolicies += @{app=$spec.app; key=$key; value=$value.$key; source=($path -replace '^Registry::HKEY_USERS\\S-1-[0-9-]+', 'HKCU:')}
        }
      }
    }
  }
}
try {
  $profiles = @(Get-NetFirewallProfile)
  $o.profiles = @($profiles | ForEach-Object {
    @{name=[string]$_.Name; enabled=[bool]$_.Enabled; blocked=[bool]$_.LogBlocked; allowed=[bool]$_.LogAllowed}
  })
  foreach ($path in @($profiles.LogFileName | Sort-Object -Unique)) {
    try {
      $path = [Environment]::ExpandEnvironmentVariables($path)
      $head = @(Get-Content -LiteralPath $path -TotalCount 30 | ForEach-Object { $_.ToString() })
      $fields = @($head | Where-Object { $_ -like '#Fields:*' } | Select-Object -Last 1)
      $tail = @(Get-Content -LiteralPath $path -Tail 1000 | ForEach-Object { $_.ToString() })
      $o.logs += @{fields=($fields -join ''); lines=$tail; capped=($tail.Count -ge 1000)}
    } catch { $o.errors += 'Firewall traffic log unreadable' }
  }
} catch { $o.errors += 'Firewall logging configuration unavailable' }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))

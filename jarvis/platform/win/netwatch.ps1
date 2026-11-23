
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.adapters = @(Get-NetAdapter | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; status=[string]$_.Status
                     mac=[string]$_.MacAddress; type=[string]$_.MediaType
                     up=[bool]($_.Status -eq 'Up') }})

# netsh is the only place BSSID, channel, authentication and cipher are all
# exposed together, so it is parsed as text rather than reinvented.
$o.wlan = [string](netsh wlan show interfaces 2>$null | Out-String)

$o.ipcfg = @(Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    iface=[string]$_.InterfaceAlias
    ipv4=[string]($_.IPv4Address.IPAddress -join ',')
    gw=[string]($_.IPv4DefaultGateway.NextHop -join ',')
    dns=[string](($_.DNSServer | Where-Object {$_.AddressFamily -eq 2}).ServerAddresses -join ',')
  }})

$o.neighbors = @(Get-NetNeighbor -AddressFamily IPv4 |
  Where-Object { $_.State -in 'Reachable','Stale','Permanent' } |
  ForEach-Object { [pscustomobject]@{ ip=[string]$_.IPAddress
                                      mac=[string]$_.LinkLayerAddress }})

# Windows' own record of every wireless transition. Read incrementally — only
# what has appeared since the last fetch — which makes it cheap enough to take
# on every sample instead of every half hour.
#
# No event-ID filter. The previous version kept a hand-picked subset and capped
# at 300 events, and in a twelve-hour window that silently dropped most of the
# record: ten disconnects and seven failed connects had been reduced to two
# entries. A monitor whose whole purpose is a complete timeline cannot decide
# in advance which transitions matter.
$o.wlanlog = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'
    StartTime=__SINCE__} -MaxEvents 4000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

# The profile service sees every adapter, wired included, so a link that drops
# outside the wireless stack still lands in the timeline.
$o.netprofile = @(Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-NetworkProfile/Operational'
    StartTime=__SINCE__} -MaxEvents 1000 -EA SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ id=$_.Id
                                      time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') }})

# Wireless posture, every half hour (__POSTURE__): hotspot, VPN route bypass,
# open auto-join profiles, patch level, driver. Profiles are read WITHOUT
# key=clear: JARVIS never reveals stored Wi-Fi keys, and its own Sysmon rule
# flags any process that does.
if (__POSTURE__) {
  $p = [ordered]@{}
  $p.hosted = [string]((netsh wlan show hostednetwork 2>$null | Select-String '^\s*Status\s*:\s*(.+)$' |
                        Select-Object -First 1).Matches.Groups[1].Value).Trim()
  $p.icssvc = [string](Get-Service icssvc -EA SilentlyContinue).Status
  $p.direct = @(Get-NetAdapter -IncludeHidden | Where-Object {
      $_.InterfaceDescription -match 'Wi-Fi Direct Virtual|Hosted Network Virtual' } |
    ForEach-Object { [pscustomobject]@{ desc=[string]$_.InterfaceDescription; status=[string]$_.Status } })
  $p.vpn = @(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and
      $_.InterfaceDescription -match 'TAP-|WireGuard|Wintun|OpenVPN|VPN|NordLynx|PANGP|AnyConnect|Fortinet|ZeroTier|Tailscale' } |
    ForEach-Object { [pscustomobject]@{ iface=[string]$_.Name; name=[string]$_.InterfaceDescription } })
  $p.routes = @(Get-NetRoute -AddressFamily IPv4 -EA SilentlyContinue | Where-Object {
      $_.DestinationPrefix -notmatch '/32$' -and $_.DestinationPrefix -notmatch '^(22[4-9]|23\d|255)\.' } |
    ForEach-Object { [pscustomobject]@{ prefix=[string]$_.DestinationPrefix; nexthop=[string]$_.NextHop
                                        iface=[string]$_.InterfaceAlias; protocol=[string]$_.Protocol } })
  $wa = Get-NetAdapter | Where-Object { $_.MediaType -match '802\.11' } | Select-Object -First 1
  if ($wa) { $p.driver = [pscustomobject]@{ desc=[string]$wa.InterfaceDescription; version=[string]$wa.DriverVersion
                                             date=[string]$wa.DriverDate; provider=[string]$wa.DriverProvider } }
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -EA SilentlyContinue
  $p.build = [pscustomobject]@{ product=[string]$cv.ProductName; display=[string]$cv.DisplayVersion
                                build=[string]$cv.CurrentBuild; ubr=[string]$cv.UBR }
  $names = @(netsh wlan show profiles 2>$null | Select-String 'All User Profile\s*:\s*(.+)$' |
             ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() })
  $p.profiles = $names.Count
  $p.open_auto = @(foreach ($n in $names) {
      $t = netsh wlan show profile name="$n" 2>$null | Out-String
      if ($t -match '(?m)^\s*Authentication\s*:\s*Open\s*$' -and
          $t -match '(?m)^\s*Connection mode\s*:\s*Connect automatically') { $n } })
  $o.posture = [pscustomobject]$p
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

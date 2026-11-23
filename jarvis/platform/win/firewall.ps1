
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$o.profiles = @(Get-NetFirewallProfile | ForEach-Object {
  [pscustomobject]@{
    name=$_.Name; enabled=[bool]$_.Enabled
    inbound=[string]$_.DefaultInboundAction; outbound=[string]$_.DefaultOutboundAction
    logBlocked=[bool]$_.LogBlocked; logAllowed=[bool]$_.LogAllowed
    logFile=[string]$_.LogFileName; notify=[string]$_.NotifyOnListen
  } })

# Inbound Allow rules, joined to their program/address/port filters.
# Piping each rule into Get-NetFirewall*Filter individually is an N+1 query that
# takes minutes on a normal rule set, so the filters are fetched in bulk once and
# joined on InstanceID (which equals the rule's Name).
$appF  = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $appF[$_.InstanceID]  = [string]$_.Program }
$addrF = @{}; Get-NetFirewallAddressFilter     | ForEach-Object { $addrF[$_.InstanceID] = [string]($_.RemoteAddress -join ',') }
$portF = @{}; Get-NetFirewallPortFilter        | ForEach-Object { $portF[$_.InstanceID] = "$($_.Protocol)/$($_.LocalPort -join ',')" }

$o.rules = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
  ForEach-Object {
    [pscustomobject]@{
      name    = $_.DisplayName
      group   = [string]$_.DisplayGroup
      profile = [string]$_.Profile
      app     = [string]$appF[$_.Name]
      remote  = [string]$addrF[$_.Name]
      port    = [string]$portF[$_.Name]
      owner   = [string]$_.Owner
      # A rule whose program is gone is a pre-approved hole waiting for anything
      # that lands on that exact path. Windows' own rules name the pseudo-program
      # "System" or embed %SystemRoot%-style variables, so both have to be
      # handled before a missing file means anything.
      exists  = $(
                  $a = [string]$appF[$_.Name]
                  if (-not $a -or $a -eq 'Any' -or $a -eq 'System') { $true }
                  else {
                    $x = [Environment]::ExpandEnvironmentVariables($a)
                    [bool](Test-Path -LiteralPath $x)
                  })
    } })

$o.conns = @(Get-NetTCPConnection | ForEach-Object {
  [pscustomobject]@{ state=[string]$_.State; lip=$_.LocalAddress; lport=$_.LocalPort
                     rip=$_.RemoteAddress; rport=$_.RemotePort; pid=$_.OwningProcess
                     created=if($_.CreationTime){$_.CreationTime.ToString('o')}else{''} } })

$o.procs = @(Get-CimInstance Win32_Process |
  ForEach-Object { [pscustomobject]@{ pid=$_.ProcessId; name=$_.Name; path=$_.ExecutablePath } })

# Who is connected to this machine's file shares right now.
$o.smb = @(Get-SmbSession | ForEach-Object {
  [pscustomobject]@{ client=[string]$_.ClientComputerName; user=[string]$_.ClientUserName
                     numOpen=$_.NumOpens } })

# Remote logons. The Security log usually needs elevation; the flag tells the
# report whether an empty result means "none" or "not allowed to look".
$o.secReadable = $false
$sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200
if ($sec) { $o.secReadable = $true }
$o.logons = @($sec | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ time=$_.TimeCreated.ToString('o'); type=$d['LogonType']
                       user=$d['TargetUserName']; ip=$d['IpAddress']
                       proc=$d['ProcessName'] } } |
  Where-Object { $_.type -in @('3','10') -and $_.ip -and $_.ip -ne '-' -and $_.ip -ne '127.0.0.1' })

$fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200
$o.failed = @($fail | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ time=$_.TimeCreated.ToString('o'); user=$d['TargetUserName']
                       ip=$d['IpAddress'] } } |
  Where-Object { $_.ip -and $_.ip -ne '-' })

# A service installed recently is how most remote-access footholds land.
$o.newsvc = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045;
                StartTime=(Get-Date).AddDays(-30)} -MaxEvents 40 |
  ForEach-Object { [pscustomobject]@{ time=$_.TimeCreated.ToString('o')
                                      msg=($_.Message -replace "`r`n",' ') } })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

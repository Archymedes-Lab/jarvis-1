
$since = (Get-Date).AddDays(-1)
$out = @{ auditing = 1; total = 0; top = @(); lockouts = 0 }
try {
  $ev = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} `
        -MaxEvents 5000 -ErrorAction Stop
  $out.total = $ev.Count
  $out.top = $ev | ForEach-Object {
      $x = [xml]$_.ToXml()
      $d = @{}
      $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
      $proc = [string]$d['ProcessName']
      if ($proc) { $proc = Split-Path -Leaf $proc }
      [pscustomobject]@{ user = $d['TargetUserName']; ip = $d['IpAddress']
                         status = ([string]$d['Status']).ToLower(); sub = ([string]$d['SubStatus']).ToLower()
                         proc = $proc }
    } | Group-Object { "$($_.user)|$($_.ip)|$($_.status)|$($_.sub)|$($_.proc)" } |
    Sort-Object Count -Descending | Select-Object -First 40 |
    ForEach-Object { @{ key = $_.Name; n = $_.Count } }
} catch {
  $m = "$($_.Exception.Message)"
  if ($m -match 'No events were found') { $out.auditing = 1 }
  elseif ($m -match 'Unauthorized|access is denied|not authorized') { $out.auditing = -1 }
  else { $out.auditing = 0 }
}
try {
  $out.lockouts = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=(Get-Date).AddDays(-7)} `
    -MaxEvents 200 -ErrorAction Stop).Count
} catch { }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $out -Depth 5)))

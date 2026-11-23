
$ErrorActionPreference='SilentlyContinue'
$o = @{ listening = $false; hits = @() }
$http = Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in 80,443,8080,8000,8443 }
if (-not $http) { $o.listening = $false }
else {
  $o.listening = $true
  $roots = @('C:\inetpub\wwwroot')
  try { Import-Module WebAdministration -EA Stop
        $roots += (Get-Website | ForEach-Object { $_.physicalPath }) } catch {}
  $cut = (Get-Date).AddDays(-45)
  $rx  = 'eval\(|Request\.(Item|Form|QueryString)|Server\.CreateObject|' +
         'WScript\.Shell|cmd\.exe|Process\.Start|Assembly\.Load\(Convert'
  $o.hits = Get-ChildItem -Path ($roots | Select-Object -Unique) -Recurse -File `
      -Include *.aspx,*.ashx,*.asmx,*.asp,*.jsp,*.php -EA SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $cut -and $_.Length -lt 1000000 } |
    ForEach-Object {
      $c = Get-Content $_.FullName -Raw -EA SilentlyContinue
      if ($c -and ($c -match $rx)) {
        @{ path = $_.FullName; written = $_.LastWriteTime.ToString('o') } } } |
    Select-Object -First 40
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $o -Depth 5)))

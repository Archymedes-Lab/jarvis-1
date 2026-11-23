# Owner-only consent writer. Reads {"set": {"microphone": "Deny", ...}} from
# stdin; only the listed capabilities and Allow/Deny are accepted. Writes the
# user-hive global and desktop-app (NonPackaged) values, then reads both back.
$ErrorActionPreference = 'Stop'
$o = @{result=@{}; errors=@()}
try {
  $req = $jarvisReq | ConvertFrom-Json
  $allowedCaps = @('microphone','webcam','location')
  foreach ($p in $req.set.PSObject.Properties) {
    $cap = [string]$p.Name; $val = [string]$p.Value
    if ($allowedCaps -notcontains $cap) { $o.errors += "capability not allowed: $cap"; continue }
    if ($val -ne 'Allow' -and $val -ne 'Deny') { $o.errors += "value not allowed for $cap"; continue }
    $base = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$cap"
    if (-not (Test-Path $base)) { New-Item -Path $base -Force | Out-Null }
    if (-not (Test-Path "$base\NonPackaged")) { New-Item -Path "$base\NonPackaged" -Force | Out-Null }
    Set-ItemProperty -Path $base -Name Value -Value $val -Type String
    Set-ItemProperty -Path "$base\NonPackaged" -Name Value -Value $val -Type String
    $o.result[$cap] = @{global=[string](Get-ItemProperty $base).Value;
                        nonpackaged=[string](Get-ItemProperty "$base\NonPackaged").Value}
  }
} catch { $o.errors += ('write failed: ' + $_.Exception.GetType().Name) }
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 4 -Compress)))

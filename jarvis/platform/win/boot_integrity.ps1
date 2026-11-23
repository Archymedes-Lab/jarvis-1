$ErrorActionPreference = 'Stop'
# Read-only, unelevated pre-OS evidence: firmware identity, Secure Boot and TPM
# state, virtualization-based security, and what the boot manager logged about
# recent boots and stop errors. Nothing is changed and no UEFI variable is written or read
# through a privileged path. Bounded: at most 40 events per event id.
$o = @{ firmware=$null; secureBoot=@{}; tpm=@{}; deviceGuard=$null; events=@(); errors=@() }
function Step($name, $block) {
  try { & $block } catch { $script:o.errors += ($name + ': ' + $_.Exception.GetType().Name) }
}
Step 'firmware' {
  $b = Get-CimInstance Win32_BIOS
  $script:o.firmware = @{ vendor=[string]$b.Manufacturer; version=[string]$b.SMBIOSBIOSVersion
                          released=$b.ReleaseDate.ToUniversalTime().ToString('yyyy-MM-dd') }
}
Step 'secureBoot' {
  $s = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
  $script:o.secureBoot.enabled = [int]$s.UEFISecureBootEnabled
}
Step 'secureBootServicing' {
  $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' -ErrorAction SilentlyContinue
  if ($v) {
    $script:o.secureBoot.ca2023 = [string]$v.UEFICA2023Status
    $script:o.secureBoot.dbxError = [long]$v.DBXLastUpdateError
    $script:o.secureBoot.dbxErrorReason = [string]$v.DBXLastUpdateErrorReason
  }
}
Step 'tpm' {
  foreach ($line in (tpmtool getdeviceinformation 2>$null)) {
    if ($line -match '^\s*-([^:]{1,60}):\s*(.{0,80})$') {
      $key = $Matches[1].Trim(); $value = $Matches[2].Trim()
      if ($value -ne '' -and $script:o.tpm.Count -lt 40) { $script:o.tpm[$key] = $value }
    }
  }
}
Step 'deviceGuard' {
  $d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
  $script:o.deviceGuard = @{ vbs=[int]$d.VirtualizationBasedSecurityStatus
                             running=@($d.SecurityServicesRunning | ForEach-Object { [int]$_ })
                             codeIntegrity=[int]$d.CodeIntegrityPolicyEnforcementStatus }
}
$wanted = @(
  @{ p='Microsoft-Windows-Kernel-General'; ids=@(12) },
  @{ p='Microsoft-Windows-Kernel-Boot'; ids=@(18, 20, 25, 27, 32) },
  @{ p='Microsoft-Windows-Kernel-Power'; ids=@(41) },
  @{ p='Microsoft-Windows-WHEA-Logger'; ids=@(1, 17, 18, 19, 20, 46, 47) },
  @{ p='Microsoft-Windows-WER-SystemErrorReporting'; ids=@(1001) }
)
foreach ($w in $wanted) {
  foreach ($id in $w.ids) {
    try {
      $found = Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName=$w.p; Id=$id } -MaxEvents 40 -ErrorAction Stop
      foreach ($e in $found) {
        $values = @($e.Properties | Select-Object -First 4 | ForEach-Object {
          $t = [string]$_.Value; if ($t.Length -gt 200) { $t.Substring(0, 200) } else { $t } })
        $o.events += @{ id=[int]$e.Id; source=$w.p.Substring(18)
                        time=$e.TimeCreated.ToUniversalTime().ToString('o'); values=$values }
      }
    } catch {
      # "No events were found" is a clean empty result, not a failure.
      if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
        $o.errors += ('events ' + $id + ': ' + $_.Exception.GetType().Name)
      }
    }
  }
}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Depth 6 -Compress)))

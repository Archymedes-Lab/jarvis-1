
# First statement: module autoloading searches only the system module folders.
$env:PSModulePath = "$([Environment]::SystemDirectory)\WindowsPowerShell\v1.0\Modules;$([Environment]::GetFolderPath('ProgramFiles'))\WindowsPowerShell\Modules"
$ErrorActionPreference = 'SilentlyContinue'
# The user the broker was installed for, recorded by SID at install in this
# administrator-only folder. The broker runs as SYSTEM, so per-user state is
# read from HKEY_USERS\<SID>, read-only, never from this process's environment.
$UserSid = ''
try { $UserSid = [string](Get-Content -LiteralPath (Join-Path $PSScriptRoot 'user.json') -Raw | ConvertFrom-Json).sid } catch { }
if ($UserSid -notmatch '^S-1-(5-21|12-1)(-\d+)+$') { $UserSid = '' }
$o = [ordered]@{}
# Per-user settings are unknown, not absent, when the recorded user's hive
# is not loaded (that user is signed out) or no user was recorded.
$o.user_hive = if (-not $UserSid) { 'no recorded user' } elseif (Test-Path -LiteralPath "Registry::HKEY_USERS\$UserSid") { 'loaded' } else { 'not loaded' }

$o.defender = Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,
  IoavProtectionEnabled, AntispywareEnabled, BehaviorMonitorEnabled,
  OnAccessProtectionEnabled, TamperProtectionSource, IsTamperProtected,
  AntivirusSignatureAge, AntispywareSignatureAge, AMServiceEnabled,
  NISEnabled, QuickScanAge, FullScanAge, AMRunningMode

$o.mppref = Get-MpPreference | Select-Object MAPSReporting, SubmitSamplesConsent,
  PUAProtection, EnableControlledFolderAccess, EnableNetworkProtection,
  DisableRealtimeMonitoring, ExclusionPath, ExclusionProcess,
  AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions,
  ScanAvgCPULoadFactor

$o.license = @(Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" |
  Where-Object { $_.ApplicationId -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
  ForEach-Object { [pscustomobject]@{ name=[string]$_.Name
                                      status=[int]$_.LicenseStatus
                                      desc=[string]$_.Description
                                      grace=[int]$_.GracePeriodRemaining }})

# Confirm-SecureBootUEFI needs elevation, and its access-denied looked the same
# as a legacy BIOS -- so the unelevated daemon quietly lost a "Secure Boot is
# off" high that an elevated run had found. The firmware's answer is also
# published in a registry value any user can read.
$o.secureboot = try { [bool](Confirm-SecureBootUEFI) } catch {
  $state = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled
  if ($null -ne $state) { [bool]$state } else { $null }
}
$o.tpm = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, ManagedAuthLevel

$dg = Get-CimInstance -ClassName Win32_DeviceGuard `
      -Namespace root\Microsoft\Windows\DeviceGuard
$o.deviceguard = [pscustomobject]@{
  vbs=[int]$dg.VirtualizationBasedSecurityStatus
  running=@($dg.SecurityServicesRunning)
  configured=@($dg.SecurityServicesConfigured)
}

$o.bitlocker = @(Get-BitLockerVolume | ForEach-Object {
  [pscustomobject]@{ mount=[string]$_.MountPoint
                     status=[string]$_.ProtectionStatus
                     method=[string]$_.EncryptionMethod
                     pct=[int]$_.EncryptionPercentage }})
# Get-BitLockerVolume returns nothing unelevated. The shell's per-volume
# property does not need elevation; only its unambiguous values are used
# (1/6 protected, 2 not protected), anything else stays unreadable.
if (-not $o.bitlocker.Count) {
  $shell = New-Object -ComObject Shell.Application
  $o.bitlocker = @([IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' } |
    ForEach-Object {
      $v = $shell.NameSpace($_.Name).Self.ExtendedProperty('System.Volume.BitLockerProtection')
      $status = switch ([int]$v) { 1 { 'On' } 6 { 'On' } 2 { 'Off' } default { $null } }
      if ($status) { [pscustomobject]@{ mount=$_.Name.TrimEnd('\'); status=$status
                                        method='unreadable unelevated'; pct=-1 } }
    })
}

function RVal($p,$n){ (Get-ItemProperty -Path $p -Name $n).$n }
$sys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
$o.uac = [pscustomobject]@{
  enabled=RVal $sys 'EnableLUA'
  consent=RVal $sys 'ConsentPromptBehaviorAdmin'
  securedesktop=RVal $sys 'PromptOnSecureDesktop'
}
$o.lsa = [pscustomobject]@{
  runasppl=RVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPL'
  runasppl_boot=RVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RunAsPPLBoot'
  restrictanon=RVal 'HKLM:\System\CurrentControlSet\Control\Lsa' 'RestrictAnonymous'
}
# Memory-corruption and credential-memory mitigations. Get-ProcessMitigation
# -System answers ON / OFF / NOTSET (NOTSET = the Windows default). Nothing
# here needs elevation; an unreadable value stays null, never "off".
$o.mitigations = $null
try {
  $m = Get-ProcessMitigation -System -ErrorAction Stop
  $o.mitigations = [pscustomobject]@{
    dep=[string]$m.DEP.Enable; sehop=[string]$m.SEHOP.Enable
    aslr_bottomup=[string]$m.ASLR.BottomUp; aslr_highentropy=[string]$m.ASLR.HighEntropy
    aslr_forcerelocate=[string]$m.ASLR.ForceRelocateImages; cfg=[string]$m.CFG.Enable
    user_shadow_stack=[string]$m.UserShadowStack.UserShadowStack
  }
} catch {}
$o.kernelshadow = RVal 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' 'Enabled'
$o.wdigest = RVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$o.smartscreen = [string](RVal 'HKLM:\Software\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
$o.smartscreen_shell = [string](RVal 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')
# Smart App Control: 0 off, 1 on, 2 evaluation. The value is protected; only the Windows Security app changes it.
$o.sac = RVal 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'

$o.smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
$o.smbsign = Get-SmbClientConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
$o.rdp = [pscustomobject]@{
  denied=RVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
  nla=RVal 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
}
$o.winrm = (Get-Service WinRM).Status

$o.pslog = [pscustomobject]@{
  scriptblock=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
  module=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging' 'EnableModuleLogging'
  transcript=RVal 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
}

$o.consolehost = [pscustomobject]@{
  console=$(if ($UserSid) { [string](RVal "Registry::HKEY_USERS\$UserSid\Console\%%Startup" 'DelegationConsole') } else { '' })
  terminal=$(if ($UserSid) { [string](RVal "Registry::HKEY_USERS\$UserSid\Console\%%Startup" 'DelegationTerminal') } else { '' })
}

$o.autologon = [pscustomobject]@{
  user=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName')
  auto=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
  pwd=[string](RVal 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword')
}

$o.admins = @(Get-LocalGroupMember -Group 'Administrators' |
  ForEach-Object { [pscustomobject]@{ name=[string]$_.Name
                                      source=[string]$_.PrincipalSource }})
$o.users = @(Get-LocalUser | ForEach-Object {
  [pscustomobject]@{ name=[string]$_.Name; enabled=[bool]$_.Enabled
                     pwdreq=[bool]$_.PasswordRequired
                     lastpwd=[string]$_.PasswordLastSet }})

$o.updates = [pscustomobject]@{
  lastsearch=[string](New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate
  lastinstall=[string](New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
}
$o.hotfix = @(Get-HotFix | Sort-Object InstalledOn -Descending |
  Select-Object -First 3 | ForEach-Object {
    [pscustomobject]@{ id=[string]$_.HotFixID
                       on=[string]$_.InstalledOn }})

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

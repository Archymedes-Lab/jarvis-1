# .NET runtime hijack points: read-only, unelevated.
#
# The CLR reads several settings before any managed code runs, and each is a
# documented way to put an attacker's code inside every .NET process, or to
# blind the telemetry that would see it:
#
#   COR_ENABLE_PROFILING / COR_PROFILER(_PATH)       .NET Framework profiler DLL (T1574.012)
#   CORECLR_ENABLE_PROFILING / CORECLR_PROFILER*     the same for .NET (Core)
#   DOTNET_STARTUP_HOOKS                             managed code run before Main
#   APPDOMAIN_MANAGER_ASM / APPDOMAIN_MANAGER_TYPE   AppDomainManager injection
#   COMPlus_ETWEnabled / DOTNET_ETWEnabled = 0       runtime ETW switched off
#   .NETFramework registry values                    the CLR's registry config,
#                                                    incl. ETWEnabled and
#                                                    DbgManagedDebugger
#
# AMSI is the interface through which Defender sees scripts and in-memory
# assemblies; removing its provider registration is a common bypass. Names
# and values are read; nothing is changed.
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{ env = @(); registry = @(); amsi = @(); amsi_enable = @(); errors = @() }

$pattern = '^(COR_|CORECLR_|COMPLUS_|DOTNET_|APPDOMAIN_MANAGER_)'
foreach ($scope in 'User', 'Machine') {
  try {
    $vars = [Environment]::GetEnvironmentVariables($scope)
    foreach ($k in $vars.Keys) {
      if ($k -match $pattern) {
        $o.env += [pscustomobject]@{ scope = $scope.ToLower(); name = [string]$k; value = [string]$vars[$k] }
      }
    }
  } catch { $o.errors += "environment ${scope}: $($_.Exception.GetType().Name)" }
}

foreach ($key in 'HKLM:\SOFTWARE\Microsoft\.NETFramework',
                 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework',
                 'HKCU:\SOFTWARE\Microsoft\.NETFramework') {
  if (-not (Test-Path -LiteralPath $key)) { continue }
  $item = Get-Item -LiteralPath $key
  foreach ($name in $item.GetValueNames()) {
    $o.registry += [pscustomobject]@{ key = $key; name = [string]$name; value = [string]$item.GetValue($name) }
  }
}

$providers = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
if (Test-Path -LiteralPath $providers) {
  foreach ($p in Get-ChildItem -LiteralPath $providers) {
    $clsid = $p.PSChildName
    $dll = (Get-ItemProperty -LiteralPath "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid\InprocServer32").'(default)'
    $o.amsi += [pscustomobject]@{ clsid = [string]$clsid; dll = [string]$dll }
  }
} else { $o.errors += 'AMSI provider key is absent' }

foreach ($key in 'HKCU:\Software\Microsoft\Windows Script\Settings',
                 'HKLM:\Software\Microsoft\Windows Script\Settings') {
  $v = (Get-ItemProperty -LiteralPath $key).AmsiEnable
  if ($null -ne $v) { $o.amsi_enable += [pscustomobject]@{ key = $key; value = [string]$v } }
}

$json = [pscustomobject]$o | ConvertTo-Json -Depth 4 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

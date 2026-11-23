# Compiles the native sensor with its isolated tests in memory (no executable is
# written, so Windows execution policy is not involved) and runs each test Main.
param([Parameter(Mandatory=$true)][string]$Dir)
$ErrorActionPreference = 'Stop'
$refs = @('System.ServiceProcess','System.Web.Extensions','System.Core','System.Configuration.Install','System.Xml')
$tests = 'PositionResume','TimeoutRetry'
$paths = @(Join-Path $Dir 'JarvisSensor.cs') + @($tests | ForEach-Object { Join-Path $Dir "tests\$_.cs" })
try { Add-Type -Path $paths -ReferencedAssemblies $refs } catch { Write-Output "COMPILE FAILED: $($_.Exception.Message)"; exit 2 }
$failed = 0
foreach ($t in $tests) {
    $type = [AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetType("Jarvis.Native.Tests.$t") } | Where-Object { $_ } | Select-Object -First 1
    $rc = $type.GetMethod('Main', [Reflection.BindingFlags]'Static,Public,NonPublic').Invoke($null, @())
    if ($rc -ne 0) { $failed++ }
}
exit $failed

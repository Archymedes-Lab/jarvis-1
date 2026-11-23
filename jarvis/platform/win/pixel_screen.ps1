
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

$ts = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$o.rdpDenied = (Get-ItemProperty $ts).fDenyTSConnections
$pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$o.captureProtection = (Get-ItemProperty $pol).fEnableScreenCaptureProtection
$o.rdpNla = (Get-ItemProperty "$ts\WinStations\RDP-Tcp").UserAuthentication

$o.listeners = @(Get-NetTCPConnection -State Listen |
    Select-Object -ExpandProperty LocalPort -Unique)

$o.procs = @(Get-Process | Where-Object { $_.MainModule } |
    ForEach-Object {
        [ordered]@{ name = $_.ProcessName
                    path = $_.MainModule.FileName }
    })

# Apps that declared the right to record the screen without the capture
# border that normally tells the user recording is happening.
$o.capturePkgs = @(Get-AppxPackage | ForEach-Object {
    $m = $_.InstallLocation + '\AppxManifest.xml'
    if (Test-Path $m) {
        $x = [xml](Get-Content $m -Raw)
        $caps = @($x.Package.Capabilities.Capability.Name) +
                @($x.Package.Capabilities.DeviceCapability.Name) +
                @($x.Package.Capabilities.CustomCapability.Name)
        $hit = $caps | Where-Object { $_ -like '*graphicsCapture*' }
        if ($hit) {
            [ordered]@{ name = $_.Name; caps = @($hit); publisher = [string]$_.Publisher
                        kind = [string]$_.SignatureKind; status = [string]$_.Status }
        }
    }
})

$json = $o | ConvertTo-Json -Depth 6 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

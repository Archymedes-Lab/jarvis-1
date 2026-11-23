
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}

# Root certificates. A CA in this store can mint a certificate for any site and
# the machine will believe it. Microsoft's own roots are expected; anything
# else is a trust decision somebody made.
$o.roots = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root |
  ForEach-Object { [pscustomobject]@{
    subject=[string]$_.Subject; issuer=[string]$_.Issuer
    thumb=[string]$_.Thumbprint; nb=$_.NotBefore.ToString('o')
    na=$_.NotAfter.ToString('o'); store=$_.PSParentPath -replace '.*::',''
  }})

# Proxy and PAC. AutoConfigURL in particular is a single registry value that
# silently routes every request through a script the operator controls.
$ie = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$o.proxy = [pscustomobject]@{
  enable=(Get-ItemProperty $ie).ProxyEnable
  server=[string](Get-ItemProperty $ie).ProxyServer
  pac=[string](Get-ItemProperty $ie).AutoConfigURL
  winhttp=[string](netsh winhttp show proxy 2>$null | Out-String)
}

# portproxy: a userland port forwarder built into Windows. It moves traffic
# across the host without creating a firewall rule.
$o.portproxy = [string](netsh interface portproxy show all 2>$null | Out-String)

# Third-party filtering-platform callouts operate below the firewall UI.
$o.callouts = @(Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' } |
  ForEach-Object { [pscustomobject]@{ name=$_.Name; path=$_.PathName
                                      started=[bool]$_.Started } })

$o.hosts = [string](Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -Raw)

$o.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
  ForEach-Object { [pscustomobject]@{ iface=[string]$_.InterfaceAlias
                                      servers=@($_.ServerAddresses) } })

# Drivers, with their signature status. An unsigned running driver on a modern
# Windows build is a deliberate act.
$o.drivers = @(Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.State -eq 'Running' -and $_.PathName } |
  ForEach-Object {
    $p = $_.PathName -replace '^\\\?\?\\',''
    $sig = Get-AuthenticodeSignature $p
    [pscustomobject]@{ name=$_.Name; path=$p
                       status=[string]$sig.Status
                       signer=[string]$sig.SignerCertificate.Subject }
  })

$json = [pscustomobject]$o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

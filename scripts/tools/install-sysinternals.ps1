# Install the read-only Sysinternals tools JARVIS uses during investigation.
# Downloads come from Microsoft's Sysinternals host and every executable must
# have a valid Microsoft Authenticode signature before it reaches the tool dir.
$ErrorActionPreference = 'Stop'
$destination = Join-Path $env:LOCALAPPDATA 'Jarvis\Tools\Sysinternals'
$staging = Join-Path $env:TEMP ('jarvis-sysinternals-' + [guid]::NewGuid())
$packages = @('Sigcheck', 'Autoruns', 'Handle', 'Procdump')

New-Item -ItemType Directory -Path $staging | Out-Null
try {
    foreach ($package in $packages) {
        $zip = Join-Path $staging ($package + '.zip')
        Invoke-WebRequest -UseBasicParsing `
            -Uri ('https://download.sysinternals.com/files/' + $package + '.zip') `
            -OutFile $zip
        Expand-Archive -LiteralPath $zip -DestinationPath $staging -Force
    }

    $executables = Get-ChildItem $staging -Filter '*.exe' -File
    foreach ($executable in $executables) {
        $signature = Get-AuthenticodeSignature -LiteralPath $executable.FullName
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
            throw "Invalid Microsoft signature: $($executable.Name) ($($signature.Status))"
        }
    }

    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($executable in $executables) {
        Copy-Item -LiteralPath $executable.FullName -Destination $destination -Force
    }
    Write-Host "Installed $($executables.Count) signed tools in $destination"
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}

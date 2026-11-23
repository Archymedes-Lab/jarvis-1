param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'build'))
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '64-bit .NET Framework compiler is unavailable' }
[void](New-Item -ItemType Directory -Force -Path $OutputDirectory)
$output=Join-Path $OutputDirectory 'JarvisSensor.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /r:System.ServiceProcess.dll /r:System.Web.Extensions.dll /out:$output (Join-Path $PSScriptRoot 'JarvisSensor.cs')
if ($LASTEXITCODE -ne 0) { throw 'Native sensor compilation failed' }
Get-FileHash -LiteralPath $output -Algorithm SHA256

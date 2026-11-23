
$ErrorActionPreference = 'SilentlyContinue'
$o = [ordered]@{}
$o.outlook = @(Get-ChildItem 'HKCU:\Software\Microsoft\Office' |
    ForEach-Object {
        $p = "$($_.PSPath)\Outlook\Options\Mail"
        if (Test-Path $p) {
            [ordered]@{ version = $_.PSChildName
                        blockHttp = (Get-ItemProperty $p).BlockHTTPimages }
        }
    })
$json = $o | ConvertTo-Json -Depth 5 -Compress
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))

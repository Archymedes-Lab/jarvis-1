$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\jarvis-connectivity-guard.ps1') -LibraryOnly
function Assert-Decision($expected, $status, $reachable, $failures, $first, $last, $now, $paused=$false) {
    $actual = Get-RecoveryDecision $status $reachable $failures $first $last $now $paused
    if ($actual -ne $expected) { throw "Expected $expected, got $actual" }
}
Assert-Decision online Up $true 0 0 0 1000
Assert-Decision online Disconnected $true 10 100 0 1000
Assert-Decision upstream-unreachable Up $false 10 100 0 1000
Assert-Decision adapter-unavailable Disabled $false 10 100 0 1000
Assert-Decision adapter-unavailable NotPresent $false 10 100 0 1000
Assert-Decision confirming-disconnect Disconnected $false 2 800 0 1000
Assert-Decision confirming-disconnect Disconnected $false 3 950 0 1000
Assert-Decision reconnect Disconnected $false 3 880 0 1000
Assert-Decision cooldown Disconnected $false 4 500 800 1000
Assert-Decision reconnect Disconnected $false 4 500 700 1000
Assert-Decision paused Disconnected $false 10 100 0 1000 $true
'11 recovery policy checks passed.'

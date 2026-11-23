# Clears the stale PUABundler Defender records left behind after the flagged
# file was deleted. Must run ELEVATED: Remove-MpThreat performs a clean action,
# and Defender refuses that from an unelevated token ("Errors were encountered
# while attempted to clean items detected as potentially harmful").
#
# The file it detected -- C:\Users\chris\Downloads\btweb_installer.exe,
# SHA256 A82F7649168BFA9CD13FB9763628CF3F98FF59BBD37CBA4E86B373C2FB132E7A --
# is already gone, so this only reconciles Defender's own history.

$ErrorActionPreference = 'Continue'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Run this from an elevated PowerShell." -ForegroundColor Red
    exit 1
}

Write-Host "--- before ---"
Get-MpThreat | Select-Object ThreatName, ThreatID, IsActive | Format-Table -Auto

# Re-scan the paths the detections point at first. With the file deleted the
# scan is what lets Defender retire the detection rather than re-flag it.
foreach ($p in 'C:\Users\chris\Downloads', 'C:\Users\chris\AppData\Local\BitTorrentHelper') {
    if (Test-Path -LiteralPath $p) {
        Write-Host "scanning $p"
        Start-MpScan -ScanType CustomScan -ScanPath $p
    }
}

Remove-MpThreat

Write-Host "--- after ---"
Get-MpThreat | Select-Object ThreatName, ThreatID, IsActive | Format-Table -Auto
Write-Host "Any entry still listed with IsActive=False is a historical record, not a live infection."

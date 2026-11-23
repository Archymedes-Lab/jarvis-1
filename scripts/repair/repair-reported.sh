#!/usr/bin/env bash
# Run from the affected Ubuntu shell. Repair its Windows mount, then request
# Windows elevation for the narrowly scoped firewall repair.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
windows_ps=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe

if ! stat "$windows_ps" >/dev/null 2>&1; then
    echo 'Reattaching the Windows C: drive in this shell. sudo may ask for your Ubuntu password.'
    # Mount a fresh drvfs connection over the stale one. Do not force-unmount
    # it: processes with existing references may still be using that mount.
    sudo mount -t drvfs 'C:' /mnt/c -o "uid=$(id -u),gid=$(id -g)"
fi
stat "$windows_ps" >/dev/null
python3 - <<'PY'
import os
policy = '/mnt/c/Program Files/ClaudeCode/managed-settings.json'
try:
    os.stat(policy)
    with open(policy, 'rb') as stream:
        stream.read(1)
except FileNotFoundError:
    print('Windows drive responds normally; no Claude policy file is installed.')
else:
    print('Claude managed policy file is readable and was left unchanged.')
PY

firewall_script=$(wslpath -w "$repo_root/repair-reported-firewall.ps1")
echo 'Windows will request administrator consent for the firewall repair.'
# Pass the path as data rather than interpolating it into PowerShell source.
"$windows_ps" -NoProfile -NonInteractive -Command '
    $scriptPath = $input | Out-String
    $scriptPath = $scriptPath.Trim()
    if ($scriptPath.Contains([char]34)) { throw "Invalid script path" }
    $arguments = "-NoProfile -NonInteractive -File " + [char]34 + $scriptPath + [char]34
    $process = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList $arguments
    if ($null -eq $process) { throw "Elevated repair did not start" }
    exit $process.ExitCode
' <<< "$firewall_script"
echo 'Repair finished. Run claude in this Ubuntu shell.'

#!/usr/bin/env bash
# Run in the affected WSL shell so the mount repair applies to its namespace.
# Preserve any existing Claude policy; absence of a policy is also valid.
set -euo pipefail

ps='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
if ! stat "$ps" >/dev/null 2>&1; then
    printf '%s\n' 'Windows-drive access is broken; reconnecting C: (sudo may prompt).'
    # Overlay the stale connection. Do not unmount references still in use by
    # other processes, and do not stop WSL or the monitoring service.
    sudo mount -t drvfs 'C:' /mnt/c -o "uid=$(id -u),gid=$(id -g)"
fi

python3 - <<'PY'
import json
from pathlib import Path

ps = Path('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')
ps.stat()
policy = Path('/mnt/c/Program Files/ClaudeCode/managed-settings.json')
try:
    raw = policy.read_text(encoding='utf-8-sig')
except FileNotFoundError:
    print('Windows drive is readable; no Claude managed-settings.json is present.')
else:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise SystemExit('Drive is readable, but the existing Claude policy is not a JSON object.')
    print('Windows drive is readable; the existing Claude policy is valid JSON and was preserved.')
print('Run claude again in this shell.')
PY

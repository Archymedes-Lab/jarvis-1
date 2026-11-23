#!/usr/bin/env bash
# One command to bring JARVIS fully online and keep it there.
#
#   ./quickstart.sh                 install + seal (systemd service, watchdog,
#                                   self-check, Windows wake task), enable linger,
#                                   apply the reversible browser defaults, and
#                                   pop one Windows UAC prompt for firewall
#                                   logging + ASR rules
#   ./quickstart.sh --no-priority   skip the sudo hardening (user manager only)
#   ./quickstart.sh --no-windows    Linux side only, no bridge calls
#   ./quickstart.sh --check         print the health summary and exit
#
# Safe to re-run. Everything it does is idempotent or backed up for undo.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${JARVIS_PORT:-8787}"
cd "$HERE"

mode=seal ; do_windows=1
for a in "$@"; do
  case "$a" in
    --no-priority) mode=service ;;
    --no-windows)  do_windows=0 ;;
    --check)       mode=check ;;
    -h|--help)     sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
have_bridge() { command -v powershell.exe >/dev/null 2>&1; }

HEALTH_PY='
import json, sys, time
d = json.load(sys.stdin)
jobs = d.get("jobs", [])
now = time.time()
stale = [j["name"] for j in jobs if j.get("stale")]
err = [j["name"] for j in jobs if j.get("error")]
never = [j["name"] for j in jobs if not j.get("ts")]
print("collectors:  %d registered" % len(jobs))
print("stale:       %s" % (", ".join(stale) if stale else "none"))
print("errored:     %s" % (", ".join(err) if err else "none"))
print("never run:   %s" % (", ".join(never) if never else "none"))
oldest = max((now - j["ts"] for j in jobs if j.get("ts")), default=0)
print("oldest pass: %.1f min ago" % (oldest / 60))
'

health() {
  local out
  # /api/state needs a credential; the API client reads it from the caller's
  # paired token file or the daemon's token file, never from an argument.
  if ! out="$(cd "$HERE" && python3 -c 'import json, sys
from jarvis.web import apiclient
try:
    status, body = apiclient.request("GET", "/api/state", port=int(sys.argv[1]))
except apiclient.Unpaired as exc:
    sys.exit(str(exc))
except OSError:
    sys.exit(1)
if status != 200:
    sys.exit("HTTP %d" % status)
print(json.dumps(body))' "$PORT" 2>/dev/null)"; then
    echo "dashboard not answering on :$PORT (or this account is not paired: jarvis desktop pair)"; return 1
  fi
  printf '%s' "$out" | python3 -c "$HEALTH_PY"
}

# Stage the one script that needs Administrator, on a *local* Windows path so
# the default RemoteSigned policy runs it (a \\wsl.localhost path is remote-
# zone and blocked). Then trigger a single UAC prompt to run it.
windows_phase() {
  have_bridge || { echo "no Windows bridge (powershell.exe unreachable) — skipping"; return 0; }

  echo "browser defaults (reversible, no elevation)..."
  local win_ps1
  win_ps1="$(wslpath -w "$HERE/scripts/harden/secure-internet.ps1" 2>/dev/null)" \
    || win_ps1='\\wsl.localhost\Ubuntu'"${HERE//\//\\}"'\scripts\harden\secure-internet.ps1'
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
    -File "$win_ps1" -Browsers 2>&1 | tr -d '\r' | sed 's/^/  /' || true

  local lad
  lad="$(powershell.exe -NoProfile -NonInteractive -Command '$env:LOCALAPPDATA' 2>/dev/null | tr -d '\r')"
  [ -n "$lad" ] || { echo "  could not resolve %LOCALAPPDATA% — skipping elevated step"; return 0; }
  local dir_wsl ; dir_wsl="$(wslpath -u "$lad")/Jarvis"
  mkdir -p "$dir_wsl"
  cp "$HERE/scripts/harden/harden-elevated.ps1" "$dir_wsl/harden-elevated.ps1"
  local dir_win="$lad\\Jarvis\\harden-elevated.ps1"

  echo "elevated step: firewall logging + ASR rules (audit mode)"
  echo "  a Windows UAC prompt will appear — approve it to finish"
  if powershell.exe -NoProfile -NonInteractive -Command \
       "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','$dir_win'" \
       2>/dev/null; then
    echo "  elevated step completed"
  else
    echo "  UAC declined or unavailable. Run this once in an admin PowerShell:"
    echo "    powershell -ExecutionPolicy Bypass -File \"$dir_win\""
  fi
}

if [ "$mode" = check ]; then
  say "JARVIS health" ; health
  echo "dashboard:   http://127.0.0.1:$PORT"
  exit 0
fi

total=$([ "$do_windows" = 1 ] && echo 4 || echo 3)

say "1/$total  Installing"
if [ "$mode" = seal ]; then ./install.sh --seal; else ./install.sh --service; fi

say "2/$total  Enabling linger (survives logout)"
if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
  sudo loginctl enable-linger "$USER" && echo "linger enabled for $USER"
else
  echo "linger already on"
fi

say "3/$total  Waiting for the dashboard"
for i in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/api/live" >/dev/null 2>&1 && { echo "up after ${i}s"; break; }
  sleep 1
done

if [ "$do_windows" = 1 ]; then
  say "4/$total  Windows hardening"
  windows_phase
fi

say "Health"
health || true

cat <<EOF

dashboard:   http://127.0.0.1:$PORT   (open the "ops & setup" tab)
service:     sudo systemctl status jarvis.service
logs:        journalctl -u jarvis.service -f -o cat
self-check:  systemctl --user list-timers jarvis-selfcheck.timer
undo win:    powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\\Jarvis\\harden-elevated.ps1" -Undo
enforce ASR: powershell -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\\Jarvis\\harden-elevated.ps1" -Enforce
EOF

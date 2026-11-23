#!/usr/bin/env bash
# Install jarvis, and optionally run it 24/7.
#
#   ./install.sh              put `jarvis` on PATH
#   ./install.sh --service    ...and run the daemon under systemd, always on
#   ./install.sh --priority   ...and give it top CPU/IO priority + OOM immunity
#                             (writes a system drop-in; needs sudo once)
#   ./install.sh --seal       ...and make it as hard to stop as this machine
#                             allows: systemd watchdog, no restart rate limit,
#                             and an out-of-daemon timer that restarts and
#                             emails if the daemon ever stops producing
#                             (needs sudo once)
#   ./install.sh --windows    ...and print the one Windows command that keeps
#                             WSL itself alive across reboots
#   ./install.sh --service-account
#                             RECOMMENDED: --priority, then move the daemon to
#                             its own `jarvis` account (state 0700/0600, token
#                             unreadable by this account and by Windows); see
#                             docs/guides/SERVICE-ACCOUNT.md (needs sudo once)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
PORT="${JARVIS_PORT:-8787}"
mkdir -p "$BIN"

STATE_DIR="$HOME/.jarvis"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

cat > "$BIN/jarvis" <<EOF
#!/usr/bin/env bash
cd "$HERE" && exec python3 -m jarvis "\$@"
EOF
chmod +x "$BIN/jarvis"
echo "installed: $BIN/jarvis"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "note: add $BIN to PATH — echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
esac

want_service=false; want_windows=false; want_priority=false; want_seal=false
want_account=false
for arg in "$@"; do
  case "$arg" in
    --service) want_service=true ;;
    --priority) want_service=true; want_priority=true ;;
    --seal) want_service=true; want_priority=true; want_seal=true ;;
    --windows) want_windows=true ;;
    --service-account) want_service=true; want_priority=true; want_account=true ;;
  esac
done

if $want_service && ! $want_priority; then
  # A priority/sealed installation lives under the system manager. A later
  # plain `--service` must not also enable the user unit: both commands bind
  # the same loopback port, so the loser crash-loops while the winner doubles
  # collection load. Reuse the authoritative system unit when it exists.
  if systemctl cat jarvis.service >/dev/null 2>&1; then
    systemctl --user disable --now jarvis.service 2>/dev/null || true
    echo "service:   existing system unit retained (user duplicate disabled)"
    echo "status:    sudo systemctl status jarvis"
    want_service=false
  fi
fi

if $want_service && ! $want_priority; then
  UNIT="$HOME/.config/systemd/user"
  mkdir -p "$UNIT"
  cat > "$UNIT/jarvis.service" <<EOF
[Unit]
Description=ARGUS-INSTINCT — continuous process, network and control-surface monitoring
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m jarvis serve --port $PORT
Restart=always
RestartSec=15

# This monitor is meant to win contention for the machine, not lose it.
# CPUWeight/IOWeight are relative cgroup shares (max 10000) and need no
# privilege. Nice and a negative OOMScoreAdjust require a privileged manager;
# the user manager will log and ignore them — run \`./install.sh --priority\`
# for a system drop-in that makes them stick.
CPUWeight=10000
IOWeight=10000
Nice=-10
OOMScoreAdjust=-800
# A security monitor that gets OOM-killed is the failure it exists to prevent.
MemoryHigh=1536M
MemoryMax=2G
TasksMax=4096

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now jarvis.service
  echo "service:   systemctl --user status jarvis"
  echo "logs:      journalctl --user -u jarvis -f"
  echo "dashboard: http://127.0.0.1:$PORT"

  # Without linger, systemd tears down the user manager when the last shell
  # exits — which is exactly what happens when you close your terminal.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
    echo
    echo "IMPORTANT — the daemon will stop when you close your last shell."
    echo "To keep it running without a login session:"
    echo "    sudo loginctl enable-linger $USER"
  fi
fi

if $want_priority; then
  # The user manager cannot grant a negative nice or a negative OOM score.
  # Moving the unit to the system manager (still running as this user) can.
  SYS="/etc/systemd/system/jarvis.service"
  echo
  echo "Installing $SYS (system manager, runs as $USER) for real priority."
  echo "This needs sudo once."
  sudo tee "$SYS" >/dev/null <<EOF
[Unit]
Description=ARGUS-INSTINCT — continuous monitoring (top priority)
After=network.target

[Service]
Type=simple
User=$USER
Group=$(id -gn)
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 -m jarvis serve --port $PORT
Restart=always
RestartSec=15

# Win CPU and IO contention, and do not get OOM-killed. A privileged manager
# is required for the last two, which is the whole reason this unit exists.
CPUWeight=10000
IOWeight=10000
IOSchedulingClass=best-effort
IOSchedulingPriority=0
Nice=-10
OOMScoreAdjust=-800
MemoryHigh=1536M
MemoryMax=2G
TasksMax=4096

[Install]
WantedBy=multi-user.target
EOF
  systemctl --user disable --now jarvis.service 2>/dev/null || true
  sudo systemctl daemon-reload
  sudo systemctl enable --now jarvis.service
  echo "now managed by:  sudo systemctl status jarvis"
  echo "verify:          systemctl show jarvis -p Nice -p OOMScoreAdjust -p CPUWeight"
  if ! $want_account; then
    echo "recommended:     ./install.sh --service-account  (the daemon under its own account;"
    echo "                 docs/guides/SERVICE-ACCOUNT.md)"
  fi
fi


if $want_seal; then
  echo
  echo "Sealing: watchdog, no restart rate limit, out-of-daemon self-check."
  echo "This needs sudo once."

  # 1. Drop-in on jarvis.service: WatchdogSec + StartLimitIntervalSec=0.
  sudo mkdir -p /etc/systemd/system/jarvis.service.d
  sudo cp "$HERE/systemd/hardening.conf" \
          /etc/systemd/system/jarvis.service.d/hardening.conf
  sudo systemctl daemon-reload
  sudo systemctl restart jarvis.service
  echo "  drop-in:  /etc/systemd/system/jarvis.service.d/hardening.conf"

  # 2. Let the unprivileged self-check restart the system-scoped unit, and
  #    nothing else. Validated before install so a typo cannot break sudo.
  TMP_SUDO="$(mktemp)"
  sed "s/^chris /$USER /" "$HERE/systemd/jarvis-restart.sudoers" > "$TMP_SUDO"
  if sudo visudo -cqf "$TMP_SUDO"; then
    sudo install -m 0440 -o root -g root "$TMP_SUDO" \
         /etc/sudoers.d/jarvis-restart
    echo "  sudoers:  /etc/sudoers.d/jarvis-restart (restart + reset-failed, this unit only)"
  else
    echo "  WARNING: sudoers rule failed validation and was NOT installed;"
    echo "           the self-check will report but not restart."
  fi
  rm -f "$TMP_SUDO"

  # 3. The watchdog that lives outside the daemon.
  UNIT="$HOME/.config/systemd/user"
  mkdir -p "$UNIT"
  sed "s|@REPO_ROOT@|$HERE|g" \
      "$HERE/systemd/jarvis-selfcheck.service" > "$UNIT/jarvis-selfcheck.service"
  cp "$HERE/systemd/jarvis-selfcheck.timer"   "$UNIT/"
  systemctl --user daemon-reload
  systemctl --user enable --now jarvis-selfcheck.timer
  echo "  timer:    jarvis-selfcheck.timer, every 2 min"

  # 4. The outermost ring. Everything above lives inside the distro and is gone
  #    the moment the WSL VM stops -- and nothing inside a stopped VM can start
  #    it again. This Windows task is the only layer that can.
  WAKE_DIR="$(wslpath -w "$HERE" 2>/dev/null || true)"
  if command -v powershell.exe >/dev/null 2>&1; then
    LOCAL_WAKE="/mnt/c/Users/$(powershell.exe -NoProfile -NonInteractive -Command '$env:USERNAME' 2>/dev/null | tr -d '\r')/AppData/Local/WSLKeepalive"
    mkdir -p "$LOCAL_WAKE" 2>/dev/null || true
    if cp "$HERE/jarvis-wake-watchdog.ps1" "$LOCAL_WAKE/" 2>/dev/null; then
      # Run it from a local Windows path, not the \\wsl.localhost UNC share:
      # scripts on a network path are treated as remote-zone and refused by
      # any execution policy stricter than Bypass. -RepoRoot lets each run
      # reconcile that staged copy against this checkout, so a later `git pull`
      # reaches the task without re-running install.
      powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$(wslpath -w "$LOCAL_WAKE/jarvis-wake-watchdog.ps1")" -Install \
        -RepoRoot "$HERE" 2>&1 \
        | tr -d '\r' | sed 's/^/  /'
    else
      echo "  WARNING: could not stage jarvis-wake-watchdog.ps1 to the Windows side"
    fi
    # The fast ring: a loop that checks every few seconds and re-runs a stale
    # protection source or restarts a dead daemon, instead of waiting five
    # minutes for the wake task or a human for the health monitor's email.
    LOCAL_REVIVE="$(dirname "$LOCAL_WAKE")/Jarvis/Reviver"
    mkdir -p "$LOCAL_REVIVE" 2>/dev/null || true
    if cp "$HERE/jarvis-reviver.ps1" "$LOCAL_REVIVE/" 2>/dev/null; then
      powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$(wslpath -w "$LOCAL_REVIVE/jarvis-reviver.ps1")" -Install \
        -RepoRoot "$HERE" 2>&1 \
        | tr -d '\r' | sed 's/^/  /'
    else
      echo "  WARNING: could not stage jarvis-reviver.ps1 to the Windows side"
    fi
  else
    echo "  skipped wake watchdog: powershell.exe unreachable from here"
  fi

  echo
  echo "verify:  systemctl show jarvis -p WatchdogUSec -p StartLimitIntervalUSec"
  echo "         systemctl --user list-timers jarvis-selfcheck.timer"
  echo "         jarvis selfcheck"
  echo "         powershell.exe -Command \"Get-ScheduledTask 'jarvis wake watchdog'\""
fi

if $want_windows; then
  cat <<'EOF'

--------------------------------------------------------------------
Keeping it running across Windows reboots
--------------------------------------------------------------------
WSL only runs while Windows keeps it running. Enabling linger (above)
keeps jarvis alive inside WSL; this task makes sure WSL itself starts
at logon, with no visible window.

Run this ONCE in Windows PowerShell (no elevation needed):

  $a = New-ScheduledTaskAction -Execute "wsl.exe" `
       -Argument "-d Ubuntu --exec /bin/true"
  $t = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
  $p = New-ScheduledTaskPrincipal -UserId $env:USERNAME `
       -LogonType Interactive -RunLevel Limited
  $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
       -DontStopIfGoingOnBatteries -StartWhenAvailable `
       -ExecutionTimeLimit ([TimeSpan]::Zero)
  Register-ScheduledTask -TaskName "WSL jarvis 24x7" -Action $a `
       -Trigger $t -Principal $p -Settings $s `
       -Description "Starts WSL so jarvis keeps running"

RunLevel Limited is load-bearing: asking for -RunLevel Highest makes
registration itself require an elevated shell and fails with 0x80070005.
The task does not need admin — it only has to start WSL.

Starting WSL is enough: systemd then starts jarvis.service on its own,
and linger keeps it up with no session attached.

To undo:  Unregister-ScheduledTask -TaskName "WSL jarvis 24x7"
--------------------------------------------------------------------
EOF
fi

# Last, so a --seal in the same run has installed the user self-check timer
# that the switch then moves to the jarvis account.
if $want_account; then
  echo
  echo "Moving the daemon to its own account (docs/guides/SERVICE-ACCOUNT.md)."
  sudo JARVIS_OWNER="$USER" "$HERE/scripts/repair/install-service-user.sh"
fi

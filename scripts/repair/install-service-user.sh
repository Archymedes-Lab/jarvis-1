#!/usr/bin/env bash
# Move the JARVIS daemon to its own system account (PROTECTION-REVIEW-2026-10-21 F2).
# The documented default for a workstation/WSL install; owner steps, checks and
# rollback: docs/guides/SERVICE-ACCOUNT.md.
#
#   sudo scripts/repair/install-service-user.sh --preflight   check only, change nothing
#   sudo scripts/repair/install-service-user.sh                migrate and switch
#   sudo scripts/repair/install-service-user.sh --rollback     back to the previous unit
#
# Order of operations, each step reversible:
#   1. create the system user/group `jarvis` (home /var/lib/jarvis, no login);
#   2. PREFLIGHT: as `jarvis`, run powershell.exe through WSL interop and read the
#      sensor spool. If either fails the script stops here: a daemon that cannot
#      reach Windows protects nothing, and the old unit keeps running;
#   3. stop jarvis.service (a store copied while it is written can be torn), copy
#      ~OWNER/.jarvis to /var/lib/jarvis/.jarvis, then make it private: every
#      directory 0700, every file 0600, all owned by jarvis. The daemon itself
#      refuses to start if this is not so (jarvis/core/statedir.py);
#   4. write /etc/jarvis/service-account.json (root, 0644, no secrets) so the CLI
#      knows the store is not the caller's own ~/.jarvis;
#   5. install the unit drop-in (User=jarvis, HOME=/var/lib/jarvis, the owner's uid),
#      move the self-check to a system timer run as jarvis, start, and read
#      /api/live back. No answer within the wait rolls back automatically.
# The owner's ~/.jarvis is copied, never moved or deleted: --rollback returns to it.
# Data the daemon records as jarvis after the switch stays in /var/lib/jarvis.
#
# After the switch the owner's account cannot read the store or the API token:
#   * CLI store commands refuse to read a stale copy and print the working form,
#     `sudo jarvis-svc ARGS` (installed here; runs the CLI as jarvis). `jarvis brief
#     --check` and other API callers need a paired client token:
#       sudo jarvis-svc desktop pair --name cli | jarvis desktop save
#   * Windows programs (desktop app, supervisors) read nothing through
#     \\wsl.localhost any more and must be paired (docs/guides/SERVICE-ACCOUNT.md).
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run as root (sudo).' >&2; exit 1; }
OWNER=${JARVIS_OWNER:-${SUDO_USER:-chris}}
OWNER_UID=$(id -u "$OWNER")
SRC=$(getent passwd "$OWNER" | cut -d: -f6)/.jarvis
HOME_DIR=/var/lib/jarvis
DST=$HOME_DIR/.jarvis
MARKER_DIR=/etc/jarvis
MARKER=$MARKER_DIR/service-account.json
DROPIN_DIR=/etc/systemd/system/jarvis.service.d
DROPIN=$DROPIN_DIR/service-user.conf
SELFCHECK=/etc/systemd/system/jarvis-selfcheck.service
SELFCHECK_TIMER=/etc/systemd/system/jarvis-selfcheck.timer
SUDOERS=/etc/sudoers.d/jarvis-restart-service-account
SVC_CLI=/usr/local/sbin/jarvis-svc
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
mode=${1:-apply}

owner_user_systemctl() {
  sudo -u "$OWNER" XDG_RUNTIME_DIR="/run/user/$OWNER_UID" systemctl --user "$@" 2>/dev/null || true
}

rollback() {
  rm -f "$DROPIN" "$MARKER" "$SELFCHECK" "$SELFCHECK_TIMER" "$SUDOERS" "$SVC_CLI"
  systemctl daemon-reload
  systemctl restart jarvis.service
  owner_user_systemctl enable --now jarvis-selfcheck.timer
  sleep 3; systemctl is-active jarvis.service || true
  echo "rolled back: the unit runs as before on $SRC; $HOME_DIR left in place for inspection"
}

if [[ $mode == --rollback ]]; then rollback; exit 0; fi

getent group jarvis >/dev/null || groupadd --system jarvis
id jarvis >/dev/null 2>&1 || useradd --system --gid jarvis --home-dir "$HOME_DIR" \
  --no-create-home --shell /usr/sbin/nologin jarvis

echo "[preflight] Windows interop as jarvis"
if ! sudo -u jarvis -H env -i PATH=/usr/bin:/bin WSL_INTEROP="${WSL_INTEROP:-}" \
      /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -NonInteractive -Command 'Write-Output ok' 2>/dev/null | tr -d '\r' | grep -qx ok; then
  echo "PREFLIGHT FAILED: powershell.exe does not run for the jarvis user through interop; nothing changed." >&2
  echo "This is the known risk of F2 on WSL; the daemon stays on the current unit." >&2
  exit 2
fi
sudo -u jarvis test -r /mnt/c/ProgramData/Jarvis/Sensor/health.json || { echo "PREFLIGHT FAILED: jarvis cannot read the sensor spool" >&2; exit 2; }
[[ -d $SRC ]] || { echo "PREFLIGHT FAILED: no state at $SRC" >&2; exit 2; }
workdir=$(systemctl show jarvis.service -p WorkingDirectory --value)
workdir=${workdir:-$repo}
if [[ -f $workdir/jarvis-release.py ]]; then
  exec_line="/usr/bin/python3 -I $workdir/jarvis-release.py"
else
  exec_line="/usr/bin/python3 -m jarvis"
fi
sudo -u jarvis test -r "$workdir" || { echo "PREFLIGHT FAILED: jarvis cannot read $workdir (deploy a sealed release first)" >&2; exit 2; }
echo "[preflight] ok (code: $workdir)"
[[ $mode == --preflight ]] && exit 0

systemctl stop jarvis.service
install -d -o jarvis -g jarvis -m 0700 "$HOME_DIR"
install -d -o jarvis -g jarvis -m 0700 "$DST"
rsync -a --chown=jarvis:jarvis "$SRC/" "$DST/"
find "$DST" -type d -exec chmod 0700 {} +
find "$DST" -type f -exec chmod 0600 {} +
chown -R jarvis:jarvis "$HOME_DIR"

# `sudo jarvis-svc ARGS` runs a CLI command as the daemon's account, from the
# release it runs (the owner's checkout is not readable by jarvis).
printf '#!/bin/sh\n# Installed by install-service-user.sh: the jarvis CLI as the daemon account.\ncd %s && exec sudo -u jarvis -H %s "$@"\n' \
  "$workdir" "$exec_line" > "$SVC_CLI.new"
install -o root -g root -m 0755 "$SVC_CLI.new" "$SVC_CLI"; rm -f "$SVC_CLI.new"

install -d -o root -g root -m 0755 "$MARKER_DIR"
printf '{"user": "jarvis", "state_dir": "%s", "owner": "%s", "owner_uid": %s, "cli": "sudo jarvis-svc"}\n' \
  "$DST" "$OWNER" "$OWNER_UID" > "$MARKER.new"
install -o root -g root -m 0644 "$MARKER.new" "$MARKER"; rm -f "$MARKER.new"

install -d -m 0755 "$DROPIN_DIR"
sed "s/@OWNER_UID@/$OWNER_UID/" "$repo/systemd/service-user.conf" > "$DROPIN.new"
install -o root -g root -m 0644 "$DROPIN.new" "$DROPIN"; rm -f "$DROPIN.new"

# The self-check needs the store and the alert settings: it moves to jarvis too.
sed -e "s|@REPO_ROOT@|$workdir|" -e "s|@EXEC@|$exec_line|" \
  "$repo/systemd/jarvis-selfcheck-system.service" > "$SELFCHECK.new"
install -o root -g root -m 0644 "$SELFCHECK.new" "$SELFCHECK"; rm -f "$SELFCHECK.new"
install -o root -g root -m 0644 "$repo/systemd/jarvis-selfcheck.timer" "$SELFCHECK_TIMER"
sed "s/^chris /jarvis /" "$repo/systemd/jarvis-restart.sudoers" > "$SUDOERS.new"
if visudo -cqf "$SUDOERS.new"; then install -o root -g root -m 0440 "$SUDOERS.new" "$SUDOERS"; fi
rm -f "$SUDOERS.new"
owner_user_systemctl disable --now jarvis-selfcheck.timer

systemctl daemon-reload
systemctl start jarvis.service
systemctl enable --now jarvis-selfcheck.timer
answered=false
for _ in $(seq 1 30); do
  if curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8787/api/live | grep -qx 200; then
    answered=true; break
  fi
  sleep 2
done
systemctl show jarvis.service -p User -p ActiveState
if ! $answered; then
  echo "daemon not answering as jarvis; rolling back" >&2
  journalctl -u jarvis.service -n 30 --no-pager >&2 || true
  rollback; exit 3
fi
echo
echo "switched. Pair the clients that can no longer read the token file:"
echo "  sudo jarvis-svc desktop pair --name cli | jarvis desktop save"
echo "  sudo jarvis-svc desktop pair --name desktop   (then docs/guides/SERVICE-ACCOUNT.md)"
echo "Verify over the next 15 minutes: every collector FRESH, native complete, broker results accepted."
echo "If anything regresses: sudo $0 --rollback"

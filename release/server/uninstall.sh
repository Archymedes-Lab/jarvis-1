#!/usr/bin/env bash
# Remove Argus from this server.
#
#   sudo /opt/argus/uninstall.sh          remove the program, keep its history
#   sudo /opt/argus/uninstall.sh --purge  also delete /var/lib/argus and the account
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root: sudo $0 $*" >&2; exit 1; }
PURGE=false; [ "${1:-}" = --purge ] && PURGE=true

# One unit at a time: `systemctl disable --now a b c` fails as a whole when an
# optional unit (the network sensor) was never installed, and then stops nothing.
for unit in argus.service argus-netsensor.service argus-netstate.timer argus-netstate.service; do
  systemctl disable --now "$unit" 2>/dev/null || systemctl stop "$unit" 2>/dev/null || true
done
# Nothing of Argus may keep running after its unit files are gone.
for account in argus argus-net; do
  if id "$account" >/dev/null 2>&1 && pgrep -u "$account" >/dev/null 2>&1; then
    pkill -TERM -u "$account" 2>/dev/null || true
    sleep 2
    pkill -KILL -u "$account" 2>/dev/null || true
  fi
done
rm -f /etc/systemd/system/argus.service /etc/systemd/system/argus-netsensor.service \
  /etc/systemd/system/argus-netstate.service /etc/systemd/system/argus-netstate.timer \
  /usr/local/bin/argus
systemctl daemon-reload
rm -rf /opt/argus
if $PURGE; then
  rm -rf /var/lib/argus /var/lib/argus-net /etc/argus
  userdel argus-net 2>/dev/null || true
  userdel argus 2>/dev/null || true
  echo "Argus removed, with its history."
else
  echo "Argus removed. History kept in /var/lib/argus (--purge deletes it)."
fi

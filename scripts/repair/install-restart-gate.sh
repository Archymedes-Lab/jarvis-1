#!/usr/bin/env bash
# Install the root-owned JARVIS restart gate (scripts/repair/jarvis-restart-gate).
#
#   sudo bash install-restart-gate.sh              install the gate and its sudo rule
#   sudo bash install-restart-gate.sh --revoke-legacy
#        afterwards, once the restarters use the gate: drop the passwordless
#        `systemctl restart jarvis.service` rule (reset-failed is kept); the
#        old file is backed up and restored if visudo rejects the new one
#   sudo bash install-restart-gate.sh --uninstall  undo both, restoring the backup
#
# Each sudoers file is validated with visudo before it is installed.
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run this installer as root (sudo).' >&2; exit 1; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
user=${JARVIS_USER:-chris}
gate=/usr/local/sbin/jarvis-restart-gate
rule=/etc/sudoers.d/jarvis-restart-gate
legacy=/etc/sudoers.d/jarvis-restart
backup=/var/lib/jarvis-restart-gate/jarvis-restart.sudoers.before-gate
log=/var/log/jarvis-restart-gate.jsonl
staged=$(mktemp)
trap 'rm -f -- "$staged"' EXIT

case "${1:-}" in
  "")
    /usr/bin/python3 -I -m py_compile "$here/jarvis-restart-gate"
    printf '%s ALL=(root) NOPASSWD: %s --actor * --reason *\n' "$user" "$gate" > "$staged"
    /usr/sbin/visudo -cf "$staged"
    install -d -o root -g root -m 0700 /var/lib/jarvis-restart-gate
    install -o root -g root -m 0755 "$here/jarvis-restart-gate" "$gate"
    [[ -e $log ]] || install -o root -g root -m 0644 /dev/null "$log"
    install -o root -g root -m 0440 "$staged" "$rule"
    /usr/sbin/visudo -cf "$rule"
    echo "Installed $gate, its log $log and sudo rule $rule."
    echo "Check: sudo -n $gate --actor reviver --reason unit-down   (expect: refused, unit is active)"
    ;;
  --revoke-legacy)
    [[ -x $gate && -e $rule ]] || { echo 'Install the gate first.' >&2; exit 1; }
    [[ -e $legacy ]] || { echo "No $legacy; nothing to revoke."; exit 0; }
    install -d -o root -g root -m 0700 /var/lib/jarvis-restart-gate
    [[ -e $backup ]] || cp -p -- "$legacy" "$backup"
    grep -v 'systemctl restart jarvis.service' "$backup" \
      | sed -e 's#/usr/bin/systemctl restart jarvis.service, ##' -e 's#, /usr/bin/systemctl restart jarvis.service##' \
      > "$staged"
    printf '%s ALL=(root) NOPASSWD: /usr/bin/systemctl reset-failed jarvis.service\n' "$user" >> "$staged"
    /usr/sbin/visudo -cf "$staged"
    install -o root -g root -m 0440 "$staged" "$legacy"
    if ! /usr/sbin/visudo -cf "$legacy" || grep -q 'systemctl restart jarvis' "$legacy"; then
      install -o root -g root -m 0440 "$backup" "$legacy"
      echo "Revocation failed validation; $legacy restored." >&2
      exit 1
    fi
    echo "Revoked the passwordless systemctl restart rule (backup: $backup)."
    ;;
  --uninstall)
    [[ -e $backup ]] && install -o root -g root -m 0440 "$backup" "$legacy" && echo "Restored $legacy."
    rm -f -- "$rule" "$gate"
    echo "Removed the gate and its rule; $log is kept as evidence."
    ;;
  *) echo "usage: $0 [--revoke-legacy|--uninstall]" >&2; exit 2 ;;
esac

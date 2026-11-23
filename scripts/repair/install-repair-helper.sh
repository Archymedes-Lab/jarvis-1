#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) = 0 ]] || { echo 'Run this installer as root.' >&2; exit 1; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
staged=$(mktemp)
trap 'rm -f -- "$staged"' EXIT
cat > "$staged" <<'RULE'
chris ALL=(root) NOPASSWD: /usr/local/sbin/jarvis-repair status, /usr/local/sbin/jarvis-repair monitor, /usr/local/sbin/jarvis-repair telemetry, /usr/local/sbin/jarvis-repair journal, /usr/local/sbin/jarvis-repair mount, /usr/local/sbin/jarvis-repair all
RULE
/usr/sbin/visudo -cf "$staged"
/usr/bin/python3 -I -m py_compile "$repo/systemd/jarvis-repair"
install -o root -g root -m 0755 "$repo/systemd/jarvis-repair" /usr/local/sbin/jarvis-repair
install -o root -g root -m 0440 "$staged" /etc/sudoers.d/jarvis-repair
/usr/sbin/visudo -cf /etc/sudoers.d/jarvis-repair
echo 'Installed root-owned JARVIS repair helper and fixed-operation sudo rule.'

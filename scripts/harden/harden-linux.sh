#!/usr/bin/env bash
# Linux-side hardening for the WSL2 distro, applied through /etc/sysctl.d.
#
# Most of this box is already hardened -- io_uring is off, unprivileged BPF is
# disabled, ptrace is scoped, ASLR is full, the fs.protected_* family is on.
# What follows is the remainder, plus a re-assert so a distro update cannot
# quietly revert any of it.
#
# Scope, stated honestly: WSL2 runs a Microsoft-supplied kernel inside a
# Hyper-V utility VM. There is no Secure Boot, no measured boot, no TPM and no
# module signing to configure from in here, and nothing in this file defends
# against the Windows host -- WSL is not a security boundary in that direction.
# The real hardware-adjacent controls (VBS/HVCI, Credential Guard, BitLocker,
# Secure Boot) all live on the Windows side; see harden-windows.ps1.
#
#   sudo ./harden-linux.sh          apply
#   sudo ./harden-linux.sh --dry    print what would change, change nothing

set -euo pipefail

CONF=/etc/sysctl.d/99-jarvis-hardening.conf
DRY=false
[ "${1:-}" = "--dry" ] && DRY=true

if [ "$(id -u)" -ne 0 ] && ! $DRY; then
  echo "must run as root: sudo $0" >&2
  exit 1
fi

# key = desired value, with the reason it is set.
declare -A WANT=(
  # Already set on this box; re-asserted so an update cannot revert them.
  [kernel.io_uring_disabled]=2          # io_uring bypasses syscall auditing entirely
  [kernel.unprivileged_bpf_disabled]=2  # no unprivileged eBPF program loading
  [kernel.yama.ptrace_scope]=1          # a process may only trace its own children
  [kernel.randomize_va_space]=2         # full ASLR incl. brk
  [fs.protected_hardlinks]=1
  [fs.protected_symlinks]=1
  [fs.protected_fifos]=1
  [fs.protected_regular]=2

  # Actually changed by this script.
  [kernel.dmesg_restrict]=1             # was 0: kernel log leaks addresses and
                                        # module layout to any unprivileged user
  # was 1: hide kernel pointers from everyone, root included.
  #
  # VERIFIED COMPATIBLE with Sysmon-for-Linux (2026-09-02, this box).
  # kptr_restrict=2 zeroes /proc/kallsyms for root as well as everyone else,
  # and Sysmon is the eBPF syscall interception this machine depends on -- it
  # is what took `jarvis gaps` from 68% to 84%. The concern was real: if the
  # BPF loader needed kallsyms it would fail only on the NEXT restart, long
  # after this script ran, and the interception would be gone silently.
  #
  # It does not. sysmon was reloaded under kptr_restrict=2 and delivered 94199
  # events on the following pass. That matches the mechanism: libbpf attaches
  # kprobes by symbol NAME through the kernel's own API rather than resolving
  # addresses, and BTF (/sys/kernel/btf/vmlinux) is a separate interface this
  # setting does not govern.
  #
  # Re-check after any kernel or Sysmon upgrade:
  #   sudo systemctl restart sysmon && sleep 5 && jarvis sysmon-linux
  # If it ever fails to come back, drop this to 1 and re-run.
  [kernel.kptr_restrict]=2
  [net.ipv4.conf.all.send_redirects]=0  # was 1: this box is not a router
  [net.ipv4.conf.default.send_redirects]=0
  [net.ipv4.conf.all.accept_redirects]=0
  [net.ipv4.conf.default.accept_redirects]=0
  [net.ipv4.conf.all.accept_source_route]=0
  [net.ipv4.conf.default.accept_source_route]=0
  [net.ipv4.conf.all.log_martians]=1    # log packets with impossible addresses
  [net.ipv4.tcp_syncookies]=1
  [net.ipv6.conf.all.accept_redirects]=0
  [net.ipv6.conf.default.accept_redirects]=0
)

echo "=== jarvis linux hardening ==="
changed=0; skipped=0

TMP="$(mktemp)"
{
  echo "# Written by harden-linux.sh -- see that script for the reasoning."
  echo "# Re-applied on every run; edit the script, not this file."
} > "$TMP"

for key in "${!WANT[@]}"; do
  want="${WANT[$key]}"
  if ! cur=$(sysctl -n "$key" 2>/dev/null); then
    printf '  %-42s absent on this kernel, skipping\n' "$key"
    skipped=$((skipped + 1))
    continue
  fi
  echo "$key = $want" >> "$TMP"
  if [ "$cur" != "$want" ]; then
    printf '  %-42s %s -> %s\n' "$key" "$cur" "$want"
    changed=$((changed + 1))
  fi
done

sort -o "$TMP" "$TMP"

if $DRY; then
  echo "--- would write $CONF ---"
  cat "$TMP"
  rm -f "$TMP"
  echo "=== dry run: $changed would change, $skipped unavailable ==="
  exit 0
fi

install -m 0644 -o root -g root "$TMP" "$CONF"
rm -f "$TMP"
sysctl --quiet --system
echo "=== applied: $changed changed, $skipped unavailable on this kernel ==="
echo "    persisted in $CONF"

# --- things sysctl cannot fix ---------------------------------------------
cat <<'EOF'

--- not fixable from sysctl, decide these yourself ---

X11 (/tmp/.X11-unix/X0 is mode srwxrwxrwx)
    WSLg publishes a world-connectable X11 socket. X11 grants every client
    access to every other client's input and to the framebuffer, so any
    process in this distro can log keystrokes and screenshot the desktop with
    no prompt and no record. Windows' capability ledger does not cover it.

    If you do not run Linux GUI apps, turn WSLg off entirely -- this is the
    only complete fix. In Windows, %USERPROFILE%\.wslconfig:

        [wsl2]
        guiApplications=false

    then `wsl --shutdown`. Otherwise, at least keep DISPLAY unset for anything
    that has no business drawing a window:  env -u DISPLAY <command>

Running unprivileged
    jarvis cannot read other users' command lines, kernel module details or
    eBPF map contents as `chris`. That is a deliberate trade: running the
    monitor as root would make the monitor itself the best target on the box.
    Use `sudo jarvis <cmd>` for a one-off deep look instead.
EOF

#!/usr/bin/env bash
# Install the server edition on this machine (a disposable CI runner with
# systemd), let it run, check what it did, remove it, check nothing is left.
#
#   sudo bash release/install_test.sh TARBALL DEB
#
# Each package is tested on its own: install -> service active as `argus` ->
# health answers ARGUS -> the CLI works through the native program -> the
# installed copy's verification report passes -> no Python anywhere in
# /opt/argus -> no tracebacks in the journal -> uninstall/purge leaves no
# files, units or accounts. Never run this on a machine you care about.
set -euo pipefail
TARBALL="$1"; DEB="$2"
OBSERVE="${OBSERVE:-90}"
fail() { echo "INSTALL TEST FAILED: $*" >&2; journalctl -u argus --no-pager -n 80 >&2 || true; exit 1; }

check_running() {
  systemctl is-active --quiet argus || fail "argus.service is not active"
  [ "$(systemctl show -p User --value argus)" = argus ] || fail "the service does not run as argus"
  body="$(curl -sS --max-time 5 http://127.0.0.1:8787/api/health || true)"
  printf '%s' "$body" | grep -q '"service": *"ARGUS"' || fail "health does not answer ARGUS: $body"
  /usr/local/bin/argus --help >/dev/null || fail "the CLI does not run"
  python3 -c 'import json,sys; r=json.load(open("/opt/argus/verification.json")); sys.exit(0 if r.get("ok", True) else 1)' \
    || fail "the installed copy's verification report is not ok"
  if find /opt/argus -name '*.py' -o -name '*.pyc' | grep -q .; then fail "Python source or bytecode is installed"; fi
  sleep "$OBSERVE"
  systemctl is-active --quiet argus || fail "argus.service stopped within ${OBSERVE}s"
  n="$(journalctl -u argus --no-pager | grep -c 'Traceback' || true)"
  [ "$n" = 0 ] || fail "$n tracebacks in the journal"
  echo "running OK: $(head -c 300 /opt/argus/VERSION)"
}

check_gone() {
  [ ! -e /opt/argus ] || fail "/opt/argus is left behind"
  [ ! -e /etc/systemd/system/argus.service ] || fail "the unit is left behind"
  [ ! -e /usr/local/bin/argus ] || fail "the CLI is left behind"
  ! id argus >/dev/null 2>&1 || fail "the argus account is left behind"
  [ ! -e /var/lib/argus ] || fail "/var/lib/argus is left behind after purge"
}

echo "== tarball"
work="$(mktemp -d)"; tar -xzf "$TARBALL" -C "$work"
"$work/argus-server/install.sh"
check_running
/opt/argus/uninstall.sh --purge
check_gone
rm -rf "$work"

echo "== deb"
apt-get install -y -q "$(readlink -f $DEB)"
check_running
apt-get purge -y -q argus-server
check_gone
echo "INSTALL TEST PASSED"

#!/usr/bin/env bash
# Developer setup for a fresh checkout (any cofounder or contributor; CONTRIBUTING.md).
#
#   scripts/dev/bootstrap.sh            check tools and access, enable the git hooks, run the fast tests
#   scripts/dev/bootstrap.sh --check    check only, change nothing
#
# What it changes: this repository's core.hooksPath (to .githooks) and nothing else. It never installs
# software, never starts or registers a service, never touches ~/.jarvis or Windows, and never reads a
# secret. Each missing tool is reported with the command that installs it.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
CHECK_ONLY=0; [[ "${1:-}" == "--check" ]] && CHECK_ONLY=1
fail=0; warn=0
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  MISS  %s\n' "$*"; fail=$((fail + 1)); }
soft() { printf '  warn  %s\n' "$*"; warn=$((warn + 1)); }
has()  { command -v "$1" >/dev/null 2>&1; }

echo "Tools (required for the Python core and its gates)"
if has python3 && python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then ok "python3 $(python3 -c 'import platform; print(platform.python_version())')"
else bad "python 3.12+ (sudo apt install python3.12, or https://www.python.org on Windows)"; fi
if has uv; then ok "uv $(uv --version | cut -d' ' -f2) (ruff and mypy run through uvx)"
else bad "uv: curl -LsSf https://astral.sh/uv/install.sh | sh"; fi
has git && ok "git $(git --version | cut -d' ' -f3)" || bad "git"

echo "Tools (needed only for the part you work on)"
has bun   && ok "bun $(bun --version) (desktop UI, licence and notify Workers)" || soft "bun: curl -fsSL https://bun.sh/install | bash   (desktop UI, hosted/*)"
has cargo && ok "cargo $(cargo --version | cut -d' ' -f2) (desktop app, rust-runtime)"   || soft "cargo: https://rustup.rs   (desktop app, rust-runtime)"
has 7z    && ok "7z (release readback)"                                                    || soft "7z: sudo apt install p7zip-full   (only for publishing a release)"

echo "Access"
if has gh && gh auth status >/dev/null 2>&1; then
  login=$(gh api user --jq .login 2>/dev/null || echo "?")
  ok "gh signed in as $login"
  if role=$(gh api repos/Archymedes-Lab/argus-1 --jq .permissions 2>/dev/null); then
    [[ "$role" == *'"push":true'* ]] && ok "write access to Archymedes-Lab/argus-1" || soft "no write access to Archymedes-Lab/argus-1 (ask an admin)"
  else soft "cannot read Archymedes-Lab/argus-1 (network, or not a member)"; fi
  if grep -q "^$login " release/allowed_signers 2>/dev/null; then
    if [[ -f "$HOME/.config/argus-release/signing_key" ]]; then ok "releaser: listed, signing key present"
    else soft "releaser: listed, but ~/.config/argus-release/signing_key is not on this machine (sign on the machine that holds it)"; fi
  fi
else soft "gh not signed in: gh auth login   (pull requests, CI runs, releases)"; fi
name=$(git config user.name || true); email=$(git config user.email || true)
[[ -n "$name" && -n "$email" ]] && ok "git identity: $name" || bad "git identity: git config --global user.name ...; git config --global user.email ..."
remote=$(git remote -v | awk '/Archymedes-Lab\/argus-1/ {print $1; exit}')
[[ -n "$remote" ]] && ok "remote '$remote' is Archymedes-Lab/argus-1 (the shared home)" \
  || soft "no remote points at Archymedes-Lab/argus-1: git remote add org https://github.com/Archymedes-Lab/argus-1.git"

echo "Optional"
if [[ -n "${TYPESAFE_API_KEY:-}" || -f "$HOME/.jarvis/typesafe.env" ]]; then ok "TypeSafe/Jev key configured (advisory reviews)"
else soft "no TypeSafe key: Jev reviews report 'unavailable' and fall back safely (AGENTS.md); ask for your own key"; fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  echo; echo "check only: $fail missing, $warn warnings"; exit $(( fail > 0 ))
fi
if [[ $fail -gt 0 ]]; then echo; echo "$fail required item(s) missing; fix them and run again."; exit 1; fi

echo "Setup"
current=$(git config --local core.hooksPath || true)
if [[ -z "$current" || "$current" == ".githooks" ]]; then
  git config --local core.hooksPath .githooks && ok "git hooks enabled (.githooks/pre-push runs the quick gate and changed tests)"
else soft "core.hooksPath is '$current'; left alone (set it to .githooks to use the shared hooks)"; fi

echo "First run: quick static gate and the fast tests (scratch HOME; your ~/.jarvis is never read)"
scripts/dev/static_gate.sh --quick
python3 scripts/dev/fasttest.py
echo; echo "Ready. Next: CONTRIBUTING.md (how we work), docs/architecture/CURRENT.md (what JARVIS is now)."

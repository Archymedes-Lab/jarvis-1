#!/usr/bin/env bash
# Static analysis gate: the first rung of docs/architecture/VERIFICATION-LADDER.md.
#
#   scripts/dev/static_gate.sh           lint + types + verification tests
#   scripts/dev/static_gate.sh --quick   lint + types only
#
# Exit status is non-zero on the first failing stage. Nothing here needs the
# network except ruff/mypy themselves, which uvx caches under ~/.cache/uv.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
export UV_CACHE_DIR="${UV_CACHE_DIR:-$HOME/.cache/uv}"

echo "[1/3] ruff (F, E9, I, B, PLE; see pyproject.toml)"
uvx "ruff@${RUFF_VERSION:-0.17.3}" check jarvis tests release

# Typed gate on the pure engines and the verification package. Transitive
# modules are followed silently so this stage grows package by package rather
# than failing on the whole tree at once; widen TYPED when a package is clean.
TYPED=(jarvis/core/reasoning jarvis/core/execution jarvis/core/mechanisms.py jarvis/response/reporting jarvis/verify)
echo "[2/3] mypy on ${TYPED[*]}"
uvx "mypy@${MYPY_VERSION:-2.4.1}" --ignore-missing-imports --follow-imports=silent "${TYPED[@]}"

if [[ "${1:-}" == "--quick" ]]; then exit 0; fi
echo "[3/3] invariant registry, shipped rules, property checks and model checking"
python3 -m unittest tests.test_verify_mc tests.test_verify_models tests.test_verify_props \
    tests.test_verify_invariants tests.test_verify_static tests.test_verify_ladder_model tests.test_elevation \
    tests.test_source_status tests.test_windows_launch_gate

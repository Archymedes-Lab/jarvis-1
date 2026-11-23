#!/usr/bin/env bash
# Opt-in disposable Linux native build lab only. Never invoked by campaign.py.
# Provision a reviewed nightly with rust-src, dependencies and UI build first.
# No automatic toolchain download; cargo is offline and locked.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../desktop"
if [[ "${ARGUS_DISPOSABLE_LAB:-}" != "1" ]]; then
    echo 'Requires ARGUS_DISPOSABLE_LAB=1 in a provisioned disposable native build lab' >&2
    exit 2
fi
export RUSTUP_AUTO_INSTALL=0
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$(mktemp -d /tmp/argus-sanitizers-XXXXXX)"
for sanitizer in address thread; do
    # Instrument standard library and desktop Rust. C/system libraries remain gaps.
    RUSTFLAGS="-Zsanitizer=$sanitizer" RUSTDOCFLAGS="-Zsanitizer=$sanitizer" \
        cargo +nightly test --locked --offline -Zbuild-std --target x86_64-unknown-linux-gnu
done

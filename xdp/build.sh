#!/usr/bin/env bash
# Build the Zion XDP eBPF program.
#
# Output: xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog
# The userspace loader (src/xdp.rs) reads the ELF object from
# `$ZION_XDP_OBJECT` (default: the path above).
#
# Prerequisites:
#   1. rustup toolchain install nightly-2026-01-15
#   2. cargo install bpf-linker
#   3. apt install -y libelf-dev   (for aya-log on the userspace side)
#
# Run from the zion repo root: `xdp/build.sh`

set -euo pipefail

cd "$(dirname "$0")/zion-xdp-prog"

echo "→ Building zion-xdp-prog (bpfel-unknown-none, release)…"
cargo +nightly-2026-01-15 build \
    --release \
    -Z build-std=core

OUT="$PWD/target/bpfel-unknown-none/release/zion-xdp-prog"
if [[ ! -f "$OUT" ]]; then
    echo "✗ build succeeded but artifact not found at: $OUT" >&2
    exit 1
fi

echo "✓ eBPF object built: $OUT"
echo
echo "Load with: ZION_XDP_OBJECT=$OUT zion --xdp-iface eth0 …"

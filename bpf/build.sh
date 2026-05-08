#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Build the Zion SK_REUSEPORT BPF demux program (issue #53).
#
# Output: bpf/zion-bpf-demux/target/bpfel-unknown-none/release/zion-bpf-demux
# The userspace loader (src/bpf_demux.rs) reads the ELF object from
# `$ZION_BPF_DEMUX_OBJECT` (default: the path above).
#
# Prerequisites — same as `xdp/build.sh`:
#   1. rustup toolchain install nightly-2026-01-15
#   2. cargo install bpf-linker
#   3. apt install -y libelf-dev   (only if you also build the loader's
#                                   userspace deps from source)
#
# Run from the zion repo root: `bpf/build.sh`

set -euo pipefail

cd "$(dirname "$0")/zion-bpf-demux"

echo "→ Building zion-bpf-demux (bpfel-unknown-none, release)…"
cargo +nightly-2026-01-15 build \
    --release \
    -Z build-std=core

OUT="$PWD/target/bpfel-unknown-none/release/zion-bpf-demux"
if [[ ! -f "$OUT" ]]; then
    echo "✗ build succeeded but artifact not found at: $OUT" >&2
    exit 1
fi

echo "✓ BPF demux object built: $OUT"
echo
echo "Load with: ZION_BPF_DEMUX_OBJECT=$OUT zion --bpf-demux …"

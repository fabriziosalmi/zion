#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The rustc flags that keep this machine's paths out of the binary (#669).
#
#   export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$(scripts/remap-rustflags.sh +1.88.0)"
#   export ZIG_GLOBAL_CACHE_DIR="$(mktemp -d)"
#   cargo +1.88.0 zigbuild --release --locked --features dist --target x86_64-unknown-linux-musl
#
# A release binary carries the source paths of its dependencies (the locations of
# their panics), and they are this machine's:
#
#   * cargo's home, in several hundred strings: remapped to /cargo;
#   * with the `rust-src` component installed (rust-toolchain.toml asks for it), the
#     standard library's sources under rustup's home, where a toolchain without the
#     component has the compiler's fixed /rustc/<commit>: remapped to that.
#
# With the two flags the bytes do not depend on where cargo's home is, on which
# components the toolchain has or on the checkout directory. Measured on v0.12.0: two
# builds that differed in all three were identical; without the flags each of the
# first two changes the binary.
#
# The flags go in CARGO_TARGET_<TRIPLE>_RUSTFLAGS: Cargo joins that with the rustflags
# of .cargo/config.toml, and RUSTFLAGS would replace them. Cargo leaves
# --remap-path-prefix out of the hashes it names files with, so the flags do not change
# anything else about the build.
#
# The third thing a rebuild needs is not a flag: an empty zig cache
# (ZIG_GLOBAL_CACHE_DIR). zig keeps compiled C objects by path and flags, not by
# SOURCE_DATE_EPOCH, and the allocator's C code contains the date and time of its
# compilation: an object from another day's build of the same source is reused, with
# that day in it.
#
# Argument: the toolchain, as cargo takes it (+1.88.0). Default: whatever `rustc` is.

set -euo pipefail

TOOLCHAIN=()
if [ $# -ge 1 ]; then
  case $1 in
    +*) TOOLCHAIN=("$1") ;;
    *)
      echo "remap-rustflags: usage: $0 [+toolchain]" >&2
      exit 2
      ;;
  esac
fi

CARGO_HOME_DIR=${CARGO_HOME:-$HOME/.cargo}
SYSROOT=$(rustc ${TOOLCHAIN[@]+"${TOOLCHAIN[@]}"} --print sysroot)
COMMIT=$(rustc ${TOOLCHAIN[@]+"${TOOLCHAIN[@]}"} -vV | sed -n 's/^commit-hash: //p')
[ -n "$SYSROOT" ] && [ ${#COMMIT} -eq 40 ] || {
  echo "remap-rustflags: could not read the sysroot and the commit of rustc" >&2
  exit 1
}
# The flags are a space-separated list: a path with a space would be split.
case "$CARGO_HOME_DIR$SYSROOT" in
  *[[:space:]]*)
    echo "remap-rustflags: cargo's home ('$CARGO_HOME_DIR') or the toolchain ('$SYSROOT') has whitespace in its path" >&2
    exit 1
    ;;
esac

echo "--remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$SYSROOT/lib/rustlib/src/rust=/rustc/$COMMIT"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The libraries zion loads in the container it ships, as a directory for
# `qemu -L` (SMOKE_SYSROOT of scripts/cpu-baseline-smoke.sh):
#
#   scripts/baseline-sysroot.sh x86_64|aarch64 DIR
#
# It is the runtime stage of the Dockerfile (debian12 distroless, digest read from
# there so the two cannot drift), whose glibc is built for the baseline of its
# architecture. The runner's own glibc is not: Ubuntu 26.04 is x86-64-v3
# throughout, and its startup code stops under an emulated Opteron_G1 before the
# binary's first instruction (#766). The smoke wants to test the binary, with the
# libc a user of the image has.
#
# Needs: docker (create and export only; no emulation is run), python3.

set -euo pipefail

fail() {
  echo "baseline-sysroot: $*" >&2
  exit 1
}

[ $# -eq 2 ] || fail "usage: $0 x86_64|aarch64 DIR"
case "$1" in
  x86_64) PLATFORM=linux/amd64 LOADER=lib64/ld-linux-x86-64.so.2 LIBC=lib/x86_64-linux-gnu/libc.so.6 ;;
  aarch64) PLATFORM=linux/arm64 LOADER=lib/ld-linux-aarch64.so.1 LIBC=lib/aarch64-linux-gnu/libc.so.6 ;;
  *) fail "architecture '$1' is neither x86_64 nor aarch64" ;;
esac
DIR=$2
cd "$(dirname "$0")/.."

IMAGE=$(sed -n 's/^FROM \(gcr\.io\/distroless\/[^ ]*@sha256:[0-9a-f]\{64\}\) AS runtime$/\1/p' Dockerfile)
[ -n "$IMAGE" ] || fail "no 'FROM gcr.io/distroless/...@sha256:... AS runtime' line in the Dockerfile"

mkdir -p "$DIR"
CID=$(docker create --platform "$PLATFORM" "$IMAGE" /unused)
trap 'docker rm "$CID" >/dev/null 2>&1 || true' EXIT
docker export "$CID" | tar -x --no-same-owner -C "$DIR"

# An image's symlinks are absolute (/lib64/ld-linux-x86-64.so.2 -> /lib/x86_64-linux-gnu/...).
# qemu -L only prefixes the path, so the host's kernel would follow such a link in the
# host's root and load the runner's loader and libc: the very ones this directory is
# here to replace. Make every link relative to where it sits.
python3 - "$DIR" <<'PY'
import os, sys
root = os.path.realpath(sys.argv[1])
for d, dirs, files in os.walk(root):
    for n in dirs + files:
        p = os.path.join(d, n)
        if os.path.islink(p):
            t = os.readlink(p)
            if os.path.isabs(t):
                os.unlink(p)
                os.symlink(os.path.relpath(root + t, d), p)
PY
# And qemu falls back to the host's file for any path the sysroot lacks. The loader reads
# /etc/ld.so.cache, which this image does not have, so it read the host's, which names
# /usr/lib/x86_64-linux-gnu/libc.so.6: not in this sysroot either (Debian 12 keeps its
# libraries in /lib), so the host's libc was loaded after all. An empty cache is ignored
# by the loader, which then searches its default directories, and those are in here.
: >"$DIR/etc/ld.so.cache"
[ -z "$(find "$DIR" -type l -lname '/*')" ] || fail "an absolute symlink is left in $DIR: qemu would follow it in the host's root"
[ -e "$DIR/$LOADER" ] || fail "$IMAGE has no /$LOADER for $PLATFORM (or its link does not resolve inside $DIR)"
[ -e "$DIR/$LIBC" ] || fail "$IMAGE has no /$LIBC for $PLATFORM"
echo "baseline-sysroot: $IMAGE ($PLATFORM) in $DIR"

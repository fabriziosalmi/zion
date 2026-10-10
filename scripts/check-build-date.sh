#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Was every C object in this binary compiled for this build?
#
#   SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) scripts/check-build-date.sh path/to/zion
#
# The allocator's C code has the date and the time of its compilation in it
# (__DATE__, __TIME__), and with SOURCE_DATE_EPOCH set they are that instant's, in UTC.
# zig keeps compiled C objects in a cache, by path and flags and not by
# SOURCE_DATE_EPOCH: a cache that served another build hands back an object with that
# build's date, and the binary is then not the one this source gives. It happened to a
# check of this repository on the day of v0.13.0: mlugg/setup-zig points both of zig's
# cache directories into the workspace and restores them from an earlier run.
#
# So: the date and the time in the binary must be SOURCE_DATE_EPOCH's. Linux binaries,
# GNU date.

set -euo pipefail

fail() {
  echo "check-build-date: $*" >&2
  exit 1
}

[ $# -eq 1 ] && [ -f "$1" ] || fail "usage: SOURCE_DATE_EPOCH=... $0 path/to/zion"
: "${SOURCE_DATE_EPOCH:?set SOURCE_DATE_EPOCH to the instant the build was made for}"

WANT_DATE=$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%b %e %Y') # "Oct  9 2026", as __DATE__ pads
WANT_TIME=$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%H:%M:%S')
DATES=$(strings -n 8 "$1" | grep -E '^[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{4}$' | sort -u || true)
TIMES=$(strings -n 8 "$1" | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}$' | sort -u || true)

[ -n "$DATES" ] && [ -n "$TIMES" ] ||
  fail "no compile date or time found in $1: the allocator's C code no longer has them, and this check has nothing to read"
[ "$DATES" = "$WANT_DATE" ] && [ "$TIMES" = "$WANT_TIME" ] ||
  fail "$1 has a C object compiled on '$(paste -sd'|' - <<<"$DATES") $(paste -sd'|' - <<<"$TIMES")', and this build is of '$WANT_DATE $WANT_TIME' (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH): an object from another build was reused. Build with empty ZIG_GLOBAL_CACHE_DIR and ZIG_LOCAL_CACHE_DIR."
echo "ok: the C objects in $1 are of this build ($WANT_DATE $WANT_TIME UTC)"

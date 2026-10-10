#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Profile-guided build of zion (issue #55): instrumented build, training
# (scripts/pgo-train.sh), merge, optimised build, and the checks that make it
# fail closed. The release workflow and a developer run this same script.
#
#   scripts/pgo-build.sh
#   PGO_CARGO="cargo zigbuild" PGO_TARGET=x86_64-unknown-linux-gnu scripts/pgo-build.sh
#   PGO_PROFDATA=zion-v1.2.3-x86_64-unknown-linux-gnu.profdata scripts/pgo-build.sh
#
# The optimised binary is left where cargo puts it, target/<target>/release/zion,
# and the merged profile in $PGO_OUT/zion.profdata.
#
# The compiler reads the profile from $PGO_PROFILE_STORE/<sha256 of the profile>.profdata,
# not from $PGO_OUT: the path of the profile is on every rustc command line, and it must
# be the same wherever and whenever the same profile is built from, and another one for
# another profile (see "where the optimised build reads the profile" below).
#
#   PGO_TARGET        target triple (default: the host)
#   PGO_CARGO         the build command of both phases (default "cargo build";
#                     the release uses "cargo zigbuild", the toolchain of the
#                     plain artefact)
#   PGO_GENERATE_LINKER the linker of the instrumented binary, when the one
#                     PGO_CARGO configures cannot link it. The release sets
#                     "cc": zig's linker driver does not take the
#                     `-u __llvm_profile_runtime` of an instrumented link, and
#                     that binary only runs here, for the training.
#   PGO_FEATURES      cargo features (default "dist")
#   PGO_OUT           work directory (default target/pgo)
#   PGO_PROFILE_STORE where the profile is put for the compiler, under the name of
#                     its sha256 (default /tmp/zion-pgo). Part of the build: with
#                     another directory the same profile gives other bytes.
#   PGO_PROFDATA      a merged profile to build from: no instrumented build, no
#                     training. This is how a release is rebuilt from the
#                     profile published with it.
#   PGO_MIN_FUNCTIONS fewest functions the training must have executed (default
#                     2450: scripts/pgo-train.sh executes about 2590 Rust
#                     functions at v0.12.0, the three-endpoint workload it
#                     replaced 2312; with a clang-family C compiler, zig's
#                     included, the cc crate instruments the C dependencies
#                     too and the count is some 650 higher)
#   PGO_MAX_MISSING   most "no profile data" warnings the optimised build may
#                     print (default 1000; 814 at v0.12.0)
#   PGO_MAX_GLIBC     highest glibc symbol version the binary may need (ELF only)
#   PGO_VERIFY        1: replay the training workload against the optimised
#                     binary, every phase checked (default when this run did
#                     the training); 0: do not (default with PGO_PROFDATA)
#   PGO_TEST=1        also run the test suite compiled with the profile, in its
#                     own target directory (a third full build)
#   PGO_CARGO_TEST    the test command (default "cargo test"; the release uses
#                     "cargo-zigbuild test", so that the tests are built with
#                     the crate identities the profile was made with)
#
# The profile flags go in CARGO_TARGET_<TRIPLE>_RUSTFLAGS and never in RUSTFLAGS.
# Cargo joins the per-target variable with the rustflags of .cargo/config.toml,
# and DROPS the config's rustflags when RUSTFLAGS is set: a PGO build made with
# RUSTFLAGS silently loses whatever the config sets for the target, and is then
# not the plain build plus a profile. (Up to v0.12.0 that was x86-64-v3 on Linux
# x86_64, and the -pgo tarball was the one build without it.)
#
# Which processors the binary runs on is not checked here: the workflows run
# scripts/cpu-baseline-smoke.sh on it, as on every other binary.

set -euo pipefail
cd "$(dirname "$0")/.."

HOST=$(rustc -vV | sed -n 's/^host: //p')
TARGET=${PGO_TARGET:-$HOST}
CARGO=${PGO_CARGO:-cargo build}
FEATURES=${PGO_FEATURES:-dist}
OUT=${PGO_OUT:-target/pgo}
MIN_FUNCTIONS=${PGO_MIN_FUNCTIONS:-2450}
MAX_MISSING=${PGO_MAX_MISSING:-1000}

fail() {
  echo "pgo-build: $*" >&2
  exit 1
}

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
# The flags are a space-separated list: a path with a space would be split.
case $OUT in *[[:space:]]*) fail "the work directory '$OUT' contains whitespace" ;; esac
BIN=target/$TARGET/release/zion
[ "${TARGET#*windows}" = "$TARGET" ] || BIN=$BIN.exe
FLAGS_VAR=CARGO_TARGET_$(tr 'a-z.-' 'A-Z__' <<<"$TARGET")_RUSTFLAGS
[ -z "${RUSTFLAGS:-}" ] || fail "RUSTFLAGS is set ('$RUSTFLAGS'): it would replace the rustflags of .cargo/config.toml. Unset it."
[ -z "${CARGO_ENCODED_RUSTFLAGS:-}" ] || fail "CARGO_ENCODED_RUSTFLAGS is set: it would replace the rustflags of .cargo/config.toml. Unset it."
# What the caller already has in that variable goes on every rustc command line of this
# script, before the profile flags (the release passes scripts/remap-rustflags.sh's this
# way). Profile flags there would be this script's own job done twice.
BASE_FLAGS=${!FLAGS_VAR:-}
case $BASE_FLAGS in *profile-generate* | *profile-use*) fail "$FLAGS_VAR already has profile flags ('$BASE_FLAGS'): this script sets them." ;; esac

# rustc's own llvm-profdata (the llvm-tools component): its raw-profile format
# is the one this rustc writes. A system llvm-profdata of another LLVM refuses
# the files, or worse, merges a subset.
PROFDATA=$(rustc --print sysroot)/lib/rustlib/$HOST/bin/llvm-profdata
[ -x "$PROFDATA" ] || fail "no llvm-profdata in the toolchain: rustup component add llvm-tools"

# The logs are read by the checks below: no colour codes in them, whatever CARGO_TERM_COLOR says.
build() { # log file, extra rustflags
  # shellcheck disable=SC2086  # $CARGO is a command with arguments
  env "$FLAGS_VAR=${BASE_FLAGS:+$BASE_FLAGS }$2" CARGO_TERM_COLOR=never $CARGO -v --release --locked --features "$FEATURES" --target "$TARGET" >"$1" 2>&1 ||
    { tail -40 "$1" >&2; fail "the build failed, full log in $1"; }
}

# The command line of the zion binary crate in a build log, as cargo ran it.
rustc_line() {
  grep -E 'Running `.*rustc --crate-name zion .*--crate-type bin' "$1" | tail -1 || true
}

echo "pgo-build: target $TARGET, '$CARGO', features $FEATURES, $(rustc --version)"

if [ -n "${PGO_PROFDATA:-}" ]; then
  [ -s "$PGO_PROFDATA" ] || fail "PGO_PROFDATA=$PGO_PROFDATA is not a file"
  [ "$(cd "$(dirname "$PGO_PROFDATA")" && pwd)/$(basename "$PGO_PROFDATA")" = "$OUT/zion.profdata" ] || cp "$PGO_PROFDATA" "$OUT/zion.profdata"
  echo "[1-3/4] profile given ($PGO_PROFDATA): no instrumented build, no training"
else
  echo "[1/4] instrumented build"
  rm -rf "$OUT/profraw"
  mkdir -p "$OUT/profraw"
  # Both phases use the same build command. A crate's identity (-C metadata, which is in
  # every mangled function name) comes from cargo's configuration and not from the
  # rustflags, and `cargo zigbuild` runs cargo with target-applies-to-host=false, which
  # changes it for every crate: an instrumented binary built with plain `cargo build`
  # names its functions differently, and most of its profile then matches nothing in the
  # optimised build (measured: 5,024 functions without profile data instead of 814).
  # So the instrumented link is redirected with a rustflag instead: the last -C linker wins.
  # Its own target directory: nothing of it may be mistaken for the release build.
  CARGO_TARGET_DIR="$OUT/generate-target" build "$OUT/build-generate.log" \
    "-Cprofile-generate=$OUT/profraw${PGO_GENERATE_LINKER:+ -Clinker=$PGO_GENERATE_LINKER}"
  INSTRUMENTED=$OUT/generate-target/${BIN#target/}
  [ -x "$INSTRUMENTED" ] || fail "no instrumented binary at $INSTRUMENTED"

  echo "[2/4] training"
  ZION_BIN="$INSTRUMENTED" PGO_PROFILE_DIR="$OUT/profraw" bash scripts/pgo-train.sh

  echo "[3/4] merge"
  "$PROFDATA" merge -o "$OUT/zion.profdata" "$OUT"/profraw/*.profraw
  rm -rf "$OUT/generate-target"
fi

# Functions the training executed at least once.
FUNCTIONS=$("$PROFDATA" show --value-cutoff=1 "$OUT/zion.profdata" | sed -n 's/^Number of functions with maximum count (>= 1): //p')
echo "      profile: $(wc -c <"$OUT/zion.profdata" | tr -d ' ') bytes, ${FUNCTIONS:-?} functions executed in training (at least $MIN_FUNCTIONS required)"
[ "${FUNCTIONS:-0}" -ge "$MIN_FUNCTIONS" ] || fail "the training executed ${FUNCTIONS:-0} functions, fewer than $MIN_FUNCTIONS: it did not run as intended"

# ── where the optimised build reads the profile ──────────────────────────────
# The path is on rustc's command line, and Cargo hashes the command line into the file
# names of everything it builds; the order of code and data in the binary follows.
# Measured with one profile and two fresh builds each: at one path the two binaries are
# identical, at two paths they have the same size and differ in 7,015 bytes. And Cargo
# does not look inside the file: a new profile at an old path leaves the dependencies
# "fresh", compiled with the old one.
# So the path is made a function of the profile and of nothing else: a fixed directory,
# the sha256 of the content as the name. The same profile is the same command line on any
# machine, in any work directory; another profile is another command line, and Cargo
# rebuilds everything.
STORE=${PGO_PROFILE_STORE:-/tmp/zion-pgo}
case $STORE in /*) ;; *) fail "PGO_PROFILE_STORE ('$STORE') must be an absolute path: rustc runs in other directories" ;; esac
case $STORE in *[[:space:]]*) fail "PGO_PROFILE_STORE ('$STORE') contains whitespace" ;; esac
SUM=$(sha256sum "$OUT/zion.profdata" | cut -d' ' -f1)
[ ${#SUM} -eq 64 ] || fail "could not take the sha256 of $OUT/zion.profdata"
mkdir -p "$STORE"
[ -O "$STORE" ] || fail "$STORE belongs to another user: set PGO_PROFILE_STORE (it changes the bytes of the build)"
USE=$STORE/$SUM.profdata
[ -e "$USE" ] || cp "$OUT/zion.profdata" "$USE"
[ "$(sha256sum "$USE" | cut -d' ' -f1)" = "$SUM" ] || fail "$USE is not the profile its name says"
echo "      the compiler reads it from $USE"

echo "[4/4] optimised build"
# The zion crate is always compiled anew, so that its command line is in the log
# for the checks below even when cargo would find the last build still fresh.
cargo clean --release --target "$TARGET" -p zion >/dev/null 2>&1 || true
build "$OUT/build-use.log" "-Cprofile-use=$USE -Cllvm-args=-pgo-warn-missing-function"

# ── checks ───────────────────────────────────────────────────────────────────
RUSTC_LINE=$(rustc_line "$OUT/build-use.log")
[ -n "$RUSTC_LINE" ] || fail "no rustc command for the zion binary in $OUT/build-use.log"
if [ -s "$OUT/build-generate.log" ] && [ -z "${PGO_PROFDATA:-}" ]; then
  ID_USE=$(grep -o -E -- '-C metadata=[0-9a-f]+' <<<"$RUSTC_LINE" | head -1)
  ID_GENERATE=$(rustc_line "$OUT/build-generate.log" | grep -o -E -- '-C metadata=[0-9a-f]+' | head -1)
  [ -n "$ID_USE" ] && [ "$ID_USE" = "$ID_GENERATE" ] ||
    fail "the instrumented and the optimised build give the zion crate two identities ('$ID_GENERATE', '$ID_USE'): the profile names functions the optimised build does not have"
fi
grep -qF -- "-Cprofile-use=$USE" <<<"$RUSTC_LINE" || fail "the zion binary was not compiled with the profile"
CPU=$(grep -o -E -- '-C ?target-cpu=[A-Za-z0-9_.-]+' <<<"$RUSTC_LINE" | tail -1 | sed 's/.*=//' || true)
echo "      target-cpu of the zion crate: ${CPU:-<none: the compiler default>}"

MISSING=$(grep -c 'no profile data available for function' "$OUT/build-use.log" || true)
MISMATCH=$(grep -c -i -E 'hash mismatch|profile data may be out of date|control flow change detected' "$OUT/build-use.log" || true)
echo "      functions without profile data: $MISSING (at most $MAX_MISSING), stale-profile warnings: $MISMATCH (must be 0)"
[ "$MISMATCH" -eq 0 ] || fail "the profile does not match this source or compiler ($MISMATCH warnings): it was made from another build"
[ "$MISSING" -le "$MAX_MISSING" ] || fail "$MISSING functions have no profile data, more than $MAX_MISSING: the training no longer covers the code"

[ -x "$BIN" ] || fail "no binary at $BIN"
if [ -n "${PGO_MAX_GLIBC:-}" ]; then
  command -v objdump >/dev/null || fail "PGO_MAX_GLIBC is set and objdump is not installed"
  GLIBC=$(objdump -T "$BIN" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1)
  echo "      highest glibc symbol version needed: ${GLIBC:-none} (at most $PGO_MAX_GLIBC)"
  [ -n "$GLIBC" ] || fail "no glibc symbol versions in $BIN: is it a glibc binary?"
  [ "$(printf '%s\n%s\n' "$GLIBC" "$PGO_MAX_GLIBC" | sort -V | tail -1)" = "$PGO_MAX_GLIBC" ] ||
    fail "$BIN needs glibc $GLIBC, above the $PGO_MAX_GLIBC floor of the plain artefact"
fi

# The binary that will ship, through everything the training asks of it: about 1.2 million
# requests on every trained path, each phase checked for completion and status.
if [ "${PGO_VERIFY:-$([ -n "${PGO_PROFDATA:-}" ] && echo 0 || echo 1)}" = 1 ]; then
  echo "[+] the optimised binary, through the training workload"
  rm -rf "$OUT/verify"
  ZION_BIN="$BIN" PGO_PROFILE_DIR="$OUT/verify" PGO_TRAIN_EXPECT_PROFILE=0 bash scripts/pgo-train.sh ||
    fail "the optimised binary does not get through the training workload"
fi

# The whole test suite, compiled with the same profile: an optimisation that the
# profile enables and that breaks behaviour shows here, not in production. Its own
# target directory, so the test build never replaces the binary above.
if [ "${PGO_TEST:-0}" = 1 ]; then
  echo "[+] the test suite, compiled with the profile"
  # shellcheck disable=SC2086  # the test command has arguments
  env "$FLAGS_VAR=${BASE_FLAGS:+$BASE_FLAGS }-Cprofile-use=$USE" CARGO_TARGET_DIR="$OUT/test-target" CARGO_TERM_COLOR=never \
    ${PGO_CARGO_TEST:-cargo test} --release --locked --no-fail-fast --target "$TARGET" >"$OUT/test.log" 2>&1 || {
    grep -E 'FAILED|panicked|^error|^test result' "$OUT/test.log" | tail -30 >&2
    fail "the tests fail when compiled with the profile, full log in $OUT/test.log"
  }
  awk '/^test result/ {p += $4; f += $6} END {printf "      tests: %d passed, %d failed\n", p, f}' "$OUT/test.log"
fi

[ "$(sha256sum "$USE" | cut -d' ' -f1)" = "$SUM" ] || fail "$USE changed while the build was reading it"
echo "ok: $BIN ($(wc -c <"$BIN" | tr -d ' ') bytes), profile in $OUT/zion.profdata (sha256 $SUM)"

#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Does this zion binary run on the oldest processor of its architecture?
#
#   scripts/cpu-baseline-smoke.sh path/to/zion
#
# A binary compiled with `-C target-cpu=...` runs where it was built and stops
# with an illegal instruction on an older processor, before it can print a
# word. Two checks, and a control for the second:
#
#   1. Declared. `zion bootstrap` prints the target and the CPU features the
#      compiler was allowed to assume (build.rs stamps them). They must be the
#      compiler's defaults for that target: no -C target-cpu, no
#      -C target-feature.
#   2. Executed (Linux binaries). Under an emulated processor with the
#      architecture's baseline and nothing later, the binary starts and
#      answers: TLS, HTTP/1.1 and HTTP/2, a file from disk, a proxied and a
#      cached response, a body through the WAF, a request the WAF refuses.
#      This also covers what check 1 cannot see: the C and assembly of the
#      dependencies, and code that picks an implementation at run time.
#   control. A program of one AVX2 instruction (one LSE instruction on ARM)
#      must stop with an illegal instruction under that emulated processor and
#      run under a newer one. An emulator that let it through would make
#      check 2 pass for any binary.
#
#   SMOKE_MODE     emulate  checks 1 and 2 and the control (the default)
#                  declare  check 1 only, run natively (macOS, Windows: there is
#                           no emulator to run those binaries on an old CPU)
#                  native   checks 1 and 2 without an emulator (to try the
#                           script; proves nothing about older processors)
#   SMOKE_CPU      the emulated processor (default: Opteron_G1 for x86-64, which
#                  is SSE2 and nothing later; cortex-a53 for aarch64, ARMv8.0)
#   SMOKE_NEWER_CPU  the processor the control must run on (Haswell, neoverse-n1)
#   SMOKE_RUSTC    the compiler asked for the target's defaults (default rustc;
#                  use the one that built the binary)
#   SMOKE_CC       C compiler for the control program, for the binary's
#                  architecture (default: cc when the host is that architecture,
#                  else `zig cc`, else the Debian cross gcc)
#   SMOKE_SYSROOT  libraries for a dynamically linked binary of another
#                  architecture (default /usr/<arch>-linux-gnu, when it exists)
#
# Needs: curl, openssl, python3; in emulate mode qemu-user and a C compiler.

set -euo pipefail

fail() {
  echo "cpu-baseline-smoke: $*" >&2
  exit 1
}

[ $# -eq 1 ] || fail "usage: $0 path/to/zion"
BIN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[ -x "$BIN" ] || fail "$BIN is not an executable"
MODE=${SMOKE_MODE:-emulate}
RUSTC=${SMOKE_RUSTC:-rustc}

W=$(mktemp -d "${TMPDIR:-/tmp}/cpu-smoke-XXXXXX")
ZP=""
OP=""
cleanup() {
  set +e
  [ -n "$ZP" ] && kill "$ZP" 2>/dev/null
  [ -n "$OP" ] && kill "$OP" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# ── how the binary is run ────────────────────────────────────────────────────
RUN=() # the emulator and its arguments; empty when run natively (bash 3.2 needs the ${RUN[@]+...} form)
if [ "$MODE" = emulate ]; then
  # e_machine, two bytes at offset 18 of the ELF header.
  case "$(od -An -tx1 -j18 -N2 "$BIN" | tr -d ' \n')" in
    3e00) ARCH=x86_64 CPU=${SMOKE_CPU:-Opteron_G1} NEWER=${SMOKE_NEWER_CPU:-Haswell} ;;
    b700) ARCH=aarch64 CPU=${SMOKE_CPU:-cortex-a53} NEWER=${SMOKE_NEWER_CPU:-neoverse-n1} ;;
    *) fail "$BIN is not an x86-64 or aarch64 ELF binary (SMOKE_MODE=declare checks the others)" ;;
  esac
  QEMU=qemu-$ARCH
  command -v "$QEMU" >/dev/null || fail "$QEMU is not installed (Debian/Ubuntu: qemu-user)"
  EMU=("$QEMU")
  SYSROOT=${SMOKE_SYSROOT:-/usr/$ARCH-linux-gnu}
  if [ "$(uname -m)" != "$ARCH" ] && [ -d "$SYSROOT" ]; then
    EMU+=(-L "$SYSROOT")
  fi
  RUN=("${EMU[@]}" -cpu "$CPU")
  echo "cpu-baseline-smoke: $BIN ($ARCH) under $("$QEMU" --version | head -1), -cpu $CPU"
elif [ "$MODE" = declare ] || [ "$MODE" = native ]; then
  echo "cpu-baseline-smoke: $BIN, run natively (SMOKE_MODE=$MODE)"
else
  fail "SMOKE_MODE is '$MODE': emulate, declare or native"
fi

# ── control: the emulated processor refuses what it must refuse ──────────────
if [ "$MODE" = emulate ]; then
  if [ "$ARCH" = x86_64 ]; then
    WHAT="an AVX2 instruction"
    CFLAGS=(-mavx2)
    cat >"$W/control.c" <<'C'
int main(void) {
  __asm__ volatile("vpxor %ymm0, %ymm0, %ymm0");
  return 0;
}
C
  else
    WHAT="an LSE instruction"
    CFLAGS=(-march=armv8.1-a)
    cat >"$W/control.c" <<'C'
int main(void) {
  unsigned cell = 0, expected = 0, wanted = 1;
  __asm__ volatile("casal %w[e], %w[n], [%[p]]"
                   : [e] "+r"(expected)
                   : [n] "r"(wanted), [p] "r"(&cell)
                   : "memory");
  return cell == 1 ? 0 : 3;
}
C
  fi
  if [ -n "${SMOKE_CC:-}" ]; then
    read -r -a CC <<<"$SMOKE_CC"
  elif [ "$(uname -m)" = "$ARCH" ]; then
    CC=(cc)
  elif command -v zig >/dev/null; then
    CC=(zig cc -target "$ARCH-linux-musl")
  else
    CC=("$ARCH-linux-gnu-gcc")
  fi
  "${CC[@]}" -static -O0 "${CFLAGS[@]}" -o "$W/control" "$W/control.c" 2>"$W/control.err" ||
    { cat "$W/control.err" >&2; fail "could not compile the control program with '${CC[*]}'"; }
  set +e
  "${EMU[@]}" -cpu "$CPU" "$W/control" >/dev/null 2>&1
  OLD=$?
  "${EMU[@]}" -cpu "$NEWER" "$W/control" >/dev/null 2>&1
  NEW=$?
  set -e
  # 132 = 128 + SIGILL.
  [ "$OLD" -eq 132 ] || fail "control: $WHAT under -cpu $CPU ended with status $OLD, expected 132 (illegal instruction). This emulator does not enforce the processor model: the check would pass for any binary."
  [ "$NEW" -eq 0 ] || fail "control: $WHAT under -cpu $NEWER ended with status $NEW, expected 0. The control program is broken, not refused."
  echo "  control: $WHAT stops under -cpu $CPU (status 132) and runs under -cpu $NEWER"
fi

# ── check 1: what the binary says it was built for ───────────────────────────
# `bootstrap` also times AES-GCM for a moment: without AES instructions that is the
# portable implementation, which the daemon below would otherwise not run for long.
set +e
${RUN[@]+"${RUN[@]}"} "$BIN" bootstrap >"$W/bootstrap.json" 2>"$W/bootstrap.err"
RC=$?
set -e
[ "$RC" -eq 0 ] || {
  tail -3 "$W/bootstrap.err" >&2
  fail "\`zion bootstrap\` ended with status $RC$([ "$RC" -eq 132 ] && echo " (illegal instruction): the binary needs a newer processor than ${CPU:-this one}")"
}
TARGET=$(sed -n 's/.*"build_target":"\([^"]*\)".*/\1/p' "$W/bootstrap.json")
DECLARED=$(sed -n 's/.*"build_target_features":\[\([^]]*\)\].*/\1/p' "$W/bootstrap.json" | tr -d '" ' | tr ',' '\n' |
  grep -vx -e crt-static -e '' | LC_ALL=C sort | paste -sd, -) || true
[ -n "$TARGET" ] && [ -n "$DECLARED" ] ||
  fail "\`zion bootstrap\` printed no build_target / build_target_features (a build older than this check?)"
DEFAULTS=$("$RUSTC" --print cfg --target "$TARGET" 2>"$W/rustc.err" | sed -n 's/^target_feature="\(.*\)"$/\1/p' |
  grep -vx crt-static | LC_ALL=C sort | paste -sd, -) || true
[ -n "$DEFAULTS" ] || {
  cat "$W/rustc.err" >&2
  fail "'$RUSTC --print cfg --target $TARGET' printed no target features"
}
echo "  built for $TARGET with: $DECLARED"
if [ "$DECLARED" != "$DEFAULTS" ]; then
  echo "  the compiler's default:  $DEFAULTS ($("$RUSTC" --version))" >&2
  fail "the binary was compiled for more than the baseline of $TARGET (a -C target-cpu or -C target-feature reached the build)"
fi
echo "  declared: the defaults of $TARGET, nothing added ($("$RUSTC" --version | cut -d' ' -f1-2))"
[ "$MODE" != declare ] || {
  echo "ok: built for the baseline of $TARGET (declared; not executed on an older processor)"
  exit 0
}

# ── check 2: it serves ───────────────────────────────────────────────────────
for tool in curl openssl python3; do
  command -v "$tool" >/dev/null || fail "$tool is not installed"
done
HTTPS=${SMOKE_HTTPS_PORT:-24431}
HTTP=${SMOKE_HTTP_PORT:-28081}
BACK=${SMOKE_ORIGIN_PORT:-29090}
U="https://127.0.0.1:$HTTPS"

mkdir -p "$W/www"
head -c 150000 /dev/urandom >"$W/www/app.bin"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$W/key.pem" -out "$W/cert.pem" >/dev/null 2>&1
echo '{"user":"alice","items":[1,2,3,4,5],"note":"an ordinary sentence with a few words","ok":true}' >"$W/body.json"

# The origin: answers GET with a fixed body (cacheable under /static/), echoes a POST.
cat >"$W/origin.py" <<'PY'
import http.server
import sys


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        if self.path.startswith("/static/"):
            self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(b"origin says hello\n" * 200)

    def do_POST(self):
        self.reply(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Origin).serve_forever()
PY
python3 "$W/origin.py" "$BACK" &
OP=$!

cat >"$W/zion.toml" <<EOF
[server]
listen_http  = "127.0.0.1:$HTTP"
listen_https = "127.0.0.1:$HTTPS"

[tls]
cert_path  = "$W/cert.pem"
key_path   = "$W/key.pem"
hot_reload = false

[waf_profile.standard]
max_body_mb = 10

[upstreams]
origin = "http://127.0.0.1:$BACK"

[cache_profile.site]
mode = "memory"
max_entries = 1000
ttl_seconds = 3600

[[route]]
path = "/static/{*rest}"
upstream = "origin"
mode = "static_cache"
cache_profile = "site"
waf = false

[[route]]
path = "/w/{*rest}"
upstream = "origin"
mode = "standard"
waf_profile = "standard"

[[route]]
path = "/files/{*rest}"
mode = "static"
serve_dir = "$W/www"

[[route]]
path = "/{*rest}"
upstream = "origin"
mode = "standard"
waf = false
EOF

ZION_BOOT_FAST=1 ZION_CONFIG="$W/zion.toml" ${RUN[@]+"${RUN[@]}"} "$BIN" >"$W/zion.log" 2>&1 &
ZP=$!
READY=0
for _ in $(seq 1 240); do # an emulated start takes seconds
  if curl -ksf -m 5 "$U/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  kill -0 "$ZP" 2>/dev/null || break
  sleep 0.25
done
if [ "$READY" -ne 1 ]; then
  set +e
  wait "$ZP"
  RC=$?
  ZP=""
  tail -15 "$W/zion.log" >&2
  fail "zion did not come up (status $RC$([ "$RC" -eq 132 ] && echo ", illegal instruction"))"
fi

FAILED=0
expect() { # label, expected "status/bytes/http-version" (a part may be "any"), curl arguments...
  local label=$1 want=$2 got w g i ok=1
  shift 2
  got=$(curl -sk -m 60 -o "$W/out" -w '%{http_code}/%{size_download}/%{http_version}' "$@" 2>/dev/null) || got="000/0/none"
  IFS=/ read -r -a w <<<"$want"
  IFS=/ read -r -a g <<<"$got"
  for i in 0 1 2; do
    [ "${w[$i]}" = any ] || [ "${w[$i]}" = "${g[$i]:-}" ] || ok=0
  done
  if [ "$ok" -eq 1 ]; then
    printf '  %-34s %s\n' "$label" "$got"
  else
    printf '  %-34s %s   EXPECTED %s\n' "$label" "$got" "$want"
    FAILED=1
  fi
}
expect "health" "200/any/any" "$U/healthz"
expect "file from disk, HTTP/1.1" "200/150000/1.1" --http1.1 "$U/files/app.bin"
expect "file from disk, HTTP/2" "200/150000/2" --http2 "$U/files/app.bin"
cmp -s "$W/out" "$W/www/app.bin" || {
  echo "  the file served over HTTP/2 is not the file on disk"
  FAILED=1
}
expect "file, a range" "206/1024/any" -H "range: bytes=1000-2023" "$U/files/app.bin"
expect "proxied, HTTP/1.1" "200/3600/1.1" --http1.1 "$U/api/data"
expect "proxied, HTTP/2" "200/3600/2" --http2 "$U/api/data"
expect "cached, first request" "200/3600/any" "$U/static/a.css"
expect "cached, second request" "200/3600/any" "$U/static/a.css"
expect "POST body through the WAF" "200/$(wc -c <"$W/body.json" | tr -d ' ')/any" -H "content-type: application/json" --data-binary "@$W/body.json" "$U/w/echo"
expect "a URI the WAF refuses" "400/any/any" "$U/w/data?q=%3Cscript%3Ealert(1)%3C/script%3E"
# shellcheck disable=SC2016
expect "a body the WAF refuses" "400/any/any" -H "content-type: application/json" -d '{"q":"${jndi:ldap://x/a}"}' "$U/w/echo"
expect "plain HTTP" "301/any/1.1" "http://127.0.0.1:$HTTP/"
expect "metrics" "200/any/any" "$U/metrics"

if ! kill -0 "$ZP" 2>/dev/null; then
  set +e
  wait "$ZP"
  RC=$?
  ZP=""
  tail -15 "$W/zion.log" >&2
  fail "zion ended while serving (status $RC$([ "$RC" -eq 132 ] && echo ", illegal instruction"))"
fi
kill "$ZP"
set +e
wait "$ZP"
RC=$?
set -e
ZP=""
[ "$RC" -eq 0 ] || {
  tail -15 "$W/zion.log" >&2
  fail "zion ended with status $RC after SIGTERM, expected a clean stop"
}
[ "$FAILED" -eq 0 ] || {
  tail -15 "$W/zion.log" >&2
  fail "a request did not get the expected answer"
}
if [ "$MODE" = emulate ]; then
  echo "ok: built for the baseline of $TARGET, and it serves under -cpu $CPU"
else
  echo "ok: built for the baseline of $TARGET, and it serves (natively: says nothing about older processors)"
fi

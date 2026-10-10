#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# PGO training workload (issue #55): drives an instrumented zion (built with
# -Cprofile-generate) through the paths a deployment uses and leaves the
# *.profraw files in $PGO_PROFILE_DIR for scripts/pgo-build.sh to merge.
#
#   ZION_BIN          the instrumented binary (required)
#   PGO_PROFILE_DIR   where the profraw files go (required)
#   PGO_TRAIN_PHASE_SECONDS      the longest one load phase may take (default
#                     300; a phase takes seconds). A phase that runs out of
#                     time fails the script, after printing where it is stuck.
#   PGO_TRAIN_EXPECT_PROFILE=0   the binary is not instrumented: run the same
#                     workload with the same checks and expect no profile
#                     (scripts/pgo-build.sh does this to the optimised binary)
#
# What is trained, and why it is shaped this way:
#   * Request COUNTS, not durations: a slow runner trains the same profile as a
#     fast one, only later.
#   * Two zion instances: access log on with an ECDSA certificate (the default
#     deployment), then access log off with an RSA certificate, so both sides
#     of those branches carry counts.
#   * HTTP/1.1 and HTTP/2, cache hits, proxied requests, files from disk
#     (whole, 304, Range), full TLS handshakes, POST bodies through the WAF and
#     past it, requests the WAF refuses, error paths, health and metrics.
#   * Every load phase is checked: a phase that did not complete its requests
#     fails the script. An undertrained profile must not ship.
#
# Needs: h2load (nghttp2-client), curl, openssl, python3, go.

set -euo pipefail
cd "$(dirname "$0")/.."

: "${ZION_BIN:?set ZION_BIN to the instrumented binary}"
: "${PGO_PROFILE_DIR:?set PGO_PROFILE_DIR to the profraw output directory}"
for tool in h2load curl openssl python3 go; do
  command -v "$tool" >/dev/null || { echo "pgo-train: $tool is not installed"; exit 1; }
done
ZION_BIN=$(cd "$(dirname "$ZION_BIN")" && pwd)/$(basename "$ZION_BIN")
mkdir -p "$PGO_PROFILE_DIR"
PGO_PROFILE_DIR=$(cd "$PGO_PROFILE_DIR" && pwd)

PHASE_SECONDS=${PGO_TRAIN_PHASE_SECONDS:-300}
HTTPS=4431
HTTP=8081
BACK=9090 # benchmarks/backend/test-server.go listens here
W=$(mktemp -d "${TMPDIR:-/tmp}/pgo-train-XXXXXX")
mkdir -p "$W/www"
ZP=""
BP=""
cleanup() {
  set +e
  [ -n "$ZP" ] && kill "$ZP" 2>/dev/null
  [ -n "$BP" ] && kill "$BP" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT

# ── backend ──────────────────────────────────────────────────────────────────
# Built first, then started: `go run` would compile in the background and lose
# the readiness race on a cold runner.
(cd benchmarks/backend && go build -o "$W/backend" test-server.go)
"$W/backend" >"$W/backend.log" 2>&1 &
BP=$!
for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:$BACK/api/v1/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:$BACK/api/v1/health" >/dev/null || {
  echo "pgo-train: the backend never became ready"
  cat "$W/backend.log"
  exit 1
}

# ── files for the static route: fixed bytes, mixed sizes ─────────────────────
python3 - "$W/www" <<'PY'
import hashlib
import sys

d = sys.argv[1]


def blob(n, tag):
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(f"{tag}{i}".encode()).digest()
        i += 1
    return bytes(out[:n])


for name, size in (("index.html", 4096), ("app.js", 200_000), ("style.css", 40_000), ("img.png", 150_000),
                   ("font.woff2", 40_000), ("data.json", 1_000), ("big.bin", 3_000_000)):
    with open(f"{d}/{name}", "wb") as f:
        f.write(blob(size, name))
PY

# ── certificates: ECDSA (the common case) and RSA ────────────────────────────
cert() { # basename, then the openssl key arguments
  local base=$1
  shift
  openssl req -x509 "$@" -nodes -days 2 -subj /CN=localhost \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" \
    -keyout "$W/$base.key" -out "$W/$base.crt" >/dev/null 2>&1
}
cert ecdsa -newkey ec -pkeyopt ec_paramgen_curve:prime256v1
cert rsa -newkey rsa:2048

cat >"$W/body.json" <<'J'
{"user":"alice","items":[1,2,3,4,5],"note":"an ordinary sentence with a few words","ok":true,"n":12345}
J

config() { # access log (true|false), certificate (ecdsa|rsa)
  cat >"$W/zion.toml" <<EOF
[server]
listen_http  = "127.0.0.1:$HTTP"
listen_https = "127.0.0.1:$HTTPS"

[tls]
cert_path  = "$W/$2.crt"
key_path   = "$W/$2.key"
hot_reload = false

[access_log]
enabled = $1

[waf_profile.standard]
max_body_mb = 10

[upstreams]
backend = "http://127.0.0.1:$BACK"
dead    = "http://127.0.0.1:9"

[cache_profile.site]
mode = "memory"
max_entries = 10000
ttl_seconds = 3600

[[route]]
path = "/_next/static/{*rest}"
upstream = "backend"
mode = "static_cache"
cache_profile = "site"
waf = false

[[route]]
path = "/w/{*rest}"
upstream = "backend"
mode = "standard"
waf_profile = "standard"

[[route]]
path = "/dead/{*rest}"
upstream = "dead"
mode = "standard"
waf = false

[[route]]
path = "/files/{*rest}"
mode = "static"
serve_dir = "$W/www"

[[route]]
path = "/{*rest}"
upstream = "backend"
mode = "standard"
waf = false
EOF
}

start_zion() { # access log, certificate
  config "$1" "$2"
  LLVM_PROFILE_FILE="$PGO_PROFILE_DIR/zion-%m-%p.profraw" ZION_BOOT_FAST=1 ZION_CONFIG="$W/zion.toml" \
    "$ZION_BIN" >"$W/zion.log" 2>&1 &
  ZP=$!
  for _ in $(seq 1 60); do
    curl -ksf "https://127.0.0.1:$HTTPS/api/v1/health" >/dev/null 2>&1 && return
    sleep 0.25
  done
  echo "pgo-train: zion never became ready"
  cat "$W/zion.log"
  exit 1
}

# SIGTERM, not SIGKILL: the profile is written as the process exits.
stop_zion() {
  kill "$ZP" 2>/dev/null || true
  wait "$ZP" 2>/dev/null || true
  ZP=""
}

U="https://127.0.0.1:$HTTPS"

# A phase ran out of time: say where the bytes are and what zion is doing, while it is still
# doing it. Everything here is best effort.
stuck() {
  set +e
  echo "---- sockets, zion's side (sport $HTTPS) then the load generator's (dport $HTTPS)"
  ss -tinmH "sport = :$HTTPS" 2>/dev/null | head -40
  ss -tinmH "dport = :$HTTPS" 2>/dev/null | head -40
  echo "---- zion's threads: state, CPU ticks (user, system), the system call each is in"
  for t in /proc/"$ZP"/task/*; do
    printf '  %-8s %-18s %s  syscall %s\n' "${t##*/}" "$(cat "$t/comm" 2>/dev/null)" \
      "$(awk '{print $3, $14, $15}' "$t/stat" 2>/dev/null)" "$(cut -d' ' -f1 "$t/syscall" 2>/dev/null)"
  done
  echo "---- does zion answer a new connection? (health, then its HTTP/2 counters)"
  curl -sk -m 5 -o /dev/null -w '  /healthz: %{http_code} in %{time_total} s\n' "$U/healthz"
  curl -sk -m 5 "$U/metrics" 2>/dev/null | grep -E '^zion_(h2|http2|connections|active|inflight|flood)' | head -30
  echo "---- zion's log, last lines"
  tail -30 "$W/zion.log" 2>/dev/null | cut -c1-300
  echo "----"
}

# One h2load phase. `ok`: at least 99 % of the requests must get a 2xx or 3xx.
# `any`: they must all complete, whatever the status (the phase is about an
# error path). Either way a phase that stalls or cannot connect fails the run.
load() { # ok|any, label, requests, h2load arguments...
  local expect=$1 label=$2 n=$3 out done_ codes good
  shift 3
  # In the background, so that a phase that stalls can be looked at while it is stalled.
  local started=$SECONDS
  h2load -n "$n" "$@" >"$W/load.out" 2>&1 &
  local lp=$! ticks=0
  while kill -0 "$lp" 2>/dev/null; do
    if [ "$ticks" -ge $((PHASE_SECONDS * 5)) ]; then
      echo "pgo-train: phase '$label' did not finish in $PHASE_SECONDS s; the load generator got to:"
      tail -3 "$W/load.out"
      stuck
      kill "$lp" 2>/dev/null
      exit 1
    fi
    sleep 0.2
    ticks=$((ticks + 1))
  done
  wait "$lp" 2>/dev/null || true
  out=$(cat "$W/load.out")
  # requests: N total, N started, N done, N succeeded, N failed, N errored, N timeout
  # status codes: N 2xx, N 3xx, N 4xx, N 5xx
  done_=$(sed -n 's/^requests: .* \([0-9][0-9]*\) done, .*/\1/p' <<<"$out")
  codes=$(sed -n 's/^status codes: //p' <<<"$out")
  good=$(awk '{print $1 + $3}' <<<"$codes")
  printf '  %-34s %7s requests  %7s done  %-34s %3d s\n' "$label" "$n" "${done_:-?}" "$codes" $((SECONDS - started))
  if [ -z "$done_" ] || [ "$done_" -lt $((n * 99 / 100)) ]; then
    echo "pgo-train: phase '$label' completed ${done_:-0} of $n requests"
    tail -8 <<<"$out"
    exit 1
  fi
  if [ "$expect" = ok ] && [ "${good:-0}" -lt $((n * 99 / 100)) ]; then
    echo "pgo-train: phase '$label' got ${good:-0} good responses out of $n"
    tail -8 <<<"$out"
    exit 1
  fi
}

phase_full() { # everything, access log on
  load ok "cache hit, HTTP/2" 150000 -c 16 -m 10 "$U/_next/static/manifest.json"
  load ok "cache hit, HTTP/1.1" 150000 -c 32 --h1 "$U/_next/static/style.css"
  load ok "proxy, HTTP/1.1" 80000 -c 32 --h1 "$U/api/v1/data"
  load ok "proxy, HTTP/2" 80000 -c 16 -m 10 "$U/api/v1/data/large"
  printf '%s\n' "$U/files/index.html" "$U/files/app.js" "$U/files/style.css" "$U/files/img.png" \
    "$U/files/font.woff2" "$U/files/data.json" >"$W/uris.txt"
  load ok "files, HTTP/1.1" 120000 -c 32 --h1 -i "$W/uris.txt"
  load ok "files, HTTP/2" 40000 -c 16 -m 10 -i "$W/uris.txt"
  local etag
  etag=$(curl -sk -D- -o /dev/null "$U/files/app.js" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r')
  [ -n "$etag" ] || { echo "pgo-train: the static route sent no ETag"; exit 1; }
  load ok "files, If-None-Match (304)" 60000 -c 32 --h1 -H "if-none-match: $etag" "$U/files/app.js"
  load ok "files, Range (206)" 60000 -c 32 --h1 -H "range: bytes=0-1023" "$U/files/img.png"
  load ok "files, 3 MB body" 600 -c 4 --h1 "$U/files/big.bin"
  load ok "full TLS handshakes" 15000 -c 16 --h1 -H "connection: close" "$U/api/v1/health"
  load ok "POST through the WAF" 50000 -c 16 --h1 -d "$W/body.json" -H "content-type: application/json" "$U/w/api/v1/echo"
  load ok "POST, HTTP/2, no WAF" 30000 -c 16 -m 10 -d "$W/body.json" -H "content-type: application/json" "$U/api/v1/users"
  local q
  for _ in $(seq 1 120); do # requests the WAF refuses
    for q in "q=%3Cscript%3Ealert(1)%3C/script%3E" "q=1%27%20OR%20%271%27%3D%271" "q=..%2F..%2Fetc%2Fpasswd" "q=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D"; do
      curl -sk -o /dev/null "$U/w/api/v1/data?$q"
    done
  done
  load ok "large proxied body" 400 -c 8 --h1 "$U/api/v1/large"
  load ok "cache fill, 1 MB objects" 2500 -c 8 --h1 "$U/_next/static/blob?bytes=1048576"
  load any "upstream 404" 15000 -c 16 --h1 "$U/api/v1/status/404"
  load any "upstream down (502)" 5000 -c 16 --h1 "$U/dead/x"
  local long
  long=$(head -c 9000 /dev/zero | tr '\0' a)
  for _ in $(seq 1 300); do # method not allowed, TRACE, an over-long query
    curl -sk -o /dev/null -X PATCH "$U/files/index.html"
    curl -sk -o /dev/null -X TRACE "$U/api/v1/data"
    curl -sk -o /dev/null "$U/api/v1/data?$long"
  done
  load ok "health" 20000 -c 16 --h1 "$U/healthz"
  for _ in $(seq 1 400); do curl -sk -o /dev/null "$U/metrics"; done
  for _ in 1 2 3 4 5; do curl -sk -o /dev/null --max-time 2 "$U/api/v1/events/stream" || true; done
}

phase_light() { # the same hot paths with the access log off: the other side of those branches
  load ok "cache hit, HTTP/2" 100000 -c 16 -m 10 "$U/_next/static/manifest.json"
  load ok "cache hit, HTTP/1.1" 100000 -c 32 --h1 "$U/_next/static/style.css"
  load ok "proxy, HTTP/1.1" 60000 -c 32 --h1 "$U/api/v1/data"
  load ok "files, HTTP/1.1" 80000 -c 32 --h1 -i "$W/uris.txt"
  load ok "full TLS handshakes" 8000 -c 16 --h1 -H "connection: close" "$U/api/v1/health"
}

T0=$(date +%s)
echo "[1/2] access log on, ECDSA certificate"
start_zion true ecdsa
phase_full
stop_zion
echo "[2/2] access log off, RSA certificate"
start_zion false rsa
phase_light
stop_zion

PROFCOUNT=$(find "$PGO_PROFILE_DIR" -name '*.profraw' | wc -l | tr -d ' ')
if [ "${PGO_TRAIN_EXPECT_PROFILE:-1}" = 0 ]; then
  echo "ok: every phase completed, $(($(date +%s) - T0)) s"
  exit 0
fi
if [ "$PROFCOUNT" -lt 2 ]; then
  echo "pgo-train: $PROFCOUNT profraw files in $PGO_PROFILE_DIR, expected one per zion instance (was the binary built with -Cprofile-generate?)"
  exit 1
fi
echo "ok: $PROFCOUNT profraw files, $(($(date +%s) - T0)) s"

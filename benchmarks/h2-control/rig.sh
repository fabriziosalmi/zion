#!/usr/bin/env bash
# What do real HTTP/2 clients send zion, in control frames per second? (#475, #561)
#
#   ZION=target/release/zion benchmarks/h2-control/rig.sh grpc      # grpc-go, four shapes
#   ZION=target/release/zion benchmarks/h2-control/rig.sh browser   # you drive a browser
#
# It builds a Go backend (a web page of 120 small resources, a 300 MiB download, and a
# gRPC service, all over TLS and HTTP/2), starts it and a FRESH zion for every scenario
# (the peak is "most since start"), and prints `zion_h2_control_frames_peak` afterwards.
# Needs: go, openssl, curl, and a zion binary (ZION=, default target/release/zion).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ZION="${ZION:-$here/../../target/release/zion}"
[[ -x "$ZION" ]] || { echo "no zion binary at $ZION (set ZION=)" >&2; exit 2; }
work="$(mktemp -d)"
BACKEND=0 ZP=0
cleanup() {
  for p in $ZP $BACKEND; do [[ $p -gt 0 ]] && kill "$p" 2>/dev/null && wait "$p" 2>/dev/null; done
  rm -rf "$work"; true
}
trap cleanup EXIT

(cd "$here" && go build -o "$work/backend" ./cmd/backend && go build -o "$work/client" ./cmd/client)
# A leaf certificate, not a CA: OpenSSL 3 makes a self-signed one a CA by default, which
# rustls refuses as a server certificate.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$work/k.pem" -out "$work/c.pem" 2>/dev/null
cat > "$work/zion.toml" <<TOML
[server]
listen_http = "127.0.0.1:18080"
listen_https = "127.0.0.1:18443"
[tls]
cert_path = "$work/c.pem"
key_path = "$work/k.pem"
hot_reload = false
[upstream.web]
url = "https://localhost:19444"
ca_path = "$work/c.pem"
[[route]]
path = "/{*rest}"
upstream = "web"
TOML
"$work/backend" "$work/c.pem" "$work/k.pem" >"$work/backend.log" 2>&1 &
BACKEND=$!
sleep 1

fresh_zion() {
  [[ $ZP -gt 0 ]] && { kill "$ZP" 2>/dev/null; wait "$ZP" 2>/dev/null; }; sleep 0.4
  ZION_CONFIG="$work/zion.toml" ZION_BOOT_FAST=1 "$ZION" >"$work/zion.log" 2>&1 &
  ZP=$!
  for _ in $(seq 1 50); do curl -sk https://127.0.0.1:18443/healthz >/dev/null 2>&1 && return; sleep 0.2; done
  echo "zion did not start:"; tail -5 "$work/zion.log"; exit 1
}
peak() { curl -sk https://127.0.0.1:18443/metrics | awk '/^zion_h2_control_frames_peak/{print $2}'; }

case "${1:-}" in
  grpc)
    # label | grpc-go client mode and size
    for sc in "download 1000" "small 200" "unary 20000" "chat 5000"; do
      fresh_zion
      # shellcheck disable=SC2086
      out="$("$work/client" 127.0.0.1:18443 $sc 2>&1 | tail -1)"
      printf '%-14s %-52s peak=%s\n' "${sc%% *}" "$out" "$(peak)"
    done
    ;;
  browser)
    fresh_zion
    cat <<MSG
zion and the backend are up. In the browser (accept the self-signed certificate):

  1. page load      https://127.0.0.1:18443/            (reload it a few times)
  2. big download   https://127.0.0.1:18443/big         (300 MiB; let it finish or cancel it)
  3. leave mid-load open the page and navigate away at once; repeat a few times

Press Enter when done to read the peak.
MSG
    read -r _
    echo "zion_h2_control_frames_peak = $(peak)"
    ;;
  *)
    echo "usage: ZION=... $0 grpc|browser" >&2; exit 2 ;;
esac

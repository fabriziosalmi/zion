#!/usr/bin/env bash
# Generate a self-signed TLS cert + key for benchmarks (CN=bench.local).
# These artifacts are NOT tracked in git — see .gitignore.
# Run from repo root: bash benchmarks/certs/generate.sh
set -euo pipefail

cd "$(dirname "$0")"

if [ -f tls.key ] && [ -f tls.crt ]; then
  echo "tls.key and tls.crt already exist — skipping (delete first to regenerate)"
  exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tls.key \
  -out tls.crt \
  -days 365 \
  -subj "/CN=bench.local" \
  -addext "subjectAltName=DNS:bench.local,DNS:localhost,IP:127.0.0.1"

chmod 600 tls.key
echo "Generated: tls.crt + tls.key (CN=bench.local, valid 365 days)"

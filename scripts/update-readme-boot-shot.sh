#!/usr/bin/env bash
# Regenerate docs/img/boot.png — the README hero screenshot — from the REAL
# binary, so the image can never show a stale version again. The capture is
# scripted (docs/img/boot.tape, rendered by `vhs`): build the release binary,
# mint a throwaway self-signed cert, boot a minimal config, screenshot the
# banner. Run after bump-version.sh so the version in the shot is the
# released one (bump-version's next-steps list says so).
#
# Requires: vhs (https://github.com/charmbracelet/vhs), openssl.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

command -v vhs >/dev/null || { echo "FATAL: vhs not installed (brew install vhs)" >&2; exit 1; }

echo "building release binary..."
cargo build --release --quiet

# Fixed paths — referenced by docs/img/boot.tape.
DIR=/tmp/zion-boot-shot
rm -rf "$DIR" && mkdir -p "$DIR"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=boot-shot.local" >/dev/null 2>&1
cat > "$DIR/zion.toml" <<'EOF'
[server]
listen_http  = "127.0.0.1:18080"
listen_https = "127.0.0.1:18443"
[tls]
cert_path = "/tmp/zion-boot-shot/cert.pem"
key_path  = "/tmp/zion-boot-shot/key.pem"
[upstreams]
app = "http://127.0.0.1:18080"  # zion's own HTTP listener — probe answers, upstream shows healthy
[[route]]
path = "/{*rest}"
upstream = "app"
EOF

vhs docs/img/boot.tape
rm -rf "$DIR"

test -s docs/img/boot.png || { echo "FATAL: boot.png not produced" >&2; exit 1; }
echo "docs/img/boot.png regenerated from $(./target/release/zion --version 2>/dev/null || echo 'the freshly built binary')."

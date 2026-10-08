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

for tool in vhs openssl; do
  command -v "$tool" >/dev/null || {
    echo "FATAL: $tool not installed — see https://github.com/charmbracelet/vhs#installation for vhs" >&2
    exit 1
  }
done

echo "building release binary..."
cargo build --release --quiet

# Fixed paths — referenced by docs/img/boot.tape.
DIR=/tmp/zion-boot-shot
rm -rf "$DIR" && mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 \
  -keyout "$DIR/key.pem" -out "$DIR/cert.pem" \
  -days 1 -nodes -subj "/CN=boot-shot.local" \
  -addext "subjectAltName=DNS:boot-shot.local" >/dev/null 2>&1
# RSA and -addext, like every other script here: with `-newkey ec -pkeyopt ...` and no
# extension, LibreSSL (the macOS openssl) wrote a key zion could not pair with the
# certificate, and an X.509 v1 certificate; the screenshot then showed a fatal error
# instead of the boot. Check the image after running this.
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

# Delete the old image first, so that "the file exists" afterwards proves vhs wrote it. Before this,
# the only check was `test -s`, which a stale image passes: on 2026-10-07 the script reported
# success on v0.9.14 and left the v0.9.13 screenshot in place (#602). Put the old one back if vhs
# fails, so a failed run leaves the tree as it found it.
SHOT=docs/img/boot.png
OLD_SHOT=""
if [ -f "$SHOT" ]; then
  OLD_SHOT=$(mktemp)
  mv "$SHOT" "$OLD_SHOT"
fi
restore() { [ -n "$OLD_SHOT" ] && [ -f "$OLD_SHOT" ] && [ ! -s "$SHOT" ] && mv "$OLD_SHOT" "$SHOT"; return 0; }
trap restore EXIT

vhs docs/img/boot.tape
rm -rf "$DIR"

test -s "$SHOT" || { echo "FATAL: vhs did not produce $SHOT" >&2; exit 1; }

# An image byte-identical to the committed one, while the version it should show is not the
# committed one, was not redrawn from this binary. A rerun with nothing to change is fine
# (ZION_BOOT_SHOT_ALLOW_UNCHANGED=1).
committed_version=$(git show HEAD:Cargo.toml 2>/dev/null | awk -F'"' '/^version[[:space:]]*=/ {print $2; exit}')
current_version=$(awk -F'"' '/^version[[:space:]]*=/ {print $2; exit}' Cargo.toml)
if [ -n "$OLD_SHOT" ] && [ "$committed_version" != "$current_version" ] \
   && [ "${ZION_BOOT_SHOT_ALLOW_UNCHANGED:-0}" != "1" ] \
   && [ "$(shasum -a 256 < "$SHOT")" = "$(git show HEAD:"$SHOT" 2>/dev/null | shasum -a 256)" ]; then
  echo "FATAL: $SHOT is identical to the committed one, but the version went from $committed_version to $current_version: it was not redrawn" >&2
  exit 1
fi
[ -n "$OLD_SHOT" ] && rm -f "$OLD_SHOT"
echo "$SHOT regenerated from $(./target/release/zion --version 2>/dev/null || echo 'the freshly built binary')."

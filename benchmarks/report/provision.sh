#!/usr/bin/env bash
# Provision the benchmark box (Ubuntu 24.04, the ci-zion LXC) with the exact tools
# the release report uses. Idempotent: running it twice changes nothing. Run as the
# unprivileged `ci` user; it uses sudo only for apt. Everything that is not an apt
# package lands under $TOOLS, so the box can be rebuilt from this file alone.
#
# Every version below is a pin. Changing one changes what a report means: say so in
# the commit, and re-run the previous release on the new tool set before comparing.
set -euo pipefail

TOOLS="${TOOLS:-/opt/zion-bench}"
OHA_VERSION="1.16.0"
H2SPEC_VERSION="2.6.0"
H2SPEC_SHA256="${H2SPEC_SHA256:-157ee0de702e01ad40e752dbf074b366027e550c8e7504f9450da2809e279318}"
CACHE_TESTS_COMMIT="d644cf4bf487763646aac19d2c8b846daa0f604d"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\033[1;36m▶ %s\033[0m\n' "$*"; }

sudo install -d -o "$(id -un)" -g "$(id -gn)" "$TOOLS" "$TOOLS/bin"

say "apt packages"
# wrk, nginx and the pango stack WeasyPrint needs. nginx is the origin and the
# comparison proxy; it must never run as a system service on this box.
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  wrk nginx nghttp2-client python3-venv python3-pip libpango-1.0-0 libpangoft2-1.0-0 \
  fonts-dejavu-core jq util-linux >/dev/null
sudo systemctl disable --now nginx >/dev/null 2>&1 || true

say "oha $OHA_VERSION"
if ! "$TOOLS/bin/oha" --version 2>/dev/null | grep -q "$OHA_VERSION"; then
  # shellcheck source=/dev/null
  . "$HOME/.cargo/env"
  cargo install --locked --version "$OHA_VERSION" --root "$TOOLS" oha
fi

say "h2spec $H2SPEC_VERSION"
if ! "$TOOLS/bin/h2spec" --version 2>/dev/null | grep -q "$H2SPEC_VERSION"; then
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/h2spec.tgz" \
    "https://github.com/summerwind/h2spec/releases/download/v${H2SPEC_VERSION}/h2spec_linux_amd64.tar.gz"
  got="$(sha256sum "$tmp/h2spec.tgz" | cut -d' ' -f1)"
  if [ -z "$H2SPEC_SHA256" ]; then
    echo "h2spec sha256 not pinned yet; downloaded archive is $got" >&2
    echo "pin it: H2SPEC_SHA256=$got" >&2
    exit 3
  fi
  [ "$got" = "$H2SPEC_SHA256" ] || { echo "h2spec sha256 mismatch: $got" >&2; exit 3; }
  tar -xzf "$tmp/h2spec.tgz" -C "$TOOLS/bin" h2spec
  rm -rf "$tmp"
fi

say "cache-tests @ ${CACHE_TESTS_COMMIT:0:12} (RFC 9111)"
if [ ! -d "$TOOLS/cache-tests/.git" ]; then
  git clone --quiet https://github.com/http-tests/cache-tests "$TOOLS/cache-tests"
fi
git -C "$TOOLS/cache-tests" fetch --quiet origin
git -C "$TOOLS/cache-tests" checkout --quiet "$CACHE_TESTS_COMMIT"
# cache-tests ships no lockfile, so its dependencies would float. Ours is tracked.
if [ -f "$HERE/cache-tests.package-lock.json" ]; then
  cp "$HERE/cache-tests.package-lock.json" "$TOOLS/cache-tests/package-lock.json"
  ( cd "$TOOLS/cache-tests" && npm ci --omit=dev --silent --no-audit --no-fund )
else
  ( cd "$TOOLS/cache-tests" && npm install --omit=dev --silent --no-audit --no-fund )
  cp "$TOOLS/cache-tests/package-lock.json" "$HERE/cache-tests.package-lock.json"
  echo "wrote $HERE/cache-tests.package-lock.json (review, then commit)" >&2
fi

say "python venv (matplotlib, weasyprint)"
if [ ! -x "$TOOLS/venv/bin/python" ]; then python3 -m venv "$TOOLS/venv"; fi
if [ -f "$HERE/requirements.lock" ]; then
  "$TOOLS/venv/bin/pip" install --quiet -r "$HERE/requirements.lock"
else
  "$TOOLS/venv/bin/pip" install --quiet matplotlib weasyprint
  "$TOOLS/venv/bin/pip" freeze > "$HERE/requirements.lock"
  echo "wrote $HERE/requirements.lock (review, then commit)" >&2
fi

say "tools.lock"
{
  echo "wrk=$(wrk --version 2>&1 | head -1)"
  echo "h2load=$(h2load --version 2>&1 | head -1)"
  echo "oha=$("$TOOLS/bin/oha" --version 2>&1 | head -1)"
  echo "h2spec=$("$TOOLS/bin/h2spec" --version 2>&1 | head -1)"
  echo "nginx=$(nginx -v 2>&1 | head -1)"
  echo "node=$(node --version)"
  echo "cache_tests=$(git -C "$TOOLS/cache-tests" rev-parse HEAD)"
  echo "python=$("$TOOLS/venv/bin/python" --version 2>&1)"
  echo "weasyprint=$("$TOOLS/venv/bin/python" -c 'import weasyprint; print(weasyprint.__version__)')"
  echo "matplotlib=$("$TOOLS/venv/bin/python" -c 'import matplotlib; print(matplotlib.__version__)')"
  echo "kernel=$(uname -r)"
  echo "libc=$(ldd --version | head -1)"
} | tee "$TOOLS/tools.lock"

#!/usr/bin/env bash
# Record the equivalence harness as an animated SVG for the docs.
#
# The demo is NOT hand-drawn: it is an asciinema recording of a REAL harness
# run, converted to SVG. Regenerating it re-runs the harness, so the picture
# can never drift from what the code actually does. Run this deliberately
# (it is not wired into CI) after a change that alters the harness output.
#
#   ./tests/equivalence/record-demo.sh
#
# Requirements: asciinema, and either `svg-term` (npm) reachable via npx, or
# `agg` for a GIF fallback. Output: docs/assets/zion-import-equivalence.svg
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT_DIR="$ROOT/docs/assets"
CAST="$HERE/.demo.cast"
SVG="$OUT_DIR/zion-import-equivalence.svg"
mkdir -p "$OUT_DIR"

command -v asciinema >/dev/null || { echo "need asciinema (brew install asciinema)"; exit 1; }

# Keep the harness's verdict colors even if asciinema records without a TTY.
export FORCE_COLOR=1
unset NO_COLOR

echo "recording a real harness run…"
# asciicast-v2 so svg-term-cli can read it (asciinema 3.x defaults to v3).
# Idle capped so container pulls/waits don't bloat the cast; NO_COLOR off so
# the SVG keeps the green/yellow/red verdict colors.
asciinema rec "$CAST" \
    --overwrite \
    --output-format asciicast-v2 \
    --idle-time-limit 2 \
    --window-size 100x40 \
    --title "zion import nginx — equivalence harness" \
    --command "bash '$HERE/run.sh' multi-vhost"

echo "converting to SVG…"
if npx --yes svg-term-cli --version >/dev/null 2>&1; then
    npx --yes svg-term-cli \
        --in "$CAST" --out "$SVG" \
        --window --width 100 --height 40
    echo "wrote $SVG"
elif command -v agg >/dev/null; then
    agg "$CAST" "${SVG%.svg}.gif"
    echo "svg-term unavailable — wrote GIF fallback ${SVG%.svg}.gif"
else
    echo "cast recorded at $CAST — install svg-term-cli (npm) or agg to render"
    exit 1
fi

rm -f "$CAST"

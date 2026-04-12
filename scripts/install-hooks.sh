#!/usr/bin/env bash
set -euo pipefail

# Install git hooks for the Zion project
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$PROJECT_DIR/.git/hooks"

cp "$SCRIPT_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
cp "$SCRIPT_DIR/post-commit" "$HOOKS_DIR/post-commit"
chmod +x "$HOOKS_DIR/pre-commit" "$HOOKS_DIR/post-commit"

echo "Git hooks installed:"
echo "  pre-commit:  cargo check + cargo test"
echo "  post-commit: benchmark smoke (when ZION_BENCH=1)"
echo ""
echo "Usage:"
echo "  git commit -m '...'           # just check + test"
echo "  ZION_BENCH=1 git commit -m .. # check + test + benchmark"

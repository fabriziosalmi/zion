#!/usr/bin/env bash
# Point this clone at the version-controlled hooks in .githooks/.
# One-time setup per clone — after this, pulling new hooks is automatic.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

chmod +x .githooks/*

git config core.hooksPath .githooks

cat <<'EOF'
git hooks installed (core.hooksPath = .githooks)

  prepare-commit-msg : auto-injects Signed-off-by (DCO)
  commit-msg         : rejects commits without a valid sign-off
  pre-commit         : cargo check + cargo test
  pre-push           : verifies version SSOT (Cargo.toml ↔ Chart, README, docs)
  post-commit        : optional benchmark smoke when ZION_BENCH=1

Bypass any hook in an emergency with: ZION_SKIP_HOOK=1 git ...
EOF

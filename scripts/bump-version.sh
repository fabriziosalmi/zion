#!/usr/bin/env bash
# Bump the project version in every place it is allowed to appear.
# Cargo.toml is the canonical source; everything else is rewritten to match.
# CHANGELOG.md is left untouched — add the new section by hand.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $(basename "$0") <new-version>" >&2
  echo "  example: $(basename "$0") 0.1.11" >&2
  exit 2
fi

NEW="$1"
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: '$NEW' is not a valid semver" >&2
  exit 2
fi

# Ensure we are inside a Git repository.
if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "error: this script must be run from within a Git repository" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

OLD=$(awk '
  /^\[package\]/ { in_pkg = 1; next }
  /^\[/          { in_pkg = 0 }
  in_pkg && /^version[[:space:]]*=/ {
    gsub(/[" ]/, "", $3); print $3; exit
  }
' Cargo.toml)

if [[ -z "$OLD" ]]; then
  echo "error: could not read current version from Cargo.toml" >&2
  exit 2
fi

if [[ "$OLD" == "$NEW" ]]; then
  echo "version already $NEW — nothing to bump"
  exec scripts/check-version-sync.sh
fi

# Validate that NEW is strictly newer than OLD using semver comparison.
# Split into major.minor.patch and compare numerically.
IFS='.' read -r OLD_MAJOR OLD_MINOR OLD_PATCH <<< "$OLD"
IFS='.' read -r NEW_MAJOR NEW_MINOR NEW_PATCH <<< "$NEW"

# Strip prerelease/build metadata for numeric comparison (only compare core version)
OLD_PATCH="${OLD_PATCH%%[-+]*}"
NEW_PATCH="${NEW_PATCH%%[-+]*}"

if (( 1000000 * NEW_MAJOR + 1000 * NEW_MINOR + NEW_PATCH <= 1000000 * OLD_MAJOR + 1000 * OLD_MINOR + OLD_PATCH )); then
  echo "error: new version '$NEW' is not newer than current '$OLD'" >&2
  exit 2
fi

echo "Bumping $OLD → $NEW"

# Portable in-place sed (works on both BSD/macOS and GNU).
sedi() {
  local script="$1"; shift
  for f in "$@"; do
    sed -i.bak -E "$script" "$f" && rm -f "$f.bak"
  done
}

# 1. Cargo.toml [package] version
sedi "/^\[package\]/,/^\[/ s/^version[[:space:]]*=[[:space:]]*\"$OLD\"/version = \"$NEW\"/" Cargo.toml

# 2. Helm chart appVersion (chart `version:` is independent and not touched)
if [[ -f deploy/helm/zion/Chart.yaml ]]; then
  sedi "s/^appVersion:[[:space:]]*\"$OLD\"/appVersion: \"$NEW\"/" deploy/helm/zion/Chart.yaml
fi

# 3. README + docs — rewrite vX.Y.Z occurrences of the OLD version only.
REF_FILES=(
  "README.md"
  "docs/security/supply-chain.md"
)
for f in "${REF_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  sedi "s/v$OLD/v$NEW/g" "$f"
done

# 3b. Tailored single-line replacements where the version appears in a
# fixed context without the `v` prefix (SECURITY table, JSON examples,
# issue templates). Mirrors the PATTERN_CHECKS in check-version-sync.sh.
[[ -f SECURITY.md ]] && sedi "s/^\| < $OLD \| No \|/| < $NEW | No |/" SECURITY.md
[[ -f docs/deploy/hot-reload.md ]] && sedi "s/(\"version\":[[:space:]]*\")$OLD(\")/\1$NEW\2/" docs/deploy/hot-reload.md
[[ -f .github/ISSUE_TEMPLATE/bug_report.md ]] && sedi "s/(Zion Version: \[e\.g\.) $OLD(\])/\1 $NEW\2/" .github/ISSUE_TEMPLATE/bug_report.md

# 4. Refresh Cargo.lock so the workspace package entry matches.
# Prefer offline to avoid network during a release bump; fall back if that fails.
if cargo check --offline --quiet >/dev/null 2>&1; then
  :
elif cargo check --quiet >/dev/null 2>&1; then
  :
else
  echo "warning: cargo check failed — Cargo.lock may need a manual refresh" >&2
fi

# 5. Verify SSOT
scripts/check-version-sync.sh

cat <<EOF

bumped: $OLD → $NEW
next steps:
  1. add a CHANGELOG.md entry for $NEW
  2. git add -A && git commit -m "chore(release): v$NEW"
  3. git tag -s v$NEW -m "v$NEW"   (or unsigned: git tag v$NEW)
  4. git push && git push --tags
EOF

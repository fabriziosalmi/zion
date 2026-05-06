#!/usr/bin/env bash
# Single source of truth for the project version is Cargo.toml.
# Every other version reference must match it. This script verifies that
# invariant and exits non-zero on drift.
set -euo pipefail

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}
cd "$(repo_root)"

# ── 1. Read canonical version from Cargo.toml [package] ─────────────────────
PACKAGE_VERSION=$(awk '
  /^\[package\]/ { in_pkg = 1; next }
  /^\[/          { in_pkg = 0 }
  in_pkg && /^version[[:space:]]*=/ {
    gsub(/[" ]/, "", $3); print $3; exit
  }
' Cargo.toml)

if [[ -z "$PACKAGE_VERSION" ]]; then
  echo "error: could not read [package] version from Cargo.toml" >&2
  exit 2
fi

# We compare only the X.Y.Z core. Pre-release suffixes (-rc.1 etc.) and build
# metadata (+sha) are not validated by this script — release archive paths
# legitimately embed text right after the version (zion-v0.1.10-x86_64-...)
# and a greedy match would treat that arch tuple as a pre-release identifier.
PACKAGE_VERSION_CORE=${PACKAGE_VERSION%%[-+]*}
EXPECTED_TAG="v$PACKAGE_VERSION_CORE"
SEMVER_RE='v[0-9]+\.[0-9]+\.[0-9]+'
fail=0

note_drift() {
  fail=1
  echo "  drift: $*"
}

echo "Canonical version: $PACKAGE_VERSION  (Cargo.toml)"

# ── 2. Cargo.lock must list zion at the same version ───────────────────────
LOCK_VERSION=$(awk '
  /^name = "zion"$/        { found = 1; next }
  found && /^version = /   { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.lock 2>/dev/null || true)

if [[ -z "$LOCK_VERSION" ]]; then
  note_drift "Cargo.lock missing or has no zion entry"
elif [[ "$LOCK_VERSION" != "$PACKAGE_VERSION" ]]; then
  note_drift "Cargo.lock zion version is $LOCK_VERSION (expected $PACKAGE_VERSION)"
fi

# ── 3. Helm chart appVersion must match ────────────────────────────────────
CHART_FILE="deploy/helm/zion/Chart.yaml"
if [[ -f "$CHART_FILE" ]]; then
  CHART_APPVERSION=$(grep -E '^appVersion:' "$CHART_FILE" \
    | sed -E 's/^appVersion:[[:space:]]*"?([^"#[:space:]]+)"?.*/\1/')
  if [[ "$CHART_APPVERSION" != "$PACKAGE_VERSION" ]]; then
    note_drift "$CHART_FILE appVersion is $CHART_APPVERSION (expected $PACKAGE_VERSION)"
  fi
fi

# ── 4. Files that reference vX.Y.Z must use the current tag ────────────────
# CHANGELOG, RELEASE_NOTES, ADRs, and perf/roadmap reference past versions
# on purpose (historical record) — excluded from this check.
REF_FILES=(
  "README.md"
  "docs/security/supply-chain.md"
)
for f in "${REF_FILES[@]}"; do
  [[ -f "$f" ]] || continue
  bad_versions=$(grep -oE "$SEMVER_RE" "$f" | sort -u | grep -v "^${EXPECTED_TAG}\$" || true)
  if [[ -n "$bad_versions" ]]; then
    while IFS= read -r v; do
      occurrences=$(grep -nE "(^|[^0-9A-Za-z.-])${v}([^0-9A-Za-z.-]|\$)" "$f" \
        | head -3 | sed 's/^/      /')
      note_drift "$f references $v (expected $EXPECTED_TAG):"
      echo "$occurrences"
    done <<< "$bad_versions"
  fi
done

# ── 5. Tailored single-line checks ─────────────────────────────────────────
# Files where the version appears in a fixed context — we extract the value
# and compare it directly. Cheaper and more precise than a generic regex.
#
# Each entry: "label|file|extractor regex"
# The extractor is a sed -E expression returning ONLY the version.
PATTERN_CHECKS=(
  "SECURITY supported-versions|SECURITY.md|s/^\| < ([0-9]+\.[0-9]+\.[0-9]+) \| No \|.*/\1/p"
  "hot-reload.md snapshot example|docs/deploy/hot-reload.md|s/.*\"version\":[[:space:]]*\"([0-9]+\.[0-9]+\.[0-9]+)\".*/\1/p"
  "bug_report.md template default|.github/ISSUE_TEMPLATE/bug_report.md|s/.*Zion Version: \[e\.g\. ([0-9]+\.[0-9]+\.[0-9]+)\].*/\1/p"
)
for entry in "${PATTERN_CHECKS[@]}"; do
  IFS='|' read -r label file extractor <<< "$entry"
  [[ -f "$file" ]] || continue
  found=$(sed -nE "$extractor" "$file" | head -1)
  if [[ -n "$found" && "$found" != "$PACKAGE_VERSION_CORE" ]]; then
    note_drift "$file ($label) references $found (expected $PACKAGE_VERSION_CORE)"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "Version drift detected. Fix with: scripts/bump-version.sh $PACKAGE_VERSION"
  echo "(or pass a different target version to perform a bump)."
  exit 1
fi

echo "OK — all version references match $PACKAGE_VERSION."

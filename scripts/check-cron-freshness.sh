#!/usr/bin/env bash
# Verify that every scheduled workflow has SUCCEEDED recently.
#
# Why this exists: sovereign-data failed every weekly run from 2026-07-06 to
# 2026-08-12 — six consecutive weeks — and nothing said so. A cron that fails
# blocks no merge and notifies no one, so the datasets it maintains silently
# went stale. Red is not the problem; unwatched is.
#
# Two distinct failure modes are covered, and the second is the one people
# forget: GitHub DISABLES scheduled workflows after 60 days of repository
# inactivity. A disabled cron does not fail — it stops existing, and a check
# that only looks at the last run's conclusion would report the last success
# forever.
#
# The workflow list is DERIVED, never hardcoded: adding a cron workflow puts it
# under this guard automatically. A hardcoded list would itself go stale, which
# is the failure this script exists to prevent.
#
# Usage:  scripts/check-cron-freshness.sh [--json]
# Needs:  gh (authenticated), and `actions: read` when run in CI.
set -uo pipefail

REPO="${GITHUB_REPOSITORY:-fabriziosalmi/zion}"
WF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/workflows"
JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

# Slack over the nominal cadence: runners queue, GitHub spreads scheduled load,
# and a single missed tick is noise rather than signal. Two ticks missed is not.
DAILY_MAX_AGE_H=48
WEEKLY_MAX_AGE_H=216 # 9 days

now_epoch=$(date -u +%s)
stale=0
checked=0
declare -a ROWS=()

for f in "$WF_DIR"/*.yml; do
  cron_line=$(grep -oE "cron: *['\"][^'\"]*['\"]" "$f" 2>/dev/null | head -1) || true
  [[ -z "$cron_line" ]] && continue

  name="$(basename "$f")"

  # Skip ourselves. This workflow carries a `schedule:` trigger too, so it lands
  # in its own scan — and on the very first run it has no prior successful
  # SCHEDULED run of itself, so it would flag itself STALE and open an alarm
  # while every workflow it watches is healthy. A watchdog whose first act is a
  # false positive teaches people to ignore it.
  [[ "$name" == "cron-watchdog.yml" ]] && continue

  schedule="$(sed -E "s/cron: *['\"]//; s/['\"]$//" <<<"$cron_line")"

  # Day-of-week field pinned to a specific day => weekly, otherwise daily.
  dow="$(awk '{print $5}' <<<"$schedule")"
  if [[ "$dow" == "*" ]]; then
    max_age_h=$DAILY_MAX_AGE_H
    cadence="daily"
  else
    max_age_h=$WEEKLY_MAX_AGE_H
    cadence="weekly"
  fi

  # The most recent SUCCESSFUL scheduled run — not merely the most recent run.
  # Asking for the latest conclusion instead would go green again the moment a
  # manual dispatch succeeded, while the schedule stayed broken.
  #
  # Filtered server-side rather than by fetching N runs and filtering here.
  # Several of these workflows (scorecard, supply-chain, codeql) also run on
  # push and pull_request, so any fixed window can fill up with unrelated runs
  # and push the last scheduled success out of view — reporting STALE for a
  # perfectly healthy workflow. A watchdog that cries wolf gets muted, which
  # returns us to exactly the problem it exists to solve.
  last_ok=$(gh api \
    "repos/$REPO/actions/workflows/$name/runs?event=schedule&status=success&per_page=1" \
    --jq '.workflow_runs[0].created_at // empty' 2>/dev/null) || true

  checked=$((checked + 1))

  if [[ -z "$last_ok" ]]; then
    ROWS+=("STALE|${name%.yml}|$cadence|never succeeded on schedule")
    stale=$((stale + 1))
    continue
  fi

  last_epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$last_ok" +%s 2>/dev/null \
    || date -u -d "$last_ok" +%s 2>/dev/null) || last_epoch=0
  age_h=$(((now_epoch - last_epoch) / 3600))

  if ((age_h > max_age_h)); then
    ROWS+=("STALE|${name%.yml}|$cadence|last scheduled success ${age_h}h ago (limit ${max_age_h}h)")
    stale=$((stale + 1))
  else
    ROWS+=("OK|${name%.yml}|$cadence|${age_h}h ago")
  fi
done

if ((JSON)); then
  printf '{"checked":%d,"stale":%d,"rows":[' "$checked" "$stale"
  first=1
  for r in "${ROWS[@]}"; do
    IFS='|' read -r st wf cad detail <<<"$r"
    ((first)) || printf ','
    first=0
    printf '{"status":"%s","workflow":"%s","cadence":"%s","detail":"%s"}' "$st" "$wf" "$cad" "$detail"
  done
  printf ']}\n'
else
  for r in "${ROWS[@]}"; do
    IFS='|' read -r st wf cad detail <<<"$r"
    printf '  %-6s %-20s %-8s %s\n' "$st" "$wf" "$cad" "$detail"
  done
  echo
  echo "  checked: $checked scheduled workflow(s), stale: $stale"
fi

((stale == 0)) || exit 1

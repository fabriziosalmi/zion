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
# A workflow that is NEW has not had a chance to run on schedule yet: a weekly cron added on a
# Wednesday cannot have succeeded before the next Monday. Until it has been around for a full
# staleness window it is reported NEW, not STALE (otherwise every new cron opens a false alarm
# on its first day). Past that window with no scheduled success it is STALE as before, and a
# workflow whose age cannot be determined is treated as old (fail closed).
#
# Usage:  scripts/check-cron-freshness.sh [--json | --selftest]
# Needs:  gh (authenticated), and `actions: read` when run in CI.
set -uo pipefail

REPO="${GITHUB_REPOSITORY:-fabriziosalmi/zion}"
WF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.github/workflows"
JSON=0
[[ "${1:-}" == "--json" ]] && JSON=1

# Slack over the nominal cadence: runners queue, GitHub spreads scheduled load,
# and a single missed tick is noise rather than signal. Two ticks missed is not.
DAILY_MAX_AGE_H=48
WEEKLY_MAX_AGE_H=336 # 14 days — 2× the 168h weekly cadence, mirroring DAILY (2× its 24h). Tolerates one missed/late weekly tick instead of false-tripping at 1.28× (was 216).

to_epoch() { # RFC 3339 (Z or +hh:mm, optional fraction) -> epoch; 0 when empty or unparsable
  local t="$1"
  [[ -z "$t" ]] && { echo 0; return; }
  # normalise to "YYYY-MM-DDTHH:MM:SS+hhmm", which both BSD and GNU date accept
  t="$(sed -E 's/\.[0-9]+//; s/Z$/+0000/; s/([+-][0-9]{2}):([0-9]{2})$/\1\2/' <<<"$t")"
  date -j -f "%Y-%m-%dT%H:%M:%S%z" "$t" +%s 2>/dev/null \
    || date -d "$t" +%s 2>/dev/null || echo 0
}

# classify <last_success_epoch|0> <created_epoch|0> <max_age_h> <now_epoch>
# prints: OK <age_h> | NEW <age_h> | STALE never | STALE <age_h>
classify() {
  local last="$1" created="$2" max_h="$3" now="$4" age_h
  if ((last == 0)); then
    if ((created > 0)); then
      age_h=$(((now - created) / 3600))
      if ((age_h <= max_h)); then
        echo "NEW $age_h"
        return
      fi
    fi
    echo "STALE never"
    return
  fi
  age_h=$(((now - last) / 3600))
  if ((age_h > max_h)); then echo "STALE $age_h"; else echo "OK $age_h"; fi
}

if [[ "${1:-}" == "--selftest" ]]; then
  fail=0
  check() { # <expected> <last> <created> <max_h> <now>
    local got
    got="$(classify "$2" "$3" "$4" "$5")"
    if [[ "$got" != "$1" ]]; then
      echo "selftest FAILED: expected '$1', got '$got' (last=$2 created=$3 max=$4 now=$5)"
      fail=1
    fi
  }
  H=3600
  NOW=2000000000
  # a scheduled success inside the window
  check "OK 10" $((NOW - 10 * H)) $((NOW - 900 * H)) 336 $NOW
  # a scheduled success outside it
  check "STALE 400" $((NOW - 400 * H)) $((NOW - 900 * H)) 336 $NOW
  # never succeeded, but the workflow is new (weekly: a tick may not have come yet)
  check "NEW 48" 0 $((NOW - 48 * H)) 336 $NOW
  check "NEW 336" 0 $((NOW - 336 * H)) 336 $NOW # the edge of the window is still new
  # never succeeded and it has had its window: genuinely stale
  check "STALE never" 0 $((NOW - 337 * H)) 336 $NOW
  check "STALE never" 0 $((NOW - 20 * 24 * H)) 336 $NOW
  # daily
  check "NEW 30" 0 $((NOW - 30 * H)) 48 $NOW
  check "STALE never" 0 $((NOW - 50 * H)) 48 $NOW
  # timestamps: GitHub returns Z for runs but "+02:00" with milliseconds for a workflow's created_at
  z="$(to_epoch "2026-09-30T12:27:10Z")"
  off="$(to_epoch "2026-09-30T14:27:10.000+02:00")"
  if [[ "$z" == 0 || "$z" != "$off" ]]; then
    echo "selftest FAILED: to_epoch Z=$z offset=$off"
    fail=1
  fi
  [[ "$(to_epoch "")" == 0 && "$(to_epoch "garbage")" == 0 ]] || { echo "selftest FAILED: to_epoch of junk"; fail=1; }
  # age unknown: fail closed
  check "STALE never" 0 0 336 $NOW
  # a success always beats newness
  check "OK 5" $((NOW - 5 * H)) $((NOW - 6 * H)) 336 $NOW
  ((fail == 0)) && echo "selftest ok"
  exit "$fail"
fi

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

  last_epoch=0
  [[ -n "$last_ok" ]] && last_epoch=$(to_epoch "$last_ok")
  created_epoch=0
  if ((last_epoch == 0)); then
    # only needed to tell "new" from "stale" when there is no scheduled success to judge by
    created=$(gh api "repos/$REPO/actions/workflows/$name" --jq '.created_at // empty' 2>/dev/null) || true
    created_epoch=$(to_epoch "$created")
  fi

  read -r verdict age_h <<<"$(classify "$last_epoch" "$created_epoch" "$max_age_h" "$now_epoch")"
  case "$verdict" in
    OK) ROWS+=("OK|${name%.yml}|$cadence|${age_h}h ago") ;;
    NEW) ROWS+=("NEW|${name%.yml}|$cadence|added ${age_h}h ago, first scheduled run still due") ;;
    *)
      if [[ "$age_h" == "never" ]]; then
        ROWS+=("STALE|${name%.yml}|$cadence|never succeeded on schedule")
      else
        ROWS+=("STALE|${name%.yml}|$cadence|last scheduled success ${age_h}h ago (limit ${max_age_h}h)")
      fi
      stale=$((stale + 1))
      ;;
  esac
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

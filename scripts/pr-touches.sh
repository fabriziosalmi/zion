#!/usr/bin/env bash
# Does this pull request change a file matching any of the given git pathspecs?
#
#   scripts/pr-touches.sh 'src/waf.rs' 'src/dispatch/**' ...   ->  prints "true" or "false"
#
# For a gate that must be a REQUIRED check yet is only meaningful for some changes. A workflow
# whose `on.pull_request.paths` filter does not match never starts, and a required check that
# never reports blocks the merge forever. So the workflow always starts, asks this script, and
# its real job runs only on "true": a job skipped by its `if:` reports as passed, which satisfies
# the requirement without spending twenty minutes on a docs change.
#
# Anything that is not a pull request (a nightly, a manual run, a push) answers "true".
# Needs a checkout with history (fetch-depth: 0). BASE_REF is the PR's base branch.
set -euo pipefail
if [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  echo true
  exit 0
fi
base="${BASE_REF:?BASE_REF is required for a pull request}"
if [ -n "$(git diff --name-only "origin/${base}...HEAD" -- "$@")" ]; then
  echo true
else
  echo false
fi

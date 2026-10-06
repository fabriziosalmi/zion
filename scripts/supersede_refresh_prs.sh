#!/usr/bin/env bash
# The weekly refresh opens one pull request per region. One left open is more
# than untidy: the memory of the hysteresis (data_<region>.pending.json) only
# advances when a refresh is MERGED, so an unmerged one is a week of sightings
# that was never recorded, and the next refresh counts from what is on master.
# Two open refreshes for one region also invite merging the older.
#
#   scripts/supersede_refresh_prs.sh list  <region> <new-branch>
#       The open refresh PRs of <region> other than <new-branch>, as Markdown
#       for the new PR's body. Prints nothing when there is none.
#   scripts/supersede_refresh_prs.sh close <region> <new-branch> <new-pr-url>
#       Comments on each of them and closes it. Branches are left alone.
#
# Needs: gh (authenticated, GH_TOKEN with pull request write), python3.
set -euo pipefail

mode="${1:?list or close}"
region="${2:?region}"
new_branch="${3:?the branch of the new refresh}"
new_url="${4:-}"
now="${SUPERSEDE_NOW:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# number<TAB>opened (date)<TAB>days open, oldest first.
older() {
  gh pr list --state open --label sovereign-data --limit 100 \
    --json number,headRefName,createdAt |
    python3 -c '
import json, sys
from datetime import datetime
region, new_branch, now = sys.argv[1:4]
stamp = lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
rows = [pr for pr in json.load(sys.stdin)
        if pr["headRefName"].startswith(f"sovereign-data-{region}-")
        and pr["headRefName"] != new_branch]
for pr in sorted(rows, key=lambda pr: pr["createdAt"]):
    days = (stamp(now) - stamp(pr["createdAt"])).days
    print(pr["number"], pr["createdAt"][:10], days, sep="\t")
' "$region" "$new_branch" "$now"
}

case "$mode" in
  list)
    rows="$(older)"
    [ -n "$rows" ] || exit 0
    echo "### An earlier refresh was not merged"
    echo
    while IFS=$'\t' read -r number opened days; do
      echo "- #$number, opened $opened ($days days ago)"
    done <<< "$rows"
    echo
    echo "What it had observed was never recorded: the table's memory advances only when a refresh is merged, so the counts in this one start from what is on master. It is closed in favour of this one."
    echo
    ;;
  close)
    [ -n "$new_url" ] || { echo "close needs the URL of the new pull request" >&2; exit 2; }
    older | while IFS=$'\t' read -r number opened days; do
      gh pr comment "$number" --body "Superseded by $new_url.

This refresh was opened on $opened and not merged. What it had observed was not recorded: the table's memory (\`data_$region.pending.json\`) advances only when a refresh is merged, and the new one counts from what is on master. Closing this one so that the older of two refreshes is not merged by mistake; its branch is left in place."
      gh pr close "$number"
      echo "closed #$number (opened $opened, $days days open)"
    done
    ;;
  *)
    echo "unknown mode: $mode (list or close)" >&2
    exit 2
    ;;
esac

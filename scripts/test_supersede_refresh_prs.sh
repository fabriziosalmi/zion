#!/usr/bin/env bash
# Offline test for supersede_refresh_prs.sh. `gh` is replaced by a stub that
# serves a recorded `pr list` and logs every call, so nothing leaves the machine.
#
#   scripts/test_supersede_refresh_prs.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" | head -n 1 >> "$GH_LOG"
if [ "$1 $2" = "pr list" ]; then cat "$GH_LIST"; fi
if [ "$1 $2" = "pr comment" ]; then printf '%s\n' "$5" > "$GH_BODY.$3"; fi
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH" GH_LOG="$tmp/log" GH_LIST="$tmp/list.json" GH_BODY="$tmp/body"
export SUPERSEDE_NOW="2026-10-12T06:05:00Z"

# Two Italian refreshes left open, one EU, the new Italian one itself, and a
# pull request whose branch only looks like a refresh.
cat > "$GH_LIST" <<'JSON'
[
  {"number": 581, "headRefName": "sovereign-data-ita-20261006", "createdAt": "2026-10-06T00:08:10Z"},
  {"number": 580, "headRefName": "sovereign-data-eu-20261006", "createdAt": "2026-10-06T00:08:20Z"},
  {"number": 570, "headRefName": "sovereign-data-ita-20260928", "createdAt": "2026-09-28T06:03:00Z"},
  {"number": 590, "headRefName": "sovereign-data-ita-20261012", "createdAt": "2026-10-12T06:02:00Z"},
  {"number": 600, "headRefName": "feat/sovereign-data-ita-notes", "createdAt": "2026-10-01T10:00:00Z"}
]
JSON

fail() { echo "FAIL: $1" >&2; exit 1; }
run() { : > "$GH_LOG"; "$here/supersede_refresh_prs.sh" "$@"; }

# list: the older Italian ones, oldest first, with their age; nothing else.
out="$(run list ita sovereign-data-ita-20261012)"
[ "$(grep -c '^- #' <<< "$out")" = 2 ] || fail "list ita: two older refreshes expected, got: $out"
[ "$(grep '^- #' <<< "$out" | head -n 1)" = "- #570, opened 2026-09-28 (14 days ago)" ] || fail "list ita: oldest first"
[ "$(grep '^- #' <<< "$out" | tail -n 1)" = "- #581, opened 2026-10-06 (6 days ago)" ] || fail "list ita: second row"
grep -q '^### An earlier refresh was not merged$' <<< "$out" || fail "list ita: heading"
grep -q -- '--state open --label sovereign-data' "$GH_LOG" || fail "list: only open PRs with the label are asked for"
[ "$(wc -l < "$GH_LOG" | tr -d ' ')" = 1 ] || fail "list must only read"
echo "  ok  list names the older refreshes of the region, oldest first"

out="$(run list eu sovereign-data-eu-20261012)"
[ "$(grep '^- #' <<< "$out")" = "- #580, opened 2026-10-06 (6 days ago)" ] || fail "list eu: $out"
echo "  ok  list keeps regions apart"

# Nothing older: no output at all, so the PR body gets no empty section.
out="$(run list eu sovereign-data-eu-20261006)"
[ -z "$out" ] || fail "list with nothing older must print nothing, got: $out"
echo '[]' > "$tmp/empty.json"
out="$(GH_LIST="$tmp/empty.json" run list ita sovereign-data-ita-20261012)"
[ -z "$out" ] || fail "list on an empty repository must print nothing"
echo "  ok  list prints nothing when no refresh is older"

# close: a comment and a close for each older Italian refresh, and no other call.
out="$(run close ita sovereign-data-ita-20261012 https://github.com/o/r/pull/590)"
want="pr list --state open --label sovereign-data --limit 100 --json number,headRefName,createdAt
pr comment 570 --body Superseded by https://github.com/o/r/pull/590.
pr close 570
pr comment 581 --body Superseded by https://github.com/o/r/pull/590.
pr close 581"
[ "$(cat "$GH_LOG")" = "$want" ] || fail "close ita made these calls: $(cat "$GH_LOG")"
grep -q 'data_ita.pending.json' "$GH_BODY.570" || fail "the comment names the state file"
grep -q 'opened on 2026-09-28' "$GH_BODY.570" || fail "the comment says when it was opened"
grep -q -- '--delete-branch' "$GH_LOG" && fail "branches must be left alone"
[ "$(grep -c '^closed #' <<< "$out")" = 2 ] || fail "close reports what it closed: $out"
echo "  ok  close comments on and closes the older refreshes of the region only"

# close with no URL refuses before touching anything.
: > "$GH_LOG"
if "$here/supersede_refresh_prs.sh" close ita sovereign-data-ita-20261012 2>/dev/null; then
  fail "close without the new URL must fail"
fi
[ ! -s "$GH_LOG" ] || fail "close without the new URL must not call gh"
if "$here/supersede_refresh_prs.sh" purge ita x 2>/dev/null; then fail "an unknown mode must fail"; fi
echo "  ok  close needs the new pull request, and an unknown mode is refused"

echo
echo "5 passed"

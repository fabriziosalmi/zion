#!/usr/bin/env bash
# update-readme-stats.sh — keep README badges in sync with the codebase.
#
# Three numbers drift fastest in this repo and burn credibility when stale:
#   * module count    — every `*.rs` file under `src/` (recursive)
#   * line count      — total Rust LoC under `src/` (recursive)
#   * unit-test count — sum across lib + main bin + chaos suites (the
#                       integration suite is reported separately in the
#                       README and is excluded here on purpose)
#
# This script is the single source of truth for how those numbers are
# computed. It rewrites three lines in README.md, anchored on HTML
# marker comments so it's robust to surrounding-text edits:
#
#     30 modules, ~20,600 lines of Rust. See [arch ...]
#     <!-- zion-stats:modules-lines (kept in sync ...) -->
#
#     # Unit tests (421) <!-- zion-stats:test-count ... -->
#
# Usage:
#   bash scripts/update-readme-stats.sh             # rewrite README in place
#   bash scripts/update-readme-stats.sh --check     # exit 1 if drift exists
#
# Designed to be run from repo root (or anywhere — we cd to repo root).

set -euo pipefail

# ── locate repo root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

README="README.md"
[[ -f "$README" ]] || { echo "FATAL: $README not found at $REPO_ROOT" >&2; exit 2; }

CHECK_MODE=0
if [[ "${1:-}" == "--check" ]]; then
    CHECK_MODE=1
fi

# ── compute counts ──────────────────────────────────────────────────────
# Recurse — `src/sovereign/` and any future submodule directory must be
# counted. The previous depth=1 implementation silently undercounted.
modules=$(find src -name '*.rs' -type f | wc -l | awk '{print $1}')

# Exclude auto-generated data tables (e.g. src/sovereign/data_*.rs — baked
# CIDR datasets, tens of thousands of lines) from the *lines of Rust*
# headline: they're machine-generated data, not hand-written code, and would
# drown the signal. They still count as modules above (they are real `mod`s).
lines_total=$(find src -name '*.rs' -type f \
    -not -path 'src/sovereign/data_*.rs' \
    -exec cat {} + | wc -l | awk '{print $1}')
# Round to nearest 100 for the README — the precise count fluctuates with
# every edit and the headline number doesn't need that resolution.
# Thousands-separator formatting is done in Python below (BSD printf on
# macOS does not honour `%'d` outside specific locales).
lines_rounded=$(( (lines_total + 50) / 100 * 100 ))

# Unit-test count: aggregate across every "test result: ok. N passed"
# line cargo emits for lib + main bin + chaos. Integration tests live in
# tests/integration.rs and are #[ignore]d by default — they are reported
# separately in the README and excluded here.
#
# Cargo is ground truth: a static `grep '#[test]'` undercounts because
# proptest! macros expand into runtime test cases that share a single
# attribute in source.
test_output=$(cargo test --release --lib --bin zion --test chaos --quiet 2>&1 || true)
tests=$(printf "%s" "$test_output" \
    | grep -E '^test result: ok\. [0-9]+ passed' \
    | awk '{s+=$4} END {print s}')
if [[ -z "${tests:-}" || "$tests" == "0" ]]; then
    echo "FATAL: could not extract a non-zero test count from cargo test output" >&2
    echo "       (last 20 lines follow)" >&2
    printf "%s\n" "$test_output" | tail -20 >&2
    exit 3
fi

echo "  modules : $modules"
echo "  lines   : $lines_total → ~$lines_rounded (rounded to nearest 100)"
echo "  tests   : $tests"

# ── rewrite (or check) ──────────────────────────────────────────────────
# We use Python rather than sed because sed's behaviour around `~` and
# parentheses differs between BSD/GNU; Python is everywhere on the
# platforms this repo supports (CI: Linux, dev: macOS). Python also gives
# us guaranteed thousands-separator formatting via `{:,}`.
python3 - "$README" "$modules" "$lines_rounded" "$tests" "$CHECK_MODE" <<'PY'
import re, sys, pathlib

readme_path, modules, lines_rounded, tests, check_mode = sys.argv[1:]
modules = int(modules)
lines_rounded = int(lines_rounded)
lines_fmt = f"{lines_rounded:,}"
tests = int(tests)
check_mode = bool(int(check_mode))

src = pathlib.Path(readme_path).read_text()

# Pattern 1: "<N> modules, ~<M> lines of Rust." preceded by the marker
# comment. Marker is on its own line right above the stats line.
modules_lines_re = re.compile(
    r"(<!-- zion-stats:modules-lines[^>]*-->\n)"
    r"(\d+) modules, ~[\d,]+ lines of Rust\."
)
new_modules_line = f"{modules} modules, ~{lines_fmt} lines of Rust."
src_new, n1 = modules_lines_re.subn(
    lambda m: m.group(1) + new_modules_line,
    src,
)
if n1 != 1:
    sys.exit(
        f"FATAL: zion-stats:modules-lines marker matched {n1} times "
        f"(expected exactly 1). README structure changed — update the regex."
    )

# Pattern 2: "# Unit tests (N) <!-- zion-stats:test-count ... -->"
tests_re = re.compile(
    r"# Unit tests \(\d+\)(\s*<!-- zion-stats:test-count[^>]*-->)"
)
new_tests_line = rf"# Unit tests ({tests})\1"
src_new, n2 = tests_re.subn(new_tests_line, src_new)
if n2 != 1:
    sys.exit(
        f"FATAL: zion-stats:test-count marker matched {n2} times "
        f"(expected exactly 1). README structure changed — update the regex."
    )

if src_new == src:
    print("  README already in sync — nothing to do.")
    sys.exit(0)

if check_mode:
    print("DRIFT: README stats are stale. Run scripts/update-readme-stats.sh to fix.")
    sys.exit(1)

pathlib.Path(readme_path).write_text(src_new)
print("  README updated.")
PY

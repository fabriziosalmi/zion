#!/usr/bin/env bash
# Every `allow(dead_code)` in src/ must say why.
#
# The lint is kept on for the whole crate (see src/main.rs) because dead code is a leading
# indicator of rot: an option that parses and does nothing is the worst case. An allow is the
# one place the lint is switched off, so it carries its reason: a comment on the same line, or a
# comment line directly above (a doc comment on the item counts). `cfg_attr(not(feature ..),
# allow(dead_code))` is held to the same rule: it names the flavour, the comment names the reader.
#
#   scripts/check-dead-code-allows.sh        # exits 1 and lists every allow without a reason
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
while IFS= read -r file; do
  awk -v F="$file" '
    function is_comment(s) { return s ~ /^[[:space:]]*\/\// }
    { line[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        if (line[i] !~ /allow\(dead_code\)/ || is_comment(line[i])) continue
        if (line[i] ~ /\/\/[[:space:]]*[^[:space:]]/) continue            # trailing reason
        s = i                                                              # start of a wrapped attribute
        while (s > 1 && line[s] !~ /^[[:space:]]*#!?\[/) s--
        if (s > 1 && is_comment(line[s - 1])) continue                     # comment line above
        printf "%s:%d: allow(dead_code) without a reason: %s\n", F, i, line[i]; bad = 1
      }
      exit bad
    }
  ' "$file" || status=1
done < <(find src -name '*.rs' | sort)
if [ "$status" -ne 0 ]; then
  echo
  echo "Say why next to it (a trailing '// reason' or a comment line above), or remove the allow." >&2
fi
exit "$status"

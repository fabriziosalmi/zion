#!/usr/bin/env bash
# Profile-guided build of zion for local measurements.
#
# This used to be a second implementation of the PGO pipeline. It is now the
# one the release uses: scripts/pgo-build.sh (instrumented build, the training
# of scripts/pgo-train.sh, merge, optimised build, checks). See docs/perf/pgo.md.
#
# Usage: bash benchmarks/bench-pgo.sh        (takes the PGO_* variables of pgo-build.sh)
# The optimised binary is target/<host triple>/release/zion.

set -euo pipefail
exec bash "$(dirname "$0")/../scripts/pgo-build.sh" "$@"

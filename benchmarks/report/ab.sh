#!/usr/bin/env bash
# A/B two builds of zion on the benchmark host, base-new-base-new, same harness and rig as the
# release report, only zion as a target. The question it answers is "did this change move
# that scenario", not "how fast is zion": for the second, use report.sh.
#
#     benchmarks/report/ab.sh master perf/my-branch static_files,cache_hit_small
#
# The spread of the two base runs is the noise; a change inside it is not a result.
# Environment: BOX (default ci@192.168.0.131), TRIALS (5), DURATION (10).
set -euo pipefail
BOX="${BOX:-ci@192.168.0.131}"
BASE="${1:?usage: ab.sh BASE_REF NEW_REF scenario[,scenario...]}"; NEW="${2:?}"; ONLY="${3:?}"
TRIALS="${TRIALS:-5}"; DURATION="${DURATION:-10}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"
# A ref is a git ref (built here from `git archive`) or `bin:NAME`, a binary already on the host
# at ~/zion-ab/bin-NAME (e.g. a release artifact: PGO against not-PGO).
sha() { case "$1" in bin:*) echo "${1#bin:}";; *) git rev-parse --short "$1^{commit}";; esac; }
BSHA="$(sha "$BASE")"; NSHA="$(sha "$NEW")"
# shellcheck disable=SC2029
ssh "$BOX" "mkdir -p ~/zion-ab/harness/benchmarks ~/zion-ab/out"
rsync -a --delete --exclude reports --exclude __pycache__ "$HERE/" "$BOX:zion-ab/harness/benchmarks/report/"
rsync -a --delete --exclude __pycache__ "$REPO/benchmarks/regress/" "$BOX:zion-ab/harness/benchmarks/regress/"
for pair in "base:$BASE:$BSHA" "new:$NEW:$NSHA"; do
  IFS=: read -r label ref s <<<"$pair"
  case "$pair" in *:bin:*) continue;; esac  # prebuilt on the host: nothing to build
  # shellcheck disable=SC2029
  if ! ssh "$BOX" "test -x ~/zion-ab/bin-$s"; then
    echo "▶ building $label ($ref $s)"
    ssh "$BOX" "rm -rf ~/zion-ab/src-$s && mkdir -p ~/zion-ab/src-$s"
    git archive "$ref" | ssh "$BOX" "tar -x -C ~/zion-ab/src-$s"
    ssh "$BOX" ". ~/.cargo/env && cd ~/zion-ab/src-$s && cargo build --release --locked --features dist 2>&1 | tail -1 && cp target/release/zion ~/zion-ab/bin-$s"
  fi
done
echo "▶ measuring base=$BSHA new=$NSHA ($ONLY)"
# shellcheck disable=SC2029
ssh "$BOX" "set -e; export PATH=/opt/zion-bench/bin:\$PATH; cd ~/zion-ab/harness/benchmarks/report; rm -rf ~/zion-ab/out/*
  for round in 1 2; do for v in base new; do
    if [ \$v = base ]; then s=$BSHA; else s=$NSHA; fi
    # the host is shared: a leg whose canary drifted is measured again (3 tries), not averaged in
    for try in 1 2 3; do
      sleep 20
      python3 bench.py --zion ~/zion-ab/bin-\$s --out ~/zion-ab/out/\$v-\$round --label \$v-\$s --only $ONLY --targets zion --trials $TRIALS --duration $DURATION 2>&1 | tail -1
      python3 -c \"import json,sys; sys.exit(1 if json.load(open('/home/ci/zion-ab/out/\$v-\$round/result.json'))['canary']['noisy'] else 0)\" && break
      echo \"  canary noisy, measuring \$v-\$round again (try \$try)\"
    done
  done; done
  python3 - <<PY
import json, statistics
runs = {k: json.load(open(f'/home/ci/zion-ab/out/{k}/result.json')) for k in ('base-1','new-1','base-2','new-2')}
print(f\"{'scenario':20s} {'run':7s} {'req/s':>9s} {'µs/req':>8s} {'p90 µs':>9s} {'p99 µs':>9s}\")
for sc in runs['base-1']['scenarios']:
    for k, r in runs.items():
        s = r['scenarios'][sc]['targets']['zion']['summary']
        print(f\"{sc:20s} {k:7s} {s['rps']:9.0f} {s['cpu_us_per_req']:8.1f} {s.get('lat_p90_us') or 0:9.0f} {s.get('lat_p99_us') or 0:9.0f}\")
    for kind in ('rps','cpu_us_per_req'):
        b = statistics.mean(runs[k]['scenarios'][sc]['targets']['zion']['summary'][kind] for k in ('base-1','base-2'))
        n = statistics.mean(runs[k]['scenarios'][sc]['targets']['zion']['summary'][kind] for k in ('new-1','new-2'))
        noise = abs(runs['base-1']['scenarios'][sc]['targets']['zion']['summary'][kind] - runs['base-2']['scenarios'][sc]['targets']['zion']['summary'][kind]) / b * 100
        print(f\"  {kind:15s} new vs base {100*(n-b)/b:+6.1f}%   (base-vs-base noise {noise:.1f}%)\")
PY"

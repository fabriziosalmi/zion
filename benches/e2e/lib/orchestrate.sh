# shellcheck shell=bash
# benches/e2e/lib/orchestrate.sh — control-host helpers.
#
# Source env.sh before this. All functions run from the control host (laptop)
# and reach the SUT/attacker via `ssh <pve-host> pct exec <ctid>`, plus direct
# LAN curl to Prometheus.

# Run a command inside the attacker LXC. Complex commands (wrk/vegeta with many
# flags) are best passed via atk_push_run to avoid quoting hell.
atk_exec() { ssh "$NODE2_HOST" "pct exec $ATK_CTID -- $*"; }
sut_exec() { ssh "$NODE1_HOST" "pct exec $SUT_CTID -- $*"; }

# Push a local script file into the attacker and run it with bash. Echoes stdout.
# Usage: atk_push_run /path/to/local.sh [args...]
atk_push_run() {
  local f="$1"; shift
  local base; base="$(basename "$f")"
  scp -q -o BatchMode=yes "$f" "$NODE2_HOST:/tmp/$base"
  ssh "$NODE2_HOST" "pct push $ATK_CTID /tmp/$base /tmp/$base >/dev/null 2>&1; pct exec $ATK_CTID -- bash /tmp/$base $*"
}

# Instant Prometheus query -> raw scalar value (first result), or "NaN".
prom_query() {
  local q="$1"
  curl -gs --data-urlencode "query=$q" "$PROM/api/v1/query" \
    | python3 -c "import json,sys;r=json.load(sys.stdin)['data']['result'];print(r[0]['value'][1] if r else 'NaN')" 2>/dev/null || echo "NaN"
}

# Range query -> write full JSON to a file. Args: query start end step outfile
prom_range() {
  local q="$1" start="$2" end="$3" step="${4:-5}" out="$5"
  curl -gs "$PROM/api/v1/query_range" \
    --data-urlencode "query=$q" \
    --data-urlencode "start=$start" \
    --data-urlencode "end=$end" \
    --data-urlencode "step=$step" > "$out"
}

# Snapshot every MONEY_SERIES as a range into <dir>/<tag>.<series>.json
snapshot_money() {
  local dir="$1" tag="$2" start="$3" end="$4" step="${5:-5}"
  mkdir -p "$dir"
  local s
  for s in "${MONEY_SERIES[@]}"; do
    prom_range "$s" "$start" "$end" "$step" "$dir/${tag}.${s}.json"
  done
}

# Start a pidstat CPU sidecar for the zion process on the SUT, for <dur> seconds,
# writing to a remote temp file; returns the remote path on stdout.
sut_cpu_sidecar_start() {
  local dur="$1" tag="$2"
  ssh "$NODE1_HOST" "pct exec $SUT_CTID -- bash -c 'nohup pidstat -u -p \$(pgrep -x zion | head -1) 1 $dur > /tmp/${tag}.zion_cpu.log 2>&1 &'"
  echo "/tmp/${tag}.zion_cpu.log"
}
sut_cpu_sidecar_collect() {
  local tag="$1" dir="$2"
  ssh "$NODE1_HOST" "pct exec $SUT_CTID -- cat /tmp/${tag}.zion_cpu.log" > "$dir/${tag}.zion_cpu.log" 2>/dev/null || true
  # mean %CPU across samples (pidstat field 8 = %CPU on this build)
  awk '/Average/{print "  zion mean %CPU: "$8}' "$dir/${tag}.zion_cpu.log" 2>/dev/null || true
}

# Capture the git short-sha of the running Zion binary (pinned in manifest).
zion_sha() { sut_exec "sha256sum /usr/local/bin/zion" 2>/dev/null | awk '{print substr($1,1,12)}'; }
zion_version() { prom_query 'zion_build_info' >/dev/null 2>&1; curl -ks "https://$SUT_FQDN/" --resolve "$SUT_FQDN:443:$SUT_IP" >/dev/null 2>&1; }

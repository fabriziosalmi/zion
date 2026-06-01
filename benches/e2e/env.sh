# shellcheck shell=bash
# benches/e2e/env.sh — single source of truth for the draconian e2e bench.
#
# Topology (2-node Proxmox homelab, see TOPOLOGY.md):
#   SUT      = Zion on node1 (Skylake i7-6700, AVX2) — LXC 9001, cores 0,1 pinned
#              + nginx origin co-host on core 2, observer on core 3.
#   ATTACKER = node2 (i7-3770, 8 cores) — LXC 9101, all 8 cores. wrk/vegeta/h2load.
#   OBSERVER = Prometheus(:9090) + Grafana(:3000) on .223 (LXC 9003).
#
# The Zion binary is built with AVX2/BMI2 (Skylake target) so it CANNOT run on
# the 2012 Ivy-Bridge attacker node — which is exactly why node2 is the load
# generator and node1 is the SUT. Document this in the paper.
#
# Orchestration model: run these scripts from a control host (laptop) that has
# SSH to BOTH Proxmox hosts and direct LAN reachability to the container IPs.

# --- Proxmox hosts (SSH targets) ---
export NODE1_HOST="${NODE1_HOST:-root@192.168.0.203}"   # PVE host of the SUT
export NODE2_HOST="${NODE2_HOST:-root@192.168.0.201}"   # PVE host of the attacker

# --- Container IDs (pct exec) ---
export SUT_CTID="${SUT_CTID:-9001}"      # Zion + nginx origin
export ATK_CTID="${ATK_CTID:-9101}"      # load generator

# --- Network (direct LAN, reachable from the control host) ---
export SUT_FQDN="${SUT_FQDN:-demo.italiacdn.net}"   # real Let's Encrypt cert CN
export SUT_IP="${SUT_IP:-192.168.0.221}"
export ATK_IP="${ATK_IP:-192.168.0.224}"
export PROM="${PROM:-http://192.168.0.223:9090}"
export GRAFANA="${GRAFANA:-http://192.168.0.223:3000}"

# --- Pinning (must match the LXC cpuset config) ---
export ZION_CORES="0,1"     # Zion's 2 dedicated cores on the SUT
export ATK_CORES="0,1,2,3"  # cores wrk/vegeta pin to on the 8-core attacker

# --- Bench parameters (overridable) ---
export PAYLOADS=("/" "/1k.bin" "/10k.bin" "/100k.bin")
export CONCURRENCY=(50 100 200 400)
export REPS="${REPS:-3}"               # measured reps per data point (+1 warmup discarded)
export COOLDOWN_S="${COOLDOWN_S:-30}"  # inter-run cooldown
export RESULTS_ROOT="${RESULTS_ROOT:-$HOME/zion-bench-results}"

# --- The "money series" pulled from Prometheus for every measured run ---
export MONEY_SERIES=(
  "zion_requests_total"
  "zion_process_resident_memory_bytes"
  "zion_process_open_fds"
  "zion_active_connections"
  "zion_connections_total"
  "zion_waf_denied"
  "zion_rate_limited"
  "zion_connections_rejected_per_ip"
  "zion_panics_total"
  "zion_tls_handshake_errors"
)

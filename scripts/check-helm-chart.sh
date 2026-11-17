#!/usr/bin/env bash
# Render the Helm chart with every values file in deploy/helm/zion/ci/ and check
# that each render is a config zion accepts (`zion doctor`), plus `helm lint`.
# Usage: scripts/check-helm-chart.sh <path-to-zion-binary>
set -euo pipefail
ZION=${1:?usage: $0 <zion binary>}
CHART=deploy/helm/zion
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
# A throwaway cert for the paths the chart mounts from the TLS Secret.
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=zion-ci -days 1 \
  -addext "subjectAltName=DNS:zion-ci" \
  -keyout "$WORK/tls.key" -out "$WORK/tls.crt" >/dev/null 2>&1
fail=0
for values in "$CHART"/ci/*.yaml; do
  name=$(basename "$values" .yaml)
  helm lint --strict "$CHART" -f "$values" >/dev/null || { echo "FAIL $name: helm lint"; fail=1; continue; }
  helm template t "$CHART" -f "$values" > "$WORK/$name.yaml"
  python3 - "$WORK/$name.yaml" "$WORK" > "$WORK/$name.toml" <<'PY'
import sys, yaml
for doc in yaml.safe_load_all(open(sys.argv[1])):
    if doc and doc.get("kind") == "ConfigMap" and "zion.toml" in doc.get("data", {}):
        print(doc["data"]["zion.toml"].replace("/etc/zion/tls/", sys.argv[2] + "/"))
PY
  if ZION_CONFIG="$WORK/$name.toml" "$ZION" doctor > "$WORK/$name.doctor" 2>&1; then
    echo "ok   $name"
  else
    echo "FAIL $name: zion doctor"; grep -iE "fail|error|✗" "$WORK/$name.doctor" | head -5; fail=1
  fi
done

# A LoadBalancer Service keeps each client's source address (externalTrafficPolicy: Local).
# Without it kube-proxy presents every client from a private node address: zion counts them
# all as internal (/metrics and the snapshot answer the internet) and per-IP limits count per
# node. A ClusterIP Service must not carry the field (the API server rejects it there).
for type in LoadBalancer ClusterIP; do
  helm template t "$CHART" -f "$CHART/ci/basic.yaml" --set service.type=$type > "$WORK/svc-$type.yaml"
  python3 - "$WORK/svc-$type.yaml" "$type" <<'PY' || { echo "FAIL service ($type): externalTrafficPolicy"; fail=1; }
import sys, yaml
svc = next(d for d in yaml.safe_load_all(open(sys.argv[1])) if d and d.get("kind") == "Service")
want = "Local" if sys.argv[2] == "LoadBalancer" else None
got = svc["spec"].get("externalTrafficPolicy")
assert got == want, f"externalTrafficPolicy: want {want}, got {got}"
PY
done
# config.internalNetworks / trustedProxies reach [server] in the rendered zion.toml.
python3 - "$WORK/edge-networks.toml" <<'PY' || { echo "FAIL edge-networks: [server] lists"; fail=1; }
import sys, tomllib
server = tomllib.load(open(sys.argv[1], "rb"))["server"]
assert server.get("internal_networks") == ["127.0.0.1/32", "10.42.0.0/16"], server
assert server.get("trusted_proxies") == ["10.0.0.0/8"], server
PY
[[ $fail -eq 0 ]] && echo "ok   service traffic policy, [server] lists"
exit $fail

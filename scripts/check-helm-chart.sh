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
exit $fail

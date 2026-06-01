#!/usr/bin/env bash
# S0 — preflight correctness + cert + WAF-boundary GO/NO-GO gate.
# Runs ON the attacker LXC. Produces no headline numbers; aborts the campaign
# if the path/cert/WAF are not exactly as coded.
set -u
HOST="${SUT_FQDN:-demo.italiacdn.net}"
PROM="${PROM:-http://192.168.0.223:9090}"
fail=0
say() { printf '%s\n' "$*"; }
gate() { # gate "label" actual expected
  if [ "$2" = "$3" ]; then say "  PASS $1 ($2)"; else say "  FAIL $1 (got '$2' want '$3')"; fail=1; fi
}

say "== S0.1 cert + TLS + TTFB =="
read -r code ver sslv < <(curl -sk -o /dev/null -w '%{http_code} %{http_version} %{ssl_verify_result}' "https://$HOST/")
tlsv=$(echo | openssl s_client -connect "$HOST:443" -servername "$HOST" 2>/dev/null | grep -m1 -oE 'TLSv1\.[0-9]')
say "  http=$code http_ver=$ver tls=$tlsv ssl_verify=$sslv (informational: bench uses -k; chain is real LE, full 4-cert)"
gate "root-200" "$code" "200"
gate "tls13" "$tlsv" "TLSv1.3"

say "== S0.2 payload identity (sha256, saved) =="
for p in / /1k.bin /10k.bin /100k.bin; do
  h=$(curl -sk "https://$HOST$p" | sha256sum | cut -c1-16)
  c=$(curl -sk -o /dev/null -w '%{http_code}' "https://$HOST$p")
  say "  $p -> $c sha=$h"
  [ "$c" = 200 ] || fail=1
done | tee /tmp/zion_hashes.txt

say "== S0.3 proxy + injected headers =="
hdrs=$(curl -skI "https://$HOST/")
echo "$hdrs" | grep -qi 'x-origin-backend: nginx-zion-bench' && say "  PASS X-Origin-Backend (proves Zion->nginx origin)" || { say "  FAIL X-Origin-Backend missing"; fail=1; }
echo "$hdrs" | grep -qi 'x-request-id'                       && say "  PASS X-Request-ID (Zion injects)"            || { say "  FAIL X-Request-ID missing"; fail=1; }

say "== S0.4 WAF boundary (verified-in-src: deny=400, headers NOT scanned) =="
gate "uri-sqli-400"  "$(curl -sk -o /dev/null -w '%{http_code}' -G --data-urlencode "id=' or 1=1" "https://$HOST/api/users")" "400"
gate "uri-trav-400"  "$(curl -sk -o /dev/null -w '%{http_code}' -G --data-urlencode "path=../../../etc/passwd" "https://$HOST/files")" "400"
gate "body-xss-400"  "$(curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"c":"<script"}' "https://$HOST/api/x")" "400"
gate "hdr-ctl-200"   "$(curl -sk -o /dev/null -w '%{http_code}' -H "X-Attack: ' or 1=1--" "https://$HOST/")" "200"

say "== S0.5 Prometheus health gauges =="
say "  panics_total=$(curl -gs --data-urlencode 'query=zion_panics_total' "$PROM/api/v1/query" | python3 -c "import json,sys;r=json.load(sys.stdin)['data']['result'];print(r[0]['value'][1] if r else 'NaN')")"
say "  tls_hs_errors=$(curl -gs --data-urlencode 'query=zion_tls_handshake_errors' "$PROM/api/v1/query" | python3 -c "import json,sys;r=json.load(sys.stdin)['data']['result'];print(r[0]['value'][1] if r else 'NaN')")"
say "  target_up=$(curl -gs --data-urlencode 'query=up{job="zion"}' "$PROM/api/v1/query" | python3 -c "import json,sys;r=json.load(sys.stdin)['data']['result'];print(r[0]['value'][1] if r else 'NaN')")"
gate "prom-target-up" "$(curl -gs --data-urlencode 'query=up{job="zion"}' "$PROM/api/v1/query" | python3 -c "import json,sys;r=json.load(sys.stdin)['data']['result'];print(r[0]['value'][1] if r else 'NaN')")" "1"

say ""
if [ "$fail" = 0 ]; then say "S0 RESULT: GO ✅"; else say "S0 RESULT: NO-GO ❌ (fix before running the campaign)"; fi
exit "$fail"

#!/usr/bin/env bash
# zion import — equivalence harness (ADR-0011, fidelity ladder v1).
#
# Proves, with real instances and no mocks, that a config converted by
# `zion import nginx` routes like the nginx it came from:
#
#   1. real nginx (nginx:alpine) serves the scenario config
#   2. `zion import nginx` converts that SAME config (findings shown)
#   3. real zion serves the converted config
#   4. a corpus of (Host, path) requests is replayed against BOTH
#   5. the answering backend is diffed request by request
#
# Rows whose expectations differ between nginx and zion are DOCUMENTED
# divergences: the import report flags them with partial findings, and this
# harness proves those flags are truthful rather than hiding them.
#
# Requirements: docker, curl, openssl, bash. No Rust toolchain needed in the
# default mode (zion runs from the published container image).
#
#   ./tests/equivalence/run.sh [scenario]        # default: multi-vhost
#
# Environment:
#   ZION_IMAGE          zion container image (default: the pinned release)
#   ZION_BIN            path to a locally built linux zion binary; when set it
#                       is bind-mounted into ZION_RUNTIME_IMAGE instead of
#                       using ZION_IMAGE (this is how CI tests the tree)
#   ZION_RUNTIME_IMAGE  runtime for ZION_BIN (default: ubuntu:24.04)
#   KEEP=1              skip cleanup (debugging)
set -euo pipefail

SCENARIO="${1:-multi-vhost}"
ZION_IMAGE="${ZION_IMAGE:-ghcr.io/fabriziosalmi/zion:0.6.0}"
ZION_RUNTIME_IMAGE="${ZION_RUNTIME_IMAGE:-ubuntu:24.04}"
NGINX_IMAGE="nginx:1.27-alpine"
NET=zeq-net
NGINX_PORT=18080
ZION_PORT=18443
BACKEND_PORT=5678

HERE="$(cd "$(dirname "$0")" && pwd)"
SCEN_DIR="$HERE/scenarios/$SCENARIO"
[ -f "$SCEN_DIR/nginx.conf" ] || { echo "unknown scenario '$SCENARIO'" >&2; exit 1; }

# Color when attached to a TTY or when explicitly forced (the demo recorder
# sets FORCE_COLOR so the SVG keeps its verdict colors); NO_COLOR wins.
if { [ -t 1 ] || [ -n "${FORCE_COLOR:-}" ]; } && [ -z "${NO_COLOR:-}" ]; then
    G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else
    G=""; Y=""; R=""; B=""; N=""
fi

say() { printf '%s\n' "$*"; }
step() { printf '\n%s── %s%s\n' "$B" "$*" "$N"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zion-eq.XXXXXX")"
chmod 755 "$WORK"

cleanup() {
    [ -n "${KEEP:-}" ] && { say "KEEP=1 — leaving containers up (work dir: $WORK)"; return; }
    docker ps -aq --filter "name=^zeq-" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Backends referenced by the scenario config: zeq-be-<name>.
BACKENDS="$(grep -oE 'zeq-be-[a-z0-9-]+' "$SCEN_DIR/nginx.conf" | sed 's/^zeq-be-//' | sort -u)"

step "scenario '$SCENARIO' — backends: $(echo "$BACKENDS" | tr '\n' ' ')"
docker network create "$NET" >/dev/null

for name in $BACKENDS; do
    mkdir -p "$WORK/be-$name"
    cat > "$WORK/be-$name/default.conf" <<EOF
server {
    listen $BACKEND_PORT;
    default_type text/plain;
    location / { return 200 "$name\n"; }
}
EOF
    chmod -R a+rX "$WORK/be-$name"
    docker run -d --name "zeq-be-$name" --network "$NET" \
        -v "$WORK/be-$name/default.conf:/etc/nginx/conf.d/default.conf:ro" \
        "$NGINX_IMAGE" >/dev/null
done

step "nginx (the original) on :$NGINX_PORT"
docker run -d --name zeq-nginx --network "$NET" -p "127.0.0.1:$NGINX_PORT:80" \
    -v "$SCEN_DIR/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
    "$NGINX_IMAGE" >/dev/null

# How zion is invoked: released image, or a tree-built binary mounted into a
# plain runtime image (CI mode).
if [ -n "${ZION_BIN:-}" ]; then
    ZION_BIN="$(cd "$(dirname "$ZION_BIN")" && pwd)/$(basename "$ZION_BIN")"
    zion_docker() { # extra-docker-args... -- zion-args...
        local extra=(); while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
        docker run "${extra[@]}" -v "$ZION_BIN:/usr/local/bin/zion:ro" \
            --entrypoint /usr/local/bin/zion "$ZION_RUNTIME_IMAGE" "$@"
    }
    say "zion: local binary $ZION_BIN (runtime: $ZION_RUNTIME_IMAGE)"
else
    zion_docker() {
        local extra=(); while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
        docker run "${extra[@]}" "$ZION_IMAGE" "$@"
    }
    say "zion: $ZION_IMAGE"
fi

step "zion import nginx — converting the SAME config (findings below)"
zion_docker --rm -v "$SCEN_DIR/nginx.conf:/in/nginx.conf:ro" -- \
    import nginx /in/nginx.conf \
    > "$WORK/zion.toml" 2> "$WORK/report.txt" || { cat "$WORK/report.txt" >&2; exit 1; }
sed 's/^/  /' "$WORK/report.txt"

step "self-signed cert at the placeholder paths the importer emitted"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout "$WORK/zion.key" -out "$WORK/zion.crt" \
    -subj "/CN=zion-equivalence" \
    -addext "subjectAltName=DNS:example.com,DNS:*.example.com" >/dev/null 2>&1
chmod a+r "$WORK/zion.key" "$WORK/zion.crt" "$WORK/zion.toml"

step "zion (the converted config) on :$ZION_PORT"
zion_docker -d --name zeq-zion --network "$NET" -p "127.0.0.1:$ZION_PORT:443" \
    -v "$WORK/zion.toml:/etc/zion/zion.toml:ro" \
    -v "$WORK/zion.crt:/etc/ssl/zion/zion.crt:ro" \
    -v "$WORK/zion.key:/etc/ssl/zion/zion.key:ro" \
    -e ZION_CONFIG=/etc/zion/zion.toml -- >/dev/null

ask_nginx() { # host path -> backend id or HTTP status
    local out
    out="$(curl -s -m 5 -o - -w '|%{http_code}' -H "Host: $1" "http://127.0.0.1:$NGINX_PORT$2" || true)"
    normalize "$out"
}
ask_zion() {
    local out
    out="$(curl -sk -m 5 -o - -w '|%{http_code}' -H "Host: $1" "https://127.0.0.1:$ZION_PORT$2" || true)"
    normalize "$out"
}
normalize() { # "body|status" -> body first line, or the status when no body / >= 400
    local body="${1%|*}" code="${1##*|}"
    if [ -z "$body" ] || [ "${code:-0}" -ge 400 ] 2>/dev/null; then
        printf '%s' "${code:-000}"
    else
        printf '%s' "$(printf '%s' "$body" | head -n1)"
    fi
}

# Readiness gate: loop until the FIRST corpus row answers with its expected
# backend on BOTH instances. Zion binds and pre-warms upstreams after boot,
# so the first requests can otherwise race the listener coming up.
read -r first_host first_path want_nginx want_zion _ < <(
    awk '!/^#/ && NF {print; exit}' "$SCEN_DIR/requests.txt")
for i in $(seq 1 40); do
    [ "$(ask_nginx "$first_host" "$first_path")" = "$want_nginx" ] &&
        [ "$(ask_zion "$first_host" "$first_path")" = "$want_zion" ] && break
    [ "$i" = 40 ] && {
        echo "instances did not become ready (nginx=$(ask_nginx "$first_host" "$first_path") zion=$(ask_zion "$first_host" "$first_path"))" >&2
        docker logs zeq-zion 2>&1 | tail -20 >&2 || true
        exit 1
    }
    sleep 1
done

step "replaying the request corpus against BOTH instances"
printf '  %-22s %-22s %-10s %-10s %s\n' "HOST" "PATH" "nginx" "zion" "VERDICT"
fails=0; identical=0; documented=0
while read -r host path want_nginx want_zion; do
    case "$host" in ''|'#'*) continue ;; esac
    got_nginx="$(ask_nginx "$host" "$path")"
    got_zion="$(ask_zion "$host" "$path")"
    if [ "$got_nginx" != "$want_nginx" ] || [ "$got_zion" != "$want_zion" ]; then
        verdict="${R}FAIL (expected nginx=$want_nginx zion=$want_zion)${N}"
        fails=$((fails + 1))
    elif [ "$want_nginx" != "$want_zion" ]; then
        verdict="${Y}documented divergence (flagged by the import report)${N}"
        documented=$((documented + 1))
    else
        verdict="${G}identical${N}"
        identical=$((identical + 1))
    fi
    printf '  %-22s %-22s %-10s %-10s %s\n' "$host" "$path" "$got_nginx" "$got_zion" "$verdict"
done < "$SCEN_DIR/requests.txt"

step "result"
if [ "$fails" -eq 0 ]; then
    say "  ${G}${B}PASS${N} — $identical/$((identical + documented)) requests routed identically;"
    say "  $documented divergence(s) matched exactly what the import report declared."
else
    say "  ${R}${B}FAIL${N} — $fails request(s) deviated from expectations."
fi
exit "$((fails > 0))"

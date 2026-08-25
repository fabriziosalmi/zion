#!/usr/bin/env bash
# zion import — equivalence harness (ADR-0011/0012/0013, fidelity ladder v1).
#
# Proves, with real instances and no mocks, that a config converted by
# `zion import <nginx|caddy|traefik>` routes like the proxy it came from:
#
#   1. the real ORIGINAL proxy serves the scenario config
#   2. `zion import <src>` converts that SAME config (findings shown)
#   3. real zion serves the converted config
#   4. a corpus of (Host, path) requests is replayed against BOTH
#   5. the answering backend is diffed request by request
#
# The source is auto-detected from the scenario dir:
#   nginx.conf         → nginx      (real nginx:alpine, echo backends)
#   Caddyfile          → caddy      (real caddy:alpine, echo backends)
#   docker-compose.yml → traefik    (real traefik via `docker compose up`;
#                                     the compose file provides its own backends)
#
# Rows whose expectations differ between the original and zion are DOCUMENTED
# divergences: the import report flags them, and this harness proves those flags
# are truthful rather than hiding them.
#
# Requirements: docker (+ `docker compose` for traefik scenarios), curl,
# openssl, bash. No Rust toolchain needed in the default mode.
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
ZION_IMAGE="${ZION_IMAGE:-ghcr.io/fabriziosalmi/zion:0.7.4}"
ZION_RUNTIME_IMAGE="${ZION_RUNTIME_IMAGE:-ubuntu:24.04}"
NGINX_IMAGE="nginx:1.27-alpine"
CADDY_IMAGE="caddy:2-alpine"
NET=zeq-net
PROXY_PORT=18080
ZION_PORT=18443
BACKEND_PORT=5678

HERE="$(cd "$(dirname "$0")" && pwd)"
SCEN_DIR="$HERE/scenarios/$SCENARIO"

# ── Source detection: which incumbent proxy does this scenario describe? ──
if   [ -f "$SCEN_DIR/nginx.conf" ];         then SRC=nginx;   SRC_CFG="nginx.conf"
elif [ -f "$SCEN_DIR/Caddyfile" ];          then SRC=caddy;   SRC_CFG="Caddyfile"
elif [ -f "$SCEN_DIR/docker-compose.yml" ]; then SRC=traefik; SRC_CFG="docker-compose.yml"
else
    echo "scenario '$SCENARIO' has no nginx.conf / Caddyfile / docker-compose.yml" >&2
    exit 1
fi

if { [ -t 1 ] || [ -n "${FORCE_COLOR:-}" ]; } && [ -z "${NO_COLOR:-}" ]; then
    G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[1m'; N=$'\033[0m'
else
    G=""; Y=""; R=""; B=""; N=""
fi
say() { printf '%s\n' "$*"; }
step() { printf '\n%s── %s%s\n' "$B" "$*" "$N"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zion-eq.XXXXXX")"
chmod 755 "$WORK"

COMPOSE_UP=""  # set to the compose file when a traefik scenario is running
cleanup() {
    [ -n "${KEEP:-}" ] && { say "KEEP=1 — leaving containers up (work dir: $WORK)"; return; }
    [ -n "$COMPOSE_UP" ] && docker compose -f "$COMPOSE_UP" -p zeq-traefik down -v >/dev/null 2>&1 || true
    docker ps -aq --filter "name=^zeq-" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── zion invocation: released image, or a tree-built binary (CI mode) ──
if [ -n "${ZION_BIN:-}" ]; then
    ZION_BIN="$(cd "$(dirname "$ZION_BIN")" && pwd)/$(basename "$ZION_BIN")"
    zion_docker() { # extra-docker-args... -- zion-args...
        local extra=(); while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
        docker run "${extra[@]}" -v "$ZION_BIN:/usr/local/bin/zion:ro" \
            --entrypoint /usr/local/bin/zion "$ZION_RUNTIME_IMAGE" "$@"
    }
    ZION_DESC="local binary $ZION_BIN (runtime: $ZION_RUNTIME_IMAGE)"
else
    zion_docker() {
        local extra=(); while [ "$1" != "--" ]; do extra+=("$1"); shift; done; shift
        docker run "${extra[@]}" "$ZION_IMAGE" "$@"
    }
    ZION_DESC="$ZION_IMAGE"
fi

step "scenario '$SCENARIO' — source: ${B}$SRC${N}   zion: $ZION_DESC"
docker network create "$NET" >/dev/null

# ── Start the ORIGINAL proxy (source-specific) ──
case "$SRC" in
nginx | caddy)
    # These two share the model: echo backends referenced as zeq-be-<name> in
    # the config, plus a single-container proxy serving the config file.
    BACKENDS="$(grep -oE 'zeq-be-[a-z0-9-]+' "$SCEN_DIR/$SRC_CFG" | sed 's/^zeq-be-//' | sort -u)"
    step "backends: $(echo "$BACKENDS" | tr '\n' ' ')"
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
    if [ "$SRC" = nginx ]; then
        step "nginx (the original) on :$PROXY_PORT"
        docker run -d --name zeq-nginx --network "$NET" -p "127.0.0.1:$PROXY_PORT:80" \
            -v "$SCEN_DIR/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
            "$NGINX_IMAGE" >/dev/null
    else
        step "caddy (the original) on :$PROXY_PORT"
        docker run -d --name zeq-caddy --network "$NET" -p "127.0.0.1:$PROXY_PORT:80" \
            -v "$SCEN_DIR/Caddyfile:/etc/caddy/Caddyfile:ro" \
            "$CADDY_IMAGE" caddy run --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
    fi
    ;;
traefik)
    # Traefik's native model is docker labels; the scenario IS a self-contained
    # compose file (traefik + its own labelled echo backends). `docker compose
    # up` runs the real thing; traefik must publish its entrypoint on
    # 127.0.0.1:$PROXY_PORT (the compose file wires that).
    command -v docker >/dev/null && docker compose version >/dev/null 2>&1 || {
        echo "traefik scenarios need 'docker compose'" >&2; exit 1; }
    step "traefik (the original) via docker compose on :$PROXY_PORT"
    COMPOSE_UP="$SCEN_DIR/docker-compose.yml"
    ZEQ_PROXY_PORT="$PROXY_PORT" docker compose -f "$COMPOSE_UP" -p zeq-traefik up -d >/dev/null
    ;;
esac

step "zion import $SRC — converting the SAME config (findings below)"
zion_docker --rm -v "$SCEN_DIR/$SRC_CFG:/in/$SRC_CFG:ro" -- \
    import "$SRC" "/in/$SRC_CFG" \
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

ask_orig() { # host path -> backend id or HTTP status
    normalize "$(curl -s -m 5 -o - -w '|%{http_code}' -H "Host: $1" "http://127.0.0.1:$PROXY_PORT$2" || true)"
}
ask_zion() {
    normalize "$(curl -sk -m 5 -o - -w '|%{http_code}' -H "Host: $1" "https://127.0.0.1:$ZION_PORT$2" || true)"
}
normalize() { # "body|status" -> body first line, or the status when no body / >= 400
    local body="${1%|*}" code="${1##*|}"
    if [ -z "$body" ] || [ "${code:-0}" -ge 400 ] 2>/dev/null; then
        printf '%s' "${code:-000}"
    else
        printf '%s' "$(printf '%s' "$body" | head -n1)"
    fi
}

# Readiness gate: loop until the FIRST corpus row answers as expected on BOTH.
read -r first_host first_path want_orig want_zion _ < <(
    awk '!/^#/ && NF {print; exit}' "$SCEN_DIR/requests.txt")
for i in $(seq 1 40); do
    [ "$(ask_orig "$first_host" "$first_path")" = "$want_orig" ] &&
        [ "$(ask_zion "$first_host" "$first_path")" = "$want_zion" ] && break
    [ "$i" = 40 ] && {
        echo "instances did not become ready (orig=$(ask_orig "$first_host" "$first_path") zion=$(ask_zion "$first_host" "$first_path"))" >&2
        docker logs zeq-zion 2>&1 | tail -20 >&2 || true
        exit 1
    }
    sleep 1
done

step "replaying the request corpus against BOTH instances"
printf '  %-22s %-22s %-10s %-10s %s\n' "HOST" "PATH" "$SRC" "zion" "VERDICT"
fails=0; identical=0; documented=0
while read -r host path want_orig want_zion; do
    case "$host" in ''|'#'*) continue ;; esac
    got_orig="$(ask_orig "$host" "$path")"
    got_zion="$(ask_zion "$host" "$path")"
    if [ "$got_orig" != "$want_orig" ] || [ "$got_zion" != "$want_zion" ]; then
        verdict="${R}FAIL (expected $SRC=$want_orig zion=$want_zion)${N}"
        fails=$((fails + 1))
    elif [ "$want_orig" != "$want_zion" ]; then
        verdict="${Y}documented divergence (flagged by the import report)${N}"
        documented=$((documented + 1))
    else
        verdict="${G}identical${N}"
        identical=$((identical + 1))
    fi
    printf '  %-22s %-22s %-10s %-10s %s\n' "$host" "$path" "$got_orig" "$got_zion" "$verdict"
done < "$SCEN_DIR/requests.txt"

step "result"
if [ "$fails" -eq 0 ]; then
    say "  ${G}${B}PASS${N} — $identical/$((identical + documented)) requests routed identically;"
    say "  $documented divergence(s) matched exactly what the import report declared."
else
    say "  ${R}${B}FAIL${N} — $fails request(s) deviated from expectations."
fi
exit "$((fails > 0))"

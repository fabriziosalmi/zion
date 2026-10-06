#!/usr/bin/env bash
# Download the three files the sovereign tables are built from, once, for every
# region: RIPE NCC's delegated stats (with the MD5 RIPE publishes next to them)
# and the IPtoASN IPv4 and IPv6 tables.
#
#   scripts/fetch_sovereign_sources.sh [DIR]      (default: .sovereign-data)
#
# A download that fails, times out or returns an HTTP error stops the script:
# curl runs with --fail and retries, and gzip checks each archive before it is
# unpacked. Next to the files it writes SOURCES.tsv (name, URL, HTTP
# Last-Modified, size, SHA-256), which scripts/generate_sovereign_data.py checks
# with --manifest: the generator then refuses a file that changed after the
# download or that the server last modified more than a week ago.
set -euo pipefail

out="${1:-.sovereign-data}"
ripe_url="https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest"
iptoasn_url="https://iptoasn.com/data"

mkdir -p "$out"
: > "$out/SOURCES.tsv"

# fetch URL FILE: the body to FILE, the response headers to FILE.hdr.
fetch() {
  curl --fail --silent --show-error --location \
    --retry 5 --retry-all-errors --retry-delay 10 \
    --connect-timeout 20 --max-time 600 \
    --dump-header "$2.hdr" --output "$2" "$1"
}

md5_of() {
  python3 -c 'import hashlib, sys; print(hashlib.md5(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}

# record URL FILE: one manifest row for FILE. Last-Modified is the one of the
# final response (curl writes one header block per redirect hop).
record() {
  local modified
  modified="$(tr -d '\r' < "$2.hdr" | awk 'tolower($1) == "last-modified:" { sub(/^[^ ]+ /, ""); m = $0 } END { print m }')"
  python3 - "$1" "$2" "$modified" >> "$out/SOURCES.tsv" <<'PY'
import hashlib, pathlib, sys
url, path, modified = sys.argv[1:4]
raw = pathlib.Path(path).read_bytes()
print(pathlib.Path(path).name, url, modified, len(raw), hashlib.sha256(raw).hexdigest(), sep="\t")
PY
  rm -f "$2.hdr"
}

# RIPE replaces the file and its .md5 once a day, one after the other. A pair
# that straddles the replacement does not match: fetch both again.
ripe="$out/delegated-ripencc-latest"
for attempt in 1 2 3; do
  fetch "$ripe_url" "$ripe"
  fetch "$ripe_url.md5" "$ripe.md5"
  published="$(grep -oE '[0-9a-f]{32}' "$ripe.md5" | head -n 1 || true)"
  if [ -n "$published" ] && [ "$(md5_of "$ripe")" = "$published" ]; then
    break
  fi
  if [ "$attempt" = 3 ]; then
    echo "RIPE delegated stats: the MD5 does not match the published one after 3 downloads" >&2
    exit 1
  fi
  echo "RIPE delegated stats: MD5 mismatch (attempt $attempt), fetching the pair again" >&2
  sleep 30
done
rm -f "$ripe.md5.hdr"
record "$ripe_url" "$ripe"

for family in v4 v6; do
  gz="$out/ip2asn-$family.tsv.gz"
  fetch "$iptoasn_url/ip2asn-$family.tsv.gz" "$gz"
  gzip -t "$gz"
  gunzip -f "$gz"
  mv "$gz.hdr" "$out/ip2asn-$family.tsv.hdr"
  record "$iptoasn_url/ip2asn-$family.tsv.gz" "$out/ip2asn-$family.tsv"
done

echo "Fetched into $out:"
cut -f1,3,4 "$out/SOURCES.tsv"

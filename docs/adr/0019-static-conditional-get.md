# ADR-0019: Static file conditional GET (ETag / Last-Modified → 304)

- **Status**: accepted
- **Date**: 2026-08-02
- **Deciders**: fabriziosalmi
- **Tags**: static, caching, rfc-9110, standards

## Context

ADR-0015 shipped `mode = "static"` and explicitly deferred conditional GET
(ETag / `If-Modified-Since`) as a follow-up: v1 served every request with the
full body and no validators. That is a real regression for anyone migrating off
nginx, which revalidates static assets out of the box — a browser that already
has a file re-downloads it on every navigation instead of getting a cheap
`304 Not Modified`. This ADR closes that gap. It is the first of the ADR-0015
runtime follow-ups (range requests and streaming remain deferred).

The cache path already had the RFC 9110 §13 conditional-request logic (ADR-0018,
`dispatch::client_conditional_hit`) — but sourced from a cached representation's
stored validators. The static path needs the same decision with validators
derived from filesystem metadata instead.

## Decision

### Validators are derived from `(len, mtime)`, and the ETag is weak

On a static GET/HEAD, zion derives:

- `ETag: W/"{len:x}-{secs:x}.{nanos:x}"` — a **weak** validator. `len`+`mtime` is
  a cheap change fingerprint, not a byte-for-byte content hash, so RFC 9110
  §8.8.1 forbids treating it as strong. Weak is the honest label, and it is why
  the future `If-Range` byte-range optimization cannot reuse this tag (a
  deliberate constraint on the range follow-up, not an oversight).
- `Last-Modified:` the file mtime formatted as an RFC 9110 §5.6.7 `IMF-fixdate`.

Either validator is omitted (not fabricated) when the platform cannot supply an
mtime; the file still serves, just without revalidation.

### The 304 decision is shared, not duplicated

The `If-None-Match` (weak comparison, `*`, comma list) / `If-Modified-Since`
(exact echo) logic is factored into `http_conditional::is_not_modified`, which
takes the validators as plain `Option<&HeaderValue>`. Both callers use it:

- the cache path — `client_conditional_hit` became a thin adapter, its behavior
  pinned by the existing 10-assertion test;
- the static path — passing validators built from file metadata.

One decision function means the 304 semantics can never drift between the cache
and the file server. A matching validator returns a bodiless 304 for **both**
GET and HEAD (RFC 9110 §15.4.5); a stale or absent validator serves 200 as
before.

### The HTTP-date formatter is dependency-free

`Last-Modified` needs to *format* an mtime, which the codebase could not do —
the cache path only ever echoed the origin's date string. Rather than pull a
date crate into the core graph (the `time` crate is an optional feature, and
`mode=static` lives in the lean default build — adding a mandatory date
dependency would drag the ADR-0007 MSRV wall), `fmt_imf_fixdate` implements
Howard Hinnant's `civil_from_days` algorithm in ~25 lines, unit-tested against
canonical vectors (`Sun, 06 Nov 1994 08:49:37 GMT`, the epoch, a leap day, a
year-end rollover).

## Consequences

- **Positive**: static-asset revalidation reaches parity with nginx/Caddy, so a
  swap does not regress browser caching. Bandwidth and latency drop for the
  common "unchanged asset" case. No new dependency; core MSRV untouched.
- **Positive**: the shared `is_not_modified` removes a copy of the conditional
  logic that would otherwise drift from the cache path.
- **Neutral / risks**: the weak ETag means a same-second, same-size overwrite is
  not distinguished — acceptable for a weak validator, and the mtime nanos
  component narrows the window further on filesystems that report them. Full
  `If-Modified-Since` HTTP-date *range* comparison (vs the current exact echo)
  and `If-Range` remain follow-ups.

## Alternatives considered

- **Strong ETag (nginx-style `"{mtime}-{len}"`)** — rejected: without a content
  hash it is not truly strong, and mislabeling it would invite an incorrect
  `If-Range` byte-range reuse later. Weak states exactly what we can guarantee.
- **Add the `time` (or `httpdate`) crate** — rejected: a mandatory date
  dependency in the default build for ~25 lines of well-known calendar math, at
  the cost of the core MSRV posture (ADR-0007).
- **Duplicate the conditional logic in `static_files`** — rejected: two copies of
  a standards-sensitive decision drift. One shared function, two validator
  sources.

## References

- ADR-0015 (`mode = "static"`, which deferred this), ADR-0018 (the cache-path
  conditional logic this shares), ADR-0007 (the MSRV wall the no-dep formatter
  respects)
- RFC 9110 §8.8 (validators), §13 (conditional requests), §15.4.5 (304),
  §5.6.7 (`IMF-fixdate`)
- `src/http_conditional.rs` (`is_not_modified`, `fmt_imf_fixdate`),
  `src/static_files.rs` (`validators`, `read_file`), `src/dispatch.rs`
  (`client_conditional_hit` adapter)

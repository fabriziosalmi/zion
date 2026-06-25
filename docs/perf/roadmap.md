# Performance roadmap

What we shipped under [Track D](../../CHANGELOG.md), what's next, and the
items we intentionally deferred. Numbers in parentheses are the headroom
estimates from the original gap analysis — measure, don't trust.

## Shipped

### Sovereign log: zero-alloc hot path

Previously [`src/dispatch.rs`](../../src/dispatch.rs) called
`format!("ip={…} class={…}")` on every classified request when
`[sovereign].log_classification = true`. That's one heap allocation per
request, on the hot path, with no opt-out short of disabling the log.

The new path:

1. Always-on: bumps a per-class atomic counter
   ([`sovereign::record_classification`](../../src/sovereign/mod.rs)).
   Exposed on `/metrics` as
   `zion_sovereign_classifications_total{class="…"}`.
2. Opt-in: emits `tracing::info!` with `&'static str` label + `Display`
   for the IP. Zero allocation when the subscriber's filter rejects the
   event; format-direct-to-buffer when the subscriber accepts.

### Streaming WAF body scan (API ready, dispatch wiring opt-in)

[`waf::StreamingScanner`](../../src/waf.rs) is the chunk-by-chunk
counterpart of `validate_request`. Each call to `feed(chunk)` runs the
shared Aho-Corasick automaton over `previous_overlap || chunk` and
keeps the trailing `MAX_PATTERN_LEN - 1` bytes for the next call.
Properties:

- **Early exit**: a payload whose first chunk contains an attack
  pattern denies as soon as that chunk is scanned, regardless of total
  body size.
- **Bounded peak memory**: at most one chunk + 64 bytes of overlap is
  held at a time.
- **Boundary correctness**: a pattern straddling two chunks is matched
  via the overlap buffer. Verified by unit test
  `streaming_catches_pattern_split_across_chunks`.

Wiring into `dispatch.rs::process_request` is gated behind a future
`[waf_profile.X] streaming = true` config flag. The default path stays
buffered until benchmarks on representative workloads validate the
streaming costs.

### TLS resumption: explicit failure mode

[`tls.rs`](../../src/tls.rs) previously panicked at boot when the
platform CSPRNG refused to deliver entropy for the session ticketer.
That's now a `ZionError::Tls` with a clean exit code. The rest of the
resumption stack (`ServerSessionMemoryCache::new(16384)`, 4 TLS-1.3
tickets per connection, 0-RTT with 425-Too-Early gating, half-RTT
data, `ignore_client_order`) was already in place from v0.1.7 and is
documented inline in the source.

## Next (ready to land)

### Streaming WAF dispatch integration

Plumb `StreamingScanner::feed` into the body validation branch of
[`dispatch.rs`](../../src/dispatch.rs). Today `process_request` calls
`Limited::new(body, max_body_bytes).collect().await` and then runs the
buffered `validate_request`. Replace with a `BodyExt::frame()` loop
that feeds each frame to `StreamingScanner` and rebuilds the body for
the proxy stage on Allow.

Trade-off: the streaming variant must rebuild the body for the
proxy. Two implementation paths:

1. **Tee**: keep both the original frames and the scanner's view. Zero
   re-copy, but holds the body in memory (same peak as today). Wins on
   latency (early exit) but not memory.
2. **Re-emit**: store frames in a `Vec<Bytes>` and reconstruct
   `BodyExt::Full` from them on Allow. One extra hop on the happy
   path; saves real memory only if the scan denies.

Recommendation: ship (1) first behind `streaming = true`, measure,
then decide.

### Per-class metric labels for `zion_sovereign_classifications_total`

The renderer emits one `bucket{class="…"}` line per *enabled* class
(see [`src/sovereign/mod.rs`](../../src/sovereign/mod.rs)). The current
`classification_counts()` iterator is conditional on `geo-eu` to elide
the EU labels when the feature is off. A future `classified_at` exemplar
would link a request's W3C trace ID to the bucket — symmetric with the
latency-histogram exemplars we already emit.

## Deferred (research-level)

These items were on the original Track D list but didn't ship in this
commit. Each one has a non-trivial complexity bill that has to be paid
before the perf gain materialises.

### NUMA-aware sharding for DashMap (estimate: +5–10% on dual-socket)

`core_affinity` already pins worker threads to physical cores. The
remaining headroom is *cross-socket cache traffic on shared
`DashMap`s* — `state.rate_map`, `state.inflight`, and the L2 cache
shards.

Why deferred:

- Real NUMA topology is Linux-only (`libnuma`, `hwloc`); we'd need a
  cross-platform fallback (single-shard on macOS/Windows) and a
  feature flag to opt in.
- `dashmap::DashMap` doesn't expose per-shard placement controls; we'd
  need to fork or replace with a custom sharded lock-free hash.
- The win is multi-socket-only. Single-socket boxes (which most users
  have) gain nothing; the test harness would need a CI-runnable
  multi-socket simulation.

Path forward: write a microbenchmark that mimics
`state.rate_map`/`state.inflight` access patterns under cross-thread
contention, then reach for `papaya` or a custom sharded map only if
the bench shows the expected delta on bare-metal Linux dual-socket
hardware.

### io_uring read/write vectored, splice/sendfile (estimate: 1–2% on large payloads)

[`src/uring.rs`](../../src/uring.rs) currently uses io_uring only for
single-shot accept. Read/write vectored would reduce syscall count for
large bodies; `splice` / `sendfile` would zero-copy cacheable static
responses from the file system to the socket.

Why deferred:

- Linux-only; we need a `cfg`-gated path that doesn't break the macOS
  development experience.
- io_uring read/write needs careful integration with hyper's
  `tokio::io::AsyncRead`/`AsyncWrite` impls — not a drop-in replacement.
- The win is 1–2% on large payloads; small JSON / form bodies see no
  benefit. Premature without a workload that targets that regime.

Path forward: add a `--features io-uring-rw` flag, build a benchmark
that proxies 1 MB+ payloads and measures p99 latency, then ship if the
regression suite stays clean.

### kTLS / sendfile for TLS-terminated cacheable responses

Linux 4.13+ supports kernel TLS, allowing `sendfile()` to write
encrypted bytes straight from page cache to the socket. rustls 0.23
exposes the secret-extraction API
(`rustls::ServerConfig::enable_secret_extraction = true`), but the
plumbing into hyper and into a Linux-specific `kTLS::send_file` syscall
is non-trivial.

Why deferred: same as io_uring rw — Linux-only kernel ABI, complex
integration, win materialises only on large cacheable static
content. Documented as the natural follow-up once io_uring rw lands.

### SO_REUSEPORT + BPF demux for unified TCP/QUIC port

Today HTTP/3 (QUIC, UDP) and HTTPS (TCP) bind separate listeners on
the same `:443`. That's two kernel structures, two accept loops, two
metrics paths.

A BPF program attached via `SO_ATTACH_REUSEPORT_EBPF` can demux by
the L4 protocol byte and route to the correct listener thread.
Reduces bind overhead and aligns connection→worker affinity.

Why deferred:

- Requires writing eBPF C / Rust, loading via
  `bpf(BPF_PROG_LOAD)`, and shipping a runtime kernel-version check.
- The bind overhead is < 1% of request cost; the optimisation is mostly
  about cleaner architecture, not raw throughput.

Path forward: track upstream
[Cloudflare's Pingora](https://github.com/cloudflare/pingora) demux
patterns and lift the design once it settles in the broader Rust
ecosystem.

## Microbenchmark hygiene

Adding micro-bench targets is a Track-D-adjacent task: it's the only
way the deferred items above can be ranked objectively.
[`benchmarks/`](../../benchmarks/) currently runs end-to-end wrk
suites. We need a sibling `cargo bench` setup with `criterion` for:

- `validate_request` (buffered) vs `StreamingScanner::feed` on
  representative payloads (1 KB JSON, 1 MB form, 10 MB upload).
- `record_classification` vs the previous `format!` baseline.
- `parse_traceparent` on RFC vectors and on garbage.

This is the next-but-one Track D commit.

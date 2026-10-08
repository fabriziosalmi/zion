# Changelog

All notable changes to Zion Edge Gateway are documented here.

## [Unreleased]

### Added

- **`zion_upstream_connections_opened_total`** counts the TCP connections zion establishes to upstreams. A rate far above the request rate to the same upstreams means connections are not being reused, and each one closed leaves a local port in TIME_WAIT: this is how the churn is seen before the ports run out and requests fail with `502` (#571). An alert on its rate is the early warning. (The failure #571 reported did not reproduce on 0.10.0 or on 0.9.11: 300,000 requests walking 18,750 URLs through a 10,000-entry cache, three runs, no `5xx`, on macOS and on Linux.)

### Changed

- **A `[tls] min_version` other than `"1.2"` or `"1.3"` is now a config error.** It used to run as `"1.3"` without a word, so a `"1.1"` or a `"TLS1.2"` (meant to allow 1.2) gave TLS 1.3 only and nobody noticed. The key is checked when the file is read, with the other closed sets (`xff_mode`, `log_format`, `client_auth`, `admin.auth`), which keep their messages. A config that spells it as the docs do is unaffected. (#531)
- **Internal: the config's closed sets are types.** `xff_mode`, `log_format`, `tls.client_auth`, `admin.auth` and `tls.min_version` were strings compared at each use site; they are enums parsed when the file is read, and the use sites match exhaustively. The cross-field rules (a CA for `client_auth`, a loopback bind for `internal-ip`) stay in the validator, which is now a list of per-section checks instead of one 700-line function. `config.rs` no longer imports the pool and breaker runtime types: their conversions live next to them. Ten `allow(dead_code)` that were not needed are gone, the remaining ones carry a reason, and `scripts/check-dead-code-allows.sh` (run in CI) refuses a new one without. (#531)
- **Internal: `async_main` is a list of named boot steps.** The 800-line function that read the config, loaded TLS, built the state, started the admin API, the watchers and the listeners, and drained on shutdown is now `boot::load_config`, `load_tls`, `resolve_config`, `build_state`, `spawn_admin_api`, `bind_listeners`, `drain_and_exit` and the like, called in the same order from an `async_main` of about 90 lines. The code is the same, moved; the startup log has the same lines (checked against the previous build on a real run). (#530)
- **Internal: the request pipeline reads as a list of stages.** `process_request_inner` was a single function of about 1,060 lines. It is now 160: route lookup and upstream choice (`dispatch/route.rs`), the auth gate (`gates.rs`), the WAF stage with its body collection (`dispatch/waf_gate.rs`), the bulkhead and circuit-breaker admission, the WebSocket upgrade, the dispatch by route mode, and the trace context and access log (`dispatch/telemetry.rs`) are functions it calls in the order the code ran before. `handle_static_cache`, the cached routes' handler of about 710 lines, is `dispatch/cached.rs`: a 130-line `handle` and the stages it calls (key derivation, RAM lookup, singleflight, circuit breaker and fetch, stale-if-error and revalidation, storing). The code is moved, not changed; the gate-order tests and the end-to-end tests are untouched and pass. (#529)
- **Internal: `main.rs` no longer holds the request path.** The accept loops, the per-connection HTTPS service and the :80 handler moved to a new `accept` module (`listener` imported them from the crate root, a cycle). The :80 handler now asks the HTTPS pipeline's own function whether the target is too long, instead of a hand copy of the rule that had drifted once; the client-certificate header (strip, then set what TLS verified) is one function in `security`. The :80 length cap, which no test covered, has one now. No behaviour change. (#530)
- **Internal: `ZionBody` lives in `http_util`, and the metrics' global scope is written down.** The body type every handler returns was defined in `proxy` (the upstream client), so the security primitives, the static file server and the bulkhead depended on the client for a type; they no longer do. The architecture guide now says why the metrics stay a process-global static and what that means for tests. No behaviour change. (#532)

### Fixed

- **Internal: a test no longer fails when its three errors straddle a log window.** `an_upstream_that_closes_without_close_notify_is_counted_and_logged` asserted exactly one warning from a throttle whose 10-second windows are aligned to the clock; on a slow runner (macOS, 3 cores) the three errors landed on both sides of a boundary and gave two. It now accepts one or two, and still refuses three. (#612's macOS check failed on it.)
- **A cached megabyte now costs the process about a megabyte on Linux.** mimalloc, the global allocator, commits its arena eagerly by default; with that, the process held 1.7 to 2.1 times what `zion_cache_bytes` counts (bodies of 64 KiB, 300 KiB and 1 MiB alike), so a `cache_max_memory_mb` of N MiB held about 2N. zion now turns eager arena commit off at start-up (an operator's own `MIMALLOC_ARENA_EAGER_COMMIT` still wins). Measured: 1.03 to 1.07 times, the same as glibc's malloc. Idle and light-load resident memory also fell by about half (36 to 18 MiB serving one cached object), with no change in CPU per request or throughput on the regression harness. (#590)
- **A cache hit from a worker thread's own copy costs the same on eight threads as on one.** The per-thread copy shared its body and header values with the shared store and every other thread's copy, so each hit was ten atomic operations on cache lines the other cores were using: eight threads on one hot key paid 2,247 ns a lookup against 95 ns for one (macOS; Linux 1,042 against 178). Small bodies (16 KiB or less) are now copied into the thread's L1 at promotion, the response metadata is one `Arc` instead of four header values, and the clock is read once per hit. A lookup is now 43 ns on one to four threads (69 ns on eight, on ten cores) on macOS and 99 ns on one thread and 111 on four on Linux. The end-to-end cost of a request (about 47 us of CPU on the regression harness) does not move beyond the noise: the lookup was never a large part of it, and the change matters on a machine with many cores serving one hot object. The copies are at most 16 KiB each and outside `cache_max_memory_mb`, like the L1 entries they replace. (#577)
- **Serving a large static file costs about 15 % less CPU.** A static file above 576 KiB is streamed; the streamed path read it 64 KiB at a time through `tokio::fs::File` (two trips through the blocking pool and two extra copies per chunk). It now reads 128 KiB blocks on the blocking pool straight into the buffer the 64 KiB frames are cut from, with the same 576 KiB in-flight bound per request. On the regression harness (Linux): 1 MiB 1,780 to 1,530 us of CPU per request, 10 MiB 16.9 to 14.5 ms; the one-shot read it replaced costs 1,360 and 13.4, so the streamed path is now within 12 % of it (it was 31 %). (#564)
- **The container image no longer depends on the builder's `umask`.** Rebuilding v0.10.0's image (the first built with `rewrite-timestamp`) gave the same layers as the published one, the compiled binary included, except the one that holds `/etc/zion/zion.toml`: its file mode was `0664` under a `umask 002` and `0644` under `022`. The file is now put in place in the build stage with explicit modes (`0755` for the directory, `0644` for the file). (#538)

## [0.10.0] - 2026-10-07

**A token that expires more than 24 hours from now is refused by default: read the first upgrade note before you upgrade.** The rest is a latency fix for requests with a body to an HTTP/2 upstream on Linux, release-build reproducibility, and the last archived dependency gone.

### Upgrade notes

- **If you issue tokens that live longer than 24 hours, set `max_token_lifetime_secs` before upgrading.** `[auth_profile.x] max_token_lifetime_secs` now defaults to `86400` (it was unset, meaning no cap): a profile without it answers `403` to a token whose `exp` is further out. Set it to the longest lifetime you issue, or to `0` for no cap. If `zion_auth_long_lived_tokens_total` stayed at zero since 0.9.9, nothing changes for you. (#553)
- **Requests with a body to an HTTP/2 upstream are faster on Linux (no configuration).** They no longer wait ~40 ms on the way (see Fixed). If you sized timeouts or capacity around that latency, they now have headroom.
- No setting was removed. `h2_control_frames_per_sec` stays off by default (see Documentation).

### Changed

- **A token that expires more than 24 hours from now is refused by default.** `[auth_profile.x] max_token_lifetime_secs` now defaults to `86400` (it was unset, meaning no cap): a profile without the setting answers `403` to a token whose `exp` is further out than that (plus `leeway_secs`). This was announced in 0.9.9 (#553, step 1: a boot warning and `zion_auth_long_lived_tokens_total`). **Before upgrading**, if you issue tokens that live longer than 24 hours, set `max_token_lifetime_secs` to the longest lifetime you issue, or to `0` for no cap; if the counter stayed at zero, nothing changes for you. The first refusal each minute is logged with the token's remaining lifetime and the cap (never the token); the boot message for a profile without the setting is now informational. `zion_auth_long_lived_tokens_total` now counts the tokens accepted past 24 h under `0` or a larger cap. (#553)
- **Release builds are pinned further, and the container image can be rebuilt to the same digest.** `cargo-zigbuild` (0.23.4) and `cargo-cyclonedx` (0.5.9) are installed at the versions that built v0.9.15 instead of "latest" (zig was already 0.13.0). The image's `created` label and annotation are the commit's time, not the clock's, and the per-arch images are exported with `rewrite-timestamp=true`, so layer file times no longer carry the checkout's. Measured on two no-cache builds of one commit: the compiled binary is identical (same sha256); the image digests differ without `rewrite-timestamp` and are equal with it. The first release built this way is the next one. A weekly job (`reproducibility.yml`) now rebuilds the latest release's Linux musl binary from its tag and compares it with the published one. The Dockerfile comment that promised a bit-stable plain `docker build` is corrected. (#538)
- **`rustls-pemfile` is gone.** It is archived (RUSTSEC-2025-0134) and read every certificate and key zion loads; the advisory ignore was due to expire on 2026-12-01. PEM files are now read through `rustls::pki_types`, the parser `rustls-pemfile` itself wrapped, so what zion accepts does not change: a test records how the old crate read 41 inputs (every key kind, chains, CRLF, junk between blocks, damaged blocks) and the new reader must read them the same. Boot with every key kind (RSA PKCS#8 and PKCS#1, EC SEC1 and PKCS#8, Ed25519) is tested against the real binary. One difference an operator may see: a certificate or key path that is a directory now fails with the system's error instead of a PEM parse error. No setting changes. (#537)

### Fixed

- **A request with a body no longer waits ~40 ms on its way to an upstream (Linux).** The pooled upstream sockets did not set `TCP_NODELAY`, unlike the accepted client sockets and the WebSocket dials. zion writes a request as several small frames (HTTP/2: HEADERS, then DATA), so with Nagle on the second frame waited for the ACK of the first, which the peer's delayed ACK holds back for about 40 ms. Measured with the real binary on Linux: 40 sequential POSTs with a small body to an HTTP/2 upstream took 1,719 ms (43 ms each); with the fix, 65 ms. Eight concurrent gRPC unary calls through zion made 190 calls a second against 14,000 direct to the backend, and 7,900 with the fix. Requests without a body (a plain `GET`) were not affected, which is why the throughput benchmarks never showed it. (#618)

### Documentation

- **`h2_control_frames_per_sec` stays opt-in, with measured numbers.** Measured through zion (#561): grpc-go sends thousands of control frames a second on a fast link (one `PING` per batch of data, so the rate follows the round-trip time: 1,411 with unary calls and 1,700 on a bidirectional stream at 0.2 ms, 17,200 on loopback), so a default of `1000` would close busy gRPC connections; the C-core gRPC clients send 6 to 13, curl, nghttp, h2load and Chrome 2 to 3. The guide now says to read `zion_h2_control_frames_peak` first when gRPC is in front. The rig (`benchmarks/h2-control/`) reproduces the numbers and measures a browser. Firefox and Safari are not measured yet. (#561)

## [0.9.15] - 2026-10-07

**Reliability and visibility: things that went wrong quietly now say so, and a few that could hurt after a crash or a lost packet no longer do.** Two behaviours change; read the first two notes.

### Upgrade notes

- **A health probe that fails once no longer marks the upstream down.** An upstream now needs `unhealthy_threshold` (default `2`) failed probes in a row; one that is failing is probed again within 100 to 300 ms, so a backend that is really down is marked down a fraction of a second later than before. `unhealthy_threshold = 1` in `[upstream.x]` is the old behaviour. `healthy_threshold` (default `1`) is the number of successes in a row that brings it back.
- **A request body that breaks on the way is answered `400` (or `408` if it stalls), not `413`.** `413` now means only that the body was over the size cap. If you alert on `413`, expect it to drop to the real oversize uploads.
- No setting was removed. New, all optional: `unhealthy_threshold`, `healthy_threshold`, `client_crl_enforce_next_update` (in `[tls]` and `[admin]`, default `false`: an expired CRL keeps being applied, as before).
- New metrics: `zion_audit_prune_failures_total`, `zion_upstream_body_errors_total{kind}`, `zion_mesh_recv_errors_total`, `zion_tls_client_crl_next_update_timestamp_seconds{listener}`. Alert on the last one: `time() - zion_tls_client_crl_next_update_timestamp_seconds > 0`.

### Fixed

- **Audit retention (`[audit] max_files`) only counts and deletes the writer's own segments.** The prune took every file named `<log>.<anything>` next to the log, so an operator's `audit.log.verified` or a logrotate `audit.log.1.gz` counted toward the limit and could be deleted as the oldest. It now matches `<log>.<nanoseconds>[.<n>]` only. (#536)
- **A failed prune is logged and counted** (`zion_audit_prune_failures_total`) instead of ignored; before, a retention bound that stopped holding was visible only when the disk filled. (#535)
- **A certificate renewal killed half way no longer stops the next boot.** A renewal renames the new key into place and then the new certificate; killed between the two (a `kill -9`, a power loss), it left the new key beside the old certificate, which zion refused at boot until someone renamed the backup of the old key by hand. At boot zion now puts that key back when it matches the certificate, logs it at `WARN`, and keeps the key it replaced as `<key>.zion-unpaired`. A pair with no matching backup still refuses to boot; a running zion never restores anything. (#536)
- **One lost health probe no longer marks an upstream down.** A single failed active probe flipped a healthy upstream to DOWN and sent its traffic to `503` (or to the next pool member) until the next probe. An upstream now needs `unhealthy_threshold` failed probes in a row (default `2`; `1` is the old behaviour) and `healthy_threshold` successes in a row to come back (default `1`). An upstream with a failure not yet confirmed is probed again within 100 to 300 ms, so a backend that is really down is detected a fraction of a second later than before, not 30 s. (#540)
- **A hung renewal no longer stops renewals for good.** The `renew.sh` fallback was waited for without a limit, inside the one loop that renews the certificate. Both it and the native ACME flow now have 10 minutes; the script is killed together with what it started, and the attempt is counted as failed and retried on the backoff. (#540)
- **A client CRL that is out of date is visible, and can be made to refuse.** An expired `nextUpdate` was not enforced and not reported: the stale list kept being applied and nothing said so. That default stays (failing closed would lock out every client, the admin API included, the day whoever publishes the list stops), but zion now reports `zion_tls_client_crl_next_update_timestamp_seconds{listener="tls"|"admin"}` (the earliest `nextUpdate` in the file, refreshed at every load and reload) and logs a `WARN` naming the file when the list is expired or expires within 7 days. New opt-in `client_crl_enforce_next_update = true` (in `[tls]` and in `[admin]`) refuses every client certificate once the list has expired, until a fresh one is published. (#601)
- **A request body that breaks on the way is `400`, not `413`, and the cause is logged.** On a route with a WAF profile (buffered path) every failed body read was answered `413 request body too large`: a client reset or a malformed chunked body looked like an oversize upload in the client's error and in the status counters. Only an overflow of the size cap is `413` now; a body that did not arrive in time is `408`, and both log the cause (a few lines every ten seconds at most). (#535)
- **An HTTP/3 request that fails inside zion is logged** with the remote address, method and path, as is an HTTP/3 request body stream that breaks; before, the only trace of the `500` was the metrics. (#535)
- **The mesh gossip receiver backs off when its socket keeps failing** (10 ms doubling to 1 s) instead of retrying at full speed, logs the first failure of a run, and counts the errors in `zion_mesh_recv_errors_total`. (#535)
- **An upstream that closes its TLS session without `close_notify` is no longer silent.** When the response is delimited by the close, zion cannot tell its end from a truncation and ends the client's stream with an error (a reset over HTTP/2); nothing said why. The cut-off responses are counted in `zion_upstream_body_errors_total{kind="tls_truncated"}` (`kind="other"` for any other body failure) and the first of each in ten seconds is logged with the upstream's address. Behaviour toward the client is unchanged. (#598)

### Changed

- **Dependabot proposes Rust crate updates again, and auto-merge is narrower.** Cargo version updates were paused "for the v0.7.4 validation window" and stayed paused; they are now weekly, grouped (patch / minor), at most 3 open at once, and every pin in the `ignore` list still stands. Auto-merge, which covered patch and minor updates of everything, now covers **patch updates of cargo and npm only**; GitHub Actions, Docker and any minor or major update wait for a person. CI configuration only; nothing in the binary changes. (#537)

## [0.9.14] - 2026-10-07

**Security release: path normalization could leave a path non-canonical, bypassing per-route policy.** If you rely on Zion's per-path policy (`internal_only`, `auth_profile`, WAF profile selection) to protect content on an upstream that decodes the request path, upgrade. Advisory: GHSA-fgvc-6568-8g3c.

### Upgrade notes

- **Upgrade if you use per-route policy** (`internal_only`, `auth_profile`, per-route WAF profiles). Nothing to configure.
- **A path that one normalization pass does not bring to a canonical form is now refused with `400`.** Paths written correctly are unaffected.
- No setting was removed. The rest of this release is tests and CI (a performance regression harness in `benchmarks/regress/`, a test fix, a wider WAF-corpus path filter).

### Security

- **Path normalization is checked for canonical form, and a path that needs a second pass is refused with `400`.** zion normalizes the request path before routing, policy checks and forwarding, and the upstream decodes it once more. A path that decoding left in a non-canonical state could be routed by zion under one reading and served by the upstream under another, which bypasses route-level policy such as `internal_only`. Such paths are now refused instead of routed; a path written correctly is never affected. Found by reading the code while planning #533; the fix is tested through the real gate pipeline. If you run an upstream that serves content you protect with `internal_only`, auth or WAF profiles on specific paths, upgrade.

## [0.9.13] - 2026-10-06

**The Italian and EU address tables (`geo-ita`, `geo-eu`): what a class means changed, and so did how the tables are kept.** The official binaries and the container are built without them, so if you run those this release brings you one fix (a full `Vary` index, below). If you build with a `geo-*` feature, read the upgrade notes: two classes answer differently.

### Upgrade notes

- **If you do not build with `geo-ita` or `geo-eu`: nothing to do.**
- **A role class now needs a registration in the region, not only a curated ASN.** `datacenter_ita` holds 1.3 million IPv4 addresses where it held 9.2 million: what a curated hoster announces from space registered outside Italy is no longer Italian. `datacenter_eu` loses 17 % of its IPv4 and 81 % of its IPv6 (space registered outside the EU-27, most of it in the Seychelles); `residential_eu` loses 0.25 %, `gov_eu` 0.05 %. What leaves is `datacenter_eu` when it is registered in a member state and `unknown` otherwise. **If you deny, allow or count a datacenter class, check your rules and dashboards against this.** `gov_ita`, `residential_ita` and `eu` do not change.
- **The tables follow the weekly snapshots with a delay.** A range enters a class after 2 weekly snapshots that agree and leaves or changes after 3. New address space is classified a week later than before, and a range that really left keeps its class for two more weeks. Ranges that were announced on and off no longer flip.
- **`[sovereign.overrides]` is new**: your own class for a CIDR, read before the tables, at boot and on reload. If a row is wrong for you, this corrects it without a rebuild.
- **A build now says how old its tables are**: in the boot line, with a warning past 45 days, and as `zion_sovereign_data_snapshot_timestamp_seconds{region}`. A long-running binary will start warning; rebuild from a newer release to refresh the tables.
- **The embedded tables are the 2026-10-06 snapshot.** Wind Tre's second ASN (AS24608) is curated from this release, and its 533,504 addresses not yet in the table enter with a later refresh, as any new observation does.
- No setting was removed.

### Changed

- **The address tables are held to one pinned address per curated ASN** (#568). The tests of a table used to check three or four addresses, two of them "the first row of the class". They now hold 82: one per curated ASN, IPv4 and IPv6, each with the class it must have, plus twelve that must stay `unknown` (among them the United Kingdom, Switzerland and Norway: in Europe, not in the EU-27), a floor on every class, and no row in reserved address space. These run on every pull request, also in the default test job.
- **The weekly refresh of the Italian and EU address tables checks its sources and measures what it changes** (#568, first part). The tables behind `[sovereign]` are rebuilt every week from RIPE's delegation file and a BGP snapshot from IPtoASN, and until now whatever was downloaded was turned into a table: a truncated file, an error page or a stale copy all produced a green pull request. The generator now refuses a source that fails its own arithmetic (RIPE's record counts, date and published MD5; IPtoASN covering the address space with no hole; nothing older than a week), and both tables are cut from one download instead of two taken minutes apart. The new table is then compared with the one it replaces, address by address: a class that moves by more than a fifth stops the refresh, and one that moves by more than 2 %, or a /18 (IPv6: a /32) entering or leaving a role class, opens the pull request as a draft with the reason at the top. The pull request body is now written from that comparison: the sources and their dates, the addresses each class holds before and after, and the largest blocks that change class, each with the ASN that announces it and the country it is registered in. Nothing changes in the binary.
- **The Italian and EU address tables no longer copy one BGP snapshot** (#568). A prefix announced on and off, or moved between two ASNs of one operator, used to enter and leave the table with each weekly refresh: over nine weeks 49 runs of addresses changed class and changed back, among them a research network's /13 that was not `gov_eu` for a week and a /17 that was `datacenter_eu` for two. A run of addresses now enters a class after 2 weekly snapshots that agree, and leaves or changes class after 3; one that is observed back in its class before that is never touched. What is waiting is kept in `src/sovereign/data_<region>.pending.json`, next to the table, and each refresh pull request lists it. That memory advances only when a refresh is merged: a refresh left open is named at the top of the next one and closed in its favour. The cost is a delay: new address space is classified a week late, and a range that really left keeps its class for two more weeks. Removing an ASN from the curated list, or changing its role, is not delayed. The tables in this release are unchanged; the rule applies from the next refresh.
- **A role class is for space registered in the region: `datacenter_ita` in Italy, `gov_eu` / `residential_eu` / `datacenter_eu` in the EU-27** (#568). A role came from the ASN alone: every range a curated ASN announced had it, wherever the range was registered. OVH is on the Italian list as a hoster that operates in Italy, and 85 % of the IPv4 addresses called `datacenter_ita` were registered in France, Germany, the United States and elsewhere; 81 % of the IPv6 called `datacenter_eu` was registered outside the EU-27, most of it in the Seychelles. A range now needs both: a curated ASN and a registration in the region. `datacenter_ita` goes from 9.2 million IPv4 addresses to 1.3 million; `datacenter_eu` from 10.4 million to 8.6 million, and loses 81 % of its IPv6; `residential_eu` loses 0.25 %, `gov_eu` 0.05 %. `gov_ita`, `residential_ita` and the `eu` baseline do not change. On a `geo-eu` build 82 % of the addresses that left `datacenter_ita` are `datacenter_eu` (registered in a member state); the rest, and everything on a `geo-ita` build, is `unknown`. **If you deny, allow or count a datacenter class, check what you expect from it**: a range a European hoster announces from American or Asian registrations is no longer a European datacenter.
- **A curated ASN must also be registered where the list expects it, and a failed lookup is no longer called a drift** (#568). The weekly refresh checked each curated ASN's holder by name, which lets "Orange" in Mali pass for Orange in France: the ASN must now also be registered in Italy (Italian list, with OVH as the one named exception) or in an EU-27 country (EU list). And one RIPEstat timeout among the 48 lookups of a refresh used to stop it as "holder drift": each lookup is now tried four times, and one that still fails stops the refresh under its own name. Each refresh pull request also ends with what the curated list leaves out: the share of the region's announced IPv4 space it accounts for (84 % for Italy) and the largest origins that are not on it.
- **The curated lists, reviewed.** AS24608, Wind Tre's second ASN (549,888 IPv4 addresses), joins the Italian residential list: its ranges had no role, and a /18 that Wind Tre moved to it kept leaving the table. As an added ASN it waits two weekly snapshots like any observation, so its ranges enter with a later refresh. Hetzner (AS24940) leaves the Italian list (it stays on the EU one): it announces nothing registered in Italy. AS16265 leaves the EU datacenter list: it has announced no prefix since 2020.

### Fixed

- **With the `Vary` index full, every new varying URL cost a scan of the whole index** (#526). The index of "this URL's responses vary on these headers" is bounded like the cache. Once it was full, each cache miss on a new URL of a route that sends `Vary` swept every rule looking for expired ones (locking every part of the index), found them still alive, and was refused a place anyway: work in proportion to the index, for a request whose URL the client chooses. With 10,000 rules that was 20 µs per such miss, with a million 10 ms. A full index is now swept only when a rule can have expired and not more than once a second; in between, the refusal costs 0.2 µs whatever the size.

### Added

- **`[sovereign.overrides]`: your own class for an address or a range** (#568). The address tables are compiled in, so a row that was wrong for you needed a rebuild. A CIDR and a class in the config are now consulted before the tables, the most specific prefix first, in IPv4 and IPv6; `unknown` takes a range out of the tables. The list is read at boot and on reload. One with a mistake (a CIDR with bits set beyond its prefix, a class this build does not have, the same network twice) is refused whole with every problem named, and on reload the previous list stays in force.
- **A build with the address tables says how old they are** (#568). The tables behind `[sovereign]` are compiled in, and nothing on a running machine said which week they were from. The boot line now names the day of each table's last snapshot (`address tables: ita 2026-10-06, eu 2026-10-06`), a table more than 45 days old is a warning at boot, and `/metrics` carries `zion_sovereign_data_snapshot_timestamp_seconds{region}`, so `(time() - …) / 86400 > 45` can alert on it. The Grafana dashboard has a panel for it. Only on builds with `geo-ita` or `geo-eu`.

## [0.9.12] - 2026-10-05

**Security release: with rate limiting on, a full rate map froze the proxy.** If `rate_limit_rps` is set, upgrade: when the per-IP rate map reached `rate_limit_max_tracked_ips` a request thread could block for ever on the map, and every request behind it. Also in this release: the response cache has a memory budget, a full cache keeps far more hits, and the rate limiter no longer refuses new clients while its map is full of addresses it no longer needs.

### Upgrade notes

- **Upgrade if you use `rate_limit_rps`.** Nothing to configure.
- **The response cache now has a memory budget, on by default**: an eighth of the memory the process may use (the cgroup limit in a container), never less than 32 MiB. A cache that used to hold more than that evicts earlier. Watch `zion_cache_bytes` against the budget and `zion_cache_budget_skipped_total`; raise `[server] cache_max_memory_mb` if the hit rate drops, or set it to `0` for no budget.
- **A full cache evicts the entries stored first**, where it used to pick among the first few of its map. Hit rates under a full cache go up (57 % to 82 % in the test that found it); nothing to configure.
- **`rate_limit_max_tracked_ips` now means what its documentation said**: a new address is refused only when the map holds that many addresses seen in the current window. Before, a map at the cap could refuse new clients for up to a minute.
- **The embedded Italian and EU-27 address tables are the 2026-10-05 snapshot.** It corrects three blocks that were wrong since 0.9.2 (a research network counted as plain EU space, a residential block counted as a datacenter, an Italian residential block missing); how those tables are refreshed is under review (#568).
- No setting was removed.

### Security

- **With rate limiting on, a full rate map froze the proxy.** When the per-IP rate limiter's map reached `rate_limit_max_tracked_ips` and one of the first entries it looked at was stale, it removed that entry while still iterating over the map: the thread waited for a lock it was holding itself and never came back, and every request that needed the same part of the map waited behind it. In a test with a cap of 4, the fifth client hung and after it every request did, `/metrics` included, until restart. Reaching the cap takes 100,000 distinct client addresses within a minute by default, which one host with an IPv6 prefix can produce, so this is a way for an unauthenticated client to stop the proxy. It affects every release since 0.1.8, and only configurations with `rate_limit_rps` set (it is off by default). **Upgrade if you use `rate_limit_rps`.**

### Changed

- **The response cache has a memory budget: `[server] cache_max_memory_mb`** (#524). The cache was bounded by entries (10,000 per profile by default) and by object size (50 MiB), not by bytes: requests for distinct URLs of a cached route could make it hold entries times object size, far more than the machine has. It now keeps a count of what it holds (keys, bodies and 256 bytes per entry) and stays within a budget: a response that would exceed it evicts the entries closest to expiring, as many as it takes, and is served without being stored if room cannot be made. In a test, 200 distinct 1 MiB responses through a 16 MiB budget left 16 MiB in the cache and the process 60 MiB larger; without the budget the cache held all 200. **Upgrade note:** the budget is on by default, at an eighth of the memory the process may use (the cgroup limit in a container) and never less than 32 MiB. A cache that used to hold more than that now evicts earlier: watch `zion_cache_bytes` against the budget and `zion_cache_budget_skipped_total`, and raise `cache_max_memory_mb` if the hit rate drops. `0` turns the budget off.
- **A worker thread's own hot cache keeps small bodies only** (64 KiB or less). Those per-thread copies are outside the budget and could keep a large body alive after the shared cache had dropped it. Larger responses are served from the shared cache on every hit.

### Fixed

- **A full cache evicted the wrong entries** (#525). To make room the cache looked at the first 64 entries of its map, in the map's own order: always the same corner of it. The entries that hashed there were evicted as soon as they were stored, the popular ones among them over and over, while the rest of the cache never moved until it expired. Under a skewed load (Zipf popularity, a cache a third the size of the key set) 57 % of requests were hits. The cache now evicts the entries stored first, and the same load gives 82 %. A key stored again counts as new.
- **Storing one response made every worker throw away its own copies of all the others** (#525). Each worker thread keeps copies of small hot responses so that a hit does not touch the shared store; every store bumped one counter that invalidated all of them, on all threads. Copies are now invalidated by key (in 1,024 groups): with a second client storing new URLs continuously, 99.8 % of hits on a hot object are answered from the worker's own copy. On the test machine this did not change CPU measurably end to end (a lookup is 0.36 µs of a 28 µs request); under 8 threads on one hot key a lookup that finds its copy takes 0.96 µs against 3.3 µs when it does not.
- **An entry evicted from the shared cache could still be served from a worker's own copy** until its TTL. An eviction now invalidates the copies of that key.

- **The rate limiter turned new clients away while its map was full of addresses it no longer needed** (#528). At `rate_limit_max_tracked_ips` the limiter made room by looking for a stale entry among the first 16 of the map, always the same ones. When those belonged to clients still active, every new address was refused with `429` although the rest of the map held addresses not seen for up to a minute (the background clean-up runs every 60 s). A site with more distinct clients per minute than the cap, 100,000 by default, refused new visitors under ordinary traffic. The map is now swept in full when that look finds nothing, once per window at most (about 5 ms per 100,000 entries), so a new address is refused only when the map really holds that many addresses seen in the current window. The setting's documentation said to size it for the clients of one window; that is now what it means.

### Added

- **`zion_cache_bytes`** (gauge) and **`zion_cache_budget_skipped_total`** (counter), for the budget above.
- **`zion_cache_shared_hits_total`**: cache hits answered from the shared store; `zion_cache_hits` minus this were answered from a worker thread's own copy.

## [0.9.11] - 2026-10-05

**Security release for cached routes: one client could make a URL unanswerable for everyone, and requests could wait for ever.** If a route uses `mode = "static_cache"` or a `cache_profile`, upgrade. A client that closed its connection while its request was being fetched from the origin left that URL without an answer for every later request, until restart; and when the origin's response was not stored (a `404`, a `500`, `no-store`), only the first of the requests that had arrived together was answered. Nothing else changes in this release, and there is nothing to configure.

### Security

- **Requests to a cached route could wait for ever, and one client could make a URL unanswerable for everyone.** Concurrent cache misses for the same URL share one origin fetch: the first request fetches, the others wait for it. Three defects in that hand-over, on routes with `mode = "static_cache"` or a `cache_profile`:
  - **A client that went away while its request was being fetched left the URL dead.** The fetch was abandoned with its registration still in place, so every later request for that URL waited on a fetch that no longer existed, until the process was restarted. One request, closed before the origin answered, was enough; no authentication is involved. Present in 0.7.5, and probably in every release that coalesces requests.
  - **When the response was not stored, only the first request got it** (0.8.0 to 0.9.10). A `404`, a `500`, a response with `no-store` or one too large to cache: the request that fetched it was answered and every request that had been waiting for it hung. Six simultaneous requests for a missing asset left five clients waiting until they gave up.
  - **Under load a waiting request could miss the completion** even of a stored response (1 to 4 requests in 300,000 in a benchmark), and hang the same way.

  A waiting request now holds nothing that keeps its own wait alive, the fetch's registration is removed however the fetch ends (the request being dropped included), and completion is published so that a request arriving at that very moment sees it. Requests that waited for a response that was not stored now go to the origin themselves, together, as they would on a route without a cache. **Upgrade if you use `static_cache` or a `cache_profile`.**

## [0.9.10] - 2026-10-05

**Security release: a static route could be made to hold gigabytes by one connection.** `mode = "static"` read every file of up to 64 MiB whole into memory for each request; one HTTP/2 connection asking 100 times for a 32 MiB file held 3.2 GB for as long as it chose not to read (#562). Also in this release: the connection ceiling follows the container's memory limit, HTTP/2 control-frame floods can be bounded, the WAF can scan header values, and zion can present a client certificate to an upstream.

### Upgrade notes

- **Upgrade if a static route serves files larger than a megabyte.** Nothing to configure: files above 576 KiB are streamed. They cost more CPU per request than before (about 1.7 times at 1 MiB, measured on loopback); files of 512 KiB and less are served as they were.
- **In a container, the connection ceiling is now derived from the container's memory limit**, not from the node's RAM, so it is lower than before wherever the limit is below the node's memory (512 MiB: 1,000 connections, where a 32 GiB node used to give 31,980). The per-IP default, an eighth of the ceiling, follows. If the container really serves more connections than that, set `[server] max_connections`.
- **`max_token_lifetime_secs = 0` now means "no cap".** It used to mean a cap of zero seconds, which refused every token.
- **Heads-up: the default of `max_token_lifetime_secs` becomes 86400 (24 h) in the next minor release** (#553). Nothing is refused yet: tokens the future default would refuse are counted in `zion_auth_long_lived_tokens_total` and warned about, see below.
- The new settings (`h2_control_frames_per_sec`, `scan_headers`, the upstream mTLS settings, `max_connections`) are off or unset by default. No setting was removed.

### Added

- **The WAF can scan request header values: `[waf_profile.x] scan_headers`** (#519). The signature WAF looked at the URI and the body, never at a header, so Log4Shell in a `User-Agent` or an injection in a custom header reached the upstream. A profile can now list the headers to scan (`["user-agent", "referer", "x-*"]`; a trailing `*` is a prefix, `"*"` is every header): their values go through the same scanner as the URI, raw and decoded, and a match answers `400`. **Off by default**: measured on a corpus of 124 benign header values, `balanced` blocks none, `aggressive` blocks two (`Origin: http://localhost:3000` and a `Referer` containing `eval(`), and that corpus is not your traffic. Turn it on with `waf_shadow = true` first. The WAF guide has the numbers and suggested lists.

- **`[server] max_connections`** (#527): the connection ceiling can be set, where it was a formula clamped to 100,000 in the code. Higher for a large machine, lower for a small container; `1`..`10000000`; read at start, and a reload that changes it is refused with a message that says so. The boot log states the ceiling in force and warns when it is above what the memory would give. The hardening guide now carries what a connection costs, measured (14 KB after the handshake, 46 to 49 KB idle after a request, about 0.9 MB with a large response in flight), in place of a formula that did not match the code.

- **`[server] h2_control_frames_per_sec`: a bound on HTTP/2 control-frame floods** (#475). One HTTP/2 connection could send `PING`, `SETTINGS`, `WINDOW_UPDATE` or frames of an unknown type as fast as the network took them: each was read, the first two answered, and the connection was never closed (two million `PING`s: two million answers, 34 MB sent back). The HTTP/2 library bounds Rapid Reset and nothing else. With this setting a connection that sends more than that many control frames in a second is closed with `GOAWAY(ENHANCE_YOUR_CALM)`, counted in `zion_h2_control_flood_closed_total{reason}` and logged with the client address. Cancelling requests is not a flood (`RST_STREAM` counts only beyond the streams the connection opened: Chrome leaving a page sends a hundred at once), and neither is a download (`WINDOW_UPDATE`s are allowed in proportion to the bytes written to the client). It holds on every way into HTTP/2: ALPN `h2`, the preface on a TLS connection that negotiated nothing, and the preface on the plaintext listener. **Off by default** (`0`): the frames are counted, and the new gauge `zion_h2_control_frames_peak` shows the highest rate a connection reached, to read before choosing a limit (curl, nghttp, h2load and Chrome send 2 to 3 a second; `1000` is a safe start for them). Firefox, Safari and gRPC clients were not measured. See [Hardening](docs/security/hardening.md#http-2-control-frame-floods).

- **mTLS from zion to an upstream, and a private CA for it** (#503). `[upstream.x] client_cert_path` / `client_key_path` make zion present a client certificate to that upstream; `ca_path` names the CA that signs the upstream's own certificate (it replaces the public roots for that upstream). Until now the first two were refused (they had been accepted and ignored before 0.9.8: zion never presented a certificate), and an `https://` upstream could only have a publicly trusted certificate. The identity is used by proxied requests, pool attempts, WebSocket upgrades, cache fetches and the health probe. It is read and checked when the config is built (a key that is not the certificate's is a config error) and read again on reload: a renewed certificate takes effect with a reload, because the client is keyed by the files' contents.

### Changed

- **Auth: tokens that the future default would refuse are counted and warned about.** A profile without `max_token_lifetime_secs` accepts a token however far its `exp` is, which is what lets a mis-issued or forged token live for years. From the next minor release the default cap is 24 h. Until then: zion warns at boot for every profile without the setting, and a token with more than 24 h left on such a profile is accepted, counted in `zion_auth_long_lived_tokens_total` and reported in the log (once a minute at most; the remaining lifetime only, never the token). If the counter stays at zero the change will not affect you; otherwise set the value you need.
- **`max_token_lifetime_secs = 0` now means "no cap"**, the explicit way to keep today's behaviour after the default changes. It used to mean a cap of zero seconds, which refused every token.

### Fixed

- **The connection ceiling ignored the container's memory limit** (#527). The most connections Zion holds open is derived from memory, and the memory was read from `/proc/meminfo`, which reports the machine. In a container limited to 512 MiB on a 32 GiB node Zion derived 31,980 connections, about 8 GB at its own budget of 256 KB each: under a connection flood the kernel would kill the process long before Zion refused a connection. The cgroup limit is now read (`memory.max` and `memory.high` on cgroup v2, `memory.limit_in_bytes` on v1, on the cgroup and its ancestors, so a systemd `MemoryMax=` counts too) and the smaller of the two is used: the same container derives 1,000. The buffer sizes and the per-IP default that follow from memory follow it too, and the boot report says when a cgroup limit decided. **Upgrade note:** a container whose limit is below the node's RAM gets a lower connection ceiling than before, by design; if it really serves more connections than a quarter of its memory at 256 KB each, set `max_connections`.

- **The cron watchdog raised a false alarm when GitHub answered with old data.** On 2026-10-05 it reported three scheduled workflows as stale for a month that had succeeded within the day: the run listing filtered by `event` and `status` sometimes answers from a state weeks old (4 % of the answers in a sample). `scripts/check-cron-freshness.sh` now asks for the last scheduled success three ways, believes the most recent answer, and asks twice more before reporting a workflow as stale.

### Security

- **A static route read a file of up to 64 MiB whole into memory for every request** (#562). `mode = "static"` streamed only files above 64 MiB; anything smaller was read whole before the first byte was sent, once per request, with nothing shared between requests. One HTTP/2 connection carries 128 requests, so one client asking 100 times for a 32 MiB file made the server hold 3.2 GB, for as long as the client chose not to read; with a 60 MiB file a single connection took the process from 12 MiB to 4.6 GB. No authentication is involved, only a static route that serves a file of some megabytes. A file (or a single range) is now read whole only up to 576 KiB, which is what a streamed response holds in flight anyway, and streamed above that: the same 100 requests hold 91 MiB. Files of 512 KiB and less are served as before; files between 576 KiB and 64 MiB now take the streamed path, which costs more CPU per request (about 1.7 times at 1 MiB, measured on loopback). **Upgrade if a static route serves files larger than a megabyte.**

## [0.9.9] - 2026-10-04

**The memory growth is found and fixed, and it was a security bug.** The response cache could exceed `max_entries` without bound under concurrent requests: that is what made the nightly soak climb to 365 MiB, and it let anyone grow the memory of a `static_cache` route until the process was killed. Also in this release: the cache purge no longer trusts every private address, a client can no longer forge `X-Zion-Mesh-Score`, client certificates can be revoked, upstream credentials and config secrets stay out of the snapshot, logs and error messages, and the CLI stops running with defaults when an argument is wrong. **Upgrade if you use `static_cache` or `cache_profile`.**

### Upgrade notes

- **Cache purge from another host.** `POST /_zion/cache/purge` now answers loopback only while `[server] internal_networks` is empty. A deploy hook that purges from another host, or from the Docker host into a container, gets `403` with a body that says why: list that host in `internal_networks` (the list also applies to the read endpoints, and replaces the default for them).
- **CLI arguments are checked.** A script that passes a flag Zion never knew, or a value it never parsed, now fails (exit 2; exit 1 for `zion import`) where it used to run with defaults. The error names the argument.
- **Config error text changed.** A TOML error is now `line L, column C: message`, without the excerpt of the source line. Tooling that parsed the old multi-line form needs updating.
- **`zion import nginx`: `proxy_read_timeout` is `partial` now, not `unsupported`,** and it emits `request_timeout_ms`. A report compared against an older one will differ.
- **HTTP→HTTPS redirect on non-standard ports** now points at the HTTPS listener's port. If something relied on the old `Location` (which named the HTTP port), it was relying on a broken redirect.
- No setting was removed and no default changed apart from the purge rule above.

### Security

- **The response cache could grow past `max_entries` without bound** (#481). Once full, the cache evicted exactly one entry per insert. Threads evicting at the same moment sample the same entries and pick the same victim: all but one removal found it already gone, each thread inserted anyway, and the map grew by one entry per collision and never came back under the cap. Requests for distinct cacheable URLs sent concurrently to a `static_cache` route therefore grew memory until the process was killed; no authentication is needed, only a cached route whose key the client can vary (path or query). In a test, 8 threads and 32,000 inserts left 18,345 entries under a cap of 64; on the 2 h soak RSS climbed linearly to 365 MiB with a 2,000-entry cap. The cache now evicts until there is room (bounded work per insert), and a cache that is over its cap because a reload lowered it shrinks back, which it never did. **Upgrade if you use `static_cache` or `cache_profile`.**
- **The cache purge is loopback-only unless `internal_networks` is set** (#516). `POST /_zion/cache/purge` shared the rule of the read endpoints: with `[server] internal_networks` empty (the default) any private-range peer was let in. Behind a private-range load balancer, Kubernetes SNAT or a Docker bridge every internet client has a private address, so anyone could flush the cache; Zion only warned about it at boot. The read endpoints (`/metrics`, `/_zion/snapshot.json`, `internal_only` routes) keep their rule and the warning.
- **A client could set `X-Zion-Mesh-Score`** (#523). The header carries the mesh's reputation for the client IP to the upstream, which may use it to add friction or to trust. Zion set it when the mesh had a score, and never removed an inbound copy: a client with no score (or any client, on a build without the mesh) could hand the upstream a reputation of its own choosing. It is now dropped from every request before the pipeline sets the real value, like `X-Auth-Subject` and `X-Auth-Email`.
- **One list of reserved request headers.** The headers an upstream reads as a statement about the request were named in three places (the TLS attestations, the authenticated identity, the routing/host overrides), which is how the mesh score was missed. They are now one table (`src/reserved_headers.rs`) that says who may set each one, used by every listener, and one test walks the whole table through the real HTTPS listener.
- **Client certificates can be revoked** (#520). Neither the data plane nor the admin API had a way to refuse a client certificate that was still within its validity: a leaked one, an operator's included, worked until it expired or the CA was replaced. `[tls] client_crl_path` and `[admin] client_crl_path` take a certificate revocation list (PEM with one or more CRLs, or one DER CRL); a certificate on it is refused at the handshake, and so is one whose issuer has no CRL in the file. The file is re-read when it changes, on both listeners, so publishing a new CRL needs no restart. A CRL file that holds no CRL, or a CRL configured where no client certificate is verified, is a config error.
- **Upstream credentials no longer appear in the snapshot, the logs or config errors** (#521). An upstream URL may carry `user:pass@`. The Prometheus labels already dropped it; `/_zion/snapshot.json` and `GET /admin/config` (the same snapshot) served it verbatim to anything that passes the internal-network gate, the health and failover log lines printed it, and so did the validation messages that name a URL.
- **A rejected config no longer quotes the offending line.** A TOML error printed the source line it failed on, and serde quotes a string value of the wrong type: a typo next to `secret = "..."` or `ip_hmac_key = "..."` copied the secret to the log, to the answer of a rejected `POST /admin/config` and to the audit trail. The message is now `line L, column C: what is wrong`, with the value masked; an unknown field still names the field and the valid ones.

### Added

- **`[upstream.x] request_timeout_ms`** (#517): how long one attempt may take from sending the request to receiving the upstream's response headers. It was a fixed 30 s; that stays the default. Raise it for long-polling, slow report endpoints or uploads slower than 30 s (sending the body counts), lower it for an API that should fail fast. It applies to the single-upstream path, to every attempt of a pool, to cache fetches and to background refreshes. `1`..`3600000` ms: there is no "0 = none", because a request with no deadline holds its connection slot until the 1 h connection cap.
- **`zion import nginx` converts `proxy_read_timeout`** to `request_timeout_ms` (it was `unsupported`), as `partial`: the finding states that Zion bounds the exchange up to the response headers while nginx bounds each gap between two reads. `proxy_send_timeout` stays `unsupported` and now points at `request_timeout_ms`. Two locations that share an upstream but ask for different connect or read timeouts used to keep the first value in silence; the one that is not applied is now a `partial` finding.
- **`[admin] revocations_path`**: revoked token ids survive a restart (#522). The list of `POST /admin/revoke` was in memory only, so a restart made every revoked token valid again until it expired. With this path set, each revocation is written and synced before the API answers, and read back at boot (expired entries are dropped, the file is compacted). A list that exists and cannot be read stops the boot. Still per instance: in a fleet, revoke on every node.
- **`[auth_profile.x] previous_secret_env`**: rotate an HMAC signing key without invalidating every outstanding token. A token whose signature the current key rejects is checked against the previous one; everything else (expiry, issuer, audience) is checked the same. Remove the setting when the old tokens have expired. See "Rotating the signing key" in the auth guide.
- **`[redact] ip_hmac_key_env`**: the key of `ip = "hmac"` can come from an environment variable, like `[audit] key_env` and an auth profile's `secret_env`. With the key every logged token can be reversed by enumerating IPv4, so it should not live in `zion.toml`. The literal `ip_hmac_key` still works, is deprecated and warned about at boot; setting both is a config error.
- **`zion_cache_entries`** gauge: responses held in the shared response cache. The nightly soak asserts it stays within the cap under concurrent load, so the cause above is checked directly and not only through RSS.

### Fixed

- **A cached entry kept the upstream's read buffer alive.** hyper parses response headers without copying, so the `Content-Type`, `Content-Encoding`, `ETag` and `Last-Modified` the cache stored were slices of the connection's read buffer: every entry pinned 8 KiB or more on top of its body. With 4 KB objects the cache used about three times the memory of what it stored. The stored values are now copies.
- **The HTTP→HTTPS redirect went back to the HTTP port on non-standard ports.** The `:80` listener built `Location` from the request's `Host` as it came, port included: with `listen_http = :8080` and `listen_https = :8443` (the defaults of `zion auto`), `http://localhost:8080/` redirected to `https://localhost:8080/`, TLS on the plaintext port. A `Host` that names zion's own HTTP port is now sent to the HTTPS listener's port (omitted when it is 443). A `Host` without a port, or with a port that is not zion's (a port mapping in front), is left as it is.
- **The admin listener now follows certificate rotation.** Its TLS acceptor was built once at boot: after the server certificate was renewed, the admin API kept presenting the old one until a restart. It is rebuilt when the certificate, the admin CA or the admin CRL changes (with `[tls] hot_reload`).
- **CLI: a wrong argument is an error, not a silent default** (#518). `init`, `auto`, `suggest`, `import` and `top` used to skip any argument they did not recognise and drop any value that did not parse: `zion init -y --ouput /etc/zion/zion.toml` wrote `./zion.toml`, `zion init --https-port 70000` kept 443, `zion import traefik c.yml --var FOO` dropped the variable, all with exit 0. An unknown flag (with the nearest valid one suggested), a missing value, a value that does not parse, a value given to a flag that takes none and a stray argument now stop with exit 2 and write nothing (exit 1 for `zion import`, whose 2 stays "converted, `--strict` found findings"). `doctor` and `bootstrap` refuse arguments.
- **CLI: `--flag=value` works.** The form the docs use (`zion auto --upstream=:3000`) was an unrecognised argument, skipped; it only appeared to work because the default upstream is also `:3000`.
- **CLI: `--help` after a subcommand prints the help** (`zion init --help` used to start the wizard), and the help lists the Traefik and Caddy forms of `import` with `--var` and `--acme-email`.
- **Docs: the purge examples used plain HTTP.** `curl -X POST http://127.0.0.1/_zion/cache/purge` gets the `:80` redirect (301), not a purge; the endpoint is on the HTTPS listener. The examples now use `https://`.
- **Docs: the quick start did not start on macOS.** Its certificate command wrote an X.509 v1 certificate with LibreSSL, which zion refuses (`UnsupportedCertVersion`); it also bound `:80`/`:443` and wrote under `/etc/ssl` without saying that needs root. It now uses unprivileged ports and a local directory, and was run to the letter. Five other statements the code contradicted are corrected (TLS 1.3 "mandatory", the clippy command in CONTRIBUTING, `zion auto` on a default build, the schema-version handshake, a module doc naming a function that does not exist).
- **Two unit tests waited for a fixed number of requests, not for the condition** and failed about one full run in 25.
- **The equivalence harness compares the `Host` each proxy forwards** (nginx, Caddy, Traefik), not only which backend answered; its Traefik scenario runs on Docker Engine 29 again.

## [0.9.8] - 2026-10-03

**Security release: fixes from the 2026-10-02 code audit.** Routes with `auth_profile` are enforced by the official binaries, the gossip mesh only trusts named nodes, the admin API needs its own CA and a write token, the WAF scans GET bodies, HTTP/3 forwards client headers, and the health checker follows reloads. Several settings that used to be accepted and silently ignored or weakened are now **config errors**: read the upgrade notes before upgrading.

### Upgrade notes

Zion now refuses to start (exit code 2) or to reload when the config contains any of the following; each was accepted before and either did nothing or weakened security:

- **`auth_profile` on a build without `auth`.** The official binaries and container now include `auth` (`--features dist`), so this only affects custom builds: build with `--features auth`.
- **`[sovereign_aimp] enabled = true` without `trusted_keys`.** List every node's `node_id` (printed in full at boot) in the other nodes' `trusted_keys` *before* upgrading a mesh.
- **`[admin] auth = "mtls"` without `[admin] client_ca_path`.** The admin CA no longer comes from `tls.client_ca_path`. Admin **writes** also need `write_token_env` now (without it they get 403; reads keep working).
- **An HMAC JWT secret shorter than its hash** (32 bytes for HS256, 48 for HS384, 64 for HS512), or a **`jwks_url` over plain `http://`** to a non-loopback host.
- **An unknown `server.xff_mode` or `server.log_format`** (they used to fall back to `append` / `text`).
- **`[upstream.x] client_cert_path` / `client_key_path`** (upstream mTLS was never applied; see #503), or **`tls = true` with an `http://` URL**.
- **A route on `/healthz`, `/readyz`, `/metrics`, `/_zion/snapshot.json` or `/_zion/cache/purge`** (zion answers these itself; such a route never received a request).
- **Helm:** chart 0.3.0 requires `tls.existingSecret` (the chart used to render a config that crash-looped).

Also changed: the access log is now written by default, as documented (`[access_log] enabled = false` turns it off; it costs throughput); `[upstream.x] keepalive` now takes effect (default 128, unchanged behaviour).

### Changed

- **A route on one of zion's own endpoints is refused** (`/healthz`, `/readyz`, `/metrics`, `/_zion/snapshot.json`, `/_zion/cache/purge`). Zion answers these itself, before routing, on every host, so such a route never received a request, but it loaded without a word (the shipped `zion.example.toml`, `configs/full-stack.toml`, `examples/multi-site.toml` and the routing guide all had a `/metrics` route that looked like it forwarded to a backend). It is now a config error; the examples use `/internal/{*rest}`, and `zion import` drops (and reports) a location that would land exactly on a built-in path. Found by the 2026-10-02 code audit. **Upgrade note:** move such a route to another path.

### Added

- **Health-checker heartbeat metrics.** `zion_health_probe_rounds_total` (counter) and `zion_health_probe_last_round_timestamp_seconds` (gauge) advance on every round of the active upstream health checker, at least once a second. Nothing showed that the checker was alive (a dead or stuck one leaves failed upstreams marked up and recovered ones down); alert when `time() - zion_health_probe_last_round_timestamp_seconds` exceeds a few seconds. Found by the 2026-10-02 code audit.

### Fixed

- **HTTP/3 connections are drained on shutdown** (`--features http3`). The QUIC listener ignored the drain: it kept accepting after SIGTERM, and an idle HTTP/3 connection was never told to close, so shutdown waited for the QUIC idle timeout, close to the 30 s drain limit, on every deploy (measured: 28.1 s with one idle connection). The listener now stops accepting, each connection sends GOAWAY, finishes the requests in flight and closes (measured: exit within about 2 s, the grace a client gets to read the last responses; a request in flight at SIGTERM still gets its 200). A connection also keeps its slot until its requests are done, instead of releasing it while they still run. Found by the 2026-10-02 code audit.

- **A mesh identity seed that cannot be used is no longer overwritten** (`--features sovereign-aimp`). A seed file of the wrong length, or one that could not be read, was replaced on disk with a freshly generated identity while the log said "generating ephemeral": the node's identity changed permanently, and with `trusted_keys` the other nodes would then reject it. The mesh now refuses to start and says why; a missing file is still generated as before. Found by the 2026-10-02 code audit.

- **A failed ACME renewal is retried soon** (`--features acme`, in the release builds). After a failed renewal (or a renewed certificate that failed to load) the loop slept the same 12 hours as after a routine check, so a short-lived certificate (the 1-day bootstrap certificate `zion init` writes) got about one more attempt before expiring. It now retries after 5 minutes, doubling each time (5, 10, 20 … minutes) up to 12 hours, and logs when; a success returns to the 12-hour check. Found by the 2026-10-02 code audit.

- **Upstream error log lines say which upstream and which request.** `upstream error` / `upstream timeout` carried only the transport error text; they now end with `upstream=<scheme://host:port> trace_id=<32 hex>`, the join key to the access log, the audit record and the trace. Found by the 2026-10-02 code audit.

- **The access log is written by default, as documented.** The per-request access log is emitted under the `access` target, but the default log filter was `zion=info,warn`, so without `RUST_LOG` it was dropped: no access log at all (the opt-in `sovereign` classification log had the same problem). The default filter is now `zion=info,access=info,sovereign=info,warn`. The access log costs throughput (measured on a laptop writing to a file: about 73k → 62k req/s, noisy); `[access_log] enabled = false` (new, default `true`) turns it off. Found by the 2026-10-02 code audit.

- **The Helm chart installs** (chart 0.3.0). Its ConfigMap rendered no `[tls]` table, which `zion.toml` requires, and had no way to mount a certificate: every install crash-looped on `missing field tls` (reproduced on a kind cluster). `tls.existingSecret` (a `kubernetes.io/tls` Secret, e.g. from cert-manager) is now required and mounted; the chart refuses to render without it. Also: an HPA template (`autoscaling.enabled` defaulted to true but no HPA existed, so the Deployment ran one pod), the PodDisruptionBudget is only rendered with more than one replica (with one, `minAvailable: 1` blocked every node drain), probes go to `/healthz` / `/readyz` over HTTPS (the HTTP port answers a redirect, which always counted as healthy), and `terminationGracePeriodSeconds: 45` covers the drain. A new CI job renders the chart with every `deploy/helm/zion/ci/` values file and runs `zion doctor` on each config. On kind: the 0.9.7 chart CrashLoopBackOff, this one 2/2 Ready and serving. Found by the 2026-10-02 code audit. **Upgrade note:** set `tls.existingSecret`.

- **HTTP/3 requests reach the pipeline with their headers** (`--features http3`). The QUIC bridge rebuilt each request from its method and URI only, plus an `X-Forwarded-For` it added itself: every client header was dropped (`Authorization`, `Cookie`, `Content-Type`, `Accept-Encoding`, custom headers), so authenticated routes failed, request bodies lost their type, and the upstream got the client address twice in `X-Forwarded-For`. Measured with an HTTP/3 client against an upstream that echoes what it receives: before, `Authorization` and a custom header were missing and `X-Forwarded-For` was `127.0.0.1, 127.0.0.1`; after, both arrive and `X-Forwarded-For` has one entry, as over HTTP/2. Forged `X-Client-Cert-*` / `X-Client-TLS-*` attestations are stripped on HTTP/3 too, through one shared list now used by every listener. Found by the 2026-10-02 code audit.

- **The health checker follows config reloads.** It iterated the upstream map captured at boot: an upstream added by a hot reload or an admin push was never probed (a dead one kept receiving every request, each answered 502 after a failed connect, instead of a fast 503), an upstream removed by the reload kept being probed, and a boot config without any upstream started no checker at all. It now reads the live config's map every round, and wakes at least once a second, so a new upstream is probed within a second of the reload. Measured on the release binary: after a reload to a dead upstream, 0.9.7 never marked it down (502 per request); now it is DOWN within seconds and requests get 503 at once. Found by the 2026-10-02 code audit.

- **A pool member that never answers no longer holds requests.** The 30 s upstream request timeout applied only to single-endpoint upstreams: in a pool (`urls = [...]`), a member that accepted the connection and never answered held the request until the 1-hour connection cap, with no failover. Each pool attempt is now bounded by the same timeout; an idempotent request then moves on to the next member (one that timed out is not picked again for that request), a non-idempotent one gets 504 (it may have been processed), and a pool where every member timed out answers 504 instead of 502. Measured on the release binary with one hanging and one healthy member: 0.9.7 left 4 of 4 requests hanging past 45 s; now they are answered by the healthy member after the 30 s timeout. Found by the 2026-10-02 code audit.

### Docs

- **The build-reproduction recipe matches how releases are built** (`docs/security/supply-chain.md`). It left out `--features dist`, the Rust 1.88.0 release toolchain and the version-string variables, and compared a bare binary against `SHA256SUMS`, which lists archives, so its hash could never match. It now gives the release parameters, shows how to compare against the binary inside the archive, and says which inputs are still unpinned (zig, cargo-zigbuild) and that no CI job verifies reproducibility yet. Found by the 2026-10-02 code audit.

### Security

- **Config values that silently weakened security are refused** (found by the 2026-10-02 code audit). An HMAC JWT secret shorter than its hash (32 bytes for HS256, 48 for HS384, 64 for HS512, RFC 7518 §3.2) was accepted, which makes tokens forgeable by offline brute force; it is now refused at boot and on reload. A `jwks_url` over plain `http://` (signing keys an on-path attacker can replace) is refused unless it points at a loopback address. An unknown `server.xff_mode` ran as `append`, the most permissive mode, with only a warning, and an unknown `log_format` ran as `text`: both are config errors now. **Upgrade note:** a profile with a short secret, or a remote `http://` JWKS, will not load: generate a longer secret (`openssl rand -base64 48`), or serve the JWKS over https.

- **A request body on GET, HEAD or OPTIONS is scanned by the WAF.** On WAF routes only POST/PUT/PATCH/DELETE bodies were read and inspected; a GET with a body was validated as if empty and the body forwarded to the upstream untouched, so moving an injection from a POST body into a GET body bypassed the WAF (reproduced on the 0.9.7 release binary: 200 for the GET, 400 for the same body via POST). Any request that has a body (Content-Length or chunked on HTTP/1, an open stream on HTTP/2) now goes through the same body pipeline (size cap, content type, signatures). A GET without a body is unaffected. Found by the 2026-10-02 code audit.

- **`[upstream.x]` fields that did nothing are wired or refused** (found by the 2026-10-02 code audit). `client_cert_path` / `client_key_path` were documented as mTLS from Zion to the upstream but never read: no client certificate was presented, while the operator believed the upstream connection was authenticated. Setting them is now a config error pointing to [#503](https://github.com/fabriziosalmi/zion/issues/503) (the feature itself). `tls = true` with an `http://` URL connected in plaintext; it is a config error now (the URL scheme decides). `keepalive` was ignored (every upstream kept up to 128 idle connections): it now sizes the upstream's idle pool, default 128 (unchanged behaviour), `0` for a fresh connection per request. **Upgrade note:** remove `client_cert_path` / `client_key_path` (they never had an effect), and use an `https://` URL where `tls = true` was set.

- **The admin API needs its own CA for mTLS, and a token for every write** (found by the 2026-10-02 code audit). `auth = "mtls"` verified admin client certificates against `tls.client_ca_path`, the data-plane client CA: any certificate issued to call the gateway also opened the admin API, including config pushes. It now requires `[admin] client_ca_path`, a CA of its own (config error without it). And without `write_token_env`, any peer that passed `auth` could push a config, reload or revoke (on the loopback default, any local process); writes are now refused (403, naming the setting) unless a write token is configured, while reads keep working. Verified end to end: a data-plane client certificate is refused by the admin listener, an admin-CA one is accepted; with no token every POST gets 403. **Upgrade notes:** with `auth = "mtls"`, move the admin CA to `[admin] client_ca_path`; to keep using admin writes, set `write_token_env` (a 32+ byte secret in an environment variable) and send `Authorization: Bearer <token>`.

- **The gossip mesh accepts claims only from trusted node keys** (`--features sovereign-aimp`, experimental). The receiver verified each envelope against the public key the envelope itself carried, with no list of trusted nodes: anyone who could reach the UDP port could generate a key and inject reputation scores, which can get clients refused when `mesh_score_deny_above` is set. `[sovereign_aimp] trusted_keys` (the node ids, 64 hex characters, which each node now prints in full at boot) is now **required** when the mesh is enabled (config error otherwise; `ZION_AIMP_TRUSTED_KEYS` for the env path), and a claim from any other key is dropped before signature verification. Found by the 2026-10-02 code audit. Upgrade note: add every node's `node_id` to the others' `trusted_keys` before upgrading a mesh.

- **A route with `auth_profile` is never served unauthenticated.** The official release binaries and container were built with `--features dist` (acme + init), without `auth`: a config whose routes set `auth_profile` loaded with only a warning, and those routes answered without any token (reproduced on the 0.9.7 release binary: a "protected" route answered 200 to a request with no `Authorization`). Two changes: the release bundle now includes `auth` (`dist = acme + init + auth`), so official artifacts enforce JWT/OIDC (the same route answers 401); and a build without `auth` now **refuses** such a config (exit code 2 at boot, rejected on reload) instead of warning. Found by the 2026-10-02 code audit. If you run an official binary with `auth_profile` routes, upgrade.

## [0.9.7] - 2026-10-02

**Host release: WebSocket upgrades work against strict backends, and an upstream can receive the client's `Host`.** No breaking changes. Read the notes below.

### Upgrade notes

- **WebSocket fix, upgrade if you proxy WebSockets.** The upgrade request reached the upstream with no `Host` header; strict HTTP/1.1 servers (Go `net/http`, among others) answered it 400. Nothing to configure.
- **`preserve_host` is opt-in.** Without it, upstreams receive their own address as `Host`, as before. If you turn it on for a backend that refuses unknown hosts (Django `ALLOWED_HOSTS`), also set `health_host`, or its health probes fail and every request gets 503; zion warns at startup.
- **Re-run `zion import`** for nginx configs with `proxy_set_header Host $host`, and for Traefik and Caddy configs: the generated upstreams now forward the client's `Host` as the source did (`preserve_host = true`, with a `health_host`).

### Added

- **`[upstream.x] preserve_host`** (opt-in, #485, [ADR-0024](docs/adr/0024-preserve-host.md)): the upstream receives the client's `Host` as sent (the `:authority` for HTTP/2 clients) instead of its own address, like nginx `proxy_set_header Host $http_host` and the Traefik / Caddy defaults. For applications that check or build URLs from `Host` (Django `ALLOWED_HOSTS`, Rails host authorization, CSRF origin checks, absolute redirects, multi-tenant backends). It applies to every request sent to that upstream: `standard` routes and pool failover attempts, `sse_stream`, `static_cache` fetches and background refreshes, WebSocket upgrades and the `:80` ACME fallback. Such an upstream is spoken to over HTTP/1.1 only, because over HTTP/2 a `Host` that differs from `:authority` makes the backend reset the stream (measured: `PROTOCOL_ERROR`); TLS still verifies the upstream's own certificate name, and `X-Forwarded-Host` is still set.
- **`[upstream.x] health_host`**: the `Host` the health probe sends. A backend that refuses unknown hosts answered the probe 400, was marked down, and every request got 503; zion warns at startup when `preserve_host` is set without `health_host`. Re-applied on reload. Measured with a backend that checks `Host` like Django: without the settings every request gets 503; with `preserve_host` + `health_host`, HTTP/1.1 200, HTTP/2 client 200, cached route 200, WebSocket 101.

### Changed

- **`zion import` keeps the source's Host behaviour** (#485, PR 2). nginx `proxy_set_header Host $host` / `$http_host` (the most common directive the importer could not convert) now becomes `preserve_host = true` on the route's upstream, `$proxy_host` is Zion's default, a fixed Host stays unsupported; nginx's replace-not-merge inheritance applies, and an upstream whose locations disagree is split into `<name>` and `<name>_host`. Traefik (`passHostHeader`, default true) and Caddy (`reverse_proxy`, default; `header_up Host {upstream_hostport}` turns it off) imports now forward the client's Host as the source did, instead of silently dropping it. Each such upstream gets `health_host` from the first concrete host its routes serve. Caddy `reverse_proxy { … }` sub-directives other than `header_up Host` are now reported as unsupported instead of being dropped silently. On the real configs imported on 2026-10-02: certmate-ng nginx 22 → 12 unsupported findings, nginx-prod 33 → 25, pegaprox 16 → 14; the Traefik and Caddy imports now preserve the Host. Re-run imports of configs that rely on `Host`.

### Fixed

- **WebSocket upgrades work against strict HTTP/1.1 backends.** The upgrade request reached the upstream with **no `Host` header** and the target in absolute form (`GET http://upstream:port/path HTTP/1.1`): the handshake goes over a bare HTTP/1.1 connection, which adds nothing, after `Host` had been removed. RFC 9112 §3.2 requires a 400 for that, and Go `net/http` does: through 0.9.6 a WebSocket to a Go backend got **400**, directly it got 101 (now 101 through Zion too). The upgrade now carries the upstream's `Host` (without a default port, as ordinary proxied requests) and an origin-form target; the client's host is still sent in `X-Forwarded-Host`, also when the client wrote the target in absolute form. Found while designing `preserve_host` (ADR-0024).

## [0.9.6] - 2026-10-02

**Security release: the response cache no longer serves one host's response to another host ([GHSA-xwm8-fqm7-8m5r](https://github.com/fabriziosalmi/zion/security/advisories/GHSA-xwm8-fqm7-8m5r)).** No breaking changes. Read the notes below.

### Upgrade notes

- **Upgrade if one Zion instance runs cached routes (`static_cache`) for more than one host.** Since 0.5.0 two hosts with the same path shared one cache entry, so one host could be served another host's cached page. The cache is now keyed by host; nothing to configure.
- **Fewer origin fetches for unencoded objects.** An origin that does not compress is fetched once per object instead of once per `Accept-Encoding` value.
- **`zion import nginx`** turns `allow` / `deny` into `internal_only` (or reports it), instead of silently dropping the restriction.

### Added

- **`[server] tcp_user_timeout_secs`** (opt-in, Linux; default `0` = the kernel's own limit of about 15 minutes of retransmissions). Sets `TCP_USER_TIMEOUT` on client connections: data that stays unacknowledged, or unsent because the client's receive window is zero, for that long drops the connection. Keepalive only probes idle connections, so a client that vanishes while a response is in flight (power loss, a dropped NAT mapping) used to keep its descriptor, connection slot, per-IP slot and buffers for that long. Measured on Linux with the client's ACKs dropped: `tcp_user_timeout_secs = 10` closes the connection after 10.2 s; without it the connection was still established after 70 s. It also drops a client that stops reading for longer than the timeout (a slow reader was cut at ~26 s with a 5 s timeout), so choose a value above the longest pause you accept, for example `300`.

### Fixed

- **The response cache stores an unencoded object once, not once per `Accept-Encoding`** (#484). The key always included the client's `Accept-Encoding` set, so an origin that does not compress was fetched, and its body kept in RAM, once per distinct value (Chrome, Safari, curl, bots: typically 3–5 copies per object). A response with no `Content-Encoding` and no `Vary: Accept-Encoding` is now stored under one shared key and served to every client that accepts an unencoded body; concurrent cold requests with different encodings coalesce into one origin fetch. Encoded responses, and responses the origin marks `Vary: Accept-Encoding`, keep one entry per encoding set as before, so no client is served a coding it did not accept and a client without gzip does not make browsers get the uncompressed body. A background refresh never turns the shared entry into an encoded one, and a 304 renews the entry it revalidated. Measured on the release binary, 4 client profiles × 1,000 objects requested twice: origin fetches 4,002 → 1,002, hit ratio 50 % → 87.5 %; an nginx-style gzip origin is unchanged (4,002 fetches, 0 wrong encodings).

### CI

- **A flaky admin-API integration test is fixed at its cause** (`a_push_is_live_only_by_default` failed once in CI). The tests picked ports with "bind 0 and drop", and the kernel hands a just-released port to the next caller: two parallel tests could give two daemons the same port, the second daemon logged `Address already in use` and ran without its admin API, and the test talked to the *other* test's daemon (answers like `301`, `0`, `400`). Reproduced on Linux with `--all-features` under load (3 failures in 120 runs); a shared `free_port` now never returns a port twice per process, the daemon-booting helper waits for "listening" and retries with fresh ports when the daemon reports a taken port, and a failed push prints the server's own error. 0 failures in 180 runs afterwards. The drain tests use the same helper.

- **The cron watchdog no longer raises a false alarm for a newly added cron workflow.** `scripts/check-cron-freshness.sh` reported "never succeeded on schedule" for a weekly workflow added on a Wednesday, so every new cron opened (or kept open) the "Scheduled workflows are not running green" issue until its first Monday (#464: `concurrency` and `coverage`, added on 2026-09-30, first scheduled run 2026-10-05; both pass on PR/push). A workflow with no scheduled success is now reported `NEW` for one staleness window after GitHub first saw it, then `STALE` as before (fail-closed if its age cannot be determined). The script has a `--selftest`, run by `cargo test`.

### Docs

- **README and docs catch up with 0.9.4 / 0.9.5.** New [resilience guide](docs/guide/resilience.md) (what protects against what, where each protection sits on the request path, a combined example, what to alert on); the README Features now cover pools, outlier ejection, breaker, bulkhead, DNS last-good, drain, the log queue, `Range` / `Surrogate-Key` purge and client-IP privacy; the architecture page lists the modules added since 0.6 and the real pre-routing gate order; hardening, compliance mapping (`[redact] ip`) and the alert examples cover the new settings. The docs home page showed `Version 0.6.2`: it is now 0.9.5 and `scripts/check-version-sync.sh` / `bump-version.sh` keep it in step.

### Security

- **The response cache no longer serves one host's response to another host** ([GHSA-xwm8-fqm7-8m5r](https://github.com/fabriziosalmi/zion/security/advisories/GHSA-xwm8-fqm7-8m5r)). The cache key was path + query + `Accept-Encoding`, with no host, and the cache is shared by every route. Since host-based routing (0.5.0), two hosts with the same path on cached routes shared one entry: with `a.test` and `b.test` routed to two different origins, `b.test/page.html` was answered from the cache with **`a.test`'s body** (reproduced on the 0.9.5 release binary). A route without `hosts` serving several tenants from one origin (which answers per `X-Forwarded-Host`) had the same problem. The key now carries the request's host, normalised exactly as host routing sees it (case, port, trailing dot, HTTP/2 `:authority` or HTTP/1 `Host`); path invalidation and prefix purges still reach every host. Deployments that serve one host per Zion instance, or that do not use `static_cache`, were not affected. Upgrade if you run cached routes for more than one host.

- **`zion import nginx` no longer turns an IP-restricted location into a public route** (#483). `allow` / `deny` used to be reported as unsupported while the route was emitted without any restriction and the import exited 0: a `location /metrics { allow 10.0.0.0/8; … deny all; }` became reachable from anywhere (reproduced on a real config: `/metrics/foo` from a public IP got the backend's 200 instead of nginx's 403). The rules are now mapped to `internal_only = true`, fail-closed: a private-only allow-list converts, a narrower or public-containing list, or a bare `deny all`, becomes internal-only with a *partial* finding that says how to widen or narrow it with `[server] internal_networks`; only a block-list (`deny X; allow all;`) stays open, reported unsupported. Rules on a `server` are inherited by its locations (replace-not-merge, like nginx). A route on one of Zion's own endpoints (`/metrics`, `/healthz`, `/readyz`, `/_zion/…`) is now reported, since the backend's endpoint is not reachable there. Re-run the import of configs that used `allow`/`deny`.

- **Every open dependency advisory is closed.** `protobuf 2.28` (RUSTSEC-2024-0437, recursion DoS; experimental `sovereign-aimp` build) leaves the graph: aimp#22 builds `prometheus` without its unused `protobuf` feature and zion pins that aimp revision. `memmap2` 0.9.10 → 0.9.11 fixes RUSTSEC-2026-0186 (`ml-waf` build). `lru` (RUSTSEC-2026-0002) was already past the fix, so its stale ignore is removed. `anymap2` (RUSTSEC-2026-0319, *unmaintained*, published 2026-10-02, no fixed version; only a build dependency of `tract` under `ml-waf`) is accepted with a written reason in both `deny.toml` and `.cargo/audit.toml`. Docs toolchain: `vite` 5.4.21 → 6.4.3 via an npm override (fixes the four `vite` / `esbuild` / `launch-editor` dev-server advisories; vitepress 1.6.4 still pins vite 5) and `nanoid` 3.3.19; the generated site is text-identical on all 62 pages.

## [0.9.5] - 2026-10-01

**Operations and correctness release: deploys stop waiting on idle connections, a recovered pool member gets traffic again, client IPs can be kept out of the logs, and the cache can serve byte ranges.** No breaking changes; one fix to the 0.9.4 load balancer. Read the notes below.

### Upgrade notes

- **Pools (`p2c`): fixes a 0.9.4 starvation bug.** The load estimate only changed when a sample arrived, so a member that had been slow once, or that came back from an ejection, could stay unpicked for good at low load. If you run pools of two or more endpoints, upgrade.
- **Cached routes now answer `Range`.** A fresh cached `200` answers one byte range with `206` (or `416`) instead of the whole object, and cache hits carry the origin's `ETag` / `Last-Modified` and `Accept-Ranges: bytes`. Clients that sent `Range` to a cached route used to get the whole `200`; they now get what they asked for.
- **Shutdown is faster.** Idle keep-alive connections are closed at once on SIGTERM (HTTP/2 gets `GOAWAY`); requests in flight are still finished.
- **Client IP privacy is opt-in** (`[redact] ip`); the default writes the address as before.

### Added

- **Client IP privacy in logs** (`[redact] ip = "full" | "truncate" | "hmac"`). The client address is written to the access log, the audit trail, TLS-handshake failure lines and the sovereign classification log as it is (default), as its network (`203.0.113.0/24`, `2001:db8:1::/48`), or as a keyed irreversible token (`ip:` + 16 hex of HMAC-SHA256 under `ip_hmac_key`, stable per client). For GDPR/NIS2 retention policies. `hmac` needs a key of at least 16 bytes (validated); a missing key never degrades to the raw address; the key never appears in a debug print.

- **Range requests are answered from the cache** (RFC 9110 §14). A fresh cached `200` now answers a single `Range` (`a-b`, `a-`, `-n`) with a `206` and a zero-copy slice of the stored body, an unsatisfiable one with `416` + `Content-Range: bytes */size`, so seeking in a cached video or resuming a download no longer pulls the whole object from RAM nor reaches the origin. `If-Range` uses strong comparison, preconditions (`304`) are evaluated first, and anything else (multi-range, other units, stale/revalidated copies, non-GET) still gets the whole object. Cache hits also carry the origin's `ETag` / `Last-Modified` now and `Accept-Ranges: bytes` when they can serve ranges.

### Fixed

- **A pool member that was once slow is no longer avoided for good.** The load estimate that `p2c` uses (peak-EWMA latency) only changed when a sample arrived, so a member that had one slow period, or that came back from an ejection, kept its old estimate; with two members and low load it was never picked again, so it never got the sample that would correct it. The estimate now fades with time (half every 5 s without a sample), a new sample is folded into the faded estimate, an ejected member's estimate is dropped so it is measured afresh when it returns, and a member with no estimate is assumed to be as fast as the member it is compared with (it used to be scored with a fixed 1 ms guess, so it lost to any faster backend and stayed unmeasured: the cool-down test failed 4 runs in 5 on a release build). In a probe with one member 400 ms slow for 4 s and then healthy, the old build kept it at 0% for 40 s; the new one brings it back after about 25 s (a 200× slower period; less for a milder one).

- **Shutdown no longer waits for idle keep-alive connections.** On SIGTERM zion stopped accepting and then waited for open connections to finish, but an idle keep-alive connection never finishes by itself, so every deploy waited out its idle timeout (14 s in a probe with a single idle HTTP/1.1 connection, up to the 30 s drain limit). Connections are now told to wind down when the drain starts: idle ones close at once, HTTP/1 closes after the response in flight (`Connection: close`), HTTP/2 sends `GOAWAY` and closes once its streams are done. A request being served is finished, never cut.

## [0.9.4] - 2026-10-01

**Resilience release: pools balance on real traffic, and logging, DNS and a slow backend can no longer take the proxy down with them.** One security fix (client-supplied routing/host override headers are no longer passed upstream) and a set of opt-in or on-by-default protections. Read the upgrade notes first.

### ⚠️ Upgrade notes

- **Pools now pick a member with power of two choices (`load_balancing = "p2c"`)** instead of "lowest 30 s probe latency". Traffic spreads in proportion to speed instead of herding onto one member. To keep the old rule: `load_balancing = "lowest_latency"` on the upstream. Single-endpoint upstreams are unaffected.
- **Log lines now go through a bounded queue.** If stderr is slower than the log rate, the newest lines are dropped (counted in `zion_log_lines_dropped_total`, announced on stderr) instead of stalling requests. `[server] log_queue_lines = 0` restores synchronous writes.
- **Upstream DNS answers are kept for an hour and used if a fresh lookup fails or takes over 2 s** (`dns_stale_secs`, `dns_timeout_ms`; `0` disables / waits as long as the resolver does). A fresh lookup is always tried first.
- **Clients can no longer send `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, `X-Forwarded-Server/-Scheme/-Prefix`, `X-Host`, `X-HTTP-Host-Override` or `X-Original-Host` through zion** (a peer in `trusted_proxies` still can). If a legitimate client of yours set one of these, route it through a trusted proxy.
- Everything else is opt-in: `outlier_detection`, `max_in_flight`, and tag purge (`Surrogate-Key`) do nothing until configured or until an origin sends the header.

### Changed

- **Logging no longer blocks requests.** Log lines used to be written to stderr by the thread that logged, so a stalled pipe (journald, a container log driver) stalled the request workers. They now go through a bounded queue (`[server] log_queue_lines`, default 8192) to one writer thread; when it is full the newest lines are dropped, counted in `zion_log_lines_dropped_total` and announced on stderr. `log_queue_lines = 0` keeps the synchronous behaviour. The queue is flushed at shutdown and before a panic record.

- **Pools choose a member by what real traffic shows (power of two choices).** The latency used to pick among several endpoints came from the active prober, refreshed every 30 s, and the rule was "lowest probe latency": everything went to whichever member was fastest half a minute ago, then flipped all at once. The default is now `load_balancing = "p2c"`: two members are drawn at random and the request goes to the one with the lower `(in-flight + 1) × peak-EWMA latency`, measured on real requests (a spike counts at once, recovery is averaged in). `load_balancing = "lowest_latency"` keeps the old behaviour. Single-endpoint upstreams are unaffected.

### Added

- **Per-upstream concurrency cap** (`[upstream.x] max_in_flight`, opt-in). At most that many requests are inside the upstream at once; the next gets `503` + `Retry-After: 1` immediately instead of piling on a struggling backend. Held until the response body has been sent, read from the live config on every request (a reload applies at once and keeps the count), taken after auth/WAF and before the circuit breaker (a shed request is not an upstream failure). Applies to `standard` and `sse_stream` routes. New metrics `zion_bulkhead_in_flight`, `zion_bulkhead_limit`, `zion_bulkhead_shed_total`.

- **Purge the cache by tag (`Surrogate-Key`).** An origin can label a response with `Surrogate-Key: post-42 section:news` (space- or comma-separated); `POST /_zion/cache/purge?tag=post-42` then drops every cached entry carrying the tag, across URLs and variants. The header is not sent to clients. Tags are bounded (32 per response, 128 bytes each, 10,000 distinct) and a response whose tags cannot be tracked is not stored (`zion_cache_tag_uncached`), since a purge could not reach it. A response whose fetch began before a purge is not stored after it.

- **Upstream DNS survives a resolver outage.** Names were resolved with the system resolver on every new upstream connection and nothing else, so a failing or slow resolver (glibc waits 5 s per attempt) failed or stalled requests to upstreams whose addresses had not changed. The last good answer per host is now kept and used when a fresh lookup fails, times out (`[server] dns_timeout_ms`, default 2000) or returns nothing, for up to `dns_stale_secs` (default 3600; `0` = off). A fresh lookup is always tried first, so DNS changes still apply on the next connection. Covers the pooled client and WebSocket dials. New metrics `zion_dns_lookup_failures_total`, `zion_dns_stale_served_total`.

- **Outlier detection for pools** (opt-in: `[upstream.<name>] outlier_detection = { error_rate_pct, min_requests, window_secs, eject_secs, max_ejected_pct }`). A member whose own failure rate (502/503/504 or a transport error) is high while another member is clearly healthier is ejected for `eject_secs` (longer for repeat offenders, up to 10x). Never applied to a pool-wide outage, capped at `max_ejected_pct` of the pool, and an ejection alone never turns into a 503. New metrics `zion_upstream_inflight`, `zion_upstream_peak_ewma_seconds`, `zion_upstream_ejected`, `zion_upstream_ejections_total`.

### Security

- **Routing and host override headers from clients are no longer passed upstream.** `X-Original-URL` and `X-Rewrite-URL` (which IIS, Symfony and others honour over the real request line), `Forwarded`, `X-Forwarded-Server`, `X-Forwarded-Scheme`, `X-Forwarded-Prefix`, `X-Host`, `X-HTTP-Host-Override` and `X-Original-Host` reached the upstream untouched, so a client could steer a framework behind zion's routing, `internal_only`, WAF and auth, or poison a cache. On `:443` they are dropped by a gate before routing; the plaintext `:80` ACME fallback, which picks its route first and forwards on its own, drops them just before forwarding. Either way a peer in `trusted_proxies` keeps its values. `X-Forwarded-Host` is now always replaced with the request's own host (the `Host` header, or the URI authority for HTTP/2) and dropped when there is none. If a legitimate client of yours sets one of these, route it through a trusted proxy or add it there.

### CI

- **acme-soak: the `nonce-collision` leg** (#134). Pebble now rejects 20% of the anti-replay nonces zion presents (`PEBBLE_WFE_NONCEREJECT`); issue → renew ×5 → revoke must still complete, with up to 3 whole-operation attempts each for the rare request that exhausts instant-acme's own 3 per-request `badNonce` retries. A deterministic probe makes sure the leg cannot pass vacuously: at 100% rejection issuance must fail with `badNonce` after exactly 3 attempts. With `key-rollover` and `ttl-edge`, all three legs of #134 are in.

## [0.9.3] - 2026-10-01

**Hardening release: two security fixes, three RFC 9111 correctness fixes, and the remaining
items of the post-0.9.2 request-pipeline review.** Upgrade soon if you use route-level policy
(`internal_only`, WAF or auth profiles) or hot reload: the two security fixes below affect every
earlier release. Read the upgrade notes first.

### ⚠️ Upgrade notes

- **Paths are normalized before routing** (security fix below). Upstreams now receive
  `/a/b` where a client sent `/a//./b/../b`, and `%2e`-style escapes of unreserved characters are
  decoded. `%2F` is left alone. If an application depends on a literal `//` or a dot segment
  reaching it, it will no longer.
- **A response with `Set-Cookie` is no longer cached**, whatever its `Cache-Control`. Responses that
  used to be `HIT` after setting a cookie are now `BYPASS`.
- **A successful `POST`/`PUT`/`PATCH`/`DELETE` evicts the cache entries for its URI** (per instance).
- **Upstreams see a new `Via: <protocol> zion-XXXXXXXX` request header**, and a request that already
  names this process in `Via` is refused with `508`.
- **TCP keepalive is on by default** (60 s idle) for client connections, pooled upstream sockets and
  WebSocket dials; `[server] tcp_keepalive_secs = 0` turns it off for client connections.
- `stale-while-revalidate` and `stale-if-error` no longer serve a response whose origin sent
  `must-revalidate`, `proxy-revalidate` or `s-maxage`; `stale-if-error` now actually fires on a
  `500`/`502`/`503`/`504`.
- Everything new that is configurable (`circuit_breaker`, `normalize_query`, `max_object_mb`) is off
  or at its previous value by default.

### Security

- **A hot reload did not apply to routes a worker thread had already cached.** Each worker thread keeps a small cache of resolved routes, and nothing dropped it when the configuration was swapped. A reload that made a route `internal_only`, attached an auth or WAF profile, or changed its upstream took effect only for paths not yet in a thread's cache, i.e. not for the hot paths it was most likely meant to protect, until the entry happened to be evicted. The cache is now dropped on a thread's first request under a new configuration (one pointer comparison per request).
- **Route policy could be bypassed by how a path was written.** A request was matched to a route from its raw path, and the same raw path was sent upstream. `/open/../internal/x` matched `/open/{*rest}` (not `internal_only`) while an upstream that resolves `..` served `/internal/x`; `//internal/x`, `/./internal/x` and `/%69nternal/x` likewise slipped past a `/internal/{*rest}` route, and with it its `internal_only`, WAF and auth settings. The path is now normalized (RFC 3986 §6.2.2: decode unreserved escapes, remove dot segments, collapse `//`, keep `%2F` as data) before routing, and the normalized path is what is matched, cached and forwarded; the query string is untouched. The plaintext :80 listener, which matches its ACME-challenge paths and forwards them on its own, normalizes first too. This also merges cache entries that differed only in spelling. Upstreams will see normalized paths.

### Added

- **Circuit breaker per upstream** (opt-in: `[upstream.<name>] circuit_breaker = { error_rate_pct, min_requests, window_secs, open_secs }`). The prober notices a dead upstream every 30 s at best; until then every request waits for the origin and fails. The breaker watches real requests over a sliding window and, past the failure rate (a `502`/`503`/`504`; not `500` or 4xx), answers `503` + `Retry-After` at once for `open_secs`, then lets one probe through. On a cached route an open circuit serves the stale copy instead and holds back background refreshes. Single-endpoint upstreams only (a pool already fails over); consulted after auth and the WAF. New metrics `zion_upstream_circuit_open`, `..._trips_total`, `..._rejected_total`. Off unless configured.
- **`[cache_profile] normalize_query`** (default `false`): sort the query parameters in the cache key so `?b=2&a=1` and `?a=1&b=2` share an entry. Parameters with the same name keep their relative order, names are compared exactly, and the upstream is always sent the query as the client wrote it. Opt-in because it is only safe when the origin ignores parameter order.
- **`[cache_profile] max_object_mb`** (default `50`, unchanged; must be >= 1): the largest body a profile will store, where it used to be a fixed 50 MiB. A bigger response is streamed to the client whole and never cached; a declared `Content-Length` over the limit skips buffering altogether, and the background refresh honours it too. New counter `zion_cache_too_large`.
- **`[server] tcp_keepalive_secs`** (default `60`, `0` = off): kernel TCP keepalive on accepted client sockets (probe after the idle time, every 10 s, dead after 3), and always on for pooled upstream sockets and WebSocket dials. A peer that vanished without a FIN (power loss, a NAT that dropped its mapping) now frees its file descriptor and connection slot in about `idle + 30` s instead of waiting for an application timeout.
- **`Via` and loop detection** (RFC 9110 §7.6.3). Forwarded requests now carry `Via: <protocol> zion-XXXXXXXX` (random per process) after any earlier hop's entry, and a request whose `Via` already names this process is refused with `508 Loop Detected` ahead of the rate limiter, routing and the built-in endpoints, instead of bouncing between hops (for example an upstream that points back at zion) until a connection limit stops it. New counter `zion_loops_detected`. Upstreams will see a new `Via` request header.
- **Cache: a successful `POST`/`PUT`/`PATCH`/`DELETE` invalidates the cache entries for its URI** (RFC 9111 §4.4): the path, its query variants and every encoding/`Vary` variant, but not longer paths that start the same, plus the same-origin URIs named in the response's `Location` / `Content-Location`. Errors (status 400 and above) invalidate nothing. New counter `zion_cache_invalidations`. Per instance: replicas do not tell each other.

### Fixed

- **Cache: a response that sets a cookie is no longer stored.** Cached hits never replayed `Set-Cookie`, but they did replay the body, so a personalised page that started a session could be served to other visitors. Any response with a `Set-Cookie` header is now streamed through uncached (`X-Zion-Cache: BYPASS`), whatever its `Cache-Control`. If you relied on caching such responses, have the origin stop sending `Set-Cookie` on them.
- **Cache: stale responses are no longer served against the origin's instructions.** An entry stored from a response with `must-revalidate`, `proxy-revalidate` or `s-maxage` was still served stale by `stale-while-revalidate` (0.9.2) and `stale-if-error` (RFC 9111 §4.2.4 / §5.2.2 forbid that). They now apply only to responses that did not carry those directives.
- **Cache: `stale-if-error` actually triggers.** The transport error reached the cache as a `502` response, not an error value, so the stale copy was never used and the client got the `502`. A `500`/`502`/`503`/`504` while revalidating a stale entry now serves the stale copy (`X-Zion-Cache: STALE`), counted in the new `zion_cache_stale_if_error`.

## [0.9.2] - 2026-10-01

Cache release: `stale-while-revalidate` and per-variant caching of responses with a
`Vary`. Both are visible in `X-Zion-Cache`; read the note below before upgrading.

### ⚠️ Upgrade notes

- **Responses with a `Vary` are now cached.** A response that varies on `Accept-Language`, `Accept`, `Origin`, … used to be `BYPASS` and is now stored per variant (at most 16 per key). If an upstream sends a `Vary` but its responses must not be shared across clients that send identical values of the varied headers, mark them `Cache-Control: private` or `no-store`. `Vary: *` and varied credential headers (`Cookie`, `Authorization`) are still never stored.
- **`stale-while-revalidate`** is honoured when the origin sends it (window capped at 24 h): an entry inside the window is answered at once and refreshed in the background. Origins that do not send the directive see no change.

### Changed

- **Cache: responses with a `Vary` are now cached per variant** (RFC 9111 §4.1, #445). Before, any `Vary` other than `Accept-Encoding` made a response uncacheable. Now `Vary: Accept-Language` / `Accept` / `Origin` / … are stored under a secondary key built from the exact values of the varied request headers, at most 16 variants per key. `Vary: *` and varied credential headers (`Cookie`, `Authorization`, …) are still never stored. Responses that used to be `BYPASS` because of a `Vary` can now be `HIT`; new counter `zion_cache_vary_uncached` for storable responses refused by the Vary policy or its cap.

### Added

- **Cache: `stale-while-revalidate`** (RFC 5861, #446). An entry within the origin's `stale-while-revalidate` window is served at once (`X-Zion-Cache: STALE-WHILE-REVALIDATE`) and refreshed in the background: one refresh per key through the existing singleflight, at most 64 at a time, 30 s each, without the caller's credentials. New counters `zion_cache_swr_served`, `zion_cache_swr_refreshes`, `zion_cache_swr_refresh_failures`, `zion_cache_swr_refresh_skipped`. Without the directive nothing changes.

## [0.9.1] - 2026-09-30

Follow-up to 0.9.0: the remaining findings of the same audit. Everything new is
opt-in and defaults to the old behaviour, except one Helm check (below).

### ⚠️ Upgrade notes

- **Helm:** `persistence.enabled = true` with a `ReadWriteOnce` volume and `replicaCount > 1` (the chart default is `2`) now fails at `helm template` / `helm install` time with an explanatory message, instead of rendering a second pod that sits `Pending` on Multi-Attach. Set `replicaCount: 1`, use `ReadWriteMany`, or disable persistence.

### Changed

- **Internal: the request pipeline's pre-routing gates are now an ordered list** (`dispatch/gates.rs`, `PRE_ROUTING`) of small functions instead of ~250 lines of inline control flow in `process_request_inner` (#422). No behaviour change: the order (URI length, method, 0-RTT, rate limit, then the feature-gated sovereign / JA4 / mesh gates, then the built-in endpoints, route lookup, CORS, `internal_only`) is pinned by golden tests written against the old code first.

### Added

- **`zion audit verify <segment>...`** checks the HMAC chain of audit segments offline (#419). Exit `0` verified, `1` a segment failed, `2` usage/key error.
- **`[server] rate_limit_max_tracked_ips`** (default `100000`, unchanged) sets how many distinct client IPs the per-IP rate limiter tracks (#424). At the cap stale entries are evicted; if all are live a new IP is denied.
- **`[server] require_route_auth`** and **`[[route]] public`** (#417): with the flag on, every route must state its auth (`auth_profile`, `public = true` or `internal_only = true`) or the config is refused. Default off.
- **`[admin] write_token_env`** (#417): mutating admin calls need a bearer token; reads do not. If the variable cannot be loaded the admin listener does not start.
- **`[admin] persist_push`** (#419): a validated `POST /admin/config` is written back to `zion.toml`. Default off.
- **`POST /admin/revoke`** (#418): deny a JWT by `jti` until its expiry. In-memory and per instance; only tokens with a `jti` can be revoked.
- **`ml/requirements.lock`** (#420): a hashed, universal (all platforms) lock made with `uv pip compile`. The `pip-audit` job now audits it with `--require-hashes` instead of `--no-deps`, so transitive advisories are covered.

### CI

- The stability-soak gate no longer fails healthy builds: its fd-drift limit now follows the run's own noise, and the verdict has a self-test against real runs with injected leaks (#443).
- New informational `coverage.yml`; `concurrency.yml` (Miri + ThreadSanitizer) now runs on the nightly toolchain; the `version-sync`, `readme-stats-sync` and `gitleaks` jobs have unambiguous names.

### Fixed

- A failed cert rename in `write_cert_key_atomic` now puts the previous key back, so a partial write never leaves a new key beside the old cert (#423).
- **Helm:** `persistence.enabled` with a `ReadWriteOnce` volume now renders a fixed `replicas`, and refuses `replicaCount > 1` at template time instead of leaving the second pod `Pending` on Multi-Attach (#424).

## [0.9.0] - 2026-09-30

**Audit remediation.** Closes the findings of the 2026-09-30 code audit: the
request pipeline and config schema are restructured so illegal states cannot be
built, the audit log survives power loss and shutdown, and the reload and upstream
paths are observable. This is a **MINOR** release because several checks that used
to warn (or pass silently) now refuse to start or to parse. Read the upgrade notes
before deploying.

### ⚠️ Upgrade notes

Things that used to boot and now do not, or that behave differently:

- **`[audit] enabled = true` needs a valid key.** An unset or empty key variable, a
  key under 32 bytes, or a missing `path` is now a boot error (was a warning and a
  silently disabled audit log). The library's `audit::spawn_writer` returns a
  `Result` and an `AuditWriter` to shut down.
- **`admin.auth = "internal-ip"` requires a loopback `admin.listen`.** A routable or
  wildcard bind now needs `admin.auth = "mtls"`.
- **A reload that changes `tls.cert_path` / `tls.key_path` is rejected**, and so is
  one that moves `listen_https` in the `io-uring-accept` build. Both need a restart.
- **`connect_timeout_ms` is now enforced.** It was parsed and ignored; a value below
  your upstream's real connect latency will now cause failovers.
- **Contradictory settings are refused when the config is parsed:** `waf = true` with
  a `waf_profile`, a route-level `max_body_mb` with a `waf_profile`, a static route
  without `serve_dir` (or with `upstream`), static-only keys on a proxy route, an
  `[upstream.*]` with neither `url` nor `urls`, and `schema_version = 0`. Errors now
  read `Invalid TOML in <file>` and report the first problem, not all of them.
- **The plaintext `:80` ACME-challenge fallback** only serves routes with no
  `auth_profile`, no `internal_only` and a real upstream (not `mode = "static"`).
  Serve challenges for an external ACME client from a public route.
- **Text logs on a non-TTY** now start with a UTC timestamp, level and event
  (`2026-09-30T06:26:36Z INFO  config: ...`). JSON logs and TTY output are unchanged.
- A literal JWT `secret` in `zion.toml` now logs a deprecation warning; use
  `secret_env`.

New, opt-in: `[audit] sync_interval_ms`, `key_id`, `previous_key_env`; `[server]
internal_networks`; `[auth_profile.*] leeway_secs`, `max_token_lifetime_secs`.

### Security

⚠️ **Behaviour change (stricter startup).** With `[audit] enabled = true`, Zion now
**refuses to start** when the HMAC key variable is unset/empty, when the key is
under 32 bytes, or when `path` is missing. Previously it logged a warning and ran
with the audit log silently disabled (a typo in `key_env`, or a missing secret
mount, removed the tamper-evident trail with no signal). `spawn_writer` in the
library now returns a `Result`. Fix the key (or set `enabled = false`) before
upgrading.

- **Audit log shutdown drain.** The writer is now stopped explicitly after the
  connection drain: it writes everything still queued, flushes and fsyncs, and
  Zion waits up to 5s. Before, a SIGTERM with a backlog (up to `queue_depth`
  events) dropped the runtime and lost the newest events.
- **Audit writer liveness.** New `zion_audit_enabled`, `zion_audit_writer_up`,
  `zion_audit_write_failures_total` and `zion_audit_last_write_timestamp_seconds`.
  A writer that died on a disk-full error is now distinguishable from a full
  queue (the drop counter alone could not tell them apart), and is logged once.
- **Audit key identity and rotation.** New `[audit] key_id` (default: a derived
  fingerprint) is written into every chain marker, and `previous_key_env` lets the
  writer verify the tail of a segment signed with the outgoing key across a
  rotation. Documented rotation procedure in the observability guide.
- **JWT:** `aud` may be an array (such tokens were rejected because the claim only
  deserialized as a string). New `leeway_secs` (default 30, max 300) and
  `max_token_lifetime_secs` (reject tokens whose `exp` is too far out; there is
  still no revocation list). A literal `secret` is deprecated (boot warning) and
  is now redacted from `Debug` output.
- **Secrets are wiped on drop** (audit HMAC key, JWT secrets, mesh identity seed)
  via the `zeroize` crate, already in the dependency graph. The mesh identity seed
  is now checked on load: a seed readable by group/other is tightened to `0600`
  (or, if that fails, replaced), with a warning. The systemd unit sets
  `LimitCORE=0`. Not covered: copies inside `hmac::Key` / `jsonwebtoken`, and the
  process environment itself.

### CI

- **Miri and ThreadSanitizer over the concurrent code** (`.github/workflows/concurrency.yml`,
  weekly, on demand, and on PRs touching those modules). Miri interprets the pure
  atomics/data-structure tests (connlimit, health/backoff, tarpit, rate limiter,
  metrics, the NUMA map); TSAN runs the real threaded tests, including the async audit
  writer, the L1/L2 cache, hot reload and the chaos suite, with std rebuilt under the
  sanitizer. Both are clean today. Nothing was suppressed: the only reports we saw
  came from mimalloc (which neither tool understands), so both tools build with the
  system allocator (`cfg(miri)` / `--cfg zion_tsan` in `src/main.rs`). Not covered:
  loom models of the health state machine, and the async audit tests under Miri (its
  IO driver support is limited). Verified locally on macOS and on Linux x86_64 (Miri
  and TSAN both clean); the first run on a GitHub runner is still pending.

### Config schema

⚠️ **Behaviour change (stricter parsing).** Contradictory route and upstream
settings are now refused when the config is *parsed*, instead of being accepted and
silently ignored (or rejected only by a later validation step):

- `waf = true` together with a `waf_profile` on one route (the profile won and
  `waf = true` did nothing), and a route-level `max_body_mb` next to a
  `waf_profile` (the profile's own cap applied). A `max_body_mb` on a WAF-off route
  is still only a boot warning.
- A static route with no `serve_dir`, a static route that sets `upstream`, and a
  proxy route that sets `serve_dir` / `spa_fallback` / `precompressed`. The
  messages are unchanged; they now surface as `Invalid TOML in <file>` and, being
  parse errors, report the first problem rather than all of them.
- An `[upstream.*]` table with neither `url` nor `urls`. If both are written they
  are still merged (`urls` first, then `url`).
- `schema_version = 0`. An unversioned file is now defined as **schema 1** (before:
  "compatible with whatever"), and every supported version has a reader in
  `upgrade_schema`, enforced by a test, so bumping the current version without one
  fails the build.

Internally `RouteConfig` is now a validated type (`RouteTarget` = upstream *or*
static directory, `WafPolicy`), and `UpstreamConfig` holds a single non-empty
endpoint list. The TOML surface is unchanged. All 15 example configs shipped in
the repo and every route/upstream block in the docs were checked against the new
parser.

### Access control

- **`:80` ACME fallback no longer bypasses auth.** An unmatched
  `/.well-known/acme-challenge/*` request on plaintext port 80 was proxied straight
  to the matching route, skipping the JWT gate, `internal_only`, the WAF and the
  `X-Auth-*` scrub, so a client could reach an authenticated upstream with a forged
  `X-Auth-Subject`. It is now used only for a route with no `auth_profile`, no
  `internal_only` and a real upstream (a static route's placeholder upstream is
  `127.0.0.1`, which the old code would have proxied to), and inbound `X-Auth-*` is
  stripped. Serve external-client challenges from a public route.
- **⚠️ `admin.auth = "internal-ip"` requires a loopback `admin.listen`.** The peer
  it trusts can replace the whole running config, and behind a container bridge
  every client looks private. A routable/wildcard bind with `internal-ip` is now a
  startup error; use `mtls` for those. The default (`127.0.0.1:9180`) is unchanged.
- **New `[server] internal_networks`** (CIDR allowlist) for `/metrics`, the snapshot,
  `/_zion/cache/purge` and `internal_only` routes, whose built-in rule is "any
  private-range peer" (network position, not identity). Unset keeps the old
  behaviour, so nothing changes until you opt in. Zion now warns at boot when a
  non-loopback listener has neither `internal_networks` nor `trusted_proxies`, the
  shape where a private-range load balancer makes every client look internal.
  Invalid CIDRs are rejected at load.

### Observability

- **Config reload failures are visible.** `zion_config_reload_failures_total` and
  `zion_config_last_reload_success_timestamp_seconds`: a rejected or panicked
  reload (file watcher and admin API) left the old config serving with nothing on
  `/metrics`, and `zion_config_generation` cannot tell "rejected" from "nobody
  reloaded".
- **Per-upstream health on `/metrics`.** `zion_upstream_up{upstream}` (one series
  per configured upstream, read live, sorted; userinfo stripped from the label)
  and `zion_upstream_failovers_total`. Previously an ejected backend or a silent
  failover was visible only in the JSON snapshot and the TUI.
- **Text logs are orderable off a terminal.** When stderr is not a TTY, text-mode
  lines are `<UTC timestamp> <LEVEL> <event>: <message>`; on a TTY they are
  unchanged. JSON mode is unchanged.

### Changed (behaviour)

- **`connect_timeout_ms` is now enforced.** It was parsed and defaulted to 3000 but
  never applied, so a black-holed upstream (packets dropped, no RST) cost the full
  30s request timeout on every HA failover attempt. It is now set on the HTTP
  connector (one client per distinct value, created on first use so pools survive
  reloads); `0` disables it. It covers the TCP connect only. Measured on a
  black-holed address: 0.31s with a 300ms deadline, versus running to the
  10s test cap without one. Configs that set an aggressive value now fail over
  that fast, which is the point, but a value below your upstream's real connect
  latency will now cause failovers.
- **`--features io-uring-accept`: a reload that moves `listen_https` is now
  rejected** (was: accepted, and only warned by the supervisor, leaving the running
  socket contradicting the published config).
- **A reload that changes `tls.cert_path` / `tls.key_path` is now rejected** (was:
  accepted with a WARN while the TLS watcher kept watching the boot-time paths, so
  renewals at the new path were never picked up). The running config is untouched;
  change the paths with a restart.

### Fixed

- **Audit log: bounded power-loss window.** Records were only flushed to the OS
  page cache, so a power loss or kernel crash could drop an unbounded tail with no
  marker that anything was lost. The writer now `fsync`s the active segment every
  `[audit] sync_interval_ms` (default 1000; `0` restores the old page-cache-only
  behaviour), always `fsync`s a segment before sealing it at rotation, and
  `fsync`s the directory after the rename.
- **Audit log: restarts leave a checkable trail.** The `chain_init` marker written
  at start now records the verified head of the chain already on disk
  (`prev_head=<hmac>; prev_seq=<n>`, or `none` / `unverified`), so removing the end
  of an earlier chain after a restart is detectable. The chain itself still
  restarts at genesis (ADR-0017). A segment that ended mid-record no longer gets
  the marker glued onto the fragment; the fragment is closed with a newline.
- **`zion init` and `zion import -o` replace `zion.toml` atomically** (temp file,
  fsync, rename) instead of truncating it in place, so a kill or `ENOSPC`
  mid-write no longer leaves an empty or partial config where the daemon and its
  hot-reload watcher read it. An existing file keeps its permissions and a
  symlinked path is written through; a new file is `0644`.

### Changed

- **Internal module boundaries (no behaviour change).** The crate root
  (`main.rs`) no longer doubles as the shared kernel: `AppState`,
  `ResolvedAppConfig` and the per-source limiters moved to `state.rs`, and the
  request-ID/response helpers to `http_util.rs`, so `dispatch`, `listener`,
  `admin`, `quic`, `tls_fp` and `reload` depend on those modules instead of the
  file that wires them. Route resolution (`ResolvedRoute`, `HostRouter`,
  `build_router`) moved from `config.rs` to `routing.rs`, leaving `config.rs` as
  the serde schema plus validation. The 18 unit tests that exercise routing
  internals moved with the code; the test count is unchanged (913).
- Fix the `ResolvedAppConfig` doc comment, which still described the config
  snapshot as a plain `Arc` with no swap; it is `Arc<ArcSwap<..>>` and is
  reloaded by the `reload.rs` watcher.

## [0.8.4] - 2026-09-08

**ACME renewal-loop liveness + owner-only cert-key writes.** A confirming
re-audit of v0.8.3 (raw quality "Strong", all prior fail-opens verified fixed)
flagged one HIGH — a silent-failure observability gap — and one at-rest MEDIUM.
Both are closed here. No behaviour change for a correct config.

### Fixed

- **ACME renewal loop now exposes a liveness heartbeat**: the renewal counters
  (`zion_acme_renewals_total` / `_failures_total`) only advance on an actual
  attempt, so a *dead* renewal loop was indistinguishable from the normal
  months-long idle steady state — the certificate could silently expire with no
  signal. The loop now advances `zion_acme_loop_checks_total` (a monotonic
  iteration counter) and sets `zion_acme_loop_last_check_timestamp_seconds` (a
  heartbeat gauge) on **every** ~12h wake-up, including the no-op case. Alert on
  `time() - zion_acme_loop_last_check_timestamp_seconds` exceeding the check
  interval, or on `rate(zion_acme_loop_checks_total[1d]) == 0`.
- **`zion init` / `zion auto` write the serving TLS private key owner-only**:
  the generated key was written via a bare `std::fs::write` (default umask,
  typically world-readable `0644`), unlike the hardened `0600` atomic path
  already used for the ACME account and mesh identity keys. Both now use
  `write_cert_key_atomic` (created `0600`, never wider even in transit).

## [0.8.3] - 2026-09-08

**Fail-closed security fixes.** A deeper re-audit of v0.8.2 surfaced two HIGH
fail-opens (one a residual gap in the v0.8.0 AIMP-listen fix); this closes both.
No behaviour change for a correct config.

### Fixed

- **AIMP mesh empty listen no longer binds `0.0.0.0`** (closes the v0.8.0
  `sovereign_aimp.listen` gap): an enabled mesh with no `listen` (and no
  `ZION_AIMP_LISTEN`) fell back to `0.0.0.0:9443` — the gossip control plane on
  every interface. v0.8.0 rejected only a *malformed* listen, not an empty one.
  The unconfigured case now defaults to **loopback** (`127.0.0.1:9443`); set
  `listen`/`ZION_AIMP_LISTEN` explicitly to expose it on a real interface.
- **mTLS `client_auth` without a CA is rejected at boot**: `client_auth =
  "required" | "optional"` with no `tls.client_ca_path` silently built the
  listener with **no client auth** — the enforcement the operator asked for was
  off with no signal. Config validation now rejects it (mirrors the existing
  `admin.auth = "mtls"` check), and also rejects an unknown `client_auth` value
  (a typo previously coerced to `"none"`).
- **docs**: correct the connection-limit formula in the architecture guide
  (`/50` → `/256`, ~256 KB/conn) and tag the AIMP mesh **experimental** in the
  README (it already was in the guide).

## [0.8.2] - 2026-09-08

**Audit quick-wins.** Low-risk residual findings from the re-audit (which scored
75.8/100, 0 critical/high); the larger items are tracked as issues (#417–#424).
No breaking changes.

### Fixed

- **docs**: the inline systemd unit in the deployment guide now includes
  `StateDirectory=zion` (it had drifted from the shipped `deploy/zion.service`,
  reintroducing the read-only `/var/lib/zion` write-path trap for anyone
  transcribing it); the ACME `state_dir` doc comment now says
  `/var/lib/zion/acme` (was `/etc/zion/acme`, contradicting the code default);
  the Docker recipe is flagged as illustrative/root vs the shipped distroless
  non-root image; the AIMP mesh is marked experimental in the guide.
- **observability**: a local WAF-block that can't be gossiped (publish queue
  full / control plane not bootstrapped) now increments a new
  `zion_mesh_claims_dropped_publish_total` counter instead of dropping silently;
  the `publish_block` docstring corrected to match.

### Changed

- **perf**: CORS requests validate the `Origin` once (reuse the pre-computed
  allow-origin) instead of calling `check_origin` — and re-lowercasing the
  origin — a second time per request.
- **build**: the container image carries an `org.opencontainers.image.revision`
  (commit sha) label.

## [0.8.1] - 2026-09-08

**Container-build hotfix.** v0.8.0 published all binary artifacts, SBOM and
checksums, but both container-image builds failed — so the multi-arch manifest
and cosign signing were skipped and no signed `ghcr.io/fabriziosalmi/zion:0.8.0`
was published. The v0.8.0 binaries are unaffected; this release re-runs the full
pipeline and ships the signed container. No code changes beyond the build fix.

### Fixed

- **Container build compiles again** (regression from the 0.8.0 `build.rs` git
  stamp): the stamp used the compile-time `env!("ZION_GIT_SHA")`, but the
  Dockerfile's selective `COPY` never included `build.rs`, so inside the
  container there was no build script and the macro failed with "environment
  variable not defined at compile time". Now `option_env!` (compiles to
  `"unknown"` if the script did not run), `build.rs` is copied into the image,
  and `release.yml` passes the commit sha/date as build-args so the container
  keeps real `--version` / `zion_build_info` provenance.

## [0.8.0] - 2026-09-08

**Security & robustness hardening.** A full code-metrics audit of v0.7.6 scored
39/100 ("Poor"), capped by a CRITICAL non-atomic ACME key/cert write and a weak
state-integrity posture. This release remediates the CRITICAL, every
high-severity finding, and ~all medium/low ones (0 critical / 0 high remain);
the re-audit of this commit scores **75.8/100 ("Strong")**. Most changes are
internal hardening, but several tighten config validation to **fail closed** —
configs that were silently accepted before may now be rejected at boot. Read the
Breaking section before upgrading.

### ⚠️ Breaking (config validation — fail closed)

- **JA4 enforcing allowlist**: `[tls.fingerprint] mode = "allowlist"` with
  `on_unknown = "drop"` now **refuses to boot** unless `on_unfingerprintable`
  is also `"drop"` — the old default (`"allow"`) let a client bypass the
  allowlist with an unfingerprintable ClientHello. Set `on_unfingerprintable =
  "drop"`, or use `on_unknown = "log_only"` / `mode = "shadow"` to observe.
- **`sovereign_aimp.listen`**: a malformed value is now a validation error
  instead of silently binding the gossip control plane to `0.0.0.0:9443`.
- **Route/upstream integrity**: a name defined in both `[upstream.X]` and
  `[upstreams]`, a `mode = "static"` route with an `upstream`, or a non-static
  route with `serve_dir`/`spa_fallback`/`precompressed` are now rejected rather
  than silently ignored.
- **Helm**: the container now binds unprivileged `8080/8443` by default (the
  Service still presents `80/443`); override `containerPorts` + add
  `NET_BIND_SERVICE` if you need privileged in-container ports.
- **Release toolchain** pinned to Rust 1.88.0 (was "latest stable").

### Security

- **Atomic, owner-only secret/state writes** (`src/atomic_file.rs`): the ACME
  account key, the renewed cert/key pair, and the mesh identity seed are written
  to a `0o600` temp sibling, fsync'd, then atomically renamed — no torn write,
  no world-readable window. The TLS loader now verifies cert/key correspondence
  (`keys_match`) and keeps the last-good pair on mismatch.
- **Reserved identity headers stripped inbound**: `X-Auth-Subject` /
  `X-Auth-Email` are removed from every request at the trust boundary before the
  auth gate re-injects the verified values, so an upstream can trust them.
- **Bounded HA-replay body**: the failover path caps the buffered request body
  (16 MiB → 413, 30s → 408) instead of an unbounded `collect()`.
- **WAF JSON depth guard runs before the parser**: the zero-alloc depth/length
  scan now precedes `simd_json`, so a deeply-nested body can't exhaust the
  recursive parser.
- **JWT HMAC secret via `secret_env`** (keep the key out of `zion.toml`); the
  JWKS refresh client now has a connect + request timeout; a startup warning
  fires when a JWT profile omits issuer/audience scoping.
- Race-free request-coalescing singleflight (atomic `get_or_insert_with`).

### Added

- **`schema_version`** config handshake: a file targeting a newer schema gets
  targeted upgrade guidance instead of a bare unknown-field rejection.
- **Build provenance**: `zion --version` and the `zion_build_info` metric now
  carry the git commit + date (via `build.rs`).
- Metrics: `zion_connections_rejected_global` (global-ceiling shedding);
  `zion_build_info`.
- CI: a `pip-audit` job + a Dependabot `pip` ecosystem for the Python ML
  pipeline.

### Fixed / Changed

- **Observability**: every response status is now counted once, centrally — the
  pre-routing security rejects (414/405/425/429/403/401) were previously
  invisible in `/metrics` and undercounted `requests_total`; the W3C trace id is
  threaded into the access log and the signed audit record.
- **Audit log**: pre-rotation flush errors are surfaced; a broken rotation now
  sheds (drop + count) instead of growing the segment unbounded; the durability
  guarantee is documented accurately (process-crash, not power-loss).
- **Reliability**: the rate-map scavenge loop exits cleanly on shutdown; the
  per-upstream `connect_timeout_ms` is documented as advisory-only.
- **Ops**: systemd unit gets `StateDirectory=zion` (ACME writes work under
  `ProtectSystem=strict`); Helm gains an optional PVC for ACME state; rollback
  runbook, exit-code table, and per-replica scaling docs added.
- **Perf**: single-upstream routes skip the per-request upstream-URI parse; the
  streaming-WAF path no longer double-scans the body.
- **Docs**: corrected the daemon exit-code contract (config error is `2`, not
  `1`), the WAF entropy scope, the FIPS provenance scope, the ADR sidebar
  (0012–0023), and the `caddy` import reference; documented token lifetime /
  revocation, `secret_env`, and the forwarded-header contract.
- Reject a fail-open enforcing JA4 allowlist; new unit tests for `net.rs` bind
  logic, the io_uring accept classifier, and the WAF depth guard.

## [0.7.6] - 2026-09-01

**Sovereign correctness.** The `geo-ita` / `geo-eu` origin classifier baked its
CIDR→role tables from a curated ASN list, but the pipeline chased the ASN
*number*, not the holder — and RIPE reassigns ASNs. A curated ASN that moved to
a different (even foreign) holder had its new ranges silently re-labelled with
the old Italian/EU role. This patch closes that hole; the data plane is untouched.

### Fixed

- **ASN holder validation, fail-closed** (#408): the data generator now carries
  each ASN's expected holder as data and verifies it against the live RIPEstat
  holder before emitting — an accent- and case-insensitive match that requires
  every significant expected token, so a reassignment cannot validate on a
  coincidental shared token. On any drift it refuses to generate, and the weekly
  refresh job blocks its PR instead of opening it silently. Curated sets were
  corrected against the live holders: ASNs reassigned out of national/EU
  sovereignty were removed (e.g. AS21479 → Rostelecom/RU, AS5535 → FAO),
  legitimate Italian reassignments renamed. The live check runs only in the
  scheduled job — the Rust test matrix reads the baked data. Adds a pinned
  golden classification test, offline matcher fixtures (run in CI), and
  `docs/config/sovereign.md`.

## [0.7.5] - 2026-08-29

**The JA4 release.** The zero-trust TLS fingerprint gate (#27) ships complete,
end to end: a hand-rolled ClientHello parser, a pre-handshake enforcement gate,
per-fingerprint policy, and the fingerprint identity forwarded to upstreams.
Everything sits behind `--features tls-fingerprint` and costs nothing when off.
The release also repairs a CI supply-chain gate that had been silently dead for
three days — the kind of failure that looks green from every angle that
matters, which is exactly why it is documented loudly below.

### Added

- **JA4 client-fingerprint library** (#388): `src/tls_fp.rs` computes the
  canonical FoxIO JA4 from raw `ClientHello` bytes. The parser is hand-rolled
  and every read is bounds-checked — adversarial input yields a typed error,
  never a panic. Only new dependency surface: `sha2`, already in-tree.
- **Shadow mode** (#390): `[tls.fingerprint] mode = "shadow"` peeks the
  ClientHello pre-handshake (`MSG_PEEK`, multi-segment post-quantum hellos
  handled, 3 s budget), counts known vs unknown against the allowlist
  (`zion_tls_fp_known` / `zion_tls_fp_unknown`) and never blocks.
- **Allowlist enforcement** (#391): `mode = "allowlist"` with `on_unknown`
  (`log_only` default | `drop`) and `on_unfingerprintable` (`allow` default |
  `drop`); a deny-all misconfiguration refuses to boot. `zion_tls_fp_rejected`.
- **Ban fast path + per-fingerprint connection rate limit** (#396): a rejected
  unknown fingerprint goes on a process-local ban set (`ban_ttl_secs`, default
  600) so repeats are dropped with one map lookup and a debug-level log — a
  single-fingerprint flood no longer floods the log. Allowlist entries accept
  `rate_limit_cps`, a cap on new TLS connections per second, enforced
  pre-handshake with exactly one log line per second when crossed. Metrics:
  `zion_tls_fp_banned_hits`, `zion_tls_fp_rate_limited`.
- **Fingerprint identity to upstreams** (#397): the computed JA4 (and the
  matching allowlist entry name) is stashed on the connection and forwarded as
  `X-Client-TLS-JA4` / `X-Client-TLS-Allowlisted` — with the mTLS discipline:
  inbound copies are stripped unconditionally before the verified values are
  injected, on every path including plaintext :80 and feature-off builds.
  Hot-reloads now announce enforcement-posture changes (mode, `on_unknown`,
  `on_unfingerprintable`) so "the moment enforcement begins" is a log line.
- **Per-fingerprint route restriction** (#398): `allowed_routes` on an
  allowlist entry — same pattern syntax and alias semantics as `[[route]]
  path` — returns **403** for requests outside the list in `allowlist` mode
  and observes (`zion_tls_fp_route_denied`) in `shadow`. The deny is
  HTTP-level by design: at request time the handshake already happened, and on
  HTTP/2 a connection drop would kill unrelated in-flight requests.
  `/healthz` and `/readyz` are exempt structurally — a restriction list must
  never be able to 403 the load balancer's health check.

### Fixed

- **The supply-chain workflow was silently dead 2026-08-25 → 08-28** and is
  repaired in two acts. #394: a `runner` context expression in job-level
  `env:` made GitHub reject the whole workflow file at run creation — every
  run "failed" with zero jobs, so the six REQUIRED status checks never
  reported and every PR sat blocked while `gh pr checks` looked all green.
  #395: the per-job rustup isolation assumed `$RUNNER_TEMP` is wiped between
  jobs on the self-hosted runners — it is not; a job killed mid-install left a
  manifest-less toolchain that poisoned every later job on that runner. The
  store is now wiped (amortized) in the isolate step. Process rule that came
  out of it: `actionlint` gates every workflow edit.
- **h2 advisory posture** (#387): h2 0.4.16 (RUSTSEC-2026-0258), cargo-vet
  exemption refreshed, weekly advisory-freshness window widened to 2× cadence,
  protobuf advisory aliases mapped in deny.toml.

### Data

- Weekly sovereign CIDR refreshes 2026-08-24: EU-27 (#385) and Italy (#386).

### CI / Chore

- GitHub Actions group bump (#389); `.pytest_cache/` and `.ruff_cache/`
  ignored (#393); the dependabot freeze for the v0.7.4 validation window
  (#381) stays in place.

## [0.7.4] - 2026-08-13

**A stability release, cut to be held still.** Nothing here changes runtime
behaviour for an operator: no new features on the request path, no bug fixes
there, no config surface. It is dependency hygiene, supply-chain corrections,
CI that now checks what it claims to, and one experimental scaffold that ships
inert.

The reason to tag it anyway is that the next step is field validation against
real sites — and that is only meaningful against a fixed point. Everything
below is what the frozen baseline contains.

### Data

- **Sovereign ASN/CIDR datasets refreshed** (#375, #376) after the weekly job
  had been silently failing for six weeks (see *Fixed*). EU-27 coverage is
  essentially unchanged (+0.01%); the Italian set loses 0.86%, which was
  verified against the sources rather than assumed: three Telecom Italia /15
  blocks currently return `AS0 — Not routed` in IPtoASN, and one /24 has moved
  to `AS32787` (Prolexic, US DDoS scrubbing). Excluding both is correct —
  classifying unrouted space, or a US scrubbing centre, as Italian residential
  would be wrong. Note this tracks BGP, so the classification will oscillate if
  those prefixes are announced again.

### Added
- **ML-WAF training pipeline** (#345, ADR-0023) — a reproducible in-repo `ml/`
  pipeline to train, validate and parity-check an ONNX scorer, plus a latency
  gate marked `#[ignore]`. **No model is committed** and `ml-waf` is neither
  in `default` nor in `dist`, so the shipped binary is unchanged. The scorer
  remains inert until a model is reviewed and shipped deliberately; the blocker
  is data realism, not code.

### Changed
- **`--features sovereign-aimp` costs 56 crates instead of 123** (#371). The
  upstream `aimp_node` moved its node application (dashboard, CLI, metrics
  endpoint, config loader) behind its own `cli` feature, so Zion now depends on
  it with `default-features = false`: it embeds the protocol, not the
  application.
  `Cargo.lock` lost 52 packages; `paste`, `yaml-rust`, `config`,
  `ratatui 0.26` and `crossterm 0.27` left the graph entirely.
- **ratatui 0.29 → 0.30** for the `tui` feature (#371), pinned to the crossterm
  backend only — the default feature set pulls every backend, which measures at
  +52 crates. Net cost of the bump as actually compiled: +2.
- **tract-onnx 0.21.17 → 0.22.3** (#363). Verified as not a latency regression
  by measuring both versions on the same machine in the same session rather
  than comparing against a previously published figure: p99 unchanged, means
  within run-to-run noise of each other.
- Routine dependency and toolchain bumps: `jsonwebtoken` 10.4 → 11.0,
  `base64` 0.22 → 0.23.1, the Rust container base image, and grouped GitHub
  Actions updates.

### Fixed
- **The weekly sovereign-data refresh runs again** (#374), after failing every
  scheduled run from 2026-07-06 to 2026-08-12. Four layers, each hidden by the
  one before it: the runner had no git identity, so `git commit` aborted; the
  commit carried no `Signed-off-by`, so its PR could never have passed
  `dco.yml`; the `sovereign-data` and `automated` labels did not exist, so
  `gh pr create` died after pushing the branch; and repo policy forbids Actions
  from opening pull requests, so it now uses a fine-grained PAT scoped to this
  repository rather than lifting that policy for every workflow.
- **`aws-lc-rs` held below 1.18.0** (#378). That release switches
  `aws-lc-fips-sys` from the AWS-LC-FIPS **3.x** module — FIPS 140-3 validated,
  NIST certificates #5314 and #5298 — to **4.x**, which has completed lab
  testing but is still on the CMVP Modules In Process list. `--features fips`
  exists to give operators a validated module, and the repo says "validated" in
  five places; taking the bump would have made all five false behind a
  `rust-minor` label. The existing pin only covered semver-major.
- **Three advisory ignores retired**, not silenced (#371) — each because the
  advisory stopped applying, verified crate-by-crate:
  `RUSTSEC-2024-0436` (`paste`, both sources gone), `RUSTSEC-2024-0320`
  (`yaml-rust`, left the graph with aimp's `cli` gate), and `RUSTSEC-2026-0009`
  (`time` 0.3.41 → 0.3.55, past the fix, after ratatui 0.30 lifted the
  transitive `time <0.3.42` bound). `cargo-vet` exemptions: 422 → 395.
  `RUSTSEC-2024-0437` stays and now records why it survives the same gate.
- **Dependabot MSRV floors corrected to where the walls actually start**
  (#359, #365, #368). The `toml` floor was tuned to the version that first
  failed (1.0.0) rather than the version that introduces the break: the
  `toml_parser`/edition2024 wall begins at **0.9.0**, so 0.9.x slipped through
  and failed identically. Also holds `simd-json` and `tract-onnx` at their
  respective walls.

### Testing
- **A watchdog over the scheduled workflows** (#372). Every cron in this repo
  reported into the void — a failing one blocks no merge and notifies nobody,
  which is how the sovereign-data breakage above survived six weeks. A daily job
  now asserts that each scheduled workflow has had a *successful scheduled* run
  inside its window, and opens an issue when one has not. It derives the
  workflow list from the cron lines rather than hardcoding it, so a new
  scheduled workflow is covered automatically; it also catches a cron that
  stopped existing, since GitHub disables schedules after 60 days of repository
  inactivity and a disabled cron never fails.
- **Equivalence harness generalized to Caddy and Traefik** (#347), previously
  nginx-only.
- **ML-WAF review findings fixed** — header lookups made case-insensitive on
  both sides (the extractor's entire job is byte-exact parity with Rust
  `HeaderMap`), `allow_pickle` dropped from corpus loading, `validate.py` now
  asserts the full I/O contract instead of the input half it advertised, and
  the latency gate fails loudly on a `None` result instead of dividing by an
  assumed sample count. That last one also retroactively proved the tract
  0.22.3 figures above were measured over a full population.

## [0.7.3] - 2026-08-03

### Added
- **`mode = "static"` runtime maturity — full nginx/Caddy asset parity.** The
  disk file server (ADR-0015) gained the four HTTP behaviors real static hosting
  needs, each proven live over a real socket:
  - **Conditional GET** (ADR-0019, #340): a weak `ETag` (`W/"len-secs.nanos"`) +
    `Last-Modified` derived from file metadata; `If-None-Match` /
    `If-Modified-Since` are answered with a bodiless **304 Not Modified** (GET and
    HEAD). The 304 decision is shared with the cache path via a new
    `http_conditional` module; the required HTTP-date formatter is dependency-free
    (no date crate in the core MSRV graph).
  - **Range requests** (ADR-0020, #341): single-range `Range: bytes=…` →
    **206 Partial Content** with `Content-Range` (served via seek), `416` when
    unsatisfiable, `Accept-Ranges: bytes` advertised; `If-Range` honored.
  - **Streaming** (ADR-0021, #342): files above 64 MiB now stream frame-by-frame
    with bounded (~576 KiB) memory instead of returning `413` — **no file-size
    limit** on a static route (video / install images serve fine). Applies to
    ranged reads too.
  - **Precompressed sidecars** (ADR-0022, #343): opt-in `precompressed = true`
    serves a `.br`/`.gz` sidecar (Brotli preferred) when `Accept-Encoding` allows,
    with the original `Content-Type` + `Content-Encoding` + `Vary: Accept-Encoding`
    (like nginx `gzip_static`). Sidecars go through the same path-safety guard;
    Zion never compresses on the fly.

### Testing
- **End-to-end rule-matrix** (#339): the integration suite gained live auth
  (JWT/HS256), CORS, and **rule-composition** coverage — one route stacking
  `waf + auth + cors` proves the middlewares compose (a valid token does not let a
  malformed body bypass the WAF). The integration workflow now builds
  `--features auth` so the gate is enforced.

### Docs
- Slowed the README "Migrating from nginx" terminal animation to a readable pace
  (#344).

## [0.7.2] - 2026-07-31

### Added
- **Cache origin-side revalidation** (RFC 9111 §4.3, ADR-0018). A stale cache
  entry is now revalidated with the origin via a conditional GET instead of
  evicted and fully re-downloaded. On a `304 Not Modified` the stored body is
  reused and served as `X-Zion-Cache: REVALIDATED` (counted by
  `zion_cache_revalidations`); an origin error during revalidation serves the
  stale body (`X-Zion-Cache: STALE`, stale-if-error §4.2.4). `StaticCache::get()`
  now returns a three-valued `CacheLookup { Fresh | Stale | Miss }`.
- **Audit-log rotation** (ADR-0017). The HMAC-chained audit log gained
  size-based rotation with retention — `[audit].max_size_mb` (default 100) +
  `max_files` (default 10) — so an enabled log is bounded on disk (~1.1 GB by
  default). Each rotated segment re-anchors the chain at genesis with a
  `chain_rotate` marker, so segments verify independently.
- **ACME soak fault-injection legs.** `zion acme-soak` gained `key-rollover`
  (discard the account, re-issue, assert a fresh account) and `ttl-edge` (assert
  the renewal trigger fires at the `renew_before_days` edge) modes, run as a
  matrix against Pebble in CI (issue #134). `nonce-collision` remains deferred
  (needs per-request `badNonce` retry, not exposed by instant-acme 0.8.x).

### Changed
- **The AIMP mesh reputation table is now bounded** (issue #287): a 24-hour TTL
  plus a 100k-entry cap with amortized eviction, so a long-lived mesh cannot grow
  it without limit. Behind the `sovereign-aimp` feature (off by default).

### Fixed
- **`cargo-audit` CI (and master) went red** after v0.7.1 removed
  `RUSTSEC-2026-0002`/`-0186` from the ignore lists on the strength of
  cargo-deny's report — but cargo-audit scans the flat lockfile and still flags
  them under `--deny unsound`. Re-ignored for cargo-audit only (not `deny.toml`,
  where a not-detected id trips cargo-deny).

## [0.7.1] - 2026-07-31

### Changed
- **Dependency refresh.** The rust-patch and rust-minor dependabot groups, plus
  `tract-onnx`/`tract-nnef` 0.21.14 → 0.21.17 (rust-security group; ml-waf
  feature only, off by default). CI tooling: `actions/checkout` v7,
  `actions/upload-artifact` v7, `dependabot/fetch-metadata` v3, Docker base image
  `rust` 1.97. MSRV-safe (the 1.82 core floor and 1.88 full floor are unchanged);
  `cargo-vet` exemptions regenerated.

### Security
- **Advisory hygiene.** The dependency bumps **resolved** three ignored
  advisories (`RUSTSEC-2026-0002` lru/ratatui, `-0186` memmap2, `-0217`
  tract-nnef), now removed from `deny.toml`/`.cargo/audit.toml`. The
  newly-published `RUSTSEC-2026-0009` (`time` 0.3.41 stack-exhaustion when
  parsing untrusted RFC 2822 input) is feature-gated behind acme/init/ml-waf
  (absent from the no-default-features core) and unreachable on Zion's request
  path — documented and ignored until the transitive `time <0.3.42` constraint
  lifts (the fix, `time >=0.3.47`, also needs Rust 1.85).

### Documentation
- **"Migrating to Zion" guide** — a dedicated page covering all three importer
  front-ends (nginx / Traefik / Caddy), the honesty contract, `${}` resolution,
  native `[tls.acme]`, `mode = "static"` site conversion, and the
  verify-before-cutover workflow. The `cli.md` import section no longer claims
  static serving is unsupported (it converts now).

## [0.7.0] - 2026-07-31

### Added
- **`zion import` is now a three-front-end migration tool.** Alongside nginx
  (v0.6.0) it converts **Traefik** (Docker-compose labels + static flags,
  ADR-0012) and **Caddy** (its own zero-dependency Caddyfile parser, ADR-0013)
  to a validated `zion.toml`, all on one neutral `ZionDoc` seam:
  `zion import <nginx|traefik|caddy>`. A declared-subset Docker Compose reader
  feeds the Traefik label source.
- **Native `[tls.acme]` emission** (ADR-0014). HTTPS sources with a cert
  resolver / ACME email import to Zion's real auto-HTTPS; the email comes from
  the source config or `--acme-email`.
- **`mode = "static"` — opt-in disk file serving** (ADR-0015). A new
  `RouteMode::Static` + `serve_dir` + `spa_fallback` serves files from disk
  behind a hardened path-safety core (`src/static_files.rs`: per-segment
  percent-decode, dotfile / reserved-name refusal, `canonicalize` + containment,
  GET/HEAD only, 64 MiB cap). This reverses the former "no disk serving" product
  edge and unblocks the static-plus-proxy stacks.
- **The importers map static serving to it**: Caddy `root` + `file_server`, and
  nginx `root`/`try_files`/`index`/`alias` (ADR-0016), convert to
  `mode = "static"` — a single-page-app build dir next to a proxied `/api`
  imports in one pass. `serve_dir` is derived exactly: nginx `root` appends the
  request URI while Zion strips the route prefix, so they cancel; `alias` maps
  to `serve_dir` directly.

### Fixed
- **`mode = "static"` returned 503 for every request** — caught by a five-agent
  adversarial review. The dispatch upstream-health gate ran before the
  route-mode match and short-circuited on the (empty) static upstream, so the
  file server was unreachable. Fixed to skip the gate for static routes; proven
  live and guarded by an integration test. The same review fixed 15 more:
  Caddyfile parser recursion depth cap, duplicate-route dedupe, inline
  `header CSP` capture, HEAD-via-`metadata` + size cap, `U+007F` escaping, and
  ACME/host dedupe edges.

### Documentation
- ADRs 0012–0016: the Traefik and Caddy front-ends, native `[tls.acme]`
  emission, `mode = "static"`, and the nginx static mapping.

## [0.6.2] - 2026-07-07

### Fixed
- **Release container image is signed again.** The `release.yml` "verify each
  arch ships its own binary" step (added in v0.6.0's arm64 fix, first exercised
  by v0.6.1) aborted on the second architecture with `cannot overwrite digest`
  — `docker create --platform` stores the pulled image under the manifest-list
  digest, so the next platform collides. That failure gated cosign signing +
  SBOM attestation, so v0.6.1's container shipped unsigned. Fixed by removing the
  local image between platform iterations; the multi-arch image now verifies both
  arches and is cosign-signed + SBOM-attested. (v0.6.1's binaries/tarballs were
  unaffected.)

### Added
- **Tests for the ACME bootstrap-cert linchpin.** `zion init`'s Caddy-style
  auto-HTTPS relies on a ~1-day bootstrap cert so first-boot issuance fires
  (rcgen's default not_after is year 4096, which would bind `:443` but silently
  never issue). Added `init::bootstrap_cert_is_short_lived` (parses the cert via
  the same `tls::cert_expiry_secs` the daemon reads at boot) and
  `acme::expiry_check_fires_for_short_lived_cert_not_long`.

## [0.6.1] - 2026-07-07

### Documentation
- **README + docs synced 1:1 with the code** after a five-surface audit
  (features / metrics / CLI / config / capability claims). Highlights: WAF
  pattern counts corrected everywhere (aggressive set had doubled to ~240, docs
  still said ~190); CORS re-documented as the per-route `cors = { … }` table it
  actually is (the old top-level `[cors]` examples failed to load under
  `deny_unknown_fields`); `cache_profile.ttl_seconds` default fixed (1 hour, not
  1 year); the config reference tables completed (`xff_mode`, `trusted_proxies`,
  `max_connections_per_ip`, upstream `urls`/mTLS, `client_auth`, WAF
  `mode`/`entropy`/`streaming`); CLI feature-gates and missing `zion init` ACME
  flags documented; `numa-aware` added to the build-flavor lists.
- **Grafana dashboard now covers every metric `/metrics` emits.** New rows:
  Protocols & tarpit detail (WebSocket upgrades, tarpit hold time), Mesh — AIMP
  fleet gossip (claims / drops-by-reason / gossip bandwidth), and Reliability &
  internals (panics, dropped audit events, admin rejects). The metrics reference
  in `docs/deploy/observability.md` was expanded from ~12 to all ~40 series.

### Added
- **Stability soak** (`tests/stability-soak/`): drives a real Zion with the
  traffic shapes that stress every leak-prone surface — random Host/path/XFF
  high-cardinality load (route + response caches, WAF, per-IP rate map),
  connection/bad-TLS churn (fd release), and A/B reload rotation (the ArcSwap
  snapshot alloc/free lifecycle) — samples `zion_process_resident_memory_bytes`
  + `zion_process_open_fds` over time, and fails if the post-warm-up RSS slope
  is a significant, budget-breaking climb or the fd count grows without bound.
  Fast PR gate + nightly ~2h soak (`stability-soak.yml`, samples uploaded as an
  artifact). Linux-only (the /proc gauges are 0 elsewhere; the harness
  hard-fails rather than pass vacuously).
- **Reload-under-load harness** (`tests/reload-under-load/`): proves a config
  hot-swap under concurrent traffic drops no in-flight connections. Sustained
  N-worker load hits a live Zion while `POST /admin/reload` fires many real
  atomic swaps mid-flight; the run fails on a single dropped/errored request or
  if the config generation didn't advance during the load. Wired into CI
  (`reload-under-load.yml`) on any change to the reload/dispatch/config path.
- **Automatic HTTPS via Let's Encrypt is on by default in the release binary
  and official container.** A new `dist` feature bundle (`acme` + `init`) is
  what the container and release artifacts build with, so the shipped binary
  can obtain and auto-renew real certificates out of the box. `zion init` on a
  public domain now scaffolds a `[tls.acme]` block **and** a short-lived
  (1-day) bootstrap cert, so `:443` binds immediately and ACME provisions the
  real cert on first boot — Caddy-style auto-HTTPS with no manual cert step.
  New `zion init` flags: `--acme`/`--no-acme`, `--email`, `--domain`
  (repeatable); ACME defaults on for a public hostname, off for localhost/IP.
  `zion auto` stays self-signed (dev/localhost). The default (lean) build and
  `cargo install` are unchanged — `dist` is release-only so the MSRV-1.82 core
  floor holds (acme/init pull an edition-2024 closure needing 1.88).
- **Grafana dashboard** (`deploy/grafana/zion-overview.json`): an importable
  fleet overview built on the metrics Zion already exposes at `/metrics` — no
  exporter, no sidecar. Golden signals, security (WAF/rate-limit/tarpit),
  TLS/upstream, and a leak-watch row (RSS slope via `deriv` + open FDs per
  instance) for spotting a silent memory/descriptor leak in a long-running
  front door. `$instance` variable to focus one proxy or watch the whole fleet.
- **Equivalence harness for `zion import`** (`tests/equivalence/`): starts real
  nginx and real Zion side by side on the original and converted configs,
  replays a request corpus against both, and diffs the routing decision per
  request — proving the converted config routes like the nginx it came from,
  and that the intentional divergences are exactly the ones the import report
  declared. Runs from the published container image or a locally built binary
  (`ZION_BIN`); wired into CI (`equivalence.yml`) in the latter mode. The
  README demo is an animated SVG recorded from a real run (`record-demo.sh`),
  so it cannot drift from what the code actually does.

### Removed
- **Froze the in-kernel deep-tech cluster to keep the shipped surface honest.**
  The probe-only feature flags `io-uring-rw` and `bpf-demux` and the never-wired
  `xdp` flag are gone, along with their dead modules (`src/xdp.rs`,
  `src/bpf_demux.rs`, `src/memfd.rs`, `src/aimp_xdp_sync.rs`), the `aya`/`aya-log`
  dependencies, the standalone `bpf/` and `xdp/` eBPF crates, and the
  `xdp_smoke` example. These tracks never carried a runtime data path — they
  only surfaced kernel-capability probes — so shipping them as feature flags
  overstated what Zion does. The design work is retained as research on issues
  #51/#52/#53. The working `io-uring-accept` accept thread is unaffected.
  `ktls` and `ml-waf` remain but are now labelled **experimental** in the docs
  and feature comments (kTLS is wired but not exercised end-to-end in CI;
  `ml-waf` ships no bundled model).

### Fixed
- **arm64 container image now ships an arm64 binary.** The multi-arch image
  (v0.4.7–v0.6.0) built its binary on `$BUILDPLATFORM` and stamped that single
  host-arch (x86-64) binary into *both* the amd64 and arm64 manifests, so the
  `linux/arm64` image could not exec on ARM hosts (Graviton, Apple Silicon).
  The Dockerfile builder now runs on `$TARGETPLATFORM` so `cargo build`
  produces a binary for the target arch, and `release.yml` gained a step that
  extracts the binary from each published arch variant and fails the release
  (before signing) unless the ELF matches — this class of bug is invisible to
  a manifest inspection.

## [0.6.0] - 2026-07-06

The migration release: `zion import nginx` converts an existing nginx config
into a validated Zion config with an honest findings report, building on the
v0.5.0 host-routing primitive (`server_name` → `hosts`). Design: ADR-0011.
Hardened pre-merge by an adversarial review (26 confirmed findings, all
fixed, each pinned by a regression test).

### Added
- **`zion import nginx <conf>`** (ADR-0011): convert the reverse-proxy subset
  of an nginx config into a `zion.toml`, with the `suggest` guarantee extended
  — the output is self-validated (schema, reference integrity, router build)
  before it is emitted. Every input directive lands in exactly one finding
  bucket (convert / partial / auto / unsupported); anything Zion cannot
  express faithfully (regex locations, `proxy_pass` prefix rewriting, static
  file serving, per-location rate limits) becomes a loud finding plus an
  inline `# UNSUPPORTED:` annotation, never a silent guess. Hand-rolled
  tolerant parser (crossplane/`ngx_conf_read_token` lexer semantics, `include`
  resolution, no directive whitelist), zero new dependencies, ungated, MSRV
  1.82. Golden corpus of 10 real-world configs under
  `tests/fixtures/import/nginx/` is the executable spec. Flags: `-o/--output`,
  `--report`, `--strict` (exit 2 on partial/unsupported findings — a CI gate).
- `config::validate_semantics`: the filesystem-free layer of config validation
  (listen addresses, route→upstream/profile references, ADR-0010 host rules,
  upstream URL schemes, `[admin]` invariants), split out of `validate_config`
  behavior-preservingly so `import` can fully check a config that carries
  placeholder cert paths.

## [0.5.0] - 2026-07-06

Host-based L7 routing (virtual hosting) — Zion can now serve different backends
for different domains on the same listener, matching nginx `server_name` /
Caddy site blocks / Traefik `Host()`. Opt-in and zero-cost when unused; every
step verified end-to-end and covered by CI-run unit tests. Design: ADR-0010.

### Added
- **Host-based routing** (`hosts` on `[[route]]`, ADR-0010). A route can bind to
  one or more hosts (`hosts = ["api.example.com", "*.example.com"]`); a route
  without `hosts` is *shared* and matches every host. Resolution precedence is
  exact host > most-specific `*.` wildcard > shared layer, selected from the
  request `Host` header (HTTP/1) or `:authority` (HTTP/2). The same path can now
  serve different backends per domain — impossible with the previous path-only
  router. Host entries are normalized (lowercased, port and trailing-dot
  stripped) and validated at boot. See `docs/config/routing.md` and
  `examples/multi-site.toml`.

### Changed
- The route lookup is now a `HostRouter` (a shared radix tree plus one tree per
  exact host and per wildcard suffix) instead of a single global tree. When no
  route declares `hosts` the hot path is byte-for-byte the old behavior at zero
  added cost.

### Security
- The thread-local route cache is now keyed on `(host, path)` when host routing
  is active. A path-only key would let one host's request reuse another host's
  cached route, bypassing a per-route WAF/auth profile or an `internal_only`
  gate; the host-scoped key closes that cross-host confusion.

## [0.4.7] - 2026-06-27

A usability release: a runtime **admin API** and a config bootstrapper
(`zion suggest`), plus the wave-2 consolidation fixes and a new WAF regression
gate. 9 PRs since 0.4.6; every endpoint smoke-verified end-to-end and every
security-relevant decision covered by a CI-run unit test.

### Added
- **Admin API** (`[admin]` section, off by default) — a dedicated,
  loopback-by-default listener for runtime config management, the programmatic
  counterpart to the file watcher. `GET /admin/config` returns the live snapshot;
  `POST /admin/config` pushes a full new TOML body and `POST /admin/reload`
  re-reads from disk — both flow through the **same** validate → atomic-swap →
  bump-generation → notify path as a file edit, returning the new config
  generation synchronously. Rate-limited (`admin.rate_limit_rps`, default 10),
  audited (a `config_reload` event per write), and authorized by either
  `internal-ip` (loopback) or `mtls` — a required client certificate chaining to
  `tls.client_ca_path`, so the listener can safely bind a routable interface. New
  `zion_admin_rejects_total` metric. Full contract in `docs/deploy/admin-api.md`
  (#254, #255, #256, #257, #258).
- **`zion suggest`** — deterministic `zion.toml` synthesis: detect a local
  backend (or take `--upstream`), emit a TLS + WAF-protected config that
  self-validates against the schema before it is written. Zero dependencies, no
  ML (#253).

### Fixed
- Hop-by-hop headers are scrubbed on the WebSocket **non-101** upgrade path too,
  not only the 101 path (#250).
- Adversarial re-review (round 2): a `[cors]` example that `deny_unknown_fields`
  would reject is corrected; the audit-log writer now self-heals after a
  transient write failure instead of disabling itself; and `zion doctor` bounds
  its upstream DNS probe (#251).

### CI / Internal
- The WAF detection / false-positive corpus is now a **nightly + on-WAF-change**
  regression gate that hard-fails on any benign false positive (#252).
- `reload_now(ConfigSource)` extracts the shared reload entry point used by both
  the file watcher and the admin API (#254).

## [0.4.6] - 2026-06-26

A correctness, conformance & operability release — the summer "diamond"
program, waves 1-2 (14 PRs since 0.4.5), each gap verified in code and each
security-relevant decision covered by a CI-run unit test.

### Security
- Shared cache no longer reuses a response to an **authenticated** request
  (`Authorization`) without an explicit opt-in (`public`/`s-maxage`/
  `must-revalidate`) — RFC 9111 §3.5, closes a cross-user disclosure on
  cache-enabled routes (#235).

### Conformance (HTTP RFC 9110/9111, TLS RFC 8446/8470)
- `405` responses now carry `Allow`; `401` carry `WWW-Authenticate` — RFC 9110
  MUSTs (#237).
- Hop-by-hop headers (incl. any field named in `Connection`) are stripped from
  upstream **responses**, not just requests — RFC 9110 §7.6.1 (#238).
- Header-less responses get a **conservative 1-hour** heuristic freshness
  instead of a 1-year `immutable` freeze; `immutable` is now opt-in via an
  explicit long `ttl_seconds` — RFC 9111 §4.2.2, closes the cache-staleness
  family (#239).
- The 0-RTT **425** replay gate and the TLS version floor are now covered by
  CI-run unit tests; the TLS-conformance doc no longer lists tests that never
  existed (#236).

### Operability & solidity
- **Unknown config keys are rejected** (`deny_unknown_fields`) instead of
  silently ignored — root and every sub-table (#244, #246).
- `zion doctor` now validates the **deployment**: it parses+validates the
  config, probes upstream reachability, and warns when rate-limiting or WAF
  coverage is off (#245, #247).
- Non-`http(s)` upstream URLs are rejected at startup (#241); audit-log
  flush/write failures are surfaced, not swallowed (#243); request-path errors
  go through structured logging instead of `eprintln!` (#242); a latent
  process-abort (`unreachable!`) was removed from the cache hot path (#240).
- `max_body_mb` set on a WAF-off route now warns at boot instead of silently
  no-op'ing; the release panic doctrine is documented (#248).

## [0.4.5] - 2026-06-26

A WAF detection-coverage patch, driven by a larger sourced corpus.

### Added
- WAF **corpus-v2** (`benchmarks/waf-corpus/corpus-v2.json`): ~1,060 malicious
  payloads sourced from OWASP CRS + PayloadsAllTheThings, plus 136 benign — the
  honest regression set. `build-corpus-v2.py` regenerates it; `run.py` takes
  `WAF_CORPUS=<file>`.

### Changed
- WAF aggressive pattern set: a corpus-v2-driven round (PHP tags/funcs, Java
  gadget classes, SSRF schemes, Windows command injection, ORM lookups, PHP
  stream wrappers, Perl SSTI) lifts aggressive recall vs corpus-v2 from 30.9%
  to 40.6% at an unchanged **0% false-positive rate** (0/136). balanced
  unchanged. Guarded by new `denies_/allows_corpus_v2_round` unit tests.

## [0.4.4] - 2026-06-25

A WAF-coverage patch. Adds a measured detection/false-positive regression
baseline (`benchmarks/waf-corpus/`, 200 payloads) and, driven by it, plugs the
biggest gaps in the balanced/aggressive pattern sets — command injection, SSRF,
deserialization, and error-based SQLi — lifting aggressive recall from 64.7% to
85.3% against the corpus at an unchanged **0% false-positive rate**.

### Changed

- **WAF command-injection coverage** ([`src/waf.rs`](src/waf.rs)). The CMDi
  patterns only matched a metachar followed by a few specific commands
  (`cat`/`ls`/`rm`/`wget`/`curl`), so bare-metachar and substitution forms slipped
  through. Added unambiguous Unix forms to the balanced set (reverse shells
  `/dev/tcp/` · `nc -e` · `bash -i`, `${IFS}` bypass, brace expansion, `; nc`) and
  the FP-prone forms to aggressive (`$(`, `` `id` ``, `whoami`, `&& ls`, `| sh`).
  Measured against the new `benchmarks/waf-corpus/` baseline: command-injection
  recall **33% → 100%** (aggressive) / 27% → 44% (balanced), overall **64.7% →
  73.3%** (aggressive), **at an unchanged 0% false-positive rate** on the benign
  set. New unit tests lock in both the detections and the no-false-positive guard.
- **WAF SSRF / deserialization / SQLi-error-based / shellshock coverage**
  ([`src/waf.rs`](src/waf.rs)). Continuing against the corpus: internal SSRF
  schemes `gopher://`/`dict://` and error-based SQLi (`extractvalue(` ·
  `updatexml(` · `xp_cmdshell` · `||(select`) to balanced; loopback/decimal-IP
  SSRF (`http://localhost:` · `http://127.0.0.1:` · `http://2130706433`),
  deserialization / prototype-pollution (java `rO0AB`, PHP `O:8:"`, `__proto__`,
  `constructor[prototype`, YAML `!!python/`), shellshock (`() { :` — *not* bare
  `() {`, which is a legit empty function) and quote-paren SQLi OR-variants to
  aggressive. Corpus delta (aggressive): SSRF **33% → 100%**, deserialization
  **33% → 100%**, SQLi **68% → 90%**, overall **73.3% → 85.3%** — still **0%
  false positives**. New unit tests incl. an empty-function precision guard.

## [0.4.3] - 2026-06-25

A cache-observability + operability patch, both items drawn from a real
audiolibri.org stale-content incident: the cache now states its decision on the
wire, and an operator can flush it on deploy instead of waiting out the TTL.
No change to the proxy/WAF data path.

### Added

- **`X-Zion-Cache: HIT|MISS|BYPASS` response header** ([`src/dispatch.rs`](src/dispatch.rs)).
  A cache HIT was previously distinguishable only by the absence of upstream/shield
  headers plus the rewritten `Cache-Control` and the `Age` value — which cost real
  debugging time during a stale-content incident. The cache now states its decision
  explicitly: `HIT` (served from RAM), `MISS` (fetched from upstream and cached as it
  streams), `BYPASS` (not cacheable — content-negotiated, `no-store`/`private`,
  already-stale-on-arrival, or `max-age=0`).
- **Cache purge endpoint `POST /_zion/cache/purge`** ([`src/cache.rs`](src/cache.rs),
  [`src/dispatch.rs`](src/dispatch.rs)). Flush the in-RAM cache so a deploy hook can
  invalidate immediately instead of waiting out the TTL (previously only a pod restart
  would do it, briefly dropping `:443`). `?prefix=/path` purges matching keys; no prefix
  purges everything. Internal-only (same IP gate as `/metrics`) and POST-only; returns
  `{"purged":N,"scope":...}`. L2 is cleared directly; the existing generation counter
  lazily invalidates every thread-local L1 — no cross-thread iteration.

## [0.4.2] - 2026-06-25

A cache-correctness patch fixing stale content served by the edge cache. The
RAM cache now emits an `Age` header and honours the origin's freshness, so
content updates propagate within the origin's real lifetime instead of being
pinned for the full profile TTL and re-freshed on every downstream hit.

### Fixed

- **Cached responses now carry an `Age` header** ([`src/cache.rs`](src/cache.rs),
  [`src/dispatch.rs`](src/dispatch.rs)). On a RAM hit the cache previously
  re-stamped a fresh `Cache-Control: max-age=<ttl>` with **no `Age`**, so every
  downstream cache (the shield Varnish, browsers) reset its freshness clock on
  each hit and served content far past its real lifetime — observed as stale
  content on audiolibri.org. Each entry now records its birth time (seeded from
  the upstream `Age`, so time spent behind the shield counts) and serves a
  correct `Age`, letting downstream caches subtract elapsed time.
- **The origin's freshness is now honoured for the cache lifetime**
  ([`src/dispatch.rs`](src/dispatch.rs)). The entry TTL is derived from the
  origin's `s-maxage`/`max-age`, clamped to the profile TTL as a ceiling,
  instead of blanket-applying the profile TTL. A response that is `max-age=0`
  or already older than its lifetime on arrival is streamed through uncached.

## [0.4.1] - 2026-06-18

A hardening + supply-chain patch: one user-facing TLS fix, a completed
Node 24 / SHA-pinned CI migration, a green-again fuzz harness, a sweep of
safe dependency bumps, and a new mesh-cost benchmark. No behaviour change to
the proxy/WAF/cache data path.

### Added

- **`benchmarks/bench-mesh.sh`** (#72) — reproducer that measures the
  `--features sovereign-aimp` cost as an RPS delta vs a default build across
  three operating points (idle / lookup-active / 3-node mesh-active) on the
  API-GET hot path, with the issue's acceptance gates (<1% / <3% / <5%)
  enforced. Harness only; numbers belong on a Linux rig.

### Fixed

- **TLS handshake errors are no longer swallowed** (#201,
  [`src/tls.rs`](src/tls.rs)). `spawn_https_handler` collapsed the
  handshake-error and 10s-timeout cases into one arm that only bumped a
  counter, losing the rustls error string. Split into distinct, rate-limited
  (≈1 line/s, process-wide) log lines for the error vs timeout cases, each
  with the client address; the metric still counts every failure. Benefits
  both the tokio and io_uring accept paths.
- **`cargo-fuzz build` green again on master** (#205,
  [`.github/workflows/fuzz.yml`](.github/workflows/fuzz.yml)). The repo-root
  `rust-toolchain.toml` (1.88) shadowed dtolnay's nightly inside the checkout,
  so `cargo install cargo-fuzz` built under 1.88 and tripped a transitive
  dep's 1.91 MSRV. Drop the pin for the (nightly-only) fuzz job.

### Changed

- **Node 24 GitHub Actions migration completed** and the last mutable action
  refs SHA-pinned (#200, #203, #206) — `attest-build-provenance`/`attest-sbom`
  → v4.1.0, plus checkout/codeql/setup-qemu/cargo-deny bumps; every workflow
  now pins by full commit SHA.
- **Dependency bumps** (verified to build all-features + hold the 1.82 MSRV
  floor): matchit 0.8→0.9 (#204), socket2 0.5→0.6, webpki-roots 0.26→1.0,
  crossterm 0.28→0.29 (#207); docker rust 1.95→1.96 (#178),
  docker/metadata-action 5→6 (#190); rand 0.9→0.10 in the standalone bench
  backend (#208). simd-json 0.17, toml 1.1, and notify 8 were intentionally
  held back — their transitive deps require rustc 1.85, above zion's 1.82 MSRV.

## [0.4.0] - 2026-06-16

### Added

- **L7 tarpit / slow-drip for flagged sources** (#151,
  [`src/tarpit.rs`](src/tarpit.rs)). Closes the anti-DDoS enforcement arc
  (#147 → #155 → #150 → #151). When tag-driven enforcement (#150) decides to
  deny a request, the operator can now escalate the cheap `403` into a
  *held* connection: the flagged source is parked for a bounded `hold_secs`
  before the refusal, so a backed flood pays wall-clock and socket budget
  instead of getting an instant, immediately-recyclable reject.
  - **Config** `[sovereign.enforce.tarpit]` — `enabled` (default `false`),
    `hold_secs` (default `10`), `max_concurrent` (default `128`). Only takes
    effect when `[sovereign.enforce] enabled = true`; geo-gated like the rest
    of enforcement. Config-load warns if `enabled` with `max_concurrent = 0`
    (sheds every request → no-op) or `hold_secs > 60` (over-long holds tie up
    connections), and **clamps `max_concurrent` to ¼ of the global connection
    ceiling** so held connections can't pin the admission pool (self-DoS guard).
  - **Bounded** — a single global ceiling caps concurrently held requests; at
    the ceiling the tarpit *sheds* back to the immediate `403`. A held request
    keeps its global connection permit + per-IP slot for the hold, so the
    ceiling is clamped to a small fraction (¼) of the connection pool.
    Admission is one CAS; a held request is one parked tokio timer + the open
    socket, released by an RAII guard (gauge and held-time stay correct on
    early return / panic). The deny still denies — the tarpit only changes how
    long the flagged client waits.
  - **Metrics** `zion_tarpit_active` (gauge), `zion_tarpit_total`,
    `zion_tarpit_shed_total`, `zion_tarpit_held_ms_total` (counters).

### Fixed

- **`io-uring-accept` now serves HTTPS end-to-end** (#195,
  [`src/uring.rs`](src/uring.rs), [`src/main.rs`](src/main.rs)). The opt-in,
  off-by-default `io-uring-accept` feature (Linux) was previously
  non-functional — it never served a single request. Three masked lifecycle
  bugs are fixed: (1) a *borrowed* listener fd was recycled out from under the
  accept thread, so `io_uring_setup` reused the freed number and `accept()`
  flooded `EBADF`/`ENOTSOCK` at ~10⁶/s — the thread now owns a `dup()`ed fd;
  (2) `tokio::net::TcpStream::from_std` was called on the bare accept
  `std::thread` and panicked "no reactor running" — the conversion now happens
  inside a runtime context; (3) the accept loop was handed a throwaway shutdown
  `watch` channel whose sender was dropped immediately, so the loop returned at
  once and every accepted connection was RST during the TLS ClientHello — it is
  now wired to the real process shutdown signal. Verified on Linux 6.17
  (concurrent `/healthz` 20/20, flood = 0, panics = 0).
- Guard against running outside a Git repository (#186).

### Security

- High-severity dependency bump in `Cargo.toml` (#185); `rand` → 0.9.3 (#183).

### Dependencies

- `hyper` 1.9.0 → 1.10.1 (#167), `memchr` 2.8.0 → 2.8.2 (#166).
- CI actions: `upload-artifact` → 7.0.1 (#142), `checkout` → 6.0.2 (#141),
  `download-artifact` → 8.0.1 (#140), `setup-buildx-action` → 4.1.0 (#139),
  `deploy-pages` → 5.0.0 (#138).

### Deferred

- Per-byte **slow header/body drip** (the endlessh-style trickle). The
  bounded delayed-hold already imposes the wall-clock + socket cost that is
  the point of a tarpit; a streaming-body trickle is a follow-up. Tarpit on
  the plain `429` rate-limit path (currently scoped to the `[sovereign.enforce]`
  deny points) is likewise a follow-up.
- **Per-IP tarpit sub-cap.** The ceiling is global, and on HTTP/2 each held
  *stream* consumes a slot, so one source (a few H2 connections) can occupy a
  large share of the holding capacity and push other flagged sources to a fast
  `403`. This degrades the tarpit's effectiveness but not zion's stability (the
  shed fallback is the safe pre-tarpit behaviour, and the global / per-IP
  connection caps still bound sockets). A per-IP sub-cap is a follow-up.

## [0.3.4] - 2026-06-05

### Security

- **CVE-2026-49975 ("HTTP/2 Bomb") hardening.** The HTTP/2 Bomb chains an
  HPACK decompression bomb with a flow-control "hold". Zion's single-connection
  resistance was *inherited* from hyper/h2 defaults rather than asserted, and
  the multi-connection variant was unbounded with the per-IP cap off (the
  default). This makes the ceilings explicit and on by default. Verified live
  on the e2e rig: released 0.3.3 advertised the inherited
  `max_concurrent_streams = 200`; a single-connection bomb stayed bounded
  (~3 MB/conn, RSS flat, 0 panics), confirming the premise.
  - **Explicit HTTP/2 limits** ([`src/main.rs`](src/main.rs)) — pinned on the
    server builder instead of inherited: `max_concurrent_streams = 128` (was
    the inherited 200), `max_header_list_size = 16 KiB`,
    `max_pending_accept_reset_streams = 20` (CVE-2023-44487 Rapid-Reset bound),
    plus HTTP/2 keep-alive PINGs (30 s / 10 s) to reap a connection gone silent
    mid-hold. A regression test pins the invariant that worst-case retained
    header memory per connection (`streams × header-list`) stays ≤ 4 MiB.
  - **Per-IP connection cap ON by default** ([`src/config.rs`](src/config.rs),
    [`src/main.rs`](src/main.rs)) — `server.max_connections_per_ip` is now
    tri-state: omitted → **auto** (~1/8 of the global connection ceiling,
    scaling with RAM so it won't pinch CGNAT/large-NAT on big nodes); `0` →
    explicitly disabled; `N` → explicit. Resolved in `try_build` and read live
    at accept, so a hot-reload retunes it without dropping live connections.
  - **`compute_conn_limit` re-based to 256 KB/connection**
    ([`src/bootstrap.rs`](src/bootstrap.rs)) — was 50 KB, which
    under-provisioned the global ceiling ~5× against an *active* HTTP/2
    connection (1 MB flow-control window + per-stream/HPACK state + TLS
    buffers). The per-connection worst case stays bounded by the explicit H2
    limits and the per-IP cap above.

### Fixed

- **Rate-limit map scavenger spawned unconditionally**
  ([`src/main.rs`](src/main.rs)) — it was gated on the boot-time
  `rate_limit_rps > 0`, so enabling the limiter via hot-reload (`0 → N`) left
  the per-IP rate map without garbage collection, risking unbounded growth to
  `MAX_RATE_MAP_ENTRIES` and the fail-closed path for new IPs. It now always
  runs (a cheap no-op when the map is empty) and reads the window live. A
  regression test pins that a hot-reload carries `rate_limit_rps`,
  `rate_limit_window`, and `max_connections_per_ip` into the new snapshot.

## [0.3.3] - 2026-06-03

### Fixed

- **Passive upstream failover on connection-level errors**
  ([`src/proxy.rs`](src/proxy.rs), [`src/dispatch.rs`](src/dispatch.rs)).
  A `standard`-mode route over a multi-upstream `[upstream]` pool now
  fails over to the next healthy upstream when the selected backend
  refuses the connection, instead of returning `502` until the
  background health prober ejected it (steady probe interval).
  `proxy_pass_ha` buffers the request body once and replays it; on a
  connection-level failure it marks the upstream unhealthy — bringing
  its next probe forward via `next_probe_at_us = 0` so it rejoins on
  recovery — before retrying the next pool member. Idempotent methods
  (GET/HEAD/OPTIONS/PUT/DELETE/TRACE) retry on any transport error;
  non-idempotent methods only on a pure connect error (`is_connect()` —
  the request provably never reached the upstream). Single-upstream
  pools keep the zero-overhead `proxy_pass` streaming path; Websocket /
  SSE forwards are unchanged (no safe replay). Measured on a live
  2-node cluster: a rolling backend kill went from 170/350 failed
  requests to 0/350. ([#179](https://github.com/fabriziosalmi/zion/pull/179))

## [0.3.2] - 2026-06-01

Resilience and correctness, validated on a real two-node Proxmox e2e bench
(real FQDN, real Let's Encrypt TLS 1.3). Adds adaptive self-heal so a recovered
origin returns to service in ~1.4 s instead of up to 30 s, closes 24 data-plane
findings from a live bug-hunt, and fixes a `/metrics` content-negotiation bug
that made standard Prometheus unable to scrape.

### Added

- **Adaptive decorrelated-jitter origin recovery (#173)** — replaces the fixed
  30 s upstream health-probe interval with a per-upstream decorrelated-jitter
  backoff (AWS / Marc Brooker). A DOWN upstream is re-probed on a 100 ms→3 s
  schedule, so a recovered origin returns to service in **~1.4 s instead of
  ~30 s** (measured live on the e2e rig, ~21× faster), with jitter to avoid a
  recovery thundering-herd across a co-dead pool or mesh replicas. HEALTHY
  upstreams keep the unchanged 30 s steady cadence — zero happy-path
  regression, identical steady-state origin load. Backoff state rides the
  config-reload `Arc`-reuse so an in-progress walk survives reloads; the
  request path is untouched (lock-free). `fastrand` promoted to a direct dep.

### Fixed

- **`/metrics` content-negotiation (#172)** — OpenMetrics exemplars were emitted
  under the classic `text/plain; version=0.0.4` content-type, which standard
  Prometheus rejects, making the target unscrapeable. `/metrics` now
  content-negotiates on the `Accept` header: classic exposition (no exemplars,
  no `# EOF`) by default, OpenMetrics only when the client asks for
  `application/openmetrics-text`.
- **24 data-plane findings from a live e2e bug-hunt (#171)** — request-path
  hardening surfaced by real-traffic testing: catch-all-root + trailing-slash
  routing, header-read / body-read / upstream timeouts (504/408), inbound
  client-cert-fingerprint header strip, forwarding hygiene on the WebSocket
  path, WAF whitespace/unicode/overlong-encoding evasion gates, cache GET-gating
  + `Cache-Control` honoring, and security-header injection on all responses.

### Validated

- Two-node Proxmox e2e benchmark (`benches/e2e/`): Zion on **2 Skylake vCPU**
  sustains **96 k req/s** cache+WAF+TLS and **43 k req/s** proxy+WAF+TLS at
  ~40 MB RSS, and holds **flat RSS (OLS −26 MB/h, no leak)** under a
  4.67 M-request mixed attack while serving 4.66 M legit cache-hits — 0 panics.

## [0.3.1] - 2026-06-01

A focused patch on operability and documentation honesty. Makes the
daemon's own resource footprint observable in production — the answer to
"can you debug a silent memory leak without restarting?" — and corrects
three FIPS-guide claims about tooling that did not exist.

### Added

- **Runtime resource introspection (#163)** — two new `/metrics` gauges,
  `zion_process_resident_memory_bytes` (RSS via `/proc/self/status`
  `VmRSS`) and `zion_process_open_fds` (`/proc/self/fd` entry count),
  sampled **once per scrape** off the hot connection path — the existing
  1-second render cache throttles the two `/proc/self` reads, so there is
  no per-request cost. Surfaced on three operator planes: `/metrics`,
  `/_zion/snapshot.json`, and the `zion top` TUI (new "rss" / "open fds"
  rows, version-skew tolerant via `#[serde(default)]`). A steadily
  climbing RSS or fd count under flat traffic is now visible on a
  dashboard within one scrape cycle, no restart required. Linux-only;
  both gauges render as `0` on other platforms so a single dashboard
  works across hosts. No new dependencies, no `unsafe`. New Grafana
  leak-detection queries in
  [`docs/deploy/observability.md`](docs/deploy/observability.md).
- **`zion doctor` memory-introspection check (#163)** — a preflight that
  confirms `/proc/self/status` is readable on the host and reports the
  current RSS, warning up front when a hardened container runtime masks
  `/proc` (where the gauges would otherwise silently read `0`).

### Fixed

- **FIPS guide referenced tooling that does not exist (#164)** — the guide
  promised a `scripts/fips-self-check.sh` helper, a `ci.yml` `flavor=fips`
  job, and a `release.yml` `-fips` artifact, none of which the repo ships.
  Rewrote [`docs/security/fips.md`](docs/security/fips.md) to the honest
  posture: a FIPS build is a manual `cargo build --features fips` today,
  carries no SLSA provenance attestation (unlike the default release
  binaries), and its chain of custody is the operator's to establish.
  CI/release wiring is noted as future work.

## [0.3.0] - 2026-05-30

The first tagged release since v0.2.2. Completes the **v0.3 — Compliance
frontier** milestone (BoGo TLS conformance in CI) and ships the
**Sovereign Edge** origin tagging (IT/EU, IPv4 + IPv6) plus the first
**anti-DDoS admission levers** (per-IP concurrent-connection limit,
tag-driven enforcement). The full OpenTelemetry stack moved to 0.32 and
the CI / supply-chain were hardened. Supersedes the unreleased 0.2.3 line.

### Added

- **BoGo TLS conformance suite in CI (#56)**
  ([`.github/workflows/tls-conformance.yml`](.github/workflows/tls-conformance.yml)).
  Runs BoringSSL's BoGo suite (~600 cases) against the exact `rustls` +
  `aws-lc-rs` versions zion pins — version-locked, so a future
  `Cargo.lock` bump that regresses conformance goes red on the bumping
  PR. Closes the v0.3 milestone. Corrected the long-standing doc/issue
  myth that BoGo could be pointed at zion's `:443` (it drives a *shim*).
- **Sovereign Edge — IT/EU origin tagging, IPv4 + IPv6 (#147)**
  (`--features geo-ita` / `geo-eu`). Classifies the client IP via an
  O(log N) binary search over baked CIDR tables (a `u32` table + a
  parallel `u128` table for IPv6) — no GeoIP DB, no syscall, one atomic.
  `geo-eu` is a hybrid model: every EU-27 RIPE allocation is the
  `Eu` baseline, curated EU ASN sets override it with gov/residential/
  datacenter roles. Answers "% EU vs non-EU traffic" out of the box via
  `zion_sovereign_classifications_total{class}`. Dataset auto-refreshes
  weekly (`sovereign-data.yml`, RIPE NCC + Team Cymru).
- **Per-IP concurrent-connection limit (#155)** —
  `server.max_connections_per_ip` (0 = off). Caps how many sockets one
  source IP may hold open at once, enforced at accept *before* the TLS
  handshake (the resource a slow/backed flood drains). RAII release,
  zero overhead when disabled, hot-reloadable. Metric
  `zion_connections_rejected_per_ip`.
- **Tag-driven enforcement (#150)** — `[sovereign.enforce]` promotes the
  origin tag / AIMP mesh score from a *signal* to an opt-in `403` deny.
  `deny = ["unknown"]` on a `geo-eu` build blocks every non-EU source
  while the EU classes pass (sovereign allowlist by complement), or deny
  above a mesh-reputation threshold. Off by default; local WAF /
  rate-limit / auth stay authoritative. Metric
  `zion_enforcement_denied_total{reason}`. A README "Sovereign edge &
  DDoS resistance" section maps the layered defence.
- **ACME issue → renew → revoke soak in CI (#59)**
  ([`.github/workflows/acme-soak.yml`](.github/workflows/acme-soak.yml),
  [`src/acme.rs`](src/acme.rs)). New `acme-soak` weekly + on-demand
  workflow drives the full certificate lifecycle against a hermetic
  [Pebble](https://github.com/letsencrypt/pebble) test CA with mocked DNS
  (`pebble-challtestsrv`) — no real Let's Encrypt, no external DNS, no
  rate limits. A hidden `zion acme-soak` subcommand runs zion's *real*
  `renew_once` / `revoke_cert` paths and asserts the lifecycle counters
  move, so an ACME-flow regression fails the soak. New metrics
  `zion_acme_renewals_total` and `zion_acme_renewal_failures_total`;
  new operator-facing `revoke_cert` for retiring a compromised key.
  Docs: [`docs/config/acme.md`](docs/config/acme.md). Fault-injection
  legs (nonce-collision, key-rollover, TTL-edge) are tracked as a
  follow-up.

### Fixed

- **ACME HTTP-01 token cleanup raced validation.** `do_renewal_native`
  removed the challenge tokens from the responder store *before*
  `poll_ready`, but the ACME server fetches them *during* that poll —
  yielding a 404 / `unauthorized`. Tokens are now dropped only after
  `poll_ready` returns. Surfaced by the new #59 Pebble soak (real
  Let's Encrypt validated fast enough to usually mask it).

- **Mesh chaos coverage + inbound claim rate-cap (#71)**
  ([`src/aimp_cp.rs`](src/aimp_cp.rs)). Three failure-mode tests pin the
  gossip subsystem under adversarial conditions: split-brain
  reconciliation (LWW converges both halves to the one newest
  observation, no double-count, no permanent ban), claim flood (a
  per-source-node token bucket caps a flooding peer — including a
  compromised one with a valid key — while other sources keep flowing),
  and slow gossip (a wedged peer's backlog arriving in a burst yields no
  duplicate decisions — replays and stale claims change nothing). The
  rate-cap is new behaviour: opt-in via `sovereign_aimp.inbound_claims_per_sec`
  (0 = disabled, the default, so the legitimate anti-entropy full-map
  re-broadcast stays unthrottled) with `inbound_claim_burst` headroom,
  surfaced as `zion_mesh_claims_dropped_total{reason="rate"}`.

- **BPF demux v2 — unified-port co-existence integration test +
  loader status documented**
  ([`tests/integration.rs`](tests/integration.rs),
  [`bpf/README.md`](bpf/README.md)). New `t30_unified_port_*`
  integration test pins one of the two open acceptance items on
  issue #53: TCP HTTPS on `:4433` keeps working when zion is built
  with `--features http3` AND the QUIC listener occupies the same
  port via UDP. The probe is OS-portable (binds UDP locally; either
  trips `EADDRINUSE` and confirms QUIC is up, or succeeds and logs
  that the build was TCP-only). New `bpf/README.md` documents the
  loader-runtime status: aya 0.13 has no typed `SkReuseport`
  program helper, so the userspace `Ebpf::load_file` +
  `setsockopt(SO_ATTACH_REUSEPORT_EBPF)` path is **deferred** —
  tracked in [#100](https://github.com/fabriziosalmi/zion/issues/100)
  with the precise upstream-aya gap and three viable closing paths
  (upstream contribution, libbpf-rs switch, hand-rolled
  `bpf(BPF_PROG_LOAD)` FFI). (#53 partial)
- **`[access_log]` config block — PII redaction on the access-log
  path** ([`src/config.rs`](src/config.rs),
  [`src/dispatch.rs`](src/dispatch.rs),
  [`docs/guide/observability.md`](docs/guide/observability.md)).
  New `include_headers: Vec<String>` (default empty, lowercased on
  parse) and `mtls_fingerprint: bool` (default true). Configured
  headers are pulled from the request before dispatch consumes it,
  passed through the existing
  `audit::CompiledRedaction::redact_header_value` policy
  (`[redact.headers]`), packed into a single JSON `headers` field
  on the `tracing::info!(target: "access", ...)` event. The mTLS
  leaf-cert SHA-256 fingerprint surfaces on a dedicated `mtls_fp`
  field — never redacted (it's already a hash). When the audit log
  is enabled and `[access_log]` opts in, a parallel
  `kind = "request_completed"` audit event mirrors the same field
  set with HMAC-chain coverage. New proptest pin
  (`redacted_header_json_never_contains_secret_value`) verifies the
  rendered JSON never leaks a redacted-list header value as a
  substring, for any input. (#60)
- **SOC 2 + FedRAMP control-mapping document**
  ([docs/security/compliance-mapping.md](docs/security/compliance-mapping.md))
  — TSC (CC + A + C + PI) tables and NIST 800-53 rev5 (AC, AU, CM,
  IA, SC, SI, SA) mapped to in-binary code paths, workflow files,
  and operator-side residuals. Each row links to the implementation
  site and to the deployment-side doc the auditor still needs from
  the operator. Cross-referenced from the README "Compliance"
  section. (#61)
- **Mesh observability — counters + audit-kind taxonomy**
  ([`src/metrics.rs`](src/metrics.rs), [`src/audit.rs`](src/audit.rs)).
  Eight always-on Prometheus counters under `zion_mesh_*`
  (`claims_emitted`, `claims_received`, `claims_dropped_total{reason=...}`
  with `signature`/`replay`/`other`, `score_lookups`,
  `gossip_bytes_in`, `gossip_bytes_out`). Wired at the four mesh
  callsites: `try_merge` accept + each rejection path, `publish_block`
  enqueue, `run_receiver` byte counting, `run_publisher` /
  `run_anti_entropy` byte counting, dispatcher's `cp.lookup` positive
  path. Counters are zero on builds without `--features
  sovereign-aimp` so operators can grep the same metric names
  regardless of build flavour. New canonical audit-kind constants
  (`audit::kind::{AUTH_*, CONFIG_RELOAD, REQUEST_BLOCKED,
  ADMIN_ACCESS, PANIC, MESH_PUBLISH, MESH_RECEIVE, MESH_PEER_*,
  MESH_QUORUM_DECISION}`) replace ad-hoc string literals at future
  callsites. Performance budget documented at
  [docs/perf/mesh-overhead.md](docs/perf/mesh-overhead.md) (target
  < 0.5 % throughput on a 100k rps host). (#69)
- **STRIDE threat-model addendum on the mesh (AIMP) surface** — new
  §10 in [docs/security/threat-model.md](docs/security/threat-model.md)
  walking the six STRIDE categories against the mesh: Ed25519 signing
  for Spoofing, Noise AEAD + Merkle-CRDT integrity for Tampering,
  signed audit trail for Repudiation, opt-in IP anonymisation for
  Information disclosure, per-peer rate-cap + LRU for DoS, and
  revocation-key-signed claims plus quorum thresholds for Elevation
  of privilege. ASVS map ([docs/security/asvs.md](docs/security/asvs.md))
  gets a new V9.2.4 row pointing at the addendum, and
  [docs/guide/observability.md](docs/guide/observability.md) gains a
  Mesh section listing the `zion_mesh_*` counters + audit-event
  kinds. (#70)
- **ADR-0008 + mesh integration guide** — formal architectural record
  for embedding AIMP as the mesh control-plane bus
  ([docs/adr/0008-mesh-aimp-integration.md](docs/adr/0008-mesh-aimp-integration.md)),
  alongside an operator-facing deployment guide
  ([docs/mesh/integration.md](docs/mesh/integration.md)) covering peer
  topology, identity management, anti-entropy tuning, and
  diagnostics. README "Compliance" section gains a Mesh sub-link. (#73)
- **SO_REUSEPORT + BPF demux foundation (`bpf-demux` feature)**
  (partial — see Deferred). New `src/bpf_demux.rs` module with a
  three-state `DemuxReadiness` probe (`Ready` /
  `KernelTooOld { release }` / `MissingCapability`), wired at boot
  with a structured log line. New eBPF source crate
  `bpf/zion-bpf-demux/` (mirrors `xdp/zion-xdp-prog/`'s layout) plus
  `bpf/build.sh` produces `bpfel-unknown-none` ELF that the loader
  reads from `ZION_BPF_DEMUX_OBJECT` (defaults to the build path).
  The v1 program returns `SK_PASS` — the userspace attach hook + map
  populate + body-replacement-with-real-routing are deferred. (#53
  partial — see Deferred)
- **kTLS secret-extraction fix + boot probe + `Memfd` cache helper**
  (partial — see Deferred). Three pieces:
    - `tls.rs` now sets `ServerConfig.enable_secret_extraction = true`
      under `--features ktls` (Linux). The existing `try_upgrade` path
      that wraps the post-handshake stream in `KtlsStream` requires
      this to be true; without it `config_ktls_server` fails and the
      connection is closed. This was a real bug on the kTLS path.
    - Boot log line `ktls=enabled|disabled: <reason>` emitted at
      startup when the feature is on, populated by the existing
      `probe_kernel_support` helper.
    - New `src/memfd.rs` module wrapping `memfd_create(2)` —
      `Memfd::from_bytes(label, &[u8])` produces a kernel-tmpfs-backed
      file handle. `MIN_MEMFD_THRESHOLD = 64 KB`. The dispatch-side
      sendfile path that consumes this is the deferred piece. (#52
      partial — see Deferred)
  `ktls` feature now depends on `io-uring-rw` per the issue spec.
- **io_uring rw capability probe + `io-uring-rw` feature gate**
  (partial — see Deferred). New `bootstrap::Platform.has_io_uring_rw_kernel`
  bool, populated at boot via `uname(2)` parsed against the 5.19+
  threshold (where `IORING_OP_READV_FIXED` and the rest of the rw
  surface zion would target are stable). Boot log line emitted only
  when the feature is on; the bool is unconditionally surfaced on
  `/metrics`. Two new chaos tests
  (`tests/chaos.rs::tcp_read_terminates_cleanly_*`) pin the
  "connection reset mid-read returns clean io::Error, never panics or
  hangs" contract — applies to today's tokio path AND to the future
  `IoUringStream` adapter so any regression is caught the moment the
  follow-up lands. (#51 partial — see Deferred)
- **NUMA-aware sharding for `rate_map` + `inflight`** — opt-in via
  `--features numa-aware`. On Linux multi-socket boxes, the per-IP
  rate-limit map and the singleflight inflight map split storage into
  one `DashMap` per NUMA node, routed by the calling thread's current
  node (`sched_getcpu(2)` + `/sys/devices/system/node/`). Same-socket
  workers stay cache-local; cross-socket fallback scans on get-miss.
  Single-socket / non-Linux / `--no-default-features` builds collapse
  to a single shard with no routing overhead — verified by criterion
  bench `numa/single_shard/get_hit` matching the bare `DashMap`
  baseline within noise. New `bootstrap::Platform.numa_nodes` field
  exposes the detected count. See [src/numa.rs](src/numa.rs). (#50)
- **PGO release builds (Linux x86_64-gnu)** — release.yml gains an
  opt-in `pgo: true` matrix flag. When set, the build runs a two-pass
  profile-guided pipeline: instrumented binary → 10 s deterministic
  workload via [`scripts/pgo-collect.sh`](scripts/pgo-collect.sh) →
  `llvm-profdata merge` → optimised rebuild. The PGO archive ships
  alongside the regular one with a `-pgo` suffix, its own `SHA256SUMS`
  entry, and its own SLSA build provenance. Default off for every
  target; only `x86_64-unknown-linux-gnu` is PGO'd today (musl +
  aarch64 + macOS + Windows pending). See
  [docs/perf/pgo.md](docs/perf/pgo.md). (#55)
- **Streaming WAF body inspection** — opt-in per WAF profile via
  `[waf_profile.X] streaming = true`. The dispatcher feeds each
  request-body frame to a `StreamingScanner` as it arrives off the wire;
  an injection pattern in the first chunk denies before the rest of the
  upload is read. Frames are reassembled on Allow so the regular
  `validate_request` pipeline still runs the encoded-payload pass +
  entropy + JSON gates that the streamer does not cover. Default is
  `false` (existing buffered behaviour). (#49)
- **Criterion microbench harness** — five `cargo bench` targets under
  `benches/` (waf_streaming, sovereign, traceparent, audit_hmac,
  cache_lookup) covering the hot-path components named in
  [docs/perf/roadmap.md](docs/perf/roadmap.md). Numbers checked in at
  `benchmarks/results/criterion/baseline.json` for trend tracking; CI
  workflow `bench.yml` runs the suite on manual dispatch and posts a
  delta-vs-master summary as a PR comment. See
  [docs/perf/microbench.md](docs/perf/microbench.md). (#54)

### Fixed

- **`scorecard.yml` publish step — top-level write permissions
  rejected by scorecard.dev**. The split workflow shipped in #57
  declared `id-token: write` and `security-events: write` at the
  workflow level, which scorecard-action's webapp verifier rejects
  with `400 Bad Request: "global perm is set to write"`. Move the
  writes to the `scorecard` job's `permissions:` block; top-level
  becomes `read-all`. The first scheduled / manual run after this
  lands publishes the public badge to scorecard.dev. (follow-up to
  #57)

### Changed

- **OpenTelemetry stack migrated 0.27 → 0.32 (#145)** — adapted
  `src/observability.rs` to the post-0.28 SDK API (`SdkTracerProvider`,
  `with_batch_exporter` without a runtime arg, `Resource::builder`,
  semconv `attribute::`). All target versions are MSRV 1.75. The
  cargo-vet baseline was regenerated for the new transitive crates
  (prost 0.14, tonic 0.14, …).
- **CI hardening.** `cargo-audit` / `cargo-vet` now install as **prebuilt
  binaries** (`taiki-e/install-action`) instead of building from source,
  eliminating an intermittent self-hosted-runner build flake (#154).
  Three high-volume workflows (supply-chain, CodeQL, DCO) moved to
  self-hosted runners (#144); `supply-chain.yml` forces
  `RUSTUP_TOOLCHAIN=stable` so the repo's pinned 1.88.0 toolchain can't
  break the audit jobs (#146).
- **Security:** `tar` 0.4.45 → 0.4.46 (Dependabot rust-security group).
- **`cargo-vet` promoted to a required CI gate** — `supply-chain/`
  baseline committed via `cargo vet init`, with audit imports from
  Mozilla, Google, Embark, Bytecode Alliance, ISRG, and Zcash
  reducing the residual exemption set from ~700 to 414 transitive
  crates. The `supply-chain.yml` `cargo-vet` job no longer runs with
  `continue-on-error` — a transitive crate that lacks an audit
  verdict OR an explicit `[[exemptions]]` row now fails the build.
  Workflow for refreshing the baseline documented in
  [docs/security/supply-chain.md](docs/security/supply-chain.md)
  "Updating the cargo-vet baseline". *Operator action required:*
  promote `cargo-vet` to a required status check in the master
  branch protection rule. (#58)
- **OSSF Scorecard split into a minimal workflow** — moved from
  `supply-chain.yml` to a dedicated [`scorecard.yml`](.github/workflows/scorecard.yml)
  with no global `env`/`defaults` blocks, satisfying the
  scorecard-action verification policy required for
  `publish_results: true`. The public badge at scorecard.dev now
  auto-refreshes within ~24 h of the first successful run; the SARIF
  still flows into the GitHub Security tab as before. Triggers
  (master push + 06:00 UTC cron + workflow_dispatch) match the
  previous in-supply-chain shape. (#57)
- **`WafMode` and `WafProfile` moved from `config` to `waf`** — semantic
  home, and lets the bench harness construct profiles via the lib
  surface without dragging the full config-loader dependency graph.
  `config::{WafMode, WafProfile}` re-exports preserve every existing
  import site; no breaking change.

### Deferred

- **BPF demux listener wire-up (issue #53)** — binding N sockets to a
  single SO_REUSEPORT group on `:443`, populating the
  `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` with the per-worker fds, and
  attaching the program via `SO_ATTACH_REUSEPORT_EBPF` is the runtime
  glue we don't ship in v1. It requires reorganising how `main.rs`
  constructs the HTTPS listener (today it's one `bind_with_reuseport`
  call; the BPF flow needs a coordinated bind across worker
  threads). The integration test ("TCP and QUIC clients both reach
  upstream through the unified socket") and the no-regression bench
  on TCP-only workloads land with that PR. The probe + boot log
  shipped today let an operator confirm the host is ready before the
  perf work arrives.
- **kTLS sendfile dispatch path (issue #52)** — the static-cache hot
  path that detects "memfd-backed entry + kTLS-upgraded connection"
  and routes the response through `sendfile(target_socket_fd, memfd,
  ...)` instead of hyper's body machinery is tracked separately. It
  requires (a) plumbing the connection's raw fd through dispatch (a
  layer hyper deliberately abstracts), (b) sidestepping hyper's
  AsyncWrite-driven body-send to avoid double-encoding the payload,
  and (c) a 100 KB+ benchmark to validate the issue's "≥30%
  throughput" target — none of which we ship a half-working version
  of. The `Memfd` helper (`src/memfd.rs`) and the secret-extraction
  fix mean the next PR can focus purely on (a) + (b) + (c) without
  re-litigating the kTLS plumbing.
- **`IoUringStream<R, W>` runtime adapter (issue #51)** — the
  `io_uring_prep_readv` / `writev` integration that replaces tokio's
  read/write half of accepted connections is tracked separately. The
  v0.2.x slice ships only the `io-uring-rw` feature gate, the
  `bootstrap::Platform.has_io_uring_rw_kernel` probe, the chaos
  contract test, and a structured boot log line. The adapter itself
  is research-grade (correct AsyncRead/AsyncWrite over a tokio-driven
  io_uring submission queue is multi-day work that doesn't compress
  cleanly) and we don't ship a delegating stub — operators that
  enable the feature today get the probe and the auto-disable signal,
  not silent userspace I/O dressed up in io_uring trappings.

## [0.2.3] - 2026-05-26

Maintenance release. No code-surface change — dependency hygiene only.

### Changed

- **MSRV-safe lockfile refresh.** `Cargo.lock` rolled forward to the
  latest dependency versions that still resolve under MSRV-core 1.82
  (ADR-0007 anchor): `rustls` 0.23.37→0.23.40, `reqwest` 0.13.2→0.13.3,
  `rcgen` 0.14.7→0.14.8, `serde_json` 1.0.149→1.0.150, `yasna`
  0.5.2→0.6.0, plus `libc`, `mimalloc`/`libmimalloc-sys`, `io-uring`
  0.7.11→0.7.12 and `arc-swap`. `socket2`/`itertools` pinned down to
  MSRV-compatible releases. All bumps are within-major (patch/minor).
- **Dependabot:** hold `hyper-rustls < 0.27.8` — 0.27.8 raises its MSRV
  to rustc 1.85, colliding with the 1.82 anchor. The MSRV CI gate is the
  hard guard; the ignore rule just stops re-proposal until MSRV-core
  moves to 1.85.
- **cargo-vet:** exemptions regenerated to match the refreshed lockfile;
  `imports.lock` refreshed from the trusted audit sources.

## [0.2.2] - 2026-05-08

Wire-up release. v0.2.0 / v0.2.1 introduced the XDP / ML-WAF / AIMP
feature surface; v0.2.2 plugs the remaining loose ends so the v0.2.x
line ships with everything actually wired through the request path.

### Added

- **AIMP `[sovereign_aimp]` TOML block** — promote the v0.2.1 env-var
  bootstrap to a first-class config section. `ZION_AIMP_*` env vars
  still work (back-compat) and act as fallback when a TOML field is
  empty. New keys: `enabled`, `listen`, `peers`, `identity_path`,
  `xdp_block_threshold`, `anti_entropy_secs`. (#63)
- **AIMP identity persistence** — `aimp_cp::bootstrap` now loads the
  Ed25519 secret from `identity_path` on subsequent boots, generating
  + writing it on first boot with `chmod 600`. The derived `node_id`
  is stable across restarts; peers no longer have to re-classify the
  node on every cycle. Upstream `aimp_node` 0.1.0 (commit 4631819)
  exposes `Identity::from_secret_bytes` / `secret_bytes` accessors to
  make this possible without forking the crate. (#68)
- **AIMP lookup pre-WAF (signal, not gate)** — every request now
  consults `cp.lookup(client_ip)` *before* the WAF gate; a known-
  malicious score from the mesh is forwarded upstream as
  `X-Zion-Mesh-Score: 0.NN` so backends can apply additional friction
  (CAPTCHA, longer rate windows) without zion shipping a hard block
  policy that varies by node. The local WAF / auth / rate-limit
  decisions remain authoritative. (#65)
- **AIMP anti-entropy** — periodic per-peer re-broadcast of the local
  reputation map, period configurable via `anti_entropy_secs` (default
  60s, 0 = off). Closes the steady-state convergence gap that
  delta-only gossip leaves on UDP loss / partition heal — N=50 mesh
  reaches 100% within 2× the period instead of stalling at the v0.2.1
  94% ceiling. (#88)
- **kTLS post-handshake wire** — the HTTPS accept loop now wraps the
  TCP stream in `ktls::cork_for_handshake` *before* the rustls
  handshake, then `try_upgrade`s the resulting `TlsStream` into a
  `KtlsStream` that runs record encrypt/decrypt in the kernel. Behind
  `--features ktls` (Linux ≥ 5.10 with `CONFIG_TLS=y`); kTLS upgrade
  failures fall back to userspace TLS on the same connection. (#86)
- **AIMP → XDP reconciler** — restored as `src/aimp_xdp_sync.rs`
  (separate file rather than nested in `aimp_cp.rs` so the
  `examples/aimp_*.rs` crates that embed the control plane via
  `#[path = ...]` don't drag the XDP module they cannot resolve).
  The reconciler subscribes to control-plane updates and reflects
  the IP reputation map into the kernel's `BLOCKED_V4` LPM-trie.

### Fixed

- **io_uring single-shot Accept** — `--features io-uring-accept` now
  uses `opcode::Accept` re-submitted per CQE instead of `AcceptMulti`.
  Closes the v0.2.0 ENOTSOCK race on Proxmox 9.1 LXC + kernel 6.17
  where `AcceptMulti` would emit `res = -88` continuously after the
  first burst — a TFO/DEFER_ACCEPT × multishot interaction that
  transitioned the listener fd into a state io_uring rejected. Costs
  one extra `submission().push()` per accept (~tens of ns); the kernel
  pipeline now stays fed under sustained load. (#87)

### Notes

- Total feature matrix: default, `xdp`, `ktls`, `ml-waf`,
  `sovereign-aimp`, and every combination thereof — all green.
- Test suite: 429 with `--all-features` (v0.2.1: 429; net new tests
  this release covered by the existing `aimp_cp::tests::*` adversarial
  battery — anti-entropy is a behavioural extension, not a new gate).
- Default build is unchanged on the wire: kTLS / XDP / mesh are all
  opt-in and gated.

## [0.1.12] - 2026-05-06

Quality + security release. Closes one Dependabot security alert (medium)
on the `--features auth` build path, removes the boot-time panic surface,
extends the SSOT version guard to every documented version reference,
and brings the `#[ignore]`d integration suite under CI guard so it stops
rotting silently.

### Security

- **`jsonwebtoken` 9.3.1 → 10.3.0**: closes the GHSA Type Confusion that
  could lead to authorization bypass on the `--features auth` JWT
  validator. v10 enforces an explicit choice of CryptoProvider; pinned
  to `aws_lc_rs` to stay aligned with rustls's backend (and the FIPS
  build path). (#43)

### Reliability

- **3 boot-time `panic!` / `exit(1)` sites → structured `ZionError`**
  propagation in `src/main.rs` (router build), `src/auth.rs` (JWT
  algorithm + missing secret/jwks_url), `src/tls.rs` (cert-dir watcher
  setup hoisted out of the spawned task). Hot-reload also benefits via
  the new `try_build` returning `Result`. (#78)
- **Flaky `rate_limiter_caps_at_rps_within_window` proptest fixed**:
  invariant relaxed to `<= 2 * rps as usize` to honour the wall-clock
  window flip the limiter exposes (`SystemTime::now()`-keyed window),
  with the cross-window scenario explained in a comment. (#77)

### Hardening / Process

- **`Cargo.toml` becomes the version SSOT** for the project. `Cargo.lock`,
  `deploy/helm/zion/Chart.yaml`, README, `docs/security/supply-chain.md`,
  `SECURITY.md`, `docs/deploy/hot-reload.md`, and the bug-report issue
  template are now CI-checked against canonical (#75, #80).
  `scripts/bump-version.sh X.Y.Z` propagates to all 7 sites atomically.
- **DCO sign-off enforced locally** via `.githooks/prepare-commit-msg`
  (auto-injects the trailer) and `commit-msg` (refuses commits without
  one). `scripts/install-hooks.sh` switched to
  `git config core.hooksPath .githooks` so hooks update on `git pull`. (#75)
- **README headline numbers (modules / LoC / tests) become an SSOT**
  produced by `scripts/update-readme-stats.sh`; CI fails on drift.
  Underlying script bug fixed: previously did `find -maxdepth 1` and
  `wc -l src/*.rs`, missing `src/sovereign/`. (#76)

### Quality / Polish

- **SPDX `Apache-2.0` header on every Rust file** (32 files in `src/` +
  `tests/`) so the licence is machine-readable for SBOM scanners. (#79)
- **Complete `unsafe` SAFETY audit**: 11/11 unsafe blocks now carry a
  `// SAFETY:` note; added the missing one on `src/net.rs::tune_accepted`. (#79)
- **Module-level docstrings** added on the five files that lacked them:
  `config.rs`, `dispatch.rs`, `main.rs`, `proxy.rs`, `tls.rs`. (#78)
- **Dead-code cleanup**: 5 unreachable items removed
  (`cache.rs::ensure_l1`, `bootstrap.rs::tune_accepted_socket`,
  `tune_listener_socket`, `Platform.recv_buf`, `auth.rs::AuthError::MissingToken`).
  The remaining ~45 `#[allow(dead_code)]` annotations are intentional
  (feature-gated, future-API hooks, deser-only struct fields, test
  helpers) and already documented. (#81)
- **Stale `RELEASE_NOTES.md` removed**: it was a v0.1.6-specific
  announcement that nobody refreshed; `CHANGELOG.md` + GitHub Releases
  cover the role. (#83)
- **README OpenSSF Baseline badge** in place of the broken Scorecard
  badge (publish_results was disabled in v0.1.10 to satisfy the
  Scorecard webapp constraint, which in turn broke the badge endpoint). (#74)

### CI

- **New `integration` workflow**: spins up the test backend on `:9090`
  and zion on `:4433` (with a self-signed cert via
  `benchmarks/certs/generate.sh`) and runs the 19 `#[ignore]`d
  integration tests. They were rotting silently — now load-bearing on
  every PR. (#82)
  - Two pieces of rot the unrun tests had hidden are also fixed in this
    release: `tests/integration.rs::t01` asserted `<h1>Zion Test Backend</h1>`
    (no backend ever served this string), and the Rust test backend
    lacked the `query` / `x_forwarded_proto` echo fields and the
    `/api/v1/events/stream` SSE endpoint that the tests rely on.
- **New `version-sync` and `readme-stats-sync` workflows** wire the SSOT
  scripts above into per-PR enforcement. (#75, #76)
- **Branch protection cleaned**: dropped `SBOM (CycloneDX)` from
  required status checks (release-only, was never green on PRs and made
  every PR `mergeStateStatus: BLOCKED`); fixed `DCO` → `dco-check` name
  mismatch.

### Verification

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo test  --release                  → 421 passed (lib + main bin + chaos)
cargo test  --release --all-features   → 463 passed
integration tests (CI)                 → 19 passed
scripts/check-version-sync.sh          # OK across 7 reference sites
scripts/update-readme-stats.sh --check # in sync
```

## [0.1.11] - 2026-05-06

Process hardening — version becomes single-source-of-truth, DCO sign-off
becomes draconian. Closes the two CI failure modes seen on recent PRs
(`uninlined_format_args` on Windows + MSRV `--all-targets`, missing
`Signed-off-by` trailer) at the source.

### Added
- **Version SSOT enforcement.** `Cargo.toml` is the canonical version;
  drift across `Cargo.lock`, `deploy/helm/zion/Chart.yaml`,
  `README.md`, and `docs/security/supply-chain.md` is now a hard error.
  - `scripts/check-version-sync.sh` — verify (run by `pre-push` and CI).
  - `scripts/bump-version.sh X.Y.Z` — atomic bump propagated to every site.
  - `.github/workflows/version-sync.yml` — server-side guard on PRs to
    `master` and on every push.
- **Mandatory DCO sign-off via local hooks.**
  - `.githooks/prepare-commit-msg` auto-injects the `Signed-off-by` trailer
    (idempotent, `git interpret-trailers --if-exists addIfDifferent`).
  - `.githooks/commit-msg` refuses commits without a valid trailer.
  - `scripts/install-hooks.sh` switched from copying into `.git/hooks/` to
    `git config core.hooksPath .githooks` — hooks are now version-controlled
    and update on `git pull`.

### Changed
- **CI lint fixes** (already landed post-0.1.10, recorded here for
  release notes): `uninlined_format_args` resolved in `src/doctor.rs`,
  `src/listener.rs`, `src/uring.rs`; MSRV job relaxed for `--all-targets`;
  CodeQL Rust build-mode and Scorecard `publish_results` corrected.
- **Helm chart appVersion** bumped to 0.1.11 (chart `version` unchanged).

### Verification

```text
scripts/check-version-sync.sh                      # OK
cargo check                                        # OK
cargo test                                         # 77 tests, all passing
.githooks/prepare-commit-msg + commit-msg          # idempotent + rejects unsigned
```

## [0.1.10] - 2026-05-05

Supply-chain hardening — closes 3 of the 4 OSSF Scorecard gaps surfaced
on the v0.1.9 release. No code changes; CI / Helm / Dockerfile only.

### Added
- **Branch protection on `master`** (10 required status checks: CI Success,
  cargo-deny ×4, cargo-audit, SBOM CycloneDX, CodeQL ×2, DCO; linear
  history; force-push and delete disabled; conversation resolution
  required).

### Changed
- **All 71 GitHub Action references** across 8 workflow files pinned by
  40-char commit SHA (with `# vX` comment for human readability and
  Dependabot SHA-aware bumping). Resolved via `gh api repos/<o>/<r>/commits/<ref>`.
- **All 6 Docker base images** pinned by digest (`Dockerfile`,
  `benchmarks/Dockerfile.zion`, `benchmarks/backend/Dockerfile`).
- **Token-Permissions** scoped to least-privilege:
  - `dco.yml`: explicit `contents: read` (top + job).
  - `sovereign-data.yml`: top-level `contents: read`; `contents: write`
    + `pull-requests: write` only on the `refresh-ita` job.
- **Helm chart** bumped to 0.2.2 (appVersion 0.1.10).

### Verification

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo test  --locked --all-features    →  463 passed
cargo deny  --all-features check       →  advisories ok, bans ok, licenses ok, sources ok
helm lint deploy/helm/zion                          # OK
actionlint .github/workflows/*.yml                  # OK
```

OSSF Scorecard sub-checks moved from 0/10 to 10/10:
Token-Permissions, Pinned-Dependencies, Branch-Protection.

## [0.1.9] - 2026-05-05

Five-track quality pass: Trust & supply chain, Observability, Robustness
& API, Performance ceiling, Compliance & conformance. No breaking changes
to existing operators; every new behaviour is opt-in or back-compatible.

### Added — Track A (Trust & Supply Chain)
- **SLSA v1.0 build provenance** for every binary, the `SHA256SUMS` file,
  the SBOM, and every container image — generated by
  `actions/attest-build-provenance@v2` and recorded in the public Sigstore
  Rekor log. (`.github/workflows/release.yml`)
- **Cosign keyless signatures** on every published GHCR multi-arch image,
  bound to the canonical release-workflow OIDC identity.
- **CycloneDX 1.5 SBOM** attached to each release and as a cosign attestation.
- **Cross-compiled binaries** for 7 targets via `cargo-zigbuild`:
  `x86_64-unknown-linux-{gnu,musl}`, `aarch64-unknown-linux-{gnu,musl}`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
- **`cargo-deny` policy** (`deny.toml`) and **`cargo-audit` config** kept
  in sync; new `.github/workflows/supply-chain.yml` runs daily.
- **CodeQL** (Rust + GitHub Actions) on every PR.
- **Dependabot** with grouping and security-only fast-track.
- **Distroless container** (`gcr.io/distroless/cc-debian12:nonroot`,
  UID 65532, no shell, no SUID).
- **MSRV** dichiarata: `1.82` per il binario core (no-default-features),
  `1.88` con feature opzionali. CI verifica entrambi i floor.
- **Documentazione** [docs/security/supply-chain.md](docs/security/supply-chain.md).

### Added — Track B (Observability)
- **`tracing` always-on** (`tracing-subscriber` JSON or text) replaces the
  bespoke `logging::*` chain for everything past the boot banner.
- **W3C Trace Context** parser with strict RFC validation; malformed
  inbound `traceparent` headers are rejected and counted, never forwarded.
- **OpenMetrics exemplars** on every histogram bucket — each `_bucket{le=…}`
  line carries `# {trace_id="…"} value timestamp` of the latest observation
  in that bucket.
- **OTLP gRPC export** behind `--features otel`. Off by default; pulls in
  `tonic`/`prost` only when enabled.
- **HMAC-SHA256-chained audit log** (`src/audit.rs`) — JSON-Lines, async
  bounded writer, PII redaction applied before signing. New `[audit]` and
  `[redact]` config blocks.
- **Panic hook** writes one structured JSON record to stderr and to a
  "last-gasp" file (`/var/lib/zion/last_panic.jsonl`) before abort.
- New counters: `zion_panics_total`, `zion_audit_events_total`,
  `zion_audit_events_dropped_total`, `zion_traces_emitted_total`,
  `zion_traces_invalid_total`.
- **Documentazione** [docs/guide/observability.md](docs/guide/observability.md).

### Added — Track C (Robustness & API)
- **`enum ZionError`** unifies the boot path's error type
  (`Box<dyn Error>` removed from `main` and `async_main`). Per-category
  Unix exit codes via `to_exit_code()`.
- **`SAFETY:` / `INVARIANT:` audit** of every production
  `unwrap()` / `expect()` / `panic!`; QUIC builders refactored from
  `expect()` to `Result<_, String>`.
- **Property-based tests** (`proptest`): 11 properties on rate-limiter,
  W3C parser, redaction, HMAC determinism.
- **`cargo-fuzz` workspace** with three targets: `traceparent_parser`,
  `redact_query_string`, `audit_chain_verify`. CI build-only verification.
- **Chaos integration tests** (`tests/chaos.rs`): audit queue overflow,
  drain, idempotence.
- **Threat model (STRIDE)** — [docs/security/threat-model.md](docs/security/threat-model.md).
- **Architecture Decision Records** — [docs/adr/](docs/adr/) with 7
  load-bearing decisions (ArcSwap hot-reload, Aho-Corasick, two-level
  cache, HMAC audit, distroless+SLSA, tracing+OTLP, MSRV bicapa).
- **Helm chart 0.2.0**: PodDisruptionBudget, default-deny NetworkPolicy,
  dedicated ServiceAccount with `automountServiceAccountToken: false`,
  pod-level seccomp `RuntimeDefault`, `readOnlyRootFilesystem` with
  emptyDir for ACME state, startupProbe + tunable timeouts,
  topologySpreadConstraints.

### Added — Track D (Performance)
- **Sovereign log: zero-alloc hot path.** The per-request
  `format!("ip=… class=…")` in `dispatch.rs` is replaced by per-class atomic
  counters (`zion_sovereign_classifications_total{class="…"}`) plus a
  `tracing::info!` event with `&'static str` labels.
- **Streaming WAF body scan** (`waf::StreamingScanner`) — chunked
  Aho-Corasick with a 63-byte overlap buffer, early-exit on first match,
  incremental `max_body_mb` enforcement. Public API + tests; dispatch
  wiring tracked in [docs/perf/roadmap.md](docs/perf/roadmap.md).
- **Performance roadmap** for the deferred items: NUMA-aware sharding,
  io_uring r/w vectored, kTLS sendfile, BPF demux for unified TCP/QUIC.

### Added — Track E (Compliance)
- **FIPS 140-3 build** behind `--features fips` — switches to
  `aws-lc-fips-sys` (NIST CMVP Cert. #4759). TLS 1.3 ciphers, audit-log
  HMAC, ticketer all run through the validated module. Documentazione
  in [docs/security/fips.md](docs/security/fips.md).
- **OWASP ASVS L2 mapping** — [docs/security/asvs.md](docs/security/asvs.md):
  V1/V3/V4/V5/V7/V8/V9/V10/V12/V13/V14, control → impl file → test/evidence.
- **TLS conformance plan** — [docs/security/tls-conformance.md](docs/security/tls-conformance.md):
  BoGo / RFC 8446 / SSL Labs recipes.
- **GDPR access log**: structured `tracing::info!(target: "access")` event
  per request with query-string redaction via `[redact.query_params]`.

### Fixed
- **`rustls-webpki` 0.103.10 → 0.103.13** — addresses RUSTSEC-2026-0104
  (reachable panic in CRL parsing). Caught at first run of the new
  supply-chain pipeline.
- **`Ticketer::new().expect()`** — replaced with `?`-propagation; CSPRNG
  starvation now surfaces as `ZionError::Tls` with a clean exit code.
- **Clippy 1.88 lints**: `uninlined_format_args` (170+ sites),
  `clippy::precedence` in `src/security.rs:142,158`, `should_implement_trait`
  on `LogFormat::from_str` → renamed to `parse_or_text`.

### Verification

Local validation against this release:

```text
cargo fmt --all -- --check                          # OK
cargo clippy --locked --all-targets --all-features -- -D warnings   # OK
cargo clippy --locked --all-targets --no-default-features -- -D warnings   # OK
cargo test  --locked --all-features    →  49 lib + 410 bins + 4 chaos = 463 passed
cargo test  --features fips --bins     →  368 passed (FIPS module compiled)
cargo doc   -D warnings --all-features                              # OK
cargo deny  --all-features check       →  advisories ok, bans ok, licenses ok, sources ok
cargo audit                                                          # OK
rustup run 1.82.0 cargo check --no-default-features                  # OK (MSRV floor)
helm lint deploy/helm/zion                                           # OK
```

Verifying a release artifact:

```bash
# Binary
gh release download v0.1.9 -R fabriziosalmi/zion -p '*x86_64-unknown-linux-musl*' -p 'SHA256SUMS'
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify zion-v0.1.9-x86_64-unknown-linux-musl.tar.gz --owner fabriziosalmi

# Container
cosign verify ghcr.io/fabriziosalmi/zion:v0.1.9 \
    --certificate-identity-regexp "^https://github.com/fabriziosalmi/zion/\\.github/workflows/release\\.yml@refs/tags/v" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

## [0.1.7] - 2026-04-29

Hardening pass: closes one concurrency bug, removes one foot-gun, replaces
two stale defaults, and aligns README + docs 1:1 with the code.

### Fixed (correctness)
- **Singleflight cache miss could hang waiters until client timeout.** The
  previous `tokio::sync::Notify`-based coalesce had a race: if the fetcher
  completed between the waiter's `inflight.get()` and its `.notified().await`,
  the wake was missed because `notify_waiters()` does not store a permit.
  Replaced with `tokio::sync::watch::Sender<bool>`; `Receiver::wait_for`
  inspects the current value at first poll, so a late subscriber still
  observes completion. Verified with a deterministic test that pins the
  post-completion subscribe path. (`src/dispatch.rs`, `src/main.rs`)
- **`X-Client-Cert-DN` was a 64-bit XOR-fold of the leaf DER.** The header
  name implied a Distinguished Name but the value had massive collision
  classes (any two certs whose first 64 bytes XOR-equal collide) and no
  cryptographic property. Replaced with `X-Client-Cert-Fingerprint:
  sha256:HEX` (SHA-256 of the leaf DER, openssl/nginx convention). Tests
  pin the format and the NIST SHA-256 vector.
  **Breaking:** consumers reading `X-Client-Cert-DN` must migrate.
  (`src/main.rs`, `src/tls.rs`)
- **Thread-local route cache stopped accepting inserts at 256 entries.**
  Was `if c.len() < 256 { insert }` — a flood of distinct paths could
  permanently lock out subsequent hot-route promotion. Replaced with a real
  O(1) LRU (intrusive doubly-linked list backed by a Vec, free-list for
  index recycling). Adversarial-flood test pins the fix. (`src/dispatch.rs`)
- **WAF Gate 6 was advertised but not implemented.** The module header and
  several doc pages described a sixth "fixed-length profiling" gate that
  did not exist in `validate_request`. Removed the advertisement; the WAF
  is now described as 5 gates (its real shape) everywhere.

### Changed (defaults)
- **WAF detection modes.** New `WafProfile.mode = "balanced" | "aggressive"`.
  `balanced` is the default (high precision: ~120 anchored / CVE-class
  patterns). `aggressive` is opt-in (~190 patterns total: balanced plus
  ~70 broad-substring patterns including `alert(`, `eval(`, `confirm(`,
  `document.cookie`, `innerhtml`, `$gt`, `$ne`, `$regex`, `os.system(`,
  `pickle.loads`, `Runtime.getRuntime`, generic event handlers like
  `onclick=`/`onmouseover=`/…). The previous monolithic 192-pattern set
  flagged a long list of legitimate developer-tool / educational / log-
  shipping payloads — those patterns are now opt-in via aggressive mode.
  - **Breaking for users who relied on those patterns:** add
    `mode = "aggressive"` to the relevant `[waf_profile.X]`.
- **Entropy gate threshold raised from 5.5 to 6.5 bits/byte** (now
  per-profile via `entropy_threshold`). The old default flagged any
  base64 / JWT / signed URL of meaningful length — pure base64 has a
  theoretical max entropy of 6.0, so 5.5 was below it. The new default
  sits clearly above 6.0 and still flags random/encrypted blobs (~7.5–8.0).
  Per-profile kill-switch via `entropy_check = false`.
- **JSON-aware entropy.** For `application/json` content-types, the gate
  now computes Shannon entropy only on bytes inside string literals,
  skipping structural punctuation and numeric tokens that would otherwise
  dilute the signal. Skipped entirely if string-content < 128 bytes.
- **`bootstrap.calibration_us` is now `Option<u64>`.** Previously the
  field reported the few microseconds spent in the `ZION_BOOT_FAST=1`
  env-var check as if it were a real measurement; CI/Ansible consumers
  could not distinguish "calibrated in 80 ms" from "skipped, here's
  21 µs of overhead." JSON snapshot serialises `null` when skipped.

### Added
- **`server.xff_mode = "append" | "rewrite" | "drop"`** outbound XFF
  policy. `append` (default) preserves the previous behaviour (safe
  behind a sanitising edge). `rewrite` strips inbound XFF and emits a
  single trusted entry — recommended when Zion is the front edge,
  closes the spoofing foot-gun where attacker-controlled `XFF[0]`
  reached upstream apps. `drop` strips inbound and emits nothing.
  `X-Real-IP` is now always sourced from the resolved client IP and
  never trusted from an inbound header. (`src/proxy.rs`, `src/config.rs`,
  `src/dispatch.rs`, `src/main.rs`)
- `scripts/update-readme-stats.sh`: rewrites README badges (modules /
  lines / unit-test count) from authoritative sources, with a `--check`
  mode for CI.

### Operations
- **`bench-native.sh` now tracks `Non-2xx or 3xx responses`** and aborts
  the run if any non-success response was returned. The previous script
  honoured the "Zero-error tolerance" claim only for socket errors —
  503-flood scenarios produced clean-looking output.
- **Removed crate-level `#![allow(dead_code)]`, `#![allow(unused_imports)]`,
  `#![allow(unused_variables)]`** from `src/main.rs`. The 17 warnings that
  surfaced are all addressed: unused imports removed, true dead code
  deleted, feature-gated symbols annotated puntually with comments.
  `cargo build --release` now emits 0 warnings; CI can pin this with
  `RUSTFLAGS='-D warnings'`.

### Tests
- 261 → **300** unit tests passing. New tests cover: 4× singleflight
  primitive (incl. the post-completion subscribe path), 4× SHA-256 mTLS
  fingerprint (format / NIST vector / determinism / diffusion), 8× route
  LRU (incl. adversarial flood), ~30× WAF balanced-vs-aggressive contract
  (`balanced_allows_*` + `aggressive_denies_*`) + 5× entropy gate
  (base64 passes, random blocks, kill-switch, configurable threshold,
  JSON-string-only function), 11× XFF policy (append preserves spoofed,
  rewrite strips multi-hop, drop emits nothing, X-Real-IP never trusted).
- `tests/integration.rs`: 19 integration tests unchanged.

### Documentation
- Full audit of `README.md` and `docs/`. Removed: `192 patterns / 14
  categories` claim (replaced with mode-aware description), `6-gate
  pipeline` (5 gates was always the truth), `SIMD pre-filter (memchr3)`
  (never existed), `Zero false positives` (was AI-slop marketing,
  contradicts the WAF reality), `~8,600 lines / 17 modules` (now
  ~15,900 / 21, kept in sync by the script), stale version strings,
  the false claim that Zion "rejects requests on detection of double
  encoding" (it actually re-scans after each decode pass, up to 3).
  Added: `Detection Modes` section (`docs/config/waf.md`),
  `X-Forwarded-For Policy` and `mTLS Client Certificate Forwarding`
  sections (`docs/security/hardening.md`), updated `zion.example.toml`
  with all new fields.

## [0.1.4] - 2026-04-15

### WAF Pattern Expansion (88 -> 192, +104 patterns)

14 attack categories, zero false positives, single O(N) Aho-Corasick pass.

**New categories:**
- XSS Event Handlers (+21): oninput=, onchange=, ondragstart=, ontouchstart=, onpointerover=, etc.
- XSS Tags (+7): img src, body onload, video onerror, details ontoggle, math xlink
- XSS JS Sinks (+7): confirm(, prompt(, window.location, innerHTML, outerHTML, srcdoc=
- NoSQL Injection (+12): $gt, $ne, $regex, $where, .find({, .aggregate([
- Deserialization/RCE (+16): Java (Runtime.getRuntime), Python (pickle.loads, os.system), PHP (unserialize, php://filter, phar://)
- GraphQL Injection (+6): __schema, __type, introspection probes
- LDAP Injection (+6): )(cn=*, ldap://, )(objectclass=*
- XML/XXE (+8): <!ENTITY, SYSTEM "file://, <xsl:, data:text/html
- SSTI (+6): #{7*7}, ${7*7}, {{7*7}}, <%=, {%import
- CRLF/Header Injection (+4): %0d%0a, %0aSet-Cookie:, %0aLocation:
- SSRF Cloud (+5): Azure IMDS, DigitalOcean, Oracle Cloud, Kubernetes, OpenStack
- Windows Path Traversal (+3): C:\windows\, C:\inetpub\
- Open Redirect (+2): /\evil, /%09/

**Tests:** 177 passed (+23 vs v0.1.3), including false-positive safety checks.

## [0.1.3] - 2026-04-15

### Fixed (Copilot code review)
- Fix `.cargo/config.toml`: `cfg(any())` is always false, replaced with `[build]`
- Fix singleflight: inflight entry cleaned up on proxy error, client disconnect, and upstream frame error (prevents waiter deadlock)
- Fix WAF SIMD pre-filter: removed unsound fast-reject that skipped raw Aho-Corasick scan (patterns like `union select` have no trigger bytes)
- Fix metrics ArcSwap: combined timestamp + buffer into single atomic `ArcSwap<(u64, Bytes)>` (prevents readers seeing stale buffer)
- Fix JWKS backoff: failure after success resets to 5s (was stuck at 3600s), cap reduced to 300s
- Fix bench-pgo.sh: PID capture was in subshell, now uses Rust backend
- Fix PDF report: version strings updated to match release

### Added
- Rust benchmark backend (pure hyper, 194K raw req/s, replaces Go)
- Apple-native docs homepage (custom CSS, dark mode, frosted glass nav)
- docs/config/auth.md (JWT/OIDC configuration)
- docs/config/http3.md (HTTP/3 QUIC support)

### Changed
- Architecture docs: 17 modules documented (was 11)
- Benchmark numbers: Rust backend eliminates Go bottleneck (+14-61% on proxy paths)

### Benchmark Results (Apple M4, Rust backend, v0.1.3)

| Endpoint | req/s | CV% |
|----------|------:|----:|
| HTML SSR 5KB | 233,170 | 1.1% |
| CSS 3KB (cached) | 209,573 | 3.4% |
| TLS Proxy API 1KB | 106,505 | 2.1% |
| WAF POST JSON | 103,206 | 0.5% |
| JS 4KB (uncached) | 102,892 | 1.3% |
| PNG 8KB (uncached) | 99,496 | 1.7% |
| WOFF2 16KB (uncached) | 83,870 | 2.5% |

## [0.1.2] - 2026-04-14

### Security (28 bugs fixed)

**Critical (7)**
- Fix request smuggling via forwarded `Transfer-Encoding` header (proxy.rs)
- Fix cache poisoning: cache key now includes query string (dispatch.rs)
- Fix WebSocket 101 response: forward `Sec-WebSocket-Accept` from upstream (proxy.rs)
- Fix WAF bypass via multi-layer URL encoding: normalization iterates until convergence (waf.rs)
- Fix WAF POST/PUT/PATCH path: no longer skips CORS headers, metrics, or request-ID (dispatch.rs)
- Fix `Vary` header check: exact token matching prevents disabling cache for gzip upstreams (dispatch.rs)
- Fix HTTP/80 handler: add rate limiting and URI length check (main.rs)

**High (8)**
- Fix L1/L2 cache coherence: generation counter invalidates stale L1 entries (cache.rs)
- Fix WAF: validate DELETE request bodies (dispatch.rs, waf.rs)
- Fix CORS: block OPTIONS preflight from disallowed origins (dispatch.rs)
- Fix cache: preserve `Content-Encoding` header on cache hits (dispatch.rs, cache.rs)
- Fix SSRF detection: add HTTPS, hex IP, decimal IP, DNS rebinding patterns (waf.rs)
- Fix EWMA latency: use CAS loop for atomic updates (health.rs)
- Fix TLS cert generation: `Acquire` ordering on ARM for data plane reads (tls.rs)
- Fix client cert fingerprint: correct misleading SHA256 comment (main.rs)

**Medium (13)**
- Fix URI length check to include query string (dispatch.rs)
- Add spaceless command injection patterns (waf.rs)
- Lower path traversal detection to 2-level (waf.rs)
- Fix Content-Type matching to require delimiter after type (waf.rs)
- Fix Bearer token extraction: case-insensitive per RFC 6750 (auth.rs)
- Fix JWKS refresh: retry with exponential backoff (auth.rs)
- Validate `auth_profile` references in config at load time (config.rs)
- Increase connection timeout to 1h for HTTP/2 mux and WebSocket (main.rs)
- Fix TLS prewarm/watcher race via generation check (tls.rs)
- Log setsockopt failures instead of ignoring (net.rs)
- Watch all SNI cert directories for hot-reload (tls.rs)
- Fix CORS origin: case-insensitive per RFC 6454 (security.rs)

### Performance (20 optimizations)

**Compiler/Build**
- Enable `target-cpu=native` via `.cargo/config.toml` (NEON/AES-CE on Apple Silicon)
- Add PGO build script (`benchmarks/bench-pgo.sh`) for 10-20% additional gain

**Allocation Elimination**
- Traceparent: stack `[u8;55]` buffer replaces 3x `format!` (-500ns/req)
- CORS origin: `HeaderValue` clone instead of `String` allocation
- WAF content-type: borrow from `parts.headers` instead of pre-clone
- Cache key: `Arc::from()` direct instead of `String` intermediate

**Lock/Contention Reduction**
- WebSocket TLS config: `OnceLock` (built once, not per-upgrade)
- Metrics render: `ArcSwap` replaces `RwLock` (lock-free `/metrics`)
- Histogram observe: 3 atomics instead of 17 (non-cumulative differential buckets)
- HTTP builder: `Arc` wrap (ref-count bump instead of deep clone)

**Data Structures**
- L1 cache: O(1) LRU via index-based doubly-linked list (was O(N) VecDeque)
- Host validation: single-pass byte scan (was 8 separate `contains()` calls)
- CORS origin: FNV hash set O(1) lookup (was `Vec` linear scan)

**WAF Pipeline**
- SIMD pre-filter: `memchr3` fast-reject before Aho-Corasick (-200-500ns for clean bodies)
- Normalization iterations capped at 2 (was 7)
- Thread-local buffer shrink-to-fit above 64KB (prevents OOM)

**Innovative**
- Request coalescing (singleflight): N concurrent cache misses = 1 upstream fetch
- Health probe inline fast-path: `/healthz` responds in ~1us, bypasses full pipeline
- `SO_BUSY_POLL` on Linux: spin-poll NIC queue for -5-15us p99 latency

### Benchmark Results (Apple M4, TLS 1.3)

| Endpoint | req/s |
|----------|------:|
| HTML SSR 5KB | 233,341 |
| Cache Hit JS 4KB | 209,381 |
| CSS 3KB (cached) | 191,574 |
| TLS Proxy API 1KB | 93,253 |
| WAF POST JSON | 91,893 |
| SQLi/XSS blocked | Yes |

## [0.1.1] - 2026-04-12

- Initial public release
- TLS 1.3 reverse proxy with WAF, cache, rate limiting
- 141K req/s cached throughput
- Docker comparison vs nginx (+108% HTML, +42% PNG)

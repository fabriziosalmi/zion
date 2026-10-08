// SPDX-License-Identifier: Apache-2.0
//! The cached route: lookup, revalidation, stale serving, singleflight and storing.
//!
//! One request on a route with a cache profile (or `static_cache` mode) runs
//! [`handle`]: it derives the cache keys, answers from a fresh or stale entry when it can,
//! otherwise becomes the one fetcher for its key (or waits for the one already running),
//! asks the circuit breaker, fetches, and stores what the origin answered while streaming it.

// The `Err` of the stages that can answer outright is the response itself, built once: boxing it
// would add an allocation to every cache hit for nothing.
#![allow(clippy::result_large_err)]

use super::*;

/// Everything a cached request knows once its keys are derived. It does not change for the rest of
/// the request, so the stages below read it instead of taking a dozen arguments each.
struct Cx<'a> {
    state: &'a Arc<AppState>,
    rule: &'a ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &'a hyper::http::uri::Scheme,
    dyn_authority: &'a hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
    breaker: Option<Arc<health::UpstreamHealth>>,
    cache_ttl: u64,
    cache_max: usize,
    max_object: usize,
    tag_epoch: u64,
    req_authenticated: bool,
    rcc_no_store: bool,
    primary_key: String,
    identity_primary: String,
    takes_identity: bool,
    cache_key: String,
    identity_key: Option<String>,
}

/// What the RAM lookup found, when it did not answer the request outright.
struct Lookup {
    /// A stale entry with a validator: the fetch below revalidates it.
    revalidate: Option<cache::CacheHit>,
    /// Any stale entry, validators or not: what an open circuit can fall back on.
    stale_entry: Option<cache::CacheHit>,
    /// The key the entry being revalidated lives under (its own key or the identity key).
    found_key: String,
}

/// Where the response of a fetch is to be stored, and how fresh it is.
struct Storage {
    initial_age: u64,
    effective_ttl: u64,
    cacheable: bool,
    store_key: Option<Arc<str>>,
}

/// What the tee-reader needs to put the streamed response into the cache.
struct TeeEntry {
    state: Arc<AppState>,
    store_key: Arc<str>,
    meta: cache::CachedMeta,
    tags: Vec<String>,
    effective_ttl: u64,
    initial_age: u64,
    cache_max: usize,
    max_object: usize,
    tag_epoch: u64,
}

/// Serve a request on a cached route.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle(
    mut req: Request<ZionBody>,
    state: Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
    breaker: Option<Arc<health::UpstreamHealth>>,
) -> Result<Response<ZionBody>, hyper::Error> {
    // Read before anything is fetched: a tag purge after this point keeps the response out.
    let tag_epoch = state.static_cache.tag_epoch();
    // Only GET is cacheable. HEAD/POST/PUT/PATCH/DELETE/OPTIONS must bypass the
    // cache and never populate it: the cache key is the path (no method), so a
    // non-GET 200 stored under it — a HEAD's empty body, or a POST response —
    // would later be served to a GET (method-confusion cache poisoning).
    if *req.method() != hyper::Method::GET {
        return unsafe_method(
            req,
            &state,
            rule,
            remote_addr,
            dyn_scheme,
            dyn_authority,
            xff_mode,
            breaker,
        )
        .await;
    }

    // Cache TTL / capacity from the profile (mode=StaticCache without an
    // explicit profile uses the conservative 1h default; see config::default_ttl).
    let (cache_ttl, cache_max, max_object) = match &rule.cache {
        Some(cp) => (
            cp.ttl_seconds,
            cp.max_entries,
            usize::try_from(cp.max_object_mb.saturating_mul(1024 * 1024)).unwrap_or(usize::MAX),
        ),
        // Conservative fallback (1h) for a static_cache route with no resolved
        // profile — never the old 1-year freeze. See config::default_ttl.
        None => (3600, 10_000, DEFAULT_MAX_OBJECT_BYTES),
    };
    let normalize_query = rule.cache.as_ref().is_some_and(|cp| cp.normalize_query);

    // RFC 9111 §3.5: capture whether the request is authenticated BEFORE `req`
    // is consumed by the upstream fetch — the storability gate below needs it
    // to avoid caching one user's authenticated response in the shared cache.
    let req_authenticated = req.headers().contains_key(hyper::header::AUTHORIZATION);

    // RFC 9111 §5.2.1: request Cache-Control. `no-store` bypasses the cache
    // (read + write); `no-cache` / `max-age=0` force a fresh response (don't
    // serve a stored one — without conditional revalidation that's a re-fetch);
    // `only-if-cached` answers from cache or 504, never contacting the origin.
    let (rcc_no_store, rcc_no_cache, rcc_only_if_cached) =
        parse_request_cache_control(req.headers());

    let (primary_key, identity_primary, takes_identity) = derive_keys(&req, normalize_query);
    // If this primary key's responses vary (RFC 9111 §4.1), the entry for THIS request
    // lives under a secondary key built from the varied request headers.
    let Some(cache_key) = lookup_key(&state, &primary_key, req.headers()) else {
        return bypass_unkeyable(
            req,
            &state,
            rule,
            remote_addr,
            dyn_scheme,
            dyn_authority,
            xff_mode,
            breaker,
        )
        .await;
    };

    // Where the shared identity entry for this request would live.
    let identity_key: Option<String> = if takes_identity {
        lookup_key(&state, &identity_primary, req.headers())
    } else {
        None
    };
    let cx = Cx {
        state: &state,
        rule,
        remote_addr,
        dyn_scheme,
        dyn_authority,
        xff_mode,
        breaker: breaker.clone(),
        cache_ttl,
        cache_max,
        max_object,
        tag_epoch,
        req_authenticated,
        rcc_no_store,
        primary_key,
        identity_primary,
        takes_identity,
        cache_key,
        identity_key,
    };

    // only-if-cached (§5.2.1.7): serve from cache or 504 — never fetch.
    if rcc_only_if_cached {
        return Ok(match cx.find().0 {
            // only-if-cached (§5.2.1.7) must not contact the origin, so a stale
            // stored response can't be revalidated → 504, same as a miss.
            cache::CacheLookup::Fresh(hit) => fresh_hit_response(hit, req.method(), req.headers()),
            _ => cache_only_if_cached_miss(),
        });
    }

    // RAM lookup. `Fresh` → zero-copy serve. `Stale` → keep the body and
    // revalidate with the origin below (RFC 9111 §4.3) instead of refetching.
    // `Miss` → fall through to a full fetch. Skipped when the client demanded a
    // fresh response (`no-cache` / `no-store`).
    let lookup = if !rcc_no_cache && !rcc_no_store {
        match cx.ram_lookup(&mut req) {
            Ok(lookup) => lookup,
            Err(resp) => return Ok(resp),
        }
    } else {
        Lookup {
            revalidate: None,
            stale_entry: None,
            found_key: cx.cache_key.clone(),
        }
    };

    let fetching = match cx.join_flight(&req).await {
        Ok(fetching) => fetching,
        Err(resp) => return Ok(resp),
    };

    cx.fetch(req, fetching, lookup).await
}

/// The primary cache key, the shared identity key and whether this client can take an identity body.
fn derive_keys(req: &Request<ZionBody>, normalize_query: bool) -> (String, String, bool) {
    // Cache key = full path+query (so /api?user=alice and /api?user=bob never
    // share an entry — cache-poisoning guard) PLUS the canonical Accept-Encoding
    // set, so encoding variants don't cross-contaminate (RFC 9111 §4.1). The
    // 0x1F unit separator can't occur in a valid request target, so the suffix
    // can never collide with a real path.
    let pq = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| req.uri().path());
    // With `normalize_query` the key carries the parameters in a canonical order; the
    // request itself (and so what the upstream is sent) is untouched. Such keys end in a
    // `\x1d` mode marker, which no request can produce, so they never share a namespace
    // with raw-query keys: the cache survives a config reload, and switching the option
    // must not let a raw request be served an entry filed under a sorted key (or the other
    // way round).
    let (key_target, mode_marker): (Cow<'_, str>, &str) = match (normalize_query, req.uri().query())
    {
        (true, Some(q)) => (
            match uri_norm::sorted_query(q) {
                Cow::Borrowed(_) => Cow::Borrowed(pq),
                Cow::Owned(sorted) => Cow::Owned(format!("{}?{sorted}", req.uri().path())),
            },
            "\u{1d}nq",
        ),
        _ => (Cow::Borrowed(pq), ""),
    };
    // The response cache is shared by every route and host, so the key carries the
    // request's host, normalised exactly as host routing sees it (case, port, trailing
    // dot; HTTP/2 `:authority` or HTTP/1 `Host`): two hosts with the same path are two
    // entries, whether they reach two origins or one multi-tenant origin. It goes last,
    // after a `\x1b` no request can produce, so path invalidation and prefix purges,
    // which match on the leading `path\x1f`, still reach every host's entry.
    let host_marker = match crate::security::request_host(&req) {
        Some(h) => format!("\u{1b}{h}"),
        None => String::new(),
    };
    let primary_key = format!(
        "{key_target}\u{1f}{}{mode_marker}{host_marker}",
        accept_encoding_key(req.headers())
    );
    // A response that is the same bytes for every client (no content coding, not chosen by
    // Accept-Encoding) is stored once, under a shared identity key, and found from any
    // `Accept-Encoding` (#484). The `\x1c` in its place cannot come from a request (header
    // values carry no control characters), so it never collides with the own key of a
    // client that sent no Accept-Encoding. It is per host like every other key.
    let identity_primary = format!("{key_target}\u{1f}\u{1c}{mode_marker}{host_marker}");
    let takes_identity = !refuses_identity(req.headers());
    (primary_key, identity_primary, takes_identity)
}

/// A method other than GET never reads or fills the cache, but the circuit still guards it, and a
/// successful unsafe one invalidates what it names (RFC 9111 §4.4).
#[allow(clippy::too_many_arguments)]
async fn unsafe_method(
    req: Request<ZionBody>,
    state: &Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
    breaker: Option<Arc<health::UpstreamHealth>>,
) -> Result<Response<ZionBody>, hyper::Error> {
    // RFC 9111 §4.4: a successful unsafe request invalidates the cached responses
    // for its target URI, and for the URIs its answer names in `Location` /
    // `Content-Location` when they are on the same origin. Capture what that needs
    // before `req` is consumed.
    let invalidating = matches!(
        *req.method(),
        hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH | hyper::Method::DELETE
    );
    let target_path = req.uri().path().to_string();
    let request_host = crate::security::request_host(&req).map(|h| h.to_ascii_lowercase());
    // The circuit guards writes to the upstream too: there is no stale copy to offer.
    let probe = match breaker.as_deref().map(breaker_admit) {
        Some(Err(ms)) => return Ok(circuit_open_response(ms)),
        Some(Ok(p)) => p,
        None => None,
    };
    let resp = proxy::proxy_pass(
        &state.client_for(rule.client_spec()),
        req,
        dyn_scheme,
        dyn_authority,
        Some(remote_addr),
        "https",
        xff_mode,
    )
    .await?;
    if let Some(entry) = &breaker {
        breaker_record(entry, resp.status(), probe);
    }
    if invalidating && resp.status().as_u16() < 400 {
        let mut removed = state.static_cache.invalidate_path(&target_path);
        for path in named_same_origin_paths(resp.headers(), request_host.as_deref()) {
            if path != target_path {
                removed += state.static_cache.invalidate_path(&path);
            }
        }
        if removed > 0 {
            metrics::METRICS
                .cache_invalidations
                .fetch_add(removed as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
    Ok(resp)
}

/// A varied request header too long to key on: do not touch the cache. The circuit still applies to
/// the origin fetch (there is no stale entry to fall back on).
#[allow(clippy::too_many_arguments)]
async fn bypass_unkeyable(
    req: Request<ZionBody>,
    state: &Arc<AppState>,
    rule: &ResolvedRoute,
    remote_addr: SocketAddr,
    dyn_scheme: &hyper::http::uri::Scheme,
    dyn_authority: &hyper::http::uri::Authority,
    xff_mode: proxy::XffMode,
    breaker: Option<Arc<health::UpstreamHealth>>,
) -> Result<Response<ZionBody>, hyper::Error> {
    // A varied request header too long to key on: do not touch the cache. The circuit
    // still applies to the origin fetch (there is no stale entry to fall back on).
    let probe = match breaker.as_deref().map(breaker_admit) {
        Some(Err(ms)) => return Ok(circuit_open_response(ms)),
        Some(Ok(p)) => p,
        None => None,
    };
    let mut resp = proxy::proxy_pass(
        &state.client_for(rule.client_spec()),
        req,
        dyn_scheme,
        dyn_authority,
        Some(remote_addr),
        "https",
        xff_mode,
    )
    .await?;
    if let Some(entry) = &breaker {
        breaker_record(entry, resp.status(), probe);
    }
    resp.headers_mut().insert(
        "X-Zion-Cache",
        hyper::header::HeaderValue::from_static("BYPASS"),
    );
    Ok(resp)
}

impl Cx<'_> {
    /// Look the request up under its own key, then under the identity key. Returns the
    /// outcome and the key (and primary key) it was found under.
    fn find(&self) -> (cache::CacheLookup, String, String) {
        let state = self.state;
        let own = state.static_cache.get(&self.cache_key);
        match (&own, &self.identity_key) {
            (cache::CacheLookup::Miss, Some(ik)) => (
                state.static_cache.get(ik),
                ik.clone(),
                self.identity_primary.clone(),
            ),
            _ => (own, self.cache_key.clone(), self.primary_key.clone()),
        }
    }

    /// The RAM lookup. `Err` is an answer: a fresh hit, or a stale one served inside its
    /// stale-while-revalidate window (the refresh runs in the background). `Ok` is a stale entry to
    /// revalidate, or nothing.
    fn ram_lookup(&self, req: &mut Request<ZionBody>) -> Result<Lookup, Response<ZionBody>> {
        let state = self.state;
        let rule = self.rule;
        let dyn_scheme = self.dyn_scheme;
        let dyn_authority = self.dyn_authority;
        let (remote_addr, xff_mode) = (self.remote_addr, self.xff_mode);
        let (cache_ttl, cache_max, max_object) = (self.cache_ttl, self.cache_max, self.max_object);
        let (identity_primary, breaker) = (&self.identity_primary, &self.breaker);
        let mut revalidate: Option<cache::CacheHit> = None;
        let mut stale_entry: Option<cache::CacheHit> = None;
        let (outcome, at_key, at_primary) = self.find();
        let found_key = at_key.clone();
        match outcome {
            cache::CacheLookup::Fresh(hit) => {
                // 304 on a matching precondition (RFC 9110 §13), else a Range slice, else all
                return Err(fresh_hit_response(hit, req.method(), req.headers()));
            }
            cache::CacheLookup::Stale(hit) => {
                stale_entry = Some(hit.clone());
                // stale-while-revalidate (RFC 5861): inside the window the origin
                // offered, answer NOW with the stale copy and refresh in the
                // background, so the client does not wait for the origin.
                // `age_secs` is whole seconds (floored), so the real staleness is in
                // [staleness, staleness + 1): `<` keeps us from ever serving past the
                // window the origin allowed.
                let staleness = hit.age_secs.saturating_sub(hit.max_age_secs);
                if hit.meta.stale_while_revalidate_secs > 0
                    && !hit.meta.must_revalidate
                    && staleness < hit.meta.stale_while_revalidate_secs
                {
                    if client_conditional_hit(req.headers(), &hit.meta) {
                        return Err(not_modified_response(&hit));
                    }
                    let refresh = SwrRefresh {
                        state: state.clone(),
                        key: Arc::from(at_key.as_str()),
                        identity_entry: at_primary == *identity_primary,
                        primary_key: Arc::from(at_primary.as_str()),
                        stale: hit.clone(),
                        request: swr_request(&req),
                        client_spec: rule.client_spec(),
                        scheme: dyn_scheme.clone(),
                        authority: dyn_authority.clone(),
                        remote_addr,
                        xff_mode,
                        cache_ttl,
                        cache_max,
                        tag_epoch: state.static_cache.tag_epoch(),
                        max_object,
                        breaker: breaker.clone(),
                    };
                    spawn_swr_refresh(refresh);
                    crate::metrics::METRICS
                        .cache_swr_served
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(cache_response(hit, "STALE-WHILE-REVALIDATE"));
                }
                // Only revalidate when we hold a validator; without one a
                // conditional GET is pointless, so fall through to a full fetch.
                if hit.meta.etag.is_some() || hit.meta.last_modified.is_some() {
                    add_conditional_headers(req.headers_mut(), &hit.meta);
                    revalidate = Some(hit);
                }
            }
            cache::CacheLookup::Miss => {}
        }
        Ok(Lookup {
            revalidate,
            stale_entry,
            found_key,
        })
    }

    /// Become the one fetcher for this request's key, or wait for the one already running.
    /// `Err` is an answer: a fresh entry the fetcher stored while this request waited.
    async fn join_flight(&self, req: &Request<ZionBody>) -> Result<Fetching, Response<ZionBody>> {
        let state = self.state;
        let (primary_key, identity_primary) = (&self.primary_key, &self.identity_primary);
        let (takes_identity, cache_key) = (self.takes_identity, &self.cache_key);
        let identity_key = &self.identity_key;
        // The in-flight (singleflight) key: the identity key whenever this client can take an
        // identity body, so cold requests with different Accept-Encoding coalesce on one fetch.
        // If that fetch turns out to be encoded for another encoding set, waiters that cannot
        // use it find nothing and fetch for themselves (the existing re-fetch path).
        let mut path_owned: Arc<str> =
            Arc::from(identity_key.clone().unwrap_or_else(|| cache_key.clone()));

        // Singleflight: coalesce concurrent cache misses for the same key.
        //
        // "Become the fetcher, or find the one already running" must be a single
        // atomic step — a separate `get()` then `insert()` lets two concurrent
        // misses both see "absent" and both register, the second clobbering the
        // first's sender (orphaning its waiters and double-fetching upstream). So
        // we use `get_or_insert_with`, which returns `inserted = true` to exactly
        // one caller. We use watch (not Notify) because `Receiver::wait_for`
        // inspects the current value at first poll: if the fetcher published `true`
        // between our registration and our `.await`, we still observe it and return
        // immediately instead of hanging.
        //
        // A waiter whose fetcher ended without storing anything (the response was not
        // storable, the fetch failed, or the fetcher's client went away) wakes when the
        // channel closes, re-checks the cache, and on a miss fetches for itself, alone.
        //
        // Two things make that wake happen, and both were missing from v0.8.0 to v0.9.10:
        //  - a waiter keeps a receiver and nothing else. It used to keep the sender it was
        //    handed, which kept the channel open for itself and for every other waiter:
        //    after a response that was not stored (a 404, a 500, `no-store`), every request
        //    that had been waiting hung for good;
        //  - the fetcher's registration is a guard ([`Fetching`]) that takes itself out of
        //    the map when dropped. The request future is dropped, at any `.await`, when its
        //    client goes away: without the guard the registration stayed, and every later
        //    request for that URL waited on a fetch that no longer existed.
        let tx = loop {
            let (tx, inserted) = state
                .inflight
                .get_or_insert_with(path_owned.clone(), || tokio::sync::watch::channel(false).0);
            if inserted {
                // We own the fetch for this key.
                break tx;
            }
            // Someone else is fetching — wait for them.
            let mut rx = tx.subscribe();
            drop(tx);
            let fetcher_stored = rx.wait_for(|v| *v).await.is_ok();
            // The fetcher may have just learned that this key varies, so the entry for
            // THIS request can now live under a secondary key: look it up afresh, under its own
            // primary key and, when it takes identity, under the identity one.
            let mut keys_now = vec![lookup_key(&state, &primary_key, req.headers())];
            if takes_identity {
                keys_now.push(lookup_key(&state, &identity_primary, req.headers()));
            }
            if let Some(hit) = keys_now
                .iter()
                .flatten()
                .find_map(|k| state.static_cache.get(k).fresh())
            {
                // get() already counted this hit — don't double-count it here.
                return Err(fresh_hit_response(hit, req.method(), req.headers()));
            }
            // Nothing usable after the wait. Two cases:
            //
            // The fetcher stored a response and it is not one this request can use (it was
            // encoded for another encoding set, and this wait was under the shared identity
            // key): wait once more, under this request's own key, with the other clients of
            // its encoding set, so that there is one fetch per set and not one per client.
            //
            // Anything else (the fetcher stored nothing, or this was already the request's own
            // key): fetch alone, and not behind another fetcher. A response that is not
            // storable would otherwise be fetched by one waiter at a time, each wake electing
            // the next, and requests would queue for as long as they arrive faster than the
            // origin answers. The key is then this request's alone: the next turn of the loop
            // registers it and goes to the origin.
            if fetcher_stored && path_owned.as_ref() != cache_key.as_str() {
                path_owned = Arc::from(cache_key.as_str());
            } else {
                static ALONE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                path_owned = Arc::from(format!(
                    "{cache_key}\u{0}{}",
                    ALONE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ));
            }
        };
        // From here the registration is taken out when this fetch ends, however it ends.
        let fetching = Fetching {
            state: state.clone(),
            key: path_owned,
            tx,
        };
        Ok(fetching)
    }

    /// Ask the circuit breaker, then fetch from the origin. An open circuit falls back on a stale copy
    /// when the origin allowed one; a failed fetch falls back on the entry being revalidated.
    async fn fetch(
        &self,
        req: Request<ZionBody>,
        fetching: Fetching,
        lookup: Lookup,
    ) -> Result<Response<ZionBody>, hyper::Error> {
        let state = self.state;
        let rule = self.rule;
        let dyn_scheme = self.dyn_scheme;
        let dyn_authority = self.dyn_authority;
        let (remote_addr, xff_mode) = (self.remote_addr, self.xff_mode);
        let breaker = &self.breaker;
        let Lookup {
            revalidate,
            stale_entry,
            found_key,
        } = lookup;
        // Opt-in circuit breaker: if the upstream's circuit is open, do not contact it. A stale
        // copy (when the origin allowed stale responses) stands in for it; otherwise the client
        // gets the 503. A fresh hit never reaches this point.
        // The breaker comes from the request's own config snapshot (passed in), not a fresh
        // load, so a reload while this request is in flight cannot change which breaker guards it.
        let breaker_cached = breaker.clone();
        let mut probe: Option<breaker::ProbeToken> = None;
        if let Some(entry) = &breaker_cached {
            match breaker_admit(entry) {
                Ok(p) => probe = p,
                Err(ms) => {
                    drop(fetching);
                    if let Some(hit) = stale_entry.as_ref().filter(|h| !h.meta.must_revalidate) {
                        metrics::METRICS
                            .cache_stale_if_error
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(cache_response(hit.clone(), "STALE"));
                    }
                    return Ok(circuit_open_response(ms));
                }
            }
        }

        // The varied request headers must outlive `req`, which the fetch consumes: the
        // response may reveal (via `Vary`) which of them the entry is keyed on.
        let req_headers = req.headers().clone();

        // RAM miss — fetch from upstream.
        // On error `fetching` is dropped. Waiters' wait_for() returns Err (channel
        // closed without receiving `true`), they re-check the cache, miss, and fetch
        // for themselves.
        let resp = match proxy::proxy_pass(
            &state.client_for(rule.client_spec()),
            req,
            dyn_scheme,
            dyn_authority,
            Some(remote_addr),
            "https",
            xff_mode,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                if let Some(entry) = &breaker_cached {
                    entry.breaker.record(false, breaker::now_ms(), probe.take());
                }
                drop(fetching);
                // stale-if-error (RFC 9111 §4.2.4): if we were revalidating a stale
                // entry and the origin is unreachable, serve the stale body rather
                // than fail — a flapping origin doesn't take cached content down.
                if let Some(hit) = revalidate.filter(|h| !h.meta.must_revalidate) {
                    metrics::METRICS
                        .cache_stale_if_error
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(cache_response(hit, "STALE"));
                }
                return Err(e);
            }
        };

        if let Some(entry) = &breaker_cached {
            breaker_record(entry, resp.status(), probe.take());
        }

        self.conclude(resp, revalidate, fetching, &found_key, &req_headers)
            .await
    }

    /// What to do with the origin's answer: serve the stale copy when the origin failed
    /// (stale-if-error), confirm a revalidated entry on a 304, store a 200, or pass the rest through.
    async fn conclude(
        &self,
        resp: Response<ZionBody>,
        revalidate: Option<cache::CacheHit>,
        fetching: Fetching,
        found_key: &str,
        req_headers: &hyper::HeaderMap,
    ) -> Result<Response<ZionBody>, hyper::Error> {
        let state = self.state;
        let (cache_ttl, cache_max, tag_epoch) = (self.cache_ttl, self.cache_max, self.tag_epoch);

        // stale-if-error (RFC 9111 §4.2.4 / RFC 5861 §4): `proxy_pass` turns a transport
        // failure into a 502 response instead of an `Err`, so an origin that is down or
        // erroring reaches us as a 5xx. While revalidating a stale entry, that is the case
        // to answer from the stale copy — unless the origin forbade stale responses.
        if let Some(hit) = revalidate.as_ref() {
            if matches!(resp.status().as_u16(), 500 | 502 | 503 | 504) && !hit.meta.must_revalidate
            {
                drop(fetching);
                metrics::METRICS
                    .cache_stale_if_error
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(cache_response(hit.clone(), "STALE"));
            }
        }

        // Revalidation outcome (RFC 9111 §4.3): a 304 confirms the stored entry is
        // still good — revive its freshness and serve the stored body without the
        // re-download. A 200 (or anything else) falls through to the normal
        // store-and-serve path, replacing the stale entry with the new content.
        if let Some(hit) = revalidate {
            if resp.status() == StatusCode::NOT_MODIFIED {
                let initial_age = upstream_age(resp.headers());
                let effective_ttl = origin_freshness(resp.headers())
                    .map(|o| o.min(cache_ttl))
                    .unwrap_or(cache_ttl);
                let mut refreshed_meta = (*hit.meta).clone();
                if resp.headers().contains_key(hyper::header::CACHE_CONTROL) {
                    refreshed_meta.stale_while_revalidate_secs = origin_swr(resp.headers());
                    refreshed_meta.must_revalidate = forbids_stale(resp.headers());
                }
                // Skipped when a tag purge ran since this request began: it must not bring back an
                // entry the purge may have just removed.
                state.static_cache.refresh_checked(
                    &found_key,
                    hit.body.clone(),
                    refreshed_meta,
                    effective_ttl,
                    initial_age,
                    cache_max,
                    tag_epoch,
                );
                fetching.stored(); // waiters observe the revived (fresh) entry
                crate::metrics::METRICS
                    .cache_revalidations
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(cache_response(hit, "REVALIDATED"));
            }
            // else: origin returned new content (200) or a non-304 status — drop the
            // stale hit and let the normal path below store/serve the fresh response.
        }

        // Only cache 200 OK responses
        if resp.status() == StatusCode::OK {
            return Ok(self.store(resp, fetching, req_headers));
        }

        // Non-200 or non-cacheable: the registration ends without signaling completion.
        // Waiters re-check the cache (miss) and fetch for themselves.
        drop(fetching);

        Ok(resp)
    }

    /// Decide whether the 200 is stored and under which key: its freshness (the origin's, capped by
    /// the profile), the RFC 9111 storability gate, and the `Vary` policy.
    fn plan_storage(&self, headers: &hyper::HeaderMap, req_headers: &hyper::HeaderMap) -> Storage {
        let state = self.state;
        let (cache_ttl, cache_max, max_object) = (self.cache_ttl, self.cache_max, self.max_object);
        let (takes_identity, rcc_no_store, req_authenticated) = (
            self.takes_identity,
            self.rcc_no_store,
            self.req_authenticated,
        );
        let (primary_key, identity_primary) = (&self.primary_key, &self.identity_primary);
        // Honor the origin's freshness instead of blanket-applying the profile
        // TTL: a short origin `max-age`/`s-maxage` shortens the lifetime, the
        // profile TTL is the ceiling. Seed the entry's age from the upstream
        // `Age` (shield Varnish) so freshness is computed across all tiers.
        let initial_age = upstream_age(headers);
        let effective_ttl = origin_freshness(headers)
            .map(|o| o.min(cache_ttl))
            .unwrap_or(cache_ttl);

        // RFC 9111 storability gate (Vary §4.1 / private-no-store §3.2 / §3.5
        // authenticated-request / freshness §4.2). A request `Cache-Control:
        // no-store` (§5.2.1.5) also forbids storing the response. On a bypass,
        // stream the body straight through without populating the shared cache.
        // A declared length over the profile's limit: do not even start buffering it.
        let too_big = headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok())
            .is_some_and(|n| n > max_object);
        if too_big {
            metrics::METRICS
                .cache_too_large
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let cacheable = !rcc_no_store
            && !too_big
            && is_shared_cacheable(req_authenticated, headers, effective_ttl, initial_age);
        // Where the entry lives: the primary key, or — when the response varies — the
        // secondary key of THIS request's varied headers (bounded; see `vary`).
        // An identity body the origin did not select by Accept-Encoding goes under the
        // identity primary key, shared by every Accept-Encoding (#484). An encoded one, or one
        // with `Vary: Accept-Encoding` (the origin may compress for other clients), stays
        // under this request's own primary key, found only by the same encoding set.
        let store_primary: &str = if !takes_identity || !shareable_identity(headers) {
            &primary_key
        } else {
            &identity_primary
        };
        let store_key: Option<Arc<str>> = if !cacheable {
            None
        } else {
            match vary::policy(headers) {
                vary::VaryPolicy::Uncacheable => None,
                vary::VaryPolicy::None => {
                    // Not varying (any more): forget an old rule so lookups use the primary key.
                    state.static_cache.vary.remove(store_primary);
                    Some(Arc::from(store_primary))
                }
                vary::VaryPolicy::Keyed(names) => state
                    .static_cache
                    .vary
                    .install(
                        store_primary,
                        names,
                        // Outlive the variants' usefulness: a stale variant is kept for
                        // revalidation / stale-while-revalidate, so the rule must still be
                        // there to find it (the profile ceiling, plus any SWR window).
                        cache_ttl
                            .max(effective_ttl)
                            .saturating_add(origin_swr(headers)),
                        cache_max,
                    )
                    .and_then(|rule| {
                        let vk = vary::variant_key(store_primary, &rule.names, req_headers)?;
                        rule.admit(&vk).then(|| Arc::from(vk.as_str()))
                    }),
            }
        };
        Storage {
            initial_age,
            effective_ttl,
            cacheable,
            store_key,
        }
    }

    /// Stream a 200 to the client while the tee-reader fills the cache with it.
    fn store(
        &self,
        resp: Response<ZionBody>,
        fetching: Fetching,
        req_headers: &hyper::HeaderMap,
    ) -> Response<ZionBody> {
        let (parts, body) = resp.into_parts();
        let Storage {
            initial_age,
            effective_ttl,
            cacheable,
            store_key,
        } = self.plan_storage(&parts.headers, req_headers);

        let Some(store_key) = store_key else {
            // Stream the body straight to the client without caching.
            // Drop the registration (no `true` sent): waiters fetch for themselves,
            // since the cache will not be populated for this key.
            drop(fetching);
            if cacheable {
                // Storable in principle but refused by the Vary policy or its cap.
                metrics::METRICS
                    .cache_vary_uncached
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let mut resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            resp.headers_mut().insert(
                "X-Zion-Cache",
                hyper::header::HeaderValue::from_static("BYPASS"),
            );
            return resp;
        };

        // `Surrogate-Key` tags (purge by tag). Tags that cannot be tracked mean the entry could
        // never be purged by them, so the response is streamed through without being stored.
        let Ok(tags) = cache::surrogate_keys(&parts.headers) else {
            drop(fetching);
            metrics::METRICS
                .cache_tag_uncached
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut resp = Response::from_parts(parts, body.map_err(hyper::Error::from).boxed());
            resp.headers_mut().insert(
                "X-Zion-Cache",
                hyper::header::HeaderValue::from_static("BYPASS"),
            );
            return resp;
        };

        // Preserve Content-Type and Content-Encoding for cache (S-05 fix).
        // Without Content-Encoding, gzip-compressed bodies are served garbled.
        let content_type = parts.headers.get(hyper::header::CONTENT_TYPE).cloned();
        let content_encoding = parts.headers.get(hyper::header::CONTENT_ENCODING).cloned();
        // Preserve validators for conditional requests (client If-None-Match →
        // 304; origin revalidation in a later phase).
        let etag = parts.headers.get(hyper::header::ETAG).cloned();
        let last_modified = parts.headers.get(hyper::header::LAST_MODIFIED).cloned();
        let meta = cache::CachedMeta {
            content_type,
            content_encoding,
            status: parts.status,
            etag,
            last_modified,
            stale_while_revalidate_secs: origin_swr(&parts.headers),
            must_revalidate: forbids_stale(&parts.headers),
        };

        let (sender, receiver) =
            tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(16);
        let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
        let stream_body = http_body_util::StreamBody::new(stream);

        spawn_tee(
            fetching,
            body,
            sender,
            TeeEntry {
                state: self.state.clone(),
                store_key,
                meta,
                tags,
                effective_ttl,
                initial_age,
                cache_max: self.cache_max,
                max_object: self.max_object,
                tag_epoch: self.tag_epoch,
            },
        );

        let mut resp = Response::from_parts(parts, stream_body.boxed());
        // This response was fetched from upstream and is being populated into
        // the cache as it streams — a MISS that fills the cache for next time.
        resp.headers_mut().insert(
            "X-Zion-Cache",
            hyper::header::HeaderValue::from_static("MISS"),
        );
        // Preserve the upstream Cache-Control if it set one; otherwise supply
        // the profile-derived default — don't blanket-stamp 1-year immutable.
        if !resp.headers().contains_key(hyper::header::CACHE_CONTROL) {
            resp.headers_mut()
                .insert("Cache-Control", profile_cache_control(effective_ttl));
        }
        resp
    }
}

/// The cache tee-reader. The registration moves into it: the fetch is not over until the body is,
/// and it ends with the task however the task ends.
fn spawn_tee(
    fetching: Fetching,
    body: ZionBody,
    sender: tokio::sync::mpsc::Sender<Result<hyper::body::Frame<Bytes>, hyper::Error>>,
    entry: TeeEntry,
) {
    tokio::spawn(async move {
        let TeeEntry {
            state: state_clone,
            store_key: store_key_clone,
            meta: meta_clone,
            tags,
            effective_ttl,
            initial_age,
            cache_max,
            max_object,
            tag_epoch,
        } = entry;
        let fetching = fetching;
        let mut cache_buffer = bytes::BytesMut::new();
        let mut total_bytes = 0;
        let mut cache_aborted = false;
        let mut stream_body = body; // Consume inner body entirely

        loop {
            match BodyExt::frame(&mut stream_body).await {
                Some(Ok(frame)) => {
                    let f = match frame.into_data() {
                        Ok(data) => {
                            if !cache_aborted {
                                total_bytes += data.len();
                                if total_bytes > max_object {
                                    cache_aborted = true; // Stop buffering, but continue streaming!
                                    metrics::METRICS
                                        .cache_too_large
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                } else {
                                    cache_buffer.extend_from_slice(&data);
                                }
                            }
                            hyper::body::Frame::data(data)
                        }
                        Err(other_frame) => other_frame,
                    };

                    // Stream chunk directly to the client immediately
                    if sender.send(Ok(f)).await.is_err() {
                        // Client disconnected mid-stream: the buffer is partial.
                        // `fetching` drops without signaling completion; waiters'
                        // wait_for returns Err and they fetch for themselves.
                        return;
                    }
                }
                Some(Err(e)) => {
                    // Upstream chunking failed: `fetching` drops (abort signal).
                    let _ = sender.send(Err(e)).await;
                    return;
                }
                None => {
                    break;
                }
            }
        }

        // Not stored when a tag purge ran after the fetch began: the response may predate it.
        let outcome = if cache_aborted {
            None
        } else {
            Some(state_clone.static_cache.insert_tagged(
                &store_key_clone,
                cache_buffer.into(),
                meta_clone,
                effective_ttl,
                initial_age,
                cache_max,
                &tags,
                tag_epoch,
            ))
        };
        if outcome == Some(cache::TagStore::IndexFull) {
            // The response is already on its way to the client (as a MISS); only the
            // metric can say it was not kept.
            metrics::METRICS
                .cache_tag_uncached
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if outcome == Some(cache::TagStore::Stored) {
            // Cache populated: signal `true` so waiters' wait_for resolves
            // immediately at the next poll, even if they hadn't subscribed
            // before this point.
            fetching.stored();
        }
        // (else not stored, e.g. the body exceeded max_object: `fetching` drops
        //  without signaling; waiters fetch for themselves.)
    });
}

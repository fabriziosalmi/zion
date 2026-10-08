// SPDX-License-Identifier: Apache-2.0
//! Route resolution and upstream selection: the two stages between the pre-routing gates and the
//! per-route gates (CORS, auth, WAF).

// The `Err` of these stages is the response that ends the request, built once on a rejection:
// boxing it would add an allocation to every refused request for nothing.
#![allow(clippy::result_large_err)]

use super::*;

/// Find the route for a request: the thread-local LRU first, then the radix tree.
///
/// `None` is a 404.
pub(super) fn resolve(
    cfg: &Arc<ResolvedAppConfig>,
    req: &Request<ZionBody>,
) -> Option<Arc<ResolvedRoute>> {
    // Hot routes hit the thread-local cache in ~5ns. Cache misses fall through
    // to the radix tree (~30ns) and are promoted to MRU. The cache is a true
    // O(1) LRU bounded at ROUTE_CACHE_CAP entries: when full, the LRU entry is
    // evicted on insert. The earlier "if len < 256 { insert }" stopped
    // promoting any new path once the cap was reached, so a client hitting
    // 256 distinct paths first (cache-busted CDN paths, scanners) permanently
    // locked out subsequent hot routes for the worker thread.
    thread_local! {
        static ROUTE_CACHE: std::cell::RefCell<route_cache::RouteCache<Arc<ResolvedRoute>>> =
            std::cell::RefCell::new(route_cache::RouteCache::new(route_cache::ROUTE_CACHE_CAP));
        // The configuration the cache above was filled from. Held (not just compared by
        // address) so that address cannot be reused by a later config while we compare.
        static ROUTE_CACHE_CONFIG: std::cell::RefCell<Option<Arc<ResolvedAppConfig>>> =
            const { std::cell::RefCell::new(None) };
    }

    // A cached route carries the policy of the configuration it was resolved under
    // (`internal_only`, WAF and auth profiles, upstream). After a hot reload the next
    // request must see the NEW policy, so a cache filled under a previous snapshot is
    // dropped on first use. Cost on the hot path: one pointer comparison.
    ROUTE_CACHE_CONFIG.with(|owner| {
        let mut owner = owner.borrow_mut();
        if !owner.as_ref().is_some_and(|c| Arc::ptr_eq(c, cfg)) {
            ROUTE_CACHE.with(|cache| cache.borrow_mut().clear());
            *owner = Some(cfg.clone());
        }
    });

    let path = req.uri().path();

    // Host-based routing (ADR-0010): extract the normalized authority only
    // when a route is host-bound — hostless deployments skip this entirely.
    // The URI :authority (HTTP/2 / absolute-form) wins over the Host header
    // (HTTP/1 origin-form).
    let host_cow = if cfg.router.host_routing_active() {
        crate::security::request_host(req)
    } else {
        None
    };
    let host = host_cow.as_deref();

    // Cache key folds the host in when present, so two authorities sharing a
    // path never collide (ADR-0010 cache invariant); with no host it is the
    // bare path hash — byte-identical to the pre-host-routing key.
    let cache_key = route_cache_key(host, path);

    // Thread-local cache hit (~5ns) — touch promotes to MRU
    if let Some(route) = ROUTE_CACHE.with(|cache| cache.borrow_mut().get(cache_key)) {
        return Some(route);
    }

    // Radix tree fallback (~30ns)
    let route = cfg.router.at(host, path)?.clone();
    ROUTE_CACHE.with(|cache| {
        cache.borrow_mut().insert(cache_key, route.clone());
    });
    Some(route)
}

/// Pick the upstream for a request and resolve its scheme and authority.
///
/// `Err` is the 503 to answer when no upstream of the route is usable.
pub(super) fn select_upstream(
    cfg: &ResolvedAppConfig,
    rule: &ResolvedRoute,
) -> Result<(hyper::http::uri::Scheme, hyper::http::uri::Authority), Response<ZionBody>> {
    // Select the healthy upstream with the lowest latency. A `mode="static"`
    // route serves from disk and has NO upstream, so it must skip this gate —
    // otherwise `select_best_upstream` sees an empty list and 503s before the
    // `RouteMode::Static` arm can run. The placeholder is only parsed into
    // dyn_scheme/authority, which that arm never reads (WAF/auth/CSP/security
    // headers still apply on the way down).
    static EMPTY_UPSTREAM: String = String::new();
    // A pool picks by its configured algorithm in every proxy mode, so ejected and
    // overloaded members are avoided by SSE, WebSocket and cached routes too (in-flight and
    // outlier accounting happen on `Standard` routes only). A single endpoint keeps the plain
    // lookup, whose "everything gray is 503" behaviour is unchanged.
    let selected = if rule.upstream_url.len() > 1 {
        pool::pick(
            &cfg.health_map,
            &rule.upstream_url,
            rule.load_balancing,
            breaker::now_ms(),
            &mut |n| fastrand::usize(..n),
        )
    } else {
        health::select_best_upstream(&cfg.health_map, &rule.upstream_url)
    };
    let target_upstream_url = match selected {
        Some(url) => url,
        None if rule.mode == config::RouteMode::Static => &EMPTY_UPSTREAM,
        None => {
            return Err(text_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream unavailable",
            ));
        }
    };

    // Resolve scheme + authority for the selected upstream. Fast path: a
    // single-upstream (or static, empty) route always resolves to
    // `upstream_url[0]`, whose scheme+authority were parsed ONCE at
    // config-build time into `rule.upstream_scheme` / `rule.upstream_authority`
    // — so skip the per-request `hyper::Uri` parse entirely (the common case).
    // Only a multi-upstream HA/latency pool, where the selected member varies
    // per request, needs to parse the chosen URL.
    //
    // SAFETY (inner unwrap on the slow path): "/" is a compile-time-constant
    // single-char URI that always parses. Used as a defensive fallback if a
    // hot-reload sneaks in a bad URL (config validation should have caught it).
    let (dyn_scheme, dyn_authority) = if rule.upstream_url.len() <= 1 {
        (
            rule.upstream_scheme.clone(),
            rule.upstream_authority.clone(),
        )
    } else {
        let target_uri: hyper::Uri = target_upstream_url
            .parse()
            .unwrap_or_else(|_| "/".parse().unwrap());
        (
            target_uri
                .scheme()
                .cloned()
                .unwrap_or_else(|| rule.upstream_scheme.clone()),
            target_uri
                .authority()
                .cloned()
                .unwrap_or_else(|| rule.upstream_authority.clone()),
        )
    };
    Ok((dyn_scheme, dyn_authority))
}

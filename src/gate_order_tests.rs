//! Golden tests for the ORDER of the request pipeline's gates (#422).
//!
//! Each case sends a request that trips two gates at once and pins which one
//! answers. The pipeline's security value is in its ordering — a cheap 414 before
//! a method check, the rate limiter before the built-in endpoints, route-level
//! policy before the upstream — so a refactor that reorders two gates changes a
//! status code here, loudly, instead of silently weakening a defence.
//!
//! These drive the real `process_request` with a real `AppState` (no sockets), and
//! were written against the pipeline BEFORE it was restructured: they describe the
//! behaviour to preserve, not the new code.

use crate::config::ZionConfig;
use crate::dispatch::process_request;
use crate::proxy::ZionBody;
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

const EXTERNAL: &str = "203.0.113.9:40000"; // TEST-NET-3: not an internal address
const INTERNAL: &str = "10.0.0.5:40000";
const LOOPBACK: &str = "127.0.0.1:40000";
const DEAD: &str = "http://127.0.0.1:10";

fn config_toml(rate_limit_rps: u32) -> String {
    format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
rate_limit_rps = {rate_limit_rps}

[tls]
cert_path = "/c"
key_path = "/k"

[upstreams]
live = "http://127.0.0.1:9"
dead = "{DEAD}"

[auth_profile.p]
secret = "test-secret-key-for-zion-gate-order"
algorithm = "HS256"

[[route]]
path = "/open/{{*rest}}"
upstream = "live"

[[route]]
path = "/internal/{{*rest}}"
upstream = "live"
internal_only = true

[[route]]
path = "/internal-down/{{*rest}}"
upstream = "dead"
internal_only = true

[[route]]
path = "/down/{{*rest}}"
upstream = "dead"

[[route]]
path = "/down-authed/{{*rest}}"
upstream = "dead"
auth_profile = "p"

[[route]]
path = "/authed-waf/{{*rest}}"
upstream = "live"
auth_profile = "p"
waf = true

[[route]]
path = "/waf/{{*rest}}"
upstream = "live"
waf = true

[[route]]
path = "/cors-internal/{{*rest}}"
upstream = "live"
internal_only = true
[route.cors]
allowed_origins = ["https://app.example"]
"#
    )
}

fn state(rate_limit_rps: u32) -> Arc<AppState> {
    let cfg: ZionConfig = toml::from_str(&config_toml(rate_limit_rps)).expect("test config parses");
    let st = AppState::for_tests(&cfg);
    // `dead` answers no probe: mark it down so route selection sees that.
    st.cfg()
        .health_map
        .get(DEAD)
        .expect("dead upstream is in the health map")
        .healthy
        .store(false, Ordering::Relaxed);
    st
}

fn req(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request<ZionBody> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// Status the pipeline answers with.
async fn status(st: &Arc<AppState>, from: &str, r: Request<ZionBody>, early: bool) -> u16 {
    let addr: SocketAddr = from.parse().unwrap();
    process_request(r, st.clone(), addr, early)
        .await
        .expect("pipeline is infallible here")
        .status()
        .as_u16()
}

async fn get(st: &Arc<AppState>, from: &str, uri: &str) -> u16 {
    status(st, from, req(Method::GET, uri, &[]), false).await
}

// ── pre-routing gates, in order ─────────────────────────────────────────────

#[tokio::test]
async fn uri_length_answers_before_the_method_whitelist() {
    let st = state(0);
    let long = format!("/open/{}", "a".repeat(9000));
    // TRACE would be 405; the oversized URI is refused first.
    assert_eq!(
        status(&st, EXTERNAL, req(Method::TRACE, &long, &[]), false).await,
        414
    );
    // sanity: each gate alone behaves
    assert_eq!(
        status(&st, EXTERNAL, req(Method::TRACE, "/open/x", &[]), false).await,
        405
    );
}

#[tokio::test]
async fn method_whitelist_answers_before_the_early_data_check() {
    let st = state(0);
    // TRACE in early data: 405, not 425.
    assert_eq!(
        status(&st, EXTERNAL, req(Method::TRACE, "/open/x", &[]), true).await,
        405
    );
    // a whitelisted state-changing method in early data IS 425
    assert_eq!(
        status(&st, EXTERNAL, req(Method::POST, "/open/x", &[]), true).await,
        425
    );
    // and GET in early data passes the gate (then 502/503 from the dead-port upstream
    // is irrelevant: it is not 425)
    assert_ne!(
        status(&st, EXTERNAL, req(Method::GET, "/open/x", &[]), true).await,
        425
    );
}

#[tokio::test]
async fn early_data_answers_before_the_rate_limiter() {
    let st = state(1);
    // burn the single token for this client
    let _ = get(&st, EXTERNAL, "/healthz").await;
    // over the limit AND early-data POST: 425 (the earlier gate) wins over 429
    assert_eq!(
        status(&st, EXTERNAL, req(Method::POST, "/open/x", &[]), true).await,
        425
    );
}

#[tokio::test]
async fn rate_limiter_answers_before_the_built_in_endpoints() {
    let st = state(1);
    assert_eq!(
        get(&st, EXTERNAL, "/healthz").await,
        200,
        "first request has budget"
    );
    // /healthz must not be a way around the limiter
    assert_eq!(get(&st, EXTERNAL, "/healthz").await, 429);
    // and another client's budget is independent
    assert_eq!(get(&st, "198.51.100.7:1", "/healthz").await, 200);
}

// ── hot reload: a changed route policy applies to the very next request ─────────

/// Each worker thread keeps a small cache of resolved routes. It must not outlive the
/// configuration it was filled from: after a reload that makes `/open` internal-only, the
/// next external request to `/open/x` is refused, on the same thread, without waiting for
/// the cached route to be evicted.
#[tokio::test]
async fn a_reload_that_changes_a_routes_policy_applies_to_the_next_request() {
    use crate::state::ResolvedAppConfig;
    let st = state(0);
    // warm the thread's route cache for this path under the original config
    let before = get(&st, EXTERNAL, "/open/x").await;
    assert_ne!(
        before, 403,
        "control: /open is not internal-only to begin with"
    );

    let tightened = config_toml(0).replace(
        "[[route]]\npath = \"/open/{*rest}\"\nupstream = \"live\"\n",
        "[[route]]\npath = \"/open/{*rest}\"\nupstream = \"live\"\ninternal_only = true\n",
    );
    assert_ne!(
        tightened,
        config_toml(0),
        "the replacement must have applied"
    );
    let cfg: ZionConfig = toml::from_str(&tightened).unwrap();
    st.config
        .store(Arc::new(ResolvedAppConfig::try_build(&cfg, 1024).unwrap()));
    assert_eq!(
        get(&st, EXTERNAL, "/open/x").await,
        403,
        "the new policy must apply at once"
    );
    assert_ne!(
        get(&st, INTERNAL, "/open/x").await,
        403,
        "internal clients are still let in"
    );

    // and back: loosening it applies at once too
    let cfg: ZionConfig = toml::from_str(&config_toml(0)).unwrap();
    st.config
        .store(Arc::new(ResolvedAppConfig::try_build(&cfg, 1024).unwrap()));
    assert_ne!(
        get(&st, EXTERNAL, "/open/x").await,
        403,
        "the old policy is gone again"
    );
}

// ── path normalization: a route's policy cannot be dodged by how the path is written ──

#[tokio::test]
async fn dot_segments_and_duplicate_slashes_cannot_dodge_a_route() {
    let st = state(0);
    // control: the plain path is refused for an external client
    assert_eq!(get(&st, EXTERNAL, "/internal/x").await, 403);
    for p in [
        "/open/../internal/x",
        "/open/%2e%2e/internal/x",
        "/open/%2E%2E/internal/x",
        "/open/.%2e/internal/x",
        "/open/./../internal/x",
        "/open/a/../../internal/x",
        "//internal/x",
        "/internal//x",
        "/./internal/x",
        "/%69nternal/x", // %69 = 'i'
    ] {
        assert_eq!(
            get(&st, EXTERNAL, p).await,
            403,
            "{p} must be treated as /internal/x"
        );
    }
    // an internal client is not blocked by any of them (it reaches the, dead, upstream)
    for p in ["/open/../internal/x", "//internal/x"] {
        assert_ne!(get(&st, INTERNAL, p).await, 403, "{p}");
    }
}

#[tokio::test]
async fn built_in_endpoints_are_reached_through_any_spelling_of_their_path() {
    let st = state(0);
    for p in ["//healthz", "/./healthz", "/open/../healthz", "/%68ealthz"] {
        assert_eq!(get(&st, EXTERNAL, p).await, 200, "{p}");
    }
    for p in ["//metrics", "/open/../metrics"] {
        assert_eq!(get(&st, EXTERNAL, p).await, 403, "{p}: still internal-only");
    }
}

// ── loop detection (Via) ────────────────────────────────────────────────────

fn own_via() -> String {
    format!("1.1 {}", crate::via::pseudonym())
}

#[tokio::test]
async fn a_request_that_already_passed_through_this_proxy_is_a_loop() {
    let st = state(0);
    let me = own_via();
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::GET, "/open/x", &[("via", &me)]),
            false
        )
        .await,
        508
    );
    // our name anywhere in the chain counts
    let chain = format!("1.0 edge, {me}, 1.1 other");
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::GET, "/open/x", &[("via", &chain)]),
            false
        )
        .await,
        508
    );
    // other proxies in the chain are not a loop, and an absent Via is not one either
    assert_ne!(
        status(
            &st,
            EXTERNAL,
            req(Method::GET, "/open/x", &[("via", "1.1 some-other-proxy")]),
            false
        )
        .await,
        508
    );
    assert_ne!(
        status(&st, EXTERNAL, req(Method::GET, "/open/x", &[]), false).await,
        508
    );
    // even the built-in endpoints refuse a looping request: the gate is ahead of them
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::GET, "/healthz", &[("via", &me)]),
            false
        )
        .await,
        508
    );
}

#[tokio::test]
async fn loop_detection_sits_after_method_and_early_data_and_before_the_rate_limiter() {
    let me = own_via();
    let st = state(1);
    // TRACE with a looping Via: the method whitelist answers first
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::TRACE, "/open/x", &[("via", &me)]),
            false
        )
        .await,
        405
    );
    // a POST in early data: 425 first
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::POST, "/open/x", &[("via", &me)]),
            true
        )
        .await,
        425
    );
    // a client that has spent its rate budget still learns it is looping (508, not 429)
    let _ = get(&st, EXTERNAL, "/healthz").await;
    assert_eq!(
        get(&st, EXTERNAL, "/healthz").await,
        429,
        "control: the budget is spent"
    );
    assert_eq!(
        status(
            &st,
            EXTERNAL,
            req(Method::GET, "/open/x", &[("via", &me)]),
            false
        )
        .await,
        508
    );
}

// ── built-ins before routing ────────────────────────────────────────────────

#[tokio::test]
async fn built_in_endpoints_answer_before_route_lookup() {
    let st = state(0);
    // none of these paths matches a route; they are served (or refused) by the
    // built-in handlers, not turned into a 404
    assert_eq!(get(&st, EXTERNAL, "/healthz").await, 200);
    assert_eq!(get(&st, EXTERNAL, "/readyz").await, 200);
    assert_eq!(
        get(&st, EXTERNAL, "/metrics").await,
        403,
        "external peer refused"
    );
    assert_eq!(get(&st, INTERNAL, "/metrics").await, 200);
    assert_eq!(get(&st, EXTERNAL, "/_zion/snapshot.json").await, 403);
    assert_eq!(get(&st, INTERNAL, "/_zion/snapshot.json").await, 200);
    // purge: who may, then method. With no `internal_networks` only loopback may purge: a
    // private address is enough to read /metrics, not to flush the cache (#516).
    assert_eq!(get(&st, EXTERNAL, "/_zion/cache/purge").await, 403);
    assert_eq!(
        get(&st, INTERNAL, "/_zion/cache/purge").await,
        403,
        "a private, non-loopback peer may not purge by default"
    );
    assert_eq!(
        get(&st, LOOPBACK, "/_zion/cache/purge").await,
        405,
        "loopback may; GET is not POST"
    );
    assert_eq!(get(&st, INTERNAL, "/no-such-route").await, 404);
}

/// `[server] internal_networks` is the operator naming who is internal: the hosts it lists
/// may purge, and nothing else may, loopback included (the list replaces the default, as it
/// does for the read endpoints).
#[tokio::test]
async fn internal_networks_decides_who_may_purge() {
    let toml = config_toml(0).replacen(
        "[server]",
        "[server]\ninternal_networks = [\"10.0.0.0/8\"]",
        1,
    );
    let st = AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"));
    assert_eq!(get(&st, INTERNAL, "/_zion/cache/purge").await, 405);
    assert_eq!(get(&st, LOOPBACK, "/_zion/cache/purge").await, 403);
    assert_eq!(get(&st, EXTERNAL, "/_zion/cache/purge").await, 403);
    // The read endpoints follow the same list, as before.
    assert_eq!(get(&st, INTERNAL, "/metrics").await, 200);
    assert_eq!(get(&st, LOOPBACK, "/metrics").await, 403);
}

// ── route-level gates, in order ─────────────────────────────────────────────

#[tokio::test]
async fn cors_preflight_answers_before_internal_only() {
    let st = state(0);
    // an external client preflighting an internal_only route with an allowed
    // origin gets the 204 preflight answer, not the internal_only 403
    let pre = req(
        Method::OPTIONS,
        "/cors-internal/x",
        &[("origin", "https://app.example")],
    );
    assert_eq!(status(&st, EXTERNAL, pre, false).await, 204);
    // a disallowed origin on a state-changing method is a CORS 403
    let bad = req(
        Method::POST,
        "/cors-internal/x",
        &[("origin", "https://evil.example")],
    );
    assert_eq!(status(&st, INTERNAL, bad, false).await, 403);
    // with no Origin the request is just an internal_only one
    assert_eq!(get(&st, EXTERNAL, "/cors-internal/x").await, 403);
}

#[tokio::test]
async fn internal_only_answers_before_upstream_selection() {
    let st = state(0);
    // the upstream is down (would be 503) but the caller is not allowed in: 403
    assert_eq!(get(&st, EXTERNAL, "/internal-down/x").await, 403);
    // an internal caller does reach the upstream check
    assert_eq!(get(&st, INTERNAL, "/internal-down/x").await, 503);
}

#[tokio::test]
async fn upstream_availability_answers_before_auth() {
    let st = state(0);
    // a route with an auth profile and a dead upstream: no token, yet 503 not 401
    assert_eq!(get(&st, EXTERNAL, "/down-authed/x").await, 503);
    assert_eq!(get(&st, EXTERNAL, "/down/x").await, 503);
}

#[cfg(feature = "auth")]
#[tokio::test]
async fn auth_answers_before_the_waf() {
    let st = state(0);
    // a balanced-WAF pattern (php://input) on an authed+WAF route, with no token: 401 (auth first)
    let q = "/authed-waf/x?f=php://input";
    assert_eq!(get(&st, EXTERNAL, q).await, 401);
}

#[tokio::test]
async fn waf_answers_before_the_request_is_dispatched() {
    let st = state(0);
    // WAF-on route, hostile query (php://input): rejected with 400 before any upstream is tried
    let q = "/waf/x?f=php://input";
    assert_eq!(get(&st, EXTERNAL, q).await, 400);
}

// ── the wrapper around all of it ────────────────────────────────────────────

#[tokio::test]
async fn every_outcome_carries_security_headers_and_the_request_id() {
    let st = state(0);
    for (uri, m) in [
        ("/healthz", Method::GET),
        ("/no-such-route", Method::GET),
        ("/open/x", Method::TRACE),
    ] {
        let addr: SocketAddr = EXTERNAL.parse().unwrap();
        let resp = process_request(
            req(m, uri, &[("x-request-id", "abc-123")]),
            st.clone(),
            addr,
            false,
        )
        .await
        .unwrap();
        assert!(
            resp.headers().contains_key("x-content-type-options"),
            "{uri}: error and built-in responses get the security headers too"
        );
        assert_eq!(
            resp.headers().get("x-request-id").unwrap(),
            "abc-123",
            "{uri}"
        );
    }
}

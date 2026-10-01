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
use crate::proxy::ZionBody;
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
        st.static_cache.get("/sc\u{1f}").fresh().is_none(),
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
            .get(&format!("{uri}\u{1f}"))
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
    let kept = match st.static_cache.get("/swr-big\u{1f}") {
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

const REWRITE_HEADERS: [&str; 9] = [
    "x-original-url",
    "x-rewrite-url",
    "forwarded",
    "x-forwarded-server",
    "x-forwarded-scheme",
    "x-forwarded-prefix",
    "x-host",
    "x-http-host-override",
    "x-original-host",
];

fn seen(o: &Origin, name: &str) -> Option<String> {
    o.last_headers
        .lock()
        .unwrap()
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

fn hostile_headers() -> Vec<(&'static str, &'static str)> {
    REWRITE_HEADERS.iter().map(|h| (*h, "/admin")).collect()
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
    for h in REWRITE_HEADERS {
        assert_eq!(seen(&o, h), None, "{h} must not reach the upstream");
    }
    // control: ordinary headers are untouched, and Zion's own trust headers are set
    assert_eq!(seen(&o, "accept-language").as_deref(), Some("de"));
    assert_eq!(seen(&o, "x-custom").as_deref(), Some("kept"));
    assert!(seen(&o, "x-forwarded-for").is_some() && seen(&o, "x-forwarded-proto").is_some());
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
    for h in REWRITE_HEADERS {
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
    for h in REWRITE_HEADERS {
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
    for h in REWRITE_HEADERS {
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
    burst(&st, "r3", 40, 4).await;
    assert!(
        hits(&os[0]) > frozen,
        "back in rotation after the cool-down"
    );
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

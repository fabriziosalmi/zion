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
    /// The `Vary` value the origin sends (empty = none).
    vary: Mutex<String>,
    /// Requests that reached the origin.
    hits: AtomicUsize,
    /// The `Cache-Control` the origin sends.
    cc: Mutex<String>,
    /// `Accept-Language` of the last request the origin saw (None if absent).
    last_lang: Mutex<Option<String>>,
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
                            .status(StatusCode::OK)
                            .header("cache-control", o.cc.lock().unwrap().clone());
                        let vary = o.vary.lock().unwrap().clone();
                        if !vary.is_empty() {
                            b = b.header("vary", vary);
                        }
                        Ok::<_, std::convert::Infallible>(
                            b.body(Full::new(Bytes::from(body))).unwrap(),
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

fn state_for(port: u16) -> Arc<AppState> {
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

[[route]]
path = "/{{*rest}}"
upstream = "o"
mode = "static_cache"
cache_profile = "c"
"#
    );
    AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
}

async fn rig(vary: &str) -> (Arc<Origin>, Arc<AppState>) {
    rig_cc(vary, "public, max-age=60").await
}

async fn rig_cc(vary: &str, cc: &str) -> (Arc<Origin>, Arc<AppState>) {
    let o = Arc::new(Origin {
        vary: Mutex::new(vary.into()),
        hits: AtomicUsize::new(0),
        cc: Mutex::new(cc.into()),
        last_lang: Mutex::new(None),
    });
    let port = start_origin(o.clone()).await;
    (o, state_for(port))
}

fn get(uri: &str, headers: &[(&str, &str)]) -> Request<ZionBody> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
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

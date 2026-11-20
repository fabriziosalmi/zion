//! End-to-end tests of stale-while-revalidate (RFC 5861, #446): the real
//! `process_request` and `AppState`, in front of a tiny in-process origin that
//! records what it is asked and can be told to be slow or to change its answer.

use crate::config::ZionConfig;
use crate::dispatch::process_request;
use crate::http_util::ReqBody;
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Origin {
    /// Requests seen: (conditional If-None-Match, had Authorization/Cookie).
    seen: Mutex<Vec<(Option<String>, bool)>>,
    /// The body and ETag the origin currently serves.
    body: Mutex<(String, String)>,
    /// Delay before answering, in ms.
    delay_ms: AtomicU64,
    /// `Cache-Control` the origin sends.
    cache_control: Mutex<String>,
    /// When set, the origin drops the connection without answering (a transport error).
    down: std::sync::atomic::AtomicBool,
    /// When set, every response carries `Vary: Accept-Encoding`.
    vary_ae: std::sync::atomic::AtomicBool,
    /// More headers on every `200`, and on every `304`.
    extra_200: Mutex<Vec<(&'static str, &'static str)>>,
    extra_304: Mutex<Vec<(&'static str, &'static str)>>,
    /// When set, the `Cache-Control` of a `304` instead of `cache_control` (empty: none).
    cache_control_304: Mutex<Option<String>>,
}

impl Origin {
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

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
                        let inm = req
                            .headers()
                            .get("if-none-match")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        let creds = req.headers().contains_key("authorization")
                            || req.headers().contains_key("cookie");
                        o.seen.lock().unwrap().push((inm.clone(), creds));
                        if o.down.load(Ordering::Relaxed) {
                            return Err("origin down");
                        }
                        let d = o.delay_ms.load(Ordering::Relaxed);
                        if d > 0 {
                            tokio::time::sleep(Duration::from_millis(d)).await;
                        }
                        let (body, etag) = o.body.lock().unwrap().clone();
                        let cc = o.cache_control.lock().unwrap().clone();
                        // (an unrelated header stands in when the flag is off)
                        let vary = if o.vary_ae.load(Ordering::Relaxed) {
                            ("vary", "Accept-Encoding")
                        } else {
                            ("x-test", "-")
                        };
                        let resp = if inm.as_deref() == Some(etag.as_str()) {
                            let cc = o.cache_control_304.lock().unwrap().clone().unwrap_or(cc);
                            let mut b = Response::builder()
                                .header(vary.0, vary.1)
                                .status(StatusCode::NOT_MODIFIED)
                                .header("etag", &etag);
                            if !cc.is_empty() {
                                b = b.header("cache-control", &cc);
                            }
                            for (k, v) in o.extra_304.lock().unwrap().iter() {
                                b = b.header(*k, *v);
                            }
                            b.body(Full::new(Bytes::new()))
                        } else {
                            let mut b = Response::builder()
                                .header(vary.0, vary.1)
                                .status(StatusCode::OK)
                                .header("etag", &etag)
                                .header("cache-control", &cc);
                            for (k, v) in o.extra_200.lock().unwrap().iter() {
                                b = b.header(*k, *v);
                            }
                            b.body(Full::new(Bytes::from(body)))
                        };
                        Ok::<_, &'static str>(resp.unwrap())
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

fn state_for(origin_port: u16) -> Arc<AppState> {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstreams]
o = "http://127.0.0.1:{origin_port}"

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
    let cfg: ZionConfig = toml::from_str(&toml).expect("config parses");
    AppState::for_tests(&cfg)
}

fn get(uri: &str, headers: &[(&str, &str)]) -> Request<ReqBody> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Full::new(Bytes::new()).map_err(|n| match n {}).boxed())
        .unwrap()
}

struct Answer {
    status: u16,
    cache: String,
    body: String,
    took: Duration,
    headers: hyper::HeaderMap,
}

async fn fetch(st: &Arc<AppState>, uri: &str, headers: &[(&str, &str)]) -> Answer {
    let t = Instant::now();
    let resp = process_request(
        get(uri, headers),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
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
    Answer {
        status,
        cache,
        body,
        took: t.elapsed(),
        headers,
    }
}

async fn origin_and_state(cc: &str) -> (Arc<Origin>, Arc<AppState>) {
    let o = Arc::new(Origin::default());
    *o.body.lock().unwrap() = ("v1".into(), "\"e1\"".into());
    *o.cache_control.lock().unwrap() = cc.into();
    let port = start_origin(o.clone()).await;
    (o, state_for(port))
}

/// Poll until `f` holds (the tee stores the entry a moment after the body ends).
async fn until(what: &str, f: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn origin_swr_reads_and_caps_the_directive() {
    use crate::dispatch::origin_swr_for_tests as swr;
    assert_eq!(swr("max-age=1, stale-while-revalidate=30"), 30);
    assert_eq!(swr("stale-while-revalidate=\"5\""), 5);
    assert_eq!(swr("max-age=1"), 0);
    assert_eq!(swr("stale-while-revalidate=abc"), 0);
    assert_eq!(swr("stale-while-revalidate=999999999"), 86_400, "capped");
}

#[tokio::test]
async fn stale_entry_is_served_at_once_and_refreshed_in_the_background() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    let first = fetch(&st, "/a", &[]).await;
    assert_eq!(
        (first.status, first.cache.as_str(), first.body.as_str()),
        (200, "MISS", "v1")
    );
    until("entry stored", || {
        st.static_cache.get("/a\u{1f}\u{1c}").fresh().is_some()
    })
    .await;

    tokio::time::sleep(Duration::from_millis(1300)).await; // now stale, inside the window
    o.delay_ms.store(600, Ordering::Relaxed); // a slow origin: the refresh must not block the client
                                              // the origin has a NEW version; the conditional refresh will fetch it
    *o.body.lock().unwrap() = ("v2".into(), "\"e2\"".into());

    let stale = fetch(
        &st,
        "/a",
        &[("authorization", "Bearer secret"), ("cookie", "s=1")],
    )
    .await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    assert_eq!(stale.body, "v1", "the stale copy is what the client gets");
    assert!(
        stale.took < Duration::from_millis(300),
        "client waited {:?}",
        stale.took
    );

    until("background refresh reaches the origin", || o.count() >= 2).await;
    {
        let seen = o.seen.lock().unwrap();
        assert_eq!(
            seen[1].0.as_deref(),
            Some("\"e1\""),
            "refresh is conditional on the stored ETag"
        );
        assert!(
            !seen[1].1,
            "the refresh must not carry the caller's Authorization/Cookie"
        );
    }
    // once it lands, the next request is a fresh hit on the NEW body
    until("refreshed entry", || {
        st.static_cache
            .get("/a\u{1f}\u{1c}")
            .fresh()
            .is_some_and(|h| h.body == "v2")
    })
    .await;
    let after = fetch(&st, "/a", &[]).await;
    assert_eq!((after.cache.as_str(), after.body.as_str()), ("HIT", "v2"));
}

#[tokio::test]
async fn a_304_refresh_revives_the_entry_without_refetching_the_body() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/b", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/b\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;

    let stale = fetch(&st, "/b", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    until("304 refresh", || o.count() >= 2).await;
    until("entry fresh again", || {
        st.static_cache.get("/b\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    let after = fetch(&st, "/b", &[]).await;
    assert_eq!((after.cache.as_str(), after.body.as_str()), ("HIT", "v1"));
}

#[tokio::test]
async fn concurrent_requests_on_a_stale_key_cause_one_refresh() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/c", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/c\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    o.delay_ms.store(400, Ordering::Relaxed);

    let mut answers = Vec::new();
    for _ in 0..12 {
        answers.push(fetch(&st, "/c", &[]).await);
    }
    assert!(answers
        .iter()
        .all(|a| a.cache == "STALE-WHILE-REVALIDATE" && a.body == "v1"));
    until("refresh done", || {
        st.static_cache.get("/c\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    assert_eq!(
        o.count(),
        2,
        "one fill + exactly one refresh, not one per request"
    );
}

#[tokio::test]
async fn outside_the_window_the_client_waits_for_the_origin_as_before() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=1").await;
    fetch(&st, "/d", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/d\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(2600)).await; // past max-age + swr
    o.delay_ms.store(300, Ordering::Relaxed);
    let a = fetch(&st, "/d", &[]).await;
    assert_ne!(
        a.cache, "STALE-WHILE-REVALIDATE",
        "outside the window nothing is served stale"
    );
    assert!(
        a.took >= Duration::from_millis(250),
        "the client must have waited for the origin"
    );
}

#[tokio::test]
async fn without_the_directive_behaviour_is_unchanged() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    fetch(&st, "/e", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/e\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    o.delay_ms.store(300, Ordering::Relaxed);
    let a = fetch(&st, "/e", &[]).await;
    assert_eq!(
        a.cache, "REVALIDATED",
        "synchronous revalidation, as before"
    );
    assert!(a.took >= Duration::from_millis(250));
}

// ── directives that forbid serving a stale response (RFC 9111 §4.2.4, §5.2.2) ──

const NO_STALE_DIRECTIVES: [&str; 3] = [
    "public, max-age=1, must-revalidate, stale-while-revalidate=30",
    "public, max-age=1, proxy-revalidate, stale-while-revalidate=30",
    "public, s-maxage=1, stale-while-revalidate=30",
];

/// `must-revalidate`, `proxy-revalidate` and (for a shared cache) `s-maxage` forbid
/// answering from a stale entry without validating it, so stale-while-revalidate must
/// not apply: the client waits for the origin.
#[tokio::test]
async fn stale_while_revalidate_is_not_used_when_the_origin_forbids_stale() {
    for (n, cc) in NO_STALE_DIRECTIVES.iter().enumerate() {
        let (o, st) = origin_and_state(cc).await;
        let uri = format!("/nsw{n}");
        fetch(&st, &uri, &[]).await;
        until("entry stored", || {
            st.static_cache
                .get(&format!("{uri}\u{1f}\u{1c}"))
                .fresh()
                .is_some()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(1300)).await;
        o.delay_ms.store(300, Ordering::Relaxed);
        let a = fetch(&st, &uri, &[]).await;
        assert_ne!(
            a.cache, "STALE-WHILE-REVALIDATE",
            "{cc}: a stale copy must not be served"
        );
        assert!(
            a.took >= Duration::from_millis(250),
            "{cc}: the client must wait for the origin, waited {:?}",
            a.took
        );
    }
}

/// Serving stale because the origin is unreachable is also "generating a stale
/// response": the same directives forbid it, and the client gets the error instead.
#[tokio::test]
async fn stale_if_error_is_not_used_when_the_origin_forbids_stale() {
    for (n, cc) in NO_STALE_DIRECTIVES.iter().enumerate() {
        let (o, st) = origin_and_state(cc).await;
        let uri = format!("/nse{n}");
        fetch(&st, &uri, &[]).await;
        until("entry stored", || {
            st.static_cache
                .get(&format!("{uri}\u{1f}\u{1c}"))
                .fresh()
                .is_some()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(1300)).await;
        o.down.store(true, Ordering::Relaxed);
        let addr: SocketAddr = "203.0.113.9:1".parse().unwrap();
        let r = process_request(get(&uri, &[]), st.clone(), addr, false).await;
        let stale = matches!(&r, Ok(resp) if resp.headers().get("x-zion-cache").is_some_and(|v| v == "STALE"));
        assert!(
            !stale,
            "{cc}: an unreachable origin must not produce a stale answer"
        );
    }
}

/// Control: without those directives stale-if-error still works, so the test above is
/// not passing merely because the harness cannot produce an origin failure.
#[tokio::test]
async fn stale_if_error_still_serves_a_stale_copy_otherwise() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    fetch(&st, "/sie", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/sie\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    o.down.store(true, Ordering::Relaxed);
    let a = fetch(&st, "/sie", &[]).await;
    assert_eq!((a.cache.as_str(), a.body.as_str()), ("STALE", "v1"));
}

/// A 304 renews the entry it revalidated: here one keyed per encoding (`Vary:
/// Accept-Encoding`), not the shared identity entry the request would also look under.
#[tokio::test]
async fn a_304_renews_a_per_encoding_entry_under_its_own_key() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    o.vary_ae.store(true, Ordering::Relaxed);
    let gz = [("accept-encoding", "gzip")];
    assert_eq!(fetch(&st, "/pe", &gz).await.cache, "MISS");
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let revalidated = fetch(&st, "/pe", &gz).await;
    assert_eq!((revalidated.status, revalidated.body.as_str()), (200, "v1"));
    assert_eq!(o.seen.lock().unwrap()[1].0.as_deref(), Some("\"e1\""));
    let after = fetch(&st, "/pe", &gz).await;
    assert_eq!(
        (after.cache.as_str(), o.count()),
        ("HIT", 2),
        "the 304 made the entry fresh again"
    );
}

// ── what an answer from a stale entry carries of the origin's headers ──

/// The headers that make an uploaded SVG inert in a browser.
const UPLOAD_HEADERS: [(&str, &str); 2] = [
    ("content-security-policy", "sandbox"),
    ("content-disposition", "attachment; filename=\"upload.svg\""),
];

fn header(a: &Answer, name: &str) -> Option<String> {
    let all: Vec<&str> = a
        .headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    (!all.is_empty()).then(|| all.join(" | "))
}

fn assert_upload_headers(a: &Answer, what: &str) {
    for (name, value) in UPLOAD_HEADERS {
        assert_eq!(
            header(a, name).as_deref(),
            Some(value),
            "{what} ({}) without the origin's {name}",
            a.cache
        );
    }
}

async fn upload_origin(cc: &str) -> (Arc<Origin>, Arc<AppState>) {
    let (o, st) = origin_and_state(cc).await;
    *o.extra_200.lock().unwrap() = UPLOAD_HEADERS.to_vec();
    (o, st)
}

/// A stale copy served at once while the refresh runs carries the origin's headers.
#[tokio::test]
async fn a_stale_while_revalidate_answer_carries_the_origin_headers() {
    let (_o, st) = upload_origin("public, max-age=1, stale-while-revalidate=30").await;
    let miss = fetch(&st, "/up-swr", &[]).await;
    assert_eq!(miss.cache, "MISS");
    assert_upload_headers(&miss, "the miss");
    until("entry stored", || {
        st.static_cache.get("/up-swr\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    let hit = fetch(&st, "/up-swr", &[]).await;
    assert_eq!(hit.cache, "HIT");
    assert_upload_headers(&hit, "a fresh hit");
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let stale = fetch(&st, "/up-swr", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    assert_upload_headers(&stale, "a stale-while-revalidate answer");
}

/// A stale copy served because the origin is down carries the origin's headers.
#[tokio::test]
async fn a_stale_if_error_answer_carries_the_origin_headers() {
    let (o, st) = upload_origin("public, max-age=1").await;
    fetch(&st, "/up-sie", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/up-sie\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    o.down.store(true, Ordering::Relaxed);
    let stale = fetch(&st, "/up-sie", &[]).await;
    assert_eq!((stale.cache.as_str(), stale.body.as_str()), ("STALE", "v1"));
    assert_upload_headers(&stale, "a stale-if-error answer");
}

/// A `304` from the origin confirms the entry: the answer, and the hits after it, keep the
/// stored headers and take the ones the 304 brought (RFC 9111 §4.3.4).
#[tokio::test]
async fn a_revalidated_entry_keeps_its_headers_and_takes_the_304s() {
    let (o, st) = upload_origin("public, max-age=1").await;
    *o.extra_304.lock().unwrap() = vec![("x-revalidated", "yes")];
    fetch(&st, "/up-rv", &[]).await;
    until("entry stored", || {
        st.static_cache.get("/up-rv\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let revalidated = fetch(&st, "/up-rv", &[]).await;
    assert_eq!(
        (revalidated.cache.as_str(), revalidated.body.as_str()),
        ("REVALIDATED", "v1")
    );
    assert_eq!(o.seen.lock().unwrap()[1].0.as_deref(), Some("\"e1\""));
    assert_upload_headers(&revalidated, "the revalidated answer");
    assert_eq!(
        header(&revalidated, "x-revalidated").as_deref(),
        Some("yes")
    );
    let after = fetch(&st, "/up-rv", &[]).await;
    assert_eq!((after.cache.as_str(), o.count()), ("HIT", 2));
    assert_upload_headers(&after, "a hit on the renewed entry");
    assert_eq!(header(&after, "x-revalidated").as_deref(), Some("yes"));
}

/// Wait until `uri`'s identity entry is stored and fresh, then until it is stale.
async fn stored_then_stale(st: &Arc<AppState>, uri: &str) {
    let key = format!("{uri}\u{1f}\u{1c}");
    until("entry stored", || {
        st.static_cache.get(&key).fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
}

/// A `304` that sets a cookie answers the client whose request it was, and does not renew the
/// shared entry, as a `200` that sets one is not stored: the next client is not given what came
/// with it, and the origin is asked again.
#[tokio::test]
async fn a_304_that_sets_a_cookie_does_not_renew_the_shared_entry() {
    let (o, st) = upload_origin("public, max-age=1").await;
    *o.extra_304.lock().unwrap() = vec![("set-cookie", "sid=x"), ("x-session", "alice")];
    fetch(&st, "/up-sc", &[]).await;
    stored_then_stale(&st, "/up-sc").await;
    let first = fetch(&st, "/up-sc", &[]).await;
    assert_eq!(
        (first.cache.as_str(), first.body.as_str()),
        ("REVALIDATED", "v1")
    );
    o.extra_304.lock().unwrap().clear();
    let next = fetch(&st, "/up-sc", &[]).await;
    assert_eq!(
        (next.cache.as_str(), o.count()),
        ("REVALIDATED", 3),
        "the cookie's 304 renewed the entry"
    );
    assert_eq!(
        header(&next, "x-session"),
        None,
        "the next client got what came with the cookie"
    );
    assert_eq!(header(&next, "set-cookie"), None);
    assert_upload_headers(&next, "the next answer");
}

/// Alice's revalidation goes to the origin with her `Cookie` or `Authorization`, and the origin
/// answers `304`, `private`, with her account in a header. That is her answer: it must not become
/// the shared entry the next user is served from (it did, and bob got alice's `X-Account` as a
/// `HIT` for the 304's 60 s).
#[tokio::test]
async fn a_private_304_to_one_user_is_not_served_to_the_next() {
    for alice in [
        &[("cookie", "sid=alice")][..],
        &[("authorization", "Bearer alice")],
    ] {
        let (o, st) = upload_origin("public, max-age=1").await;
        *o.cache_control_304.lock().unwrap() = Some("private, max-age=60".into());
        *o.extra_304.lock().unwrap() = vec![("x-account", "alice@example.com")];
        fetch(&st, "/acct", &[]).await;
        stored_then_stale(&st, "/acct").await;
        let hers = fetch(&st, "/acct", alice).await;
        assert_eq!(hers.cache, "REVALIDATED", "{alice:?}");
        assert_eq!(
            header(&hers, "x-account").as_deref(),
            Some("alice@example.com"),
            "her own answer"
        );
        // The origin answers the next revalidation with the public 304.
        *o.cache_control_304.lock().unwrap() = None;
        o.extra_304.lock().unwrap().clear();
        let bobs = fetch(&st, "/acct", &[("cookie", "sid=bob")]).await;
        assert_eq!(
            header(&bobs, "x-account"),
            None,
            "{alice:?}: bob was served alice's 304 as {}",
            bobs.cache
        );
        assert_eq!(
            header(&bobs, "cache-control").as_deref(),
            Some("public, max-age=1"),
            "{alice:?}"
        );
        assert_eq!(
            o.count(),
            3,
            "{alice:?}: alice's 304 renewed the shared entry"
        );
    }
}

/// A bare `304` (an `ETag`, no `Cache-Control`, as many application servers answer) renews the
/// entry for the lifetime the origin gave it, not for the profile's 3600 s, and the answer says
/// it was just confirmed (`Age` from the 304, not the stale entry's).
#[tokio::test]
async fn a_bare_304_renews_the_entry_for_the_origins_lifetime_only() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    *o.cache_control_304.lock().unwrap() = Some(String::new());
    fetch(&st, "/bare", &[]).await;
    stored_then_stale(&st, "/bare").await;
    let revalidated = fetch(&st, "/bare", &[]).await;
    assert_eq!(revalidated.cache, "REVALIDATED");
    assert_eq!(
        header(&revalidated, "age").as_deref(),
        Some("0"),
        "the age of the stale lookup on a response the origin just confirmed"
    );
    let hit = fetch(&st, "/bare", &[]).await;
    assert_eq!((hit.cache.as_str(), o.count()), ("HIT", 2));
    assert_eq!(
        header(&hit, "cache-control").as_deref(),
        Some("public, max-age=1")
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let again = fetch(&st, "/bare", &[]).await;
    assert_eq!(
        (again.cache.as_str(), o.count()),
        ("REVALIDATED", 3),
        "fresh past the origin's 1 s: renewed for the profile TTL"
    );
}

/// The stale-while-revalidate background refresh: a `304` updates the stored headers with its
/// own and keeps the others (RFC 9111 §4.3.4), as the foreground revalidation does.
#[tokio::test]
async fn a_background_304_refresh_updates_the_stored_headers() {
    let (o, st) = upload_origin("public, max-age=1, stale-while-revalidate=30").await;
    *o.extra_304.lock().unwrap() = vec![("x-revalidated", "yes")];
    fetch(&st, "/swr-304", &[]).await;
    stored_then_stale(&st, "/swr-304").await;
    let stale = fetch(&st, "/swr-304", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    until("the background refresh", || o.count() >= 2).await;
    until("entry fresh again", || {
        st.static_cache
            .get("/swr-304\u{1f}\u{1c}")
            .fresh()
            .is_some()
    })
    .await;
    let after = fetch(&st, "/swr-304", &[]).await;
    assert_eq!(
        (after.cache.as_str(), after.body.as_str(), o.count()),
        ("HIT", "v1", 2)
    );
    assert_upload_headers(&after, "a hit after a background 304");
    assert_eq!(header(&after, "x-revalidated").as_deref(), Some("yes"));
}

/// The stale-while-revalidate background refresh that gets new content stores the new
/// response's headers with it: a hit on it still carries the upload's.
#[tokio::test]
async fn a_background_200_refresh_stores_the_new_responses_headers() {
    let (o, st) = upload_origin("public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/swr-200", &[]).await;
    stored_then_stale(&st, "/swr-200").await;
    *o.body.lock().unwrap() = ("v2".into(), "\"e2\"".into());
    let stale = fetch(&st, "/swr-200", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    until("refreshed entry", || {
        st.static_cache
            .get("/swr-200\u{1f}\u{1c}")
            .fresh()
            .is_some_and(|h| h.body == "v2")
    })
    .await;
    let after = fetch(&st, "/swr-200", &[]).await;
    assert_eq!((after.cache.as_str(), after.body.as_str()), ("HIT", "v2"));
    assert_upload_headers(&after, "a hit after a background 200");
}

/// A `200` with more header bytes than an entry keeps is served whole, marked `BYPASS`, counted
/// in `zion_cache_too_large`, and not stored, so the next request goes to the origin; and its
/// `Vary` does not install a rule or take a variant slot for a response that is not stored.
#[tokio::test]
async fn a_response_with_more_headers_than_an_entry_keeps_is_served_and_not_stored() {
    use std::sync::atomic::Ordering::Relaxed;
    let (o, st) = origin_and_state("public, max-age=60").await;
    let huge: &'static str = Box::leak(
        "x".repeat(crate::cache::MAX_STORED_HEADER_BYTES)
            .into_boxed_str(),
    );
    *o.extra_200.lock().unwrap() = vec![("x-huge", huge), ("vary", "Accept-Language")];
    let de = [("accept-language", "de")];
    let before = crate::metrics::METRICS.cache_too_large.load(Relaxed);
    let first = fetch(&st, "/huge", &de).await;
    assert_eq!(
        (first.status, first.cache.as_str(), first.body.as_str()),
        (200, "BYPASS", "v1")
    );
    assert_eq!(
        header(&first, "x-huge").map(|v| v.len()),
        Some(huge.len()),
        "served whole"
    );
    assert!(
        crate::metrics::METRICS.cache_too_large.load(Relaxed) > before,
        "not counted in zion_cache_too_large"
    );
    assert!(
        st.static_cache.vary.get("/huge\u{1f}\u{1c}").is_none(),
        "a Vary rule was installed for a response that is not stored"
    );
    let second = fetch(&st, "/huge", &de).await;
    assert_eq!(
        (second.cache.as_str(), o.count()),
        ("BYPASS", 2),
        "stored: the origin was not asked again"
    );
}

/// The stale-while-revalidate background refresh carries no credentials, but its `304` is held
/// to the same rule as the foreground one: a `private` 304 does not renew the shared entry with
/// what it brought.
#[tokio::test]
async fn a_private_background_304_does_not_renew_the_shared_entry() {
    let (o, st) = upload_origin("public, max-age=1, stale-while-revalidate=30").await;
    *o.cache_control_304.lock().unwrap() = Some("private, max-age=60".into());
    *o.extra_304.lock().unwrap() = vec![("x-account", "alice@example.com")];
    fetch(&st, "/swr-p", &[]).await;
    stored_then_stale(&st, "/swr-p").await;
    let stale = fetch(&st, "/swr-p", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    let key: Arc<str> = Arc::from("/swr-p\u{1f}\u{1c}");
    until("the background refresh is over", || {
        o.count() >= 2 && st.inflight.get(&key).is_none()
    })
    .await;
    assert!(
        st.static_cache.get(&key).fresh().is_none(),
        "the private 304 renewed the shared entry"
    );
    let next = fetch(&st, "/swr-p", &[]).await;
    assert_eq!(header(&next, "x-account"), None, "served as {}", next.cache);
}

/// A `304` whose headers, with the stored ones, are more than an entry keeps: this client is
/// answered with them, the entry is not renewed, and the refusal is counted in
/// `zion_cache_too_large` like that of a `200`.
#[tokio::test]
async fn a_304_with_more_headers_than_an_entry_keeps_is_served_and_counted() {
    use std::sync::atomic::Ordering::Relaxed;
    let (o, st) = upload_origin("public, max-age=1").await;
    let huge: &'static str = Box::leak(
        "x".repeat(crate::cache::MAX_STORED_HEADER_BYTES)
            .into_boxed_str(),
    );
    *o.extra_304.lock().unwrap() = vec![("x-huge", huge)];
    fetch(&st, "/huge-304", &[]).await;
    stored_then_stale(&st, "/huge-304").await;
    let before = crate::metrics::METRICS.cache_too_large.load(Relaxed);
    let revalidated = fetch(&st, "/huge-304", &[]).await;
    assert_eq!(revalidated.cache, "REVALIDATED");
    assert_eq!(
        header(&revalidated, "x-huge").map(|v| v.len()),
        Some(huge.len())
    );
    assert!(
        crate::metrics::METRICS.cache_too_large.load(Relaxed) > before,
        "not counted in zion_cache_too_large"
    );
    o.extra_304.lock().unwrap().clear();
    let next = fetch(&st, "/huge-304", &[]).await;
    assert_eq!(
        (next.cache.as_str(), o.count()),
        ("REVALIDATED", 3),
        "the entry was renewed with more headers than it keeps"
    );
}

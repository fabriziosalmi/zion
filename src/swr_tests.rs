//! End-to-end tests of stale-while-revalidate (RFC 5861, #446): the real
//! `process_request` and `AppState`, in front of a tiny in-process origin that
//! records what it is asked and can be told to be slow or to change its answer.

use crate::config::ZionConfig;
use crate::dispatch::process_request;
use crate::http_util::ZionBody;
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
                            Response::builder()
                                .header(vary.0, vary.1)
                                .status(StatusCode::NOT_MODIFIED)
                                .header("etag", &etag)
                                .header("cache-control", &cc)
                                .body(Full::new(Bytes::new()))
                        } else {
                            Response::builder()
                                .header(vary.0, vary.1)
                                .status(StatusCode::OK)
                                .header("etag", &etag)
                                .header("cache-control", &cc)
                                .body(Full::new(Bytes::from(body)))
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

fn get(uri: &str, headers: &[(&str, &str)]) -> Request<ZionBody> {
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

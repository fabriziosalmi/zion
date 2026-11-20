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
    /// The headers of every request, in order.
    requests: Mutex<Vec<hyper::HeaderMap>>,
    /// The `Last-Modified` the origin sends (empty: none). An empty ETag in `body` sends none.
    last_modified: Mutex<String>,
    /// When set, the origin chooses the representation by this request header, says so in
    /// `Vary`, and gives each representation its own body and ETag (`<body> for <value>`,
    /// `nobody` when the request has none).
    vary_on: Mutex<Option<&'static str>>,
    /// When set, the origin answers per user, by this request header: every response says so in
    /// `Vary` and carries `X-Account: <its value>` (`nobody` when the request has none). The body
    /// and the ETag stay, so an entry stored before still revalidates with a `304`: an origin
    /// redeployed to vary on a header the entry was not filed under.
    per_user: Mutex<Option<&'static str>>,
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
                        o.requests.lock().unwrap().push(req.headers().clone());
                        if o.down.load(Ordering::Relaxed) {
                            return Err("origin down");
                        }
                        let d = o.delay_ms.load(Ordering::Relaxed);
                        if d > 0 {
                            tokio::time::sleep(Duration::from_millis(d)).await;
                        }
                        let (mut body, mut etag) = o.body.lock().unwrap().clone();
                        let vary_on = *o.vary_on.lock().unwrap();
                        if let Some(name) = vary_on {
                            let value = req
                                .headers()
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("nobody");
                            body = format!("{body} for {value}");
                            etag = format!("\"{}-{value}\"", etag.trim_matches('"'));
                        }
                        let lm = o.last_modified.lock().unwrap().clone();
                        let cc = o.cache_control.lock().unwrap().clone();
                        // (an unrelated header stands in when the flag is off)
                        let vary = if o.vary_ae.load(Ordering::Relaxed) {
                            ("vary", "Accept-Encoding")
                        } else {
                            ("x-test", "-")
                        };
                        // RFC 9110 §13.2.2: `If-None-Match` first (`*` matches any current
                        // representation), and `If-Modified-Since` only without it.
                        let ims = req
                            .headers()
                            .get("if-modified-since")
                            .and_then(|v| v.to_str().ok());
                        let not_modified = match inm.as_deref() {
                            Some(inm) => inm == "*" || (!etag.is_empty() && inm == etag),
                            None => !lm.is_empty() && ims == Some(lm.as_str()),
                        };
                        let mut b = Response::builder().header(vary.0, vary.1);
                        if !etag.is_empty() {
                            b = b.header("etag", &etag);
                        }
                        if !lm.is_empty() {
                            b = b.header("last-modified", &lm);
                        }
                        if let Some(name) = vary_on {
                            b = b.header("vary", name);
                        }
                        let per_user = *o.per_user.lock().unwrap();
                        if let Some(name) = per_user {
                            let account = req
                                .headers()
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("nobody");
                            b = b.header("vary", name).header("x-account", account);
                        }
                        let resp = if not_modified {
                            let cc = o.cache_control_304.lock().unwrap().clone().unwrap_or(cc);
                            b = b.status(StatusCode::NOT_MODIFIED);
                            if !cc.is_empty() {
                                b = b.header("cache-control", &cc);
                            }
                            for (k, v) in o.extra_304.lock().unwrap().iter() {
                                b = b.header(*k, *v);
                            }
                            b.body(Full::new(Bytes::new()))
                        } else {
                            b = b.status(StatusCode::OK);
                            if !cc.is_empty() {
                                b = b.header("cache-control", &cc);
                            }
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
    state_with_ttl(origin_port, 3600)
}

/// The test state, with the cache profile's `ttl_seconds` (what an entry lives when the origin
/// gives no lifetime).
fn state_with_ttl(origin_port: u16, ttl_seconds: u64) -> Arc<AppState> {
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
ttl_seconds = {ttl_seconds}
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
    for (n, alice) in [
        &[("cookie", "sid=alice")][..],
        &[("authorization", "Bearer alice")],
    ]
    .into_iter()
    .enumerate()
    {
        // A path of its own per case: on a one-core host the store is a map of the thread's,
        // shared by the two states, and the second case would find the first one's entry.
        let uri = format!("/acct{n}");
        let (o, st) = upload_origin("public, max-age=1").await;
        *o.cache_control_304.lock().unwrap() = Some("private, max-age=60".into());
        *o.extra_304.lock().unwrap() = vec![("x-account", "alice@example.com")];
        fetch(&st, &uri, &[]).await;
        stored_then_stale(&st, &uri).await;
        let hers = fetch(&st, &uri, alice).await;
        assert_eq!(hers.cache, "REVALIDATED", "{alice:?}");
        assert_eq!(
            header(&hers, "x-account").as_deref(),
            Some("alice@example.com"),
            "her own answer"
        );
        // The origin answers the next revalidation with the public 304.
        *o.cache_control_304.lock().unwrap() = None;
        o.extra_304.lock().unwrap().clear();
        let bobs = fetch(&st, &uri, &[("cookie", "sid=bob")]).await;
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
    let (o, st) = origin_and_state("public, max-age=60").await;
    *o.extra_200.lock().unwrap() = vec![("x-huge", huge()), ("vary", "Accept-Language")];
    let de = [("accept-language", "de")];
    let first = fetch(&st, "/huge", &de).await;
    assert_eq!(
        (first.status, first.cache.as_str(), first.body.as_str()),
        (200, "BYPASS", "v1")
    );
    assert_eq!(
        header(&first, "x-huge").map(|v| v.len()),
        Some(huge().len()),
        "served whole"
    );
    assert_eq!(
        st.static_cache.too_large(),
        1,
        "counted in zion_cache_too_large, once"
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
    let (o, st) = upload_origin("public, max-age=1").await;
    *o.extra_304.lock().unwrap() = vec![("x-huge", huge())];
    fetch(&st, "/huge-304", &[]).await;
    stored_then_stale(&st, "/huge-304").await;
    assert_eq!(st.static_cache.too_large(), 0);
    let revalidated = fetch(&st, "/huge-304", &[]).await;
    assert_eq!(revalidated.cache, "REVALIDATED");
    assert_eq!(
        header(&revalidated, "x-huge").map(|v| v.len()),
        Some(huge().len())
    );
    assert_eq!(
        st.static_cache.too_large(),
        1,
        "counted in zion_cache_too_large, once"
    );
    o.extra_304.lock().unwrap().clear();
    let next = fetch(&st, "/huge-304", &[]).await;
    assert_eq!(
        (next.cache.as_str(), o.count()),
        ("REVALIDATED", 3),
        "the entry was renewed with more headers than it keeps"
    );
}

/// More header bytes than an entry keeps, in one field.
fn huge() -> &'static str {
    static HUGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HUGE.get_or_init(|| "x".repeat(crate::cache::MAX_STORED_HEADER_BYTES))
}

/// Wait until the stale-while-revalidate refresh of `key` has reached the origin (its
/// `n`-th request) and is over (its singleflight registration is gone).
async fn refresh_over(o: &Origin, st: &Arc<AppState>, key: &str, n: usize) {
    let key: Arc<str> = Arc::from(key);
    until("the background refresh is over", || {
        o.count() >= n && st.inflight.get(&key).is_none()
    })
    .await;
}

/// The background `304` refresh whose headers, with the stored ones, are more than an entry
/// keeps: the entry is not renewed with them, and the refusal is counted in
/// `zion_cache_too_large`, as on the foreground path.
#[tokio::test]
async fn a_background_304_with_more_headers_than_an_entry_keeps_is_counted() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    *o.extra_304.lock().unwrap() = vec![("x-huge", huge())];
    fetch(&st, "/swr-huge-304", &[]).await;
    stored_then_stale(&st, "/swr-huge-304").await;
    let stale = fetch(&st, "/swr-huge-304", &[]).await;
    assert_eq!(stale.cache, "STALE-WHILE-REVALIDATE");
    let key = "/swr-huge-304\u{1f}\u{1c}";
    refresh_over(&o, &st, key, 2).await;
    assert_eq!(
        st.static_cache.too_large(),
        1,
        "counted in zion_cache_too_large, once"
    );
    assert!(
        st.static_cache.get(key).fresh().is_none(),
        "renewed with more headers than an entry keeps"
    );
}

/// The background `200` refresh with more header bytes than an entry keeps: not stored, and
/// counted in `zion_cache_too_large`.
#[tokio::test]
async fn a_background_200_with_more_headers_than_an_entry_keeps_is_counted() {
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/swr-huge-200", &[]).await;
    stored_then_stale(&st, "/swr-huge-200").await;
    *o.body.lock().unwrap() = ("v2".into(), "\"e2\"".into());
    *o.extra_200.lock().unwrap() = vec![("x-huge", huge())];
    let stale = fetch(&st, "/swr-huge-200", &[]).await;
    assert_eq!(
        (stale.cache.as_str(), stale.body.as_str()),
        ("STALE-WHILE-REVALIDATE", "v1")
    );
    let key = "/swr-huge-200\u{1f}\u{1c}";
    refresh_over(&o, &st, key, 2).await;
    assert_eq!(
        st.static_cache.too_large(),
        1,
        "counted in zion_cache_too_large, once"
    );
    assert!(
        st.static_cache.get(key).fresh().is_none(),
        "stored with more headers than an entry keeps"
    );
}

/// The stale-while-revalidate refresh goes without the caller's `Authorization`, but the origin
/// can still answer it for that caller (the same target; behind an auth gate, the identity is in
/// `X-Auth-Subject` too). It is held to the RFC 9111 §3.5 opt-in as the foreground request is:
/// a `304` or a `200` without `public`, `s-maxage` or `must-revalidate` does not become the
/// shared entry. It did, judged as an anonymous request: bob was served alice's `X-Account`, or
/// alice's page.
#[tokio::test]
async fn a_background_refresh_for_an_authenticated_request_is_held_to_the_opt_in() {
    let alice = [("authorization", "Bearer alice")];

    // A 304 for her.
    let (o, st) = upload_origin("public, max-age=1, stale-while-revalidate=30").await;
    *o.cache_control_304.lock().unwrap() = Some("max-age=60, stale-while-revalidate=30".into());
    *o.extra_304.lock().unwrap() = vec![("x-account", "alice@example.com")];
    fetch(&st, "/swr-auth-304", &[]).await;
    stored_then_stale(&st, "/swr-auth-304").await;
    let hers = fetch(&st, "/swr-auth-304", &alice).await;
    assert_eq!(hers.cache, "STALE-WHILE-REVALIDATE");
    let key = "/swr-auth-304\u{1f}\u{1c}";
    refresh_over(&o, &st, key, 2).await;
    assert!(
        st.static_cache.get(key).fresh().is_none(),
        "her 304 renewed the shared entry"
    );
    *o.cache_control_304.lock().unwrap() = None;
    o.extra_304.lock().unwrap().clear();
    let bobs = fetch(&st, "/swr-auth-304", &[]).await;
    assert_eq!(header(&bobs, "x-account"), None, "served as {}", bobs.cache);

    // A 200 for her.
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    fetch(&st, "/swr-auth-200", &[]).await;
    stored_then_stale(&st, "/swr-auth-200").await;
    *o.body.lock().unwrap() = ("alice's page".into(), "\"e-alice\"".into());
    *o.cache_control.lock().unwrap() = "max-age=60, stale-while-revalidate=30".into();
    let hers = fetch(&st, "/swr-auth-200", &alice).await;
    assert_eq!(
        (hers.cache.as_str(), hers.body.as_str()),
        ("STALE-WHILE-REVALIDATE", "v1")
    );
    let key = "/swr-auth-200\u{1f}\u{1c}";
    refresh_over(&o, &st, key, 2).await;
    assert!(
        st.static_cache.get(key).fresh().is_none(),
        "her page became the shared entry"
    );
}

/// With no `Cache-Control` in the stored entry or the `304`, a hit on the entry carries `public,
/// max-age=<lifetime>`. A 304 that answered one client alone (here an authenticated request
/// without the §3.5 opt-in) is not the entry: its answer said `public` with alice's `X-Account`,
/// for any shared cache downstream to keep. It now says `private`.
#[tokio::test]
async fn a_304_that_answered_one_user_alone_is_not_marked_public() {
    let o = Arc::new(Origin::default());
    *o.body.lock().unwrap() = ("v1".into(), "\"e1\"".into());
    // No Cache-Control anywhere: the entry lives the profile's 1 s.
    *o.cache_control.lock().unwrap() = String::new();
    *o.cache_control_304.lock().unwrap() = Some(String::new());
    *o.extra_304.lock().unwrap() = vec![("x-account", "alice@example.com")];
    let st = state_with_ttl(start_origin(o.clone()).await, 1);
    let miss = fetch(&st, "/np", &[]).await;
    assert_eq!(
        (
            miss.cache.as_str(),
            header(&miss, "cache-control").as_deref()
        ),
        ("MISS", Some("public, max-age=1"))
    );
    stored_then_stale(&st, "/np").await;
    let hers = fetch(&st, "/np", &[("authorization", "Bearer alice")]).await;
    assert_eq!(hers.cache, "REVALIDATED");
    assert_eq!(
        header(&hers, "x-account").as_deref(),
        Some("alice@example.com"),
        "her own answer"
    );
    assert_eq!(
        header(&hers, "cache-control").as_deref(),
        Some("private"),
        "her answer is labelled for a shared cache to keep"
    );
    // An anonymous revalidation renews the entry, and its answer is what a hit carries.
    o.extra_304.lock().unwrap().clear();
    let anon = fetch(&st, "/np", &[]).await;
    assert_eq!(
        (
            anon.cache.as_str(),
            header(&anon, "cache-control").as_deref(),
            header(&anon, "x-account")
        ),
        ("REVALIDATED", Some("public, max-age=1"), None)
    );
}

/// When the origin made the response: with `Expires`, the lifetime it gave. A hit carries the
/// origin's `Date`, as the miss did, and so does a `304` from the cache (RFC 9110 §15.4.5); a
/// `304` from the origin that renews the entry brings its own. A hit dated now, beside its
/// `Age`, had a downstream cache count the time spent in zion twice.
#[tokio::test]
async fn an_answer_from_the_cache_carries_the_origins_date() {
    const MADE: &str = "Thu, 01 Jan 2026 00:00:00 GMT";
    const CONFIRMED: &str = "Fri, 02 Jan 2026 00:00:00 GMT";
    let (o, st) = origin_and_state("public, max-age=1").await;
    *o.extra_200.lock().unwrap() =
        vec![("date", MADE), ("expires", "Thu, 01 Jan 2026 01:00:00 GMT")];
    let miss = fetch(&st, "/dated", &[]).await;
    assert_eq!(
        (miss.cache.as_str(), header(&miss, "date").as_deref()),
        ("MISS", Some(MADE))
    );
    until("entry stored", || {
        st.static_cache.get("/dated\u{1f}\u{1c}").fresh().is_some()
    })
    .await;
    let hit = fetch(&st, "/dated", &[]).await;
    assert_eq!(
        (hit.cache.as_str(), header(&hit, "date").as_deref()),
        ("HIT", Some(MADE))
    );
    let not_modified = fetch(&st, "/dated", &[("if-none-match", "\"e1\"")]).await;
    assert_eq!(
        (
            not_modified.status,
            header(&not_modified, "date").as_deref()
        ),
        (304, Some(MADE))
    );
    *o.extra_304.lock().unwrap() = vec![("date", CONFIRMED)];
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let revalidated = fetch(&st, "/dated", &[]).await;
    assert_eq!(
        (
            revalidated.cache.as_str(),
            header(&revalidated, "date").as_deref()
        ),
        ("REVALIDATED", Some(CONFIRMED))
    );
    let after = fetch(&st, "/dated", &[]).await;
    assert_eq!(
        (after.cache.as_str(), header(&after, "date").as_deref()),
        ("HIT", Some(CONFIRMED))
    );
}

/// `ETag` (and `Content-Type`, `Content-Encoding`, `Last-Modified`) live in fields of their own:
/// one over the bound with a one-byte body was stored, and charged a few hundred bytes for its
/// 32 KiB. It is now refused like any other header over the bound, and counted.
#[tokio::test]
async fn a_response_whose_etag_is_more_than_an_entry_keeps_is_not_stored() {
    let (o, st) = origin_and_state("public, max-age=60").await;
    let etag = format!("\"{}\"", "e".repeat(crate::cache::MAX_STORED_HEADER_BYTES));
    *o.body.lock().unwrap() = ("v".into(), etag);
    let first = fetch(&st, "/big-etag", &[]).await;
    assert_eq!((first.cache.as_str(), first.body.as_str()), ("BYPASS", "v"));
    assert_eq!(st.static_cache.too_large(), 1);
    let second = fetch(&st, "/big-etag", &[]).await;
    assert_eq!(
        (second.cache.as_str(), o.count()),
        ("BYPASS", 2),
        "stored: the origin was not asked again"
    );
}

/// A variant keyed on a header the background refresh leaves out (here the TLS fingerprint the
/// HTTPS listener attests in `X-Client-TLS-JA4`; behind an auth gate, `X-Auth-Subject`) is not
/// refreshed in the background. The refresh reached the origin without the header, got the
/// representation for a request without it, and stored that under this variant's key: every
/// client with this fingerprint was then served the page for no fingerprint as a `HIT`. It is
/// now revalidated in the foreground with the client's own request, as an entry without the
/// stale-while-revalidate window is.
#[tokio::test]
async fn a_variant_keyed_on_a_header_the_refresh_leaves_out_is_not_refreshed_in_the_background() {
    const JA4: &str = "t13d1516h2_8daaf6152771_02713d6af862";
    let chrome = [("x-client-tls-ja4", JA4)];
    let mine = format!("v1 for {JA4}");
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    *o.vary_on.lock().unwrap() = Some("x-client-tls-ja4");
    let miss = fetch(&st, "/ja4", &chrome).await;
    assert_eq!(
        (miss.cache.as_str(), miss.body.as_str()),
        ("MISS", mine.as_str())
    );
    let key = format!("/ja4\u{1f}\u{1c}\u{1e}x-client-tls-ja4={JA4}\u{1f}");
    until("variant stored", || {
        st.static_cache.get(&key).fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let stale = fetch(&st, "/ja4", &chrome).await;
    assert_eq!(
        (stale.cache.as_str(), stale.body.as_str()),
        ("REVALIDATED", mine.as_str()),
        "refreshed in the background without the header it is keyed on"
    );
    let after = fetch(&st, "/ja4", &chrome).await;
    assert_eq!(
        (after.cache.as_str(), after.body.as_str()),
        ("HIT", mine.as_str())
    );
    let requests = o.requests.lock().unwrap();
    assert_eq!(requests.len(), 2, "the miss and the revalidation");
    for sent in requests.iter() {
        assert_eq!(
            sent.get("x-client-tls-ja4").map(|v| v.to_str().unwrap()),
            Some(JA4),
            "the origin was asked without the fingerprint"
        );
    }
}

/// A `304` that answered one client alone (it sets a cookie) makes that client's answer: it says
/// `private` whatever the 304 or the entry said, and carries the 304's `Set-Cookie`. It went out
/// with the entry's `public, max-age=1` (or the 304's `public, max-age=60`), alice's `X-Session`,
/// and no cookie: the session the origin rotated never reached her, and a shared cache downstream
/// that does not keep a response with a `Set-Cookie` kept this one. The next client gets neither.
#[tokio::test]
async fn a_304_for_one_client_says_private_and_brings_its_set_cookie() {
    for (n, cc_304, expected) in [
        (0, None, "private, max-age=1"),
        (1, Some(""), "private, max-age=1"),
        (2, Some("public, max-age=60"), "private, max-age=60"),
    ] {
        let uri = format!("/rv-one{n}");
        let (o, st) = origin_and_state("public, max-age=1").await;
        *o.cache_control_304.lock().unwrap() = cc_304.map(str::to_string);
        *o.extra_304.lock().unwrap() = vec![("set-cookie", "sid=rotated"), ("x-session", "alice")];
        fetch(&st, &uri, &[]).await;
        stored_then_stale(&st, &uri).await;
        let hers = fetch(&st, &uri, &[("cookie", "sid=alice")]).await;
        assert_eq!(
            (hers.cache.as_str(), hers.body.as_str()),
            ("REVALIDATED", "v1")
        );
        assert_eq!(
            header(&hers, "cache-control").as_deref(),
            Some(expected),
            "304 Cache-Control {cc_304:?}"
        );
        assert_eq!(
            header(&hers, "set-cookie").as_deref(),
            Some("sid=rotated"),
            "304 Cache-Control {cc_304:?}: the 304's cookie"
        );
        assert_eq!(header(&hers, "x-session").as_deref(), Some("alice"));
        o.extra_304.lock().unwrap().clear();
        *o.cache_control_304.lock().unwrap() = None;
        let next = fetch(&st, &uri, &[]).await;
        assert_eq!(
            (
                next.cache.as_str(),
                header(&next, "set-cookie"),
                header(&next, "x-session"),
                header(&next, "cache-control").as_deref()
            ),
            ("REVALIDATED", None, None, Some("public, max-age=1")),
            "304 Cache-Control {cc_304:?}: the next client"
        );
    }
}

const OLD_LM: &str = "Thu, 01 Jan 2026 00:00:00 GMT";
const NEW_LM: &str = "Fri, 02 Jan 2026 00:00:00 GMT";

/// Preconditions and a range of a client's own, sent with a request that finds a stale entry.
fn clients_own_preconditions(if_none_match: &'static str) -> [(&'static str, &'static str); 5] {
    [
        ("if-none-match", if_none_match),
        ("if-match", "*"),
        ("if-unmodified-since", NEW_LM),
        ("if-range", OLD_LM),
        ("range", "bytes=0-0"),
    ]
}

/// What the origin was sent on its `n`-th request: zion's `If-Modified-Since` and none of the
/// client's own preconditions or its range.
fn assert_only_the_stored_validator(o: &Origin, n: usize) {
    let sent = o.requests.lock().unwrap()[n].clone();
    assert_eq!(
        sent.get("if-modified-since").map(|v| v.to_str().unwrap()),
        Some(OLD_LM),
        "the stored Last-Modified"
    );
    for name in [
        "if-none-match",
        "if-match",
        "if-unmodified-since",
        "if-range",
        "range",
    ] {
        assert_eq!(
            sent.get(name),
            None,
            "the revalidation sent the client's {name}"
        );
    }
}

/// An origin that sends `Last-Modified` and no `ETag`, its entry stored, stale, and the origin's
/// content changed since.
async fn changed_since_stored(cc: &str, uri: &str) -> (Arc<Origin>, Arc<AppState>) {
    let (o, st) = origin_and_state(cc).await;
    *o.body.lock().unwrap() = ("v1".into(), String::new());
    *o.last_modified.lock().unwrap() = OLD_LM.into();
    let miss = fetch(&st, uri, &[]).await;
    assert_eq!((miss.cache.as_str(), miss.body.as_str()), ("MISS", "v1"));
    stored_then_stale(&st, uri).await;
    *o.body.lock().unwrap() = ("v2".into(), String::new());
    *o.last_modified.lock().unwrap() = NEW_LM.into();
    (o, st)
}

/// A foreground revalidation sends the validators zion stored and none of the client's own. For
/// an entry with only `Last-Modified`, the client's `If-None-Match: *` went to the origin beside
/// zion's `If-Modified-Since`; the origin evaluates `If-None-Match` first (RFC 9110 §13.2.2), `*`
/// matches whatever it has, and its `304` renewed the entry the origin had since changed. Every
/// client was then served the old version as a `HIT`, again at each expiry the request was
/// repeated.
#[tokio::test]
async fn a_revalidation_sends_the_stored_validators_and_not_the_clients() {
    let (o, st) = changed_since_stored("public, max-age=1", "/lm-only").await;
    let theirs = fetch(&st, "/lm-only", &clients_own_preconditions("*")).await;
    assert_eq!(
        (theirs.status, theirs.body.as_str()),
        (200, "v2"),
        "the client's If-None-Match renewed the old entry ({})",
        theirs.cache
    );
    assert_only_the_stored_validator(&o, 1);
    until("the new version stored", || {
        st.static_cache
            .get("/lm-only\u{1f}\u{1c}")
            .fresh()
            .is_some_and(|h| h.body == "v2")
    })
    .await;
}

/// The stale-while-revalidate refresh does the same.
#[tokio::test]
async fn a_background_refresh_sends_the_stored_validators_and_not_the_clients() {
    let (o, st) = changed_since_stored(
        "public, max-age=1, stale-while-revalidate=30",
        "/swr-lm-only",
    )
    .await;
    let stale = fetch(&st, "/swr-lm-only", &clients_own_preconditions("\"nope\"")).await;
    assert_eq!(
        (stale.cache.as_str(), stale.body.as_str()),
        ("STALE-WHILE-REVALIDATE", "v1")
    );
    until("the new version stored", || {
        st.static_cache
            .get("/swr-lm-only\u{1f}\u{1c}")
            .fresh()
            .is_some_and(|h| h.body == "v2")
    })
    .await;
    assert_only_the_stored_validator(&o, 1);
}

/// A request that finds an entry stale while another one is revalidating it waits for that
/// revalidation, then is answered from the entry it renewed: with the body, as the plain `GET`
/// it is.
#[tokio::test]
async fn a_request_that_waited_on_a_revalidation_gets_the_body() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    fetch(&st, "/wait-rv", &[]).await;
    stored_then_stale(&st, "/wait-rv").await;
    o.delay_ms.store(300, Ordering::Relaxed);
    let first = {
        let st = st.clone();
        tokio::spawn(async move { fetch(&st, "/wait-rv", &[]).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = fetch(&st, "/wait-rv", &[]).await;
    let first = first.await.unwrap();
    assert_eq!(
        (first.status, first.cache.as_str(), first.body.as_str()),
        (200, "REVALIDATED", "v1")
    );
    assert_eq!(
        (second.status, second.body.as_str()),
        (200, "v1"),
        "the waiter was answered {} {}",
        second.status,
        second.cache
    );
    assert_eq!(o.count(), 2, "one revalidation");
}

// ── a 304 renews an entry only under the Vary it was filed under ──

/// Alice and bob, behind an origin that knows them by `X-User`. `X-Auth-Subject` would be the
/// auth gate's, which this in-process state does not run (it needs `--features auth`), and the
/// pipeline drops a client's own copy: `X-User` reaches the origin and stands in for it. What zion
/// decides on is the names in `Vary`, not which header they are.
const ALICE: [(&str, &str); 2] = [("authorization", "Bearer alice"), ("x-user", "alice")];
const BOB: [(&str, &str); 2] = [("authorization", "Bearer bob"), ("x-user", "bob")];

/// `uri` stored from a `200` (under `key`) and then stale; the origin is then redeployed to answer
/// per user by `X-User` ([`Origin::per_user`]), `public, max-age=60`, with the same ETag.
async fn stored_then_redeployed(
    o: &Origin,
    st: &Arc<AppState>,
    uri: &str,
    key: &str,
    client: &[(&str, &str)],
) {
    let miss = fetch(st, uri, client).await;
    assert_eq!(miss.cache, "MISS");
    until("entry stored", || {
        st.static_cache.get(key).fresh().is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1300)).await;
    *o.per_user.lock().unwrap() = Some("x-user");
    *o.cache_control.lock().unwrap() = "public, max-age=60".into();
}

fn is_miss(st: &Arc<AppState>, key: &str) -> bool {
    matches!(st.static_cache.get(key), crate::cache::CacheLookup::Miss)
}

fn filed_under(st: &Arc<AppState>, primary: &str) -> Option<Vec<String>> {
    st.static_cache
        .vary
        .get(primary)
        .map(|rule| rule.names.clone())
}

/// An entry was stored from a `200` with no `Vary`; the origin is redeployed and now answers per
/// user, `Vary: X-User`. Alice's revalidation gets a `304`, `public, max-age=60`, with that `Vary`
/// and her `X-Account`: the answer for her, not for the key the entry is filed under, which every
/// user's request finds. It renewed the entry there, and bob was served her `X-Account` as a
/// `HIT`. Now she is answered with it alone, the entry is taken out, and bob's request is a miss
/// whose `200` files the response under the new `Vary`.
#[tokio::test]
async fn a_304_that_varies_on_what_the_entry_is_not_filed_under_does_not_renew_it() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    let key = "/vary-moved\u{1f}\u{1c}";
    stored_then_redeployed(&o, &st, "/vary-moved", key, &[]).await;
    let hers = fetch(&st, "/vary-moved", &ALICE).await;
    assert_eq!(
        (hers.cache.as_str(), hers.body.as_str()),
        ("REVALIDATED", "v1")
    );
    assert_eq!(
        header(&hers, "x-account").as_deref(),
        Some("alice"),
        "her own answer"
    );
    let bobs = fetch(&st, "/vary-moved", &BOB).await;
    assert_eq!(
        header(&bobs, "x-account").as_deref(),
        Some("bob"),
        "bob's answer ({}) is not his own",
        bobs.cache
    );
    assert_eq!(
        (bobs.cache.as_str(), o.count()),
        ("MISS", 3),
        "the stale entry stayed under the old key"
    );
    assert_eq!(
        header(&hers, "cache-control").as_deref(),
        Some("private, max-age=60"),
        "her answer is labelled for a shared cache to keep"
    );
    assert_eq!(
        filed_under(&st, key),
        Some(vec!["x-user".to_string()]),
        "bob's 200 files the response under the new Vary"
    );
    let bobs_variant = "/vary-moved\u{1f}\u{1c}\u{1e}x-user=bob\u{1f}";
    until("bob's variant stored", || {
        st.static_cache.get(bobs_variant).fresh().is_some()
    })
    .await;
    let again = fetch(&st, "/vary-moved", &BOB).await;
    assert_eq!(
        (
            again.cache.as_str(),
            header(&again, "x-account").as_deref(),
            o.count()
        ),
        ("HIT", Some("bob"), 3)
    );
}

/// The same for a variant: the entry is filed under `Vary: Accept-Language`, and the origin's `304`
/// adds `X-User` to it.
#[tokio::test]
async fn a_304_that_adds_a_name_to_vary_does_not_renew_the_variant() {
    let (o, st) = origin_and_state("public, max-age=1").await;
    *o.vary_on.lock().unwrap() = Some("accept-language");
    let de = ("accept-language", "de");
    let key = "/vary-grew\u{1f}\u{1c}\u{1e}accept-language=de\u{1f}";
    stored_then_redeployed(&o, &st, "/vary-grew", key, &[de]).await;
    let hers = fetch(&st, "/vary-grew", &[de, ALICE[0], ALICE[1]]).await;
    assert_eq!(
        (
            hers.cache.as_str(),
            hers.body.as_str(),
            header(&hers, "x-account").as_deref()
        ),
        ("REVALIDATED", "v1 for de", Some("alice"))
    );
    let bobs = fetch(&st, "/vary-grew", &[de, BOB[0], BOB[1]]).await;
    assert_eq!(
        header(&bobs, "x-account").as_deref(),
        Some("bob"),
        "bob's answer ({}) is not his own",
        bobs.cache
    );
    assert_eq!(
        (bobs.cache.as_str(), bobs.body.as_str(), o.count()),
        ("MISS", "v1 for de", 3)
    );
    assert!(is_miss(&st, key), "the variant stayed under its old key");
    assert_eq!(
        header(&hers, "cache-control").as_deref(),
        Some("private, max-age=60")
    );
    assert_eq!(
        filed_under(&st, "/vary-grew\u{1f}\u{1c}"),
        Some(vec!["accept-language".to_string(), "x-user".to_string()])
    );
}

/// The stale-while-revalidate refresh is held to the same rule. Alice's request finds the entry in
/// its window; the refresh goes with her `X-User` (it leaves out only what `swr_drops` names), and
/// the origin answers it with a public `304` that says `Vary: X-User` and carries her `X-Account`.
/// It renewed the entry under the key that does not vary, and bob was served her `X-Account` as a
/// `HIT`. A `200` that says so was not stored, but the stale entry was served again for the rest of
/// the window. Both now renew nothing and take the stale entry out.
#[tokio::test]
async fn a_background_refresh_that_varies_on_what_the_entry_is_not_filed_under_renews_nothing() {
    // A 304.
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    let key = "/swr-vary-moved\u{1f}\u{1c}";
    stored_then_redeployed(&o, &st, "/swr-vary-moved", key, &[]).await;
    let hers = fetch(&st, "/swr-vary-moved", &ALICE).await;
    assert_eq!(
        (hers.cache.as_str(), hers.body.as_str()),
        ("STALE-WHILE-REVALIDATE", "v1")
    );
    refresh_over(&o, &st, key, 2).await;
    {
        let refresh = o.requests.lock().unwrap()[1].clone();
        let sent = |name: &str| refresh.get(name).map(|v| v.to_str().unwrap().to_string());
        assert_eq!(
            (sent("x-user").as_deref(), sent("if-none-match").as_deref()),
            (Some("alice"), Some("\"e1\"")),
            "a revalidation for alice"
        );
    }
    let bobs = fetch(&st, "/swr-vary-moved", &BOB).await;
    assert_eq!(
        header(&bobs, "x-account").as_deref(),
        Some("bob"),
        "bob's answer ({}) is not his own",
        bobs.cache
    );
    assert_eq!(
        (bobs.cache.as_str(), o.count()),
        ("MISS", 3),
        "the stale entry stayed under the old key"
    );

    // A 200 (the content changed as well).
    let (o, st) = origin_and_state("public, max-age=1, stale-while-revalidate=30").await;
    let key = "/swr-vary-moved-200\u{1f}\u{1c}";
    stored_then_redeployed(&o, &st, "/swr-vary-moved-200", key, &[]).await;
    *o.body.lock().unwrap() = ("v2".into(), "\"e2\"".into());
    let hers = fetch(&st, "/swr-vary-moved-200", &ALICE).await;
    assert_eq!(hers.cache, "STALE-WHILE-REVALIDATE");
    refresh_over(&o, &st, key, 2).await;
    let bobs = fetch(&st, "/swr-vary-moved-200", &BOB).await;
    assert_eq!(
        (
            bobs.cache.as_str(),
            bobs.body.as_str(),
            header(&bobs, "x-account").as_deref()
        ),
        ("MISS", "v2", Some("bob")),
        "bob's answer is not his own"
    );
}

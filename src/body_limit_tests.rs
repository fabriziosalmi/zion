//! `max_body_mb` on a route without a WAF and `require_content_length` (#693), end to end: the
//! real `process_request` in front of an in-process HTTP/1.1 origin that records the framing
//! headers it was sent and every body byte it received, so a body that went past the cap, or
//! reached the upstream chunked, is visible at the upstream and not only in the status code.

use crate::config::ZionConfig;
use crate::dispatch::process_request;
use crate::http_util::{BoxError, ReqBody};
use crate::state::AppState;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MIB: usize = 1_048_576;

/// What the origin saw of the last request.
#[derive(Default)]
struct Origin {
    /// Requests that reached the origin.
    hits: AtomicUsize,
    /// Body bytes of the last request, counted as they arrived.
    received: AtomicUsize,
    /// The last request's body ended cleanly (`Some(true)`) or broke (`Some(false)`).
    complete: Mutex<Option<bool>>,
    /// `Content-Length` and `Transfer-Encoding` of the last request.
    content_length: Mutex<Option<String>>,
    transfer_encoding: Mutex<Option<String>>,
    /// Set once the origin has finished reading the last body.
    done: AtomicBool,
}

impl Origin {
    /// Wait until the origin has finished with the body it was sent.
    async fn settled(&self) {
        for _ in 0..200 {
            if self.done.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the origin never finished reading the body");
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
                        o.hits.fetch_add(1, Ordering::Relaxed);
                        o.done.store(false, Ordering::Release);
                        o.received.store(0, Ordering::Relaxed);
                        let header = |n: hyper::header::HeaderName| {
                            req.headers()
                                .get(n)
                                .map(|v| v.to_str().unwrap_or("?").to_string())
                        };
                        *o.content_length.lock().unwrap() = header(hyper::header::CONTENT_LENGTH);
                        *o.transfer_encoding.lock().unwrap() =
                            header(hyper::header::TRANSFER_ENCODING);
                        let mut body = req.into_body();
                        let complete = loop {
                            match body.frame().await {
                                Some(Ok(f)) => {
                                    if let Ok(d) = f.into_data() {
                                        o.received.fetch_add(d.len(), Ordering::Relaxed);
                                    }
                                }
                                Some(Err(_)) => break false,
                                None => break true,
                            }
                        };
                        *o.complete.lock().unwrap() = Some(complete);
                        o.done.store(true, Ordering::Release);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            Bytes::from_static(b"ok"),
                        )))
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

/// Routes to the origin on `port`:
/// - `/capped/`: `max_body_mb = 1`, no WAF;
/// - `/framed/`: `require_content_length`, no cap of its own;
/// - `/framed-capped/`: both;
/// - `/waf-framed/`: `waf = true` and `require_content_length`;
/// - `/sse-capped/`: `mode = "sse_stream"`, `max_body_mb = 1`;
/// - `/cached-capped/`: a `static_cache` route, `max_body_mb = 1`;
/// - `/pool-capped/`: two upstreams (failover buffers the body), `max_body_mb = 1`;
/// - `/open/`: neither.
fn state(port: u16) -> Arc<AppState> {
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

[upstream.p]
urls = ["http://127.0.0.1:{port}", "http://localhost:{port}"]

[cache_profile.c]
ttl_seconds = 60
max_entries = 10

[[route]]
path = "/capped/{{*rest}}"
upstream = "o"
max_body_mb = 1

[[route]]
path = "/framed/{{*rest}}"
upstream = "o"
require_content_length = true

[[route]]
path = "/framed-capped/{{*rest}}"
upstream = "o"
max_body_mb = 1
require_content_length = true

[[route]]
path = "/waf-framed/{{*rest}}"
upstream = "o"
waf = true
require_content_length = true

[[route]]
path = "/sse-capped/{{*rest}}"
upstream = "o"
mode = "sse_stream"
max_body_mb = 1

[[route]]
path = "/cached-capped/{{*rest}}"
upstream = "o"
mode = "static_cache"
cache_profile = "c"
max_body_mb = 1

[[route]]
path = "/pool-capped/{{*rest}}"
upstream = "p"
max_body_mb = 1

[[route]]
path = "/open/{{*rest}}"
upstream = "o"
"#
    );
    AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
}

async fn rig() -> (Arc<Origin>, Arc<AppState>) {
    let o = Arc::new(Origin::default());
    let port = start_origin(o.clone()).await;
    (o, state(port))
}

/// A body of `len` bytes in 64 KiB frames with no declared length: what a chunked HTTP/1.1
/// upload, or an HTTP/2 one without `Content-Length`, looks like to the pipeline.
fn chunked(len: usize) -> ReqBody {
    let frames: Vec<Result<Frame<Bytes>, BoxError>> = (0..len.div_ceil(65536))
        .map(|i| {
            Ok(Frame::data(Bytes::from(vec![
                b'x';
                65536.min(len - i * 65536)
            ])))
        })
        .collect();
    StreamBody::new(tokio_stream::iter(frames)).boxed()
}

/// A body of `len` bytes whose length is known, as with `Content-Length`.
fn sized(len: usize) -> ReqBody {
    Full::new(Bytes::from(vec![b'x'; len]))
        .map_err(|never| match never {})
        .boxed()
}

async fn post(st: &Arc<AppState>, path: &str, headers: &[(&str, &str)], body: ReqBody) -> u16 {
    let mut b = Request::post(format!("https://zion.test{path}")).header("host", "zion.test");
    if !headers.iter().any(|(k, _)| *k == "content-type") {
        b = b.header("content-type", "application/octet-stream");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let resp = process_request(
        b.body(body).unwrap(),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    resp.status().as_u16()
}

// ── max_body_mb on a route without a WAF ─────────────────────────────────

#[tokio::test]
async fn a_declared_length_past_the_cap_is_refused_before_the_upstream() {
    let (o, st) = rig().await;
    assert_eq!(post(&st, "/capped/a", &[], sized(MIB + 1)).await, 413);
    // a length claimed only by the header (HTTP/3) counts too
    let claimed = MIB + 1;
    assert_eq!(
        post(
            &st,
            "/capped/a",
            &[("content-length", &claimed.to_string())],
            chunked(10)
        )
        .await,
        413
    );
    assert_eq!(
        o.hits.load(Ordering::Relaxed),
        0,
        "nothing reached the upstream"
    );
}

#[tokio::test]
async fn a_body_within_the_cap_reaches_the_upstream_whole() {
    let (o, st) = rig().await;
    assert_eq!(post(&st, "/capped/a", &[], sized(MIB)).await, 200);
    o.settled().await;
    assert_eq!(o.received.load(Ordering::Relaxed), MIB);
    assert_eq!(post(&st, "/capped/a", &[], chunked(MIB)).await, 200);
    o.settled().await;
    assert_eq!(o.received.load(Ordering::Relaxed), MIB);
    assert_eq!(*o.complete.lock().unwrap(), Some(true));
}

#[tokio::test]
async fn a_streamed_body_past_the_cap_is_cut_off_and_refused() {
    let (o, st) = rig().await;
    assert_eq!(post(&st, "/capped/a", &[], chunked(3 * MIB)).await, 413);
    o.settled().await;
    assert!(
        o.received.load(Ordering::Relaxed) <= MIB,
        "the upstream got {} bytes, past the 1 MiB cap",
        o.received.load(Ordering::Relaxed)
    );
    assert_eq!(
        *o.complete.lock().unwrap(),
        Some(false),
        "the upstream must see a broken body, not a short one that looks whole"
    );
}

#[tokio::test]
async fn every_forwarding_path_applies_the_cap() {
    let (o, st) = rig().await;
    for path in ["/sse-capped/a", "/cached-capped/a", "/pool-capped/a"] {
        assert_eq!(post(&st, path, &[], sized(MIB + 1)).await, 413, "{path}");
        assert_eq!(post(&st, path, &[], chunked(3 * MIB)).await, 413, "{path}");
        assert_eq!(post(&st, path, &[], chunked(1024)).await, 200, "{path}");
    }
    let _ = o;
}

#[tokio::test]
async fn a_route_without_a_cap_still_streams_any_size() {
    let (o, st) = rig().await;
    assert_eq!(post(&st, "/open/a", &[], chunked(3 * MIB)).await, 200);
    o.settled().await;
    assert_eq!(o.received.load(Ordering::Relaxed), 3 * MIB);
    assert_eq!(*o.complete.lock().unwrap(), Some(true));
}

// ── require_content_length ───────────────────────────────────────────────

#[tokio::test]
async fn a_body_without_a_length_reaches_the_upstream_with_one() {
    let (o, st) = rig().await;
    let len = 100 * 1024;
    assert_eq!(
        post(
            &st,
            "/framed/a",
            &[("transfer-encoding", "chunked")],
            chunked(len)
        )
        .await,
        200
    );
    o.settled().await;
    assert_eq!(*o.content_length.lock().unwrap(), Some(len.to_string()));
    assert_eq!(*o.transfer_encoding.lock().unwrap(), None);
    assert_eq!(o.received.load(Ordering::Relaxed), len);
    // on a route that does not ask for it, the same upload goes out chunked
    assert_eq!(post(&st, "/open/a", &[], chunked(len)).await, 200);
    o.settled().await;
    assert_eq!(*o.content_length.lock().unwrap(), None);
    assert_eq!(*o.transfer_encoding.lock().unwrap(), Some("chunked".into()));
}

#[tokio::test]
async fn reading_a_body_whole_is_bounded_by_the_cap() {
    let (o, st) = rig().await;
    // the route's own max_body_mb
    assert_eq!(
        post(&st, "/framed-capped/a", &[], chunked(MIB + 1)).await,
        413
    );
    // no max_body_mb: 10 MiB
    assert_eq!(
        post(&st, "/framed/a", &[], chunked(10 * MIB + 1)).await,
        413
    );
    assert_eq!(
        o.hits.load(Ordering::Relaxed),
        0,
        "nothing reached the upstream"
    );
    assert_eq!(post(&st, "/framed/a", &[], chunked(10 * MIB)).await, 200);
    o.settled().await;
    assert_eq!(
        *o.content_length.lock().unwrap(),
        Some((10 * MIB).to_string())
    );
}

#[tokio::test]
async fn a_body_the_waf_has_read_goes_on_with_its_length() {
    let (o, st) = rig().await;
    let json = br#"{"name":"zion"}"#;
    let frames: Vec<Result<Frame<Bytes>, BoxError>> = vec![
        Ok(Frame::data(Bytes::from_static(&json[..6]))),
        Ok(Frame::data(Bytes::from_static(&json[6..]))),
    ];
    let body = StreamBody::new(tokio_stream::iter(frames)).boxed();
    assert_eq!(
        post(
            &st,
            "/waf-framed/a",
            &[("content-type", "application/json")],
            body
        )
        .await,
        200
    );
    o.settled().await;
    assert_eq!(
        *o.content_length.lock().unwrap(),
        Some(json.len().to_string())
    );
    assert_eq!(*o.transfer_encoding.lock().unwrap(), None);
}

#[tokio::test]
async fn a_request_without_a_body_is_left_alone() {
    let (o, st) = rig().await;
    let resp = process_request(
        Request::get("https://zion.test/framed-capped/a")
            .header("host", "zion.test")
            .body(sized(0))
            .unwrap(),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    o.settled().await;
    assert_eq!(*o.content_length.lock().unwrap(), None);
    assert_eq!(*o.transfer_encoding.lock().unwrap(), None);
}

// ── a body the client breaks on the way ──────────────────────────────────

/// `len` bytes in 64 KiB frames, then an error: what the pipeline sees of an upload whose client
/// reset the stream or the connection mid-body.
fn broken_after(len: usize) -> ReqBody {
    let mut frames: Vec<Result<Frame<Bytes>, BoxError>> = (0..len.div_ceil(65536))
        .map(|i| {
            Ok(Frame::data(Bytes::from(vec![
                b'x';
                65536.min(len - i * 65536)
            ])))
        })
        .collect();
    frames.push(Err("connection reset by the client".into()));
    StreamBody::new(tokio_stream::iter(frames)).boxed()
}

#[tokio::test]
async fn a_body_the_client_breaks_is_the_clients_fault_not_a_502() {
    let (o, st) = rig().await;
    for path in ["/open/a", "/capped/a", "/sse-capped/a"] {
        *o.complete.lock().unwrap() = None;
        assert_eq!(
            post(&st, path, &[], broken_after(256 * 1024)).await,
            400,
            "{path}: the client broke its body; the upstream did not fail"
        );
        // The request is aborted on its way: the origin may see it break or not see it at all
        // (the abort can come before it has read the head), never as a whole body.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_ne!(
            *o.complete.lock().unwrap(),
            Some(true),
            "{path}: the upstream must not see a short body that looks whole"
        );
    }
}

/// A route whose single upstream has a circuit breaker that opens on 5 failures in 10 s.
fn guarded_state(port: u16) -> Arc<AppState> {
    guarded_state_with(port, "")
}

/// [`guarded_state`] with more settings for the upstream, such as `request_timeout_ms`.
fn guarded_state_with(port: u16, upstream_extra: &str) -> Arc<AppState> {
    let toml = format!(
        r#"
[server]
listen_http = "127.0.0.1:0"
listen_https = "127.0.0.1:0"

[tls]
cert_path = "/c"
key_path = "/k"

[upstream.g]
url = "http://127.0.0.1:{port}"
circuit_breaker = {{ error_rate_pct = 50, min_requests = 5, window_secs = 10, open_secs = 30 }}
{upstream_extra}

[[route]]
path = "/{{*rest}}"
upstream = "g"
"#
    );
    AppState::for_tests(&toml::from_str::<ZionConfig>(&toml).expect("config parses"))
}

async fn get(st: &Arc<AppState>, path: &str) -> u16 {
    process_request(
        Request::get(format!("https://zion.test{path}"))
            .header("host", "zion.test")
            .body(sized(0))
            .unwrap(),
        st.clone(),
        "203.0.113.9:1".parse::<SocketAddr>().unwrap(),
        false,
    )
    .await
    .unwrap()
    .status()
    .as_u16()
}

#[tokio::test]
async fn uploads_the_client_breaks_do_not_open_a_healthy_upstreams_circuit() {
    let o = Arc::new(Origin::default());
    let st = guarded_state(start_origin(o.clone()).await);
    for i in 1..=6 {
        assert_eq!(
            post(&st, "/upload", &[], broken_after(128 * 1024)).await,
            400,
            "broken upload {i}"
        );
    }
    assert_eq!(
        get(&st, "/").await,
        200,
        "the upstream is healthy: its circuit must still be closed"
    );
}

#[tokio::test]
async fn a_dead_upstream_still_opens_its_circuit() {
    // The control: the same breaker does open on real upstream failures.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let st = guarded_state(dead);
    for _ in 0..5 {
        // A refused connection is a 502; Windows retries the connect to a closed local port
        // until the connect timeout, a 504. The breaker counts either.
        let status = post(&st, "/upload", &[], chunked(1024)).await;
        assert!(crate::breaker::is_failure(status), "{status}");
    }
    assert_eq!(get(&st, "/").await, 503, "five refused connections open it");
}

// ── a client too slow to send its body ───────────────────────────────────

/// A body sent at the client's pace: `frames` frames of 16 KiB, `gap` apart, then its end.
fn paced(frames: usize, gap: Duration) -> ReqBody {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
    tokio::spawn(async move {
        for _ in 0..frames {
            tokio::time::sleep(gap).await;
            if tx
                .send(Ok(Frame::data(Bytes::from(vec![b'x'; 16 * 1024]))))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)).boxed()
}

#[tokio::test]
async fn a_steady_slow_upload_completes_and_does_not_open_the_circuit() {
    // #714: `request_timeout_ms` bounds time with NO body progress, not the whole upload. A
    // body slower than the deadline but always moving is not cut: it completes (200), and a
    // healthy upstream's circuit stays closed.
    let o = Arc::new(Origin::default());
    let st = guarded_state_with(start_origin(o.clone()).await, "request_timeout_ms = 300");
    // ~1 s of body in 50 ms steps against a 300 ms deadline: every step is progress.
    let uploads: Vec<_> = (0..6)
        .map(|_| {
            let st = st.clone();
            tokio::spawn(async move {
                post(&st, "/upload", &[], paced(20, Duration::from_millis(50))).await
            })
        })
        .collect();
    for (i, u) in uploads.into_iter().enumerate() {
        assert_eq!(u.await.unwrap(), 200, "steady upload {}", i + 1);
    }
    assert_eq!(
        get(&st, "/").await,
        200,
        "the upstream is healthy: its circuit must still be closed"
    );
}

#[tokio::test]
async fn a_client_that_stalls_past_the_deadline_is_a_408_and_does_not_open_the_circuit() {
    // A client that makes no progress for a whole `request_timeout_ms` window: the wait is the
    // client's (408, #713), and a healthy upstream's circuit stays closed — not a 504.
    let o = Arc::new(Origin::default());
    let st = guarded_state_with(start_origin(o.clone()).await, "request_timeout_ms = 300");
    // the first frame only after 600 ms, past the 300 ms deadline: zion is waiting on the client.
    let uploads: Vec<_> = (0..6)
        .map(|_| {
            let st = st.clone();
            tokio::spawn(async move {
                post(&st, "/upload", &[], paced(10, Duration::from_millis(600))).await
            })
        })
        .collect();
    for (i, u) in uploads.into_iter().enumerate() {
        assert_eq!(u.await.unwrap(), 408, "stalled upload {}", i + 1);
    }
    assert_eq!(
        get(&st, "/").await,
        200,
        "the upstream is healthy: its circuit must still be closed"
    );
}

/// An upstream that reads the whole request and then never answers.
async fn start_silent_origin() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let svc =
                    hyper::service::service_fn(|req: Request<hyper::body::Incoming>| async move {
                        let _ = req.into_body().collect().await;
                        std::future::pending::<()>().await;
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
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
async fn an_upstream_too_slow_to_answer_a_whole_body_is_still_a_504_and_opens_the_circuit() {
    // The control: once the client has sent everything, the time is the upstream's.
    let st = guarded_state_with(start_silent_origin().await, "request_timeout_ms = 300");
    for i in 1..=5 {
        assert_eq!(
            post(&st, "/upload", &[], chunked(64 * 1024)).await,
            504,
            "upload {i}"
        );
    }
    assert_eq!(get(&st, "/").await, 503, "five timeouts open it");
}

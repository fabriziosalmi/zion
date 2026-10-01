// SPDX-License-Identifier: Apache-2.0
//! Connection draining on shutdown.
//!
//! On SIGTERM zion stops accepting and waits for open connections to finish. A keep-alive
//! connection that is *idle* never finishes by itself, so without more the wait lasted until
//! that connection's own idle timeout (up to the 30 s drain limit) on every deploy. [`serve`]
//! tells each connection to wind down as soon as the drain starts: HTTP/1 closes after the
//! response in flight (at once when idle) and HTTP/2 sends `GOAWAY`, lets its open streams
//! finish and then closes. A request that is already being served is never cut.

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use tokio::sync::watch;

static DRAINING: LazyLock<watch::Sender<bool>> = LazyLock::new(|| watch::channel(false).0);

/// Start draining: every connection served through [`serve`] begins to wind down.
pub fn begin() {
    DRAINING.send_replace(true);
}

/// A receiver for the process-wide drain signal.
pub fn subscribe() -> watch::Receiver<bool> {
    DRAINING.subscribe()
}

/// Drive `conn` to completion. When `rx` says the drain has begun, call `graceful` (hyper's
/// `graceful_shutdown`) and let the connection finish what it is doing.
pub async fn serve<C>(
    mut conn: Pin<&mut C>,
    mut rx: watch::Receiver<bool>,
    graceful: impl FnOnce(Pin<&mut C>),
) -> C::Output
where
    C: Future,
{
    tokio::select! {
        r = conn.as_mut() => return r,
        // `Err` only if the sender is gone, which a static never is: treat it as "drain" too
        _ = rx.wait_for(|draining| *draining) => {}
    }
    graceful(conn.as_mut());
    conn.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A hyper HTTP/1 server on a loopback socket whose connection is driven through `serve`
    /// with its own drain channel (the process-wide one is left alone). `delay` is how long
    /// each request takes. Returns the client socket, the drain trigger and the server task.
    async fn rig(
        delay: Duration,
    ) -> (
        tokio::net::TcpStream,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let conn = hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(s),
                service_fn(move |_req| async move {
                    tokio::time::sleep(delay).await;
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                        http_body_util::Full::new(bytes::Bytes::from_static(b"hello")),
                    ))
                }),
            );
            tokio::pin!(conn);
            let _ = serve(conn.as_mut(), rx, |c| c.graceful_shutdown()).await;
        });
        (
            tokio::net::TcpStream::connect(addr).await.unwrap(),
            tx,
            task,
        )
    }

    async fn read_response(c: &mut tokio::net::TcpStream) -> String {
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.windows(5).any(|w| w == b"hello") {
            let n = c.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "closed before the response: {:?}",
                String::from_utf8_lossy(&got)
            );
            got.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&got).into_owned()
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_ends_as_soon_as_the_drain_begins() {
        let (mut c, tx, task) = rig(Duration::ZERO).await;
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        read_response(&mut c).await; // served; the connection is now idle, kept alive
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !task.is_finished(),
            "an idle connection stays open until told otherwise"
        );
        let t = Instant::now();
        tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(t.elapsed() < Duration::from_secs(1));
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).await.unwrap(); // the client sees a clean close
    }

    #[tokio::test]
    async fn a_request_in_flight_when_the_drain_begins_is_finished_not_cut() {
        let (mut c, tx, task) = rig(Duration::from_millis(400)).await;
        c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send_replace(true); // mid-request
        let resp = read_response(&mut c).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(
            resp.to_ascii_lowercase().contains("connection: close"),
            "the connection is closed after it, not kept alive: {resp}"
        );
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn without_a_drain_the_connection_keeps_serving() {
        let (mut c, tx, task) = rig(Duration::ZERO).await;
        for _ in 0..3 {
            c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            read_response(&mut c).await;
        }
        assert!(!task.is_finished());
        drop(tx);
        c.shutdown().await.unwrap();
        task.abort();
    }
}

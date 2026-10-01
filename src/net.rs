// SPDX-License-Identifier: Apache-2.0
//! Network socket tuning and listener management.
//!
//! Platform-specific TCP optimizations extracted from main.rs for clarity.
//! All functions are zero-cost on non-Linux platforms.

use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Bind a TCP listener with SO_REUSEPORT (Linux) + SO_REUSEADDR.
/// SO_REUSEPORT allows multiple listeners on the same port — the kernel
/// distributes incoming connections across them. On single-listener setups
/// it still helps by allowing fast restart without TIME_WAIT issues.
/// Falls back gracefully on platforms without SO_REUSEPORT.
pub fn bind_with_reuseport(addr: SocketAddr) -> Result<TcpListener, Box<dyn std::error::Error>> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

    socket.set_reuse_address(true)?;
    set_reuseport(&socket);
    tune_listener(&socket);

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

#[cfg(target_os = "linux")]
fn set_reuseport(socket: &socket2::Socket) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: FFI call to setsockopt is safe because socket.as_raw_fd() yields a valid descriptor,
    // SO_REUSEPORT is passed correctly, and val pointer size matches socklen_t.
    unsafe {
        let val: i32 = 1;
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_reuseport(_socket: &socket2::Socket) {}

/// Linux TCP tuning on listener socket.
/// TCP_DEFER_ACCEPT: kernel holds connection until client sends data.
///   Eliminates wakeup on SYN-only (scanner/probe protection + less syscalls).
/// TCP_FASTOPEN: allow data in SYN packet for returning clients (0-RTT TCP).
///   Server-side queue of 256 pending TFO connections.
#[cfg(target_os = "linux")]
fn tune_listener(socket: &socket2::Socket) {
    use std::os::unix::io::AsRawFd;
    let fd = socket.as_raw_fd();
    // SAFETY: FFI setsockopt for TCP_DEFER_ACCEPT and TCP_FASTOPEN are safe as `fd` remains
    // valid, sizes are exact to socklen_t, and valid protocol/socket options are declared.
    unsafe {
        // TCP_DEFER_ACCEPT: wake process only when data arrives (not just SYN)
        let defer: i32 = 5;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_DEFER_ACCEPT,
            &defer as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        ) != 0
        {
            eprintln!("  warning: TCP_DEFER_ACCEPT unavailable (may be in restricted container)");
        }

        // (Historical: TCP_CORK was set on the listener with the intent
        //  that accepted connections would inherit it and batch
        //  HTTP-headers + body into a single packet. In practice the
        //  kernel inherits this flag onto every accepted socket, where
        //  it holds outbound writes for up to 200ms — the canonical
        //  TCP_CORK flush timeout. Empirically: pcap of a one-shot HTTP
        //  request to /healthz showed response data delayed by exactly
        //  202ms after the request ACK. We removed the cork; small
        //  responses now flush immediately. If a future bulk-write path
        //  wants cork semantics, set/unset it explicitly around the
        //  write boundaries — never on the listener.)

        // TCP_FASTOPEN: allow data in SYN for returning clients
        let tfo: i32 = 256;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &tfo as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        ) != 0
        {
            eprintln!("  warning: TCP_FASTOPEN unavailable");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn tune_listener(_socket: &socket2::Socket) {}

/// Linux TCP tuning on accepted connection socket.
/// TCP_QUICKACK: send ACK immediately (don't wait for delayed ACK timer).
///   Reduces RTT by ~40ms on each direction.
#[cfg(target_os = "linux")]
pub fn tune_accepted(stream: &tokio::net::TcpStream) {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: FFI setsockopt for TCP_QUICKACK and SO_BUSY_POLL is sound because `fd` is
    // obtained from a live `&TcpStream` (so it remains open for the duration of this call),
    // both option values are stack-local `i32`s with `socklen_t = sizeof::<i32>()`, and the
    // kernel silently no-ops unsupported options instead of corrupting state.
    unsafe {
        // TCP_QUICKACK: send ACK immediately (don't wait for delayed ACK timer)
        let val: i32 = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );

        // SO_BUSY_POLL: spin-poll the NIC queue for up to 50μs before sleeping.
        // Trades ~1% CPU for 5-15μs p99 latency reduction. Only effective on
        // NICs with NAPI support. Silently ignored if kernel doesn't support it.
        let busy_us: i32 = 50;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BUSY_POLL,
            &busy_us as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn tune_accepted(_stream: &tokio::net::TcpStream) {}

/// Default `TCP_USER_TIMEOUT`: off (the kernel's own limits). It is opt-in because the option
/// also bounds a *slow reader*, see [`set_user_timeout`].
pub const DEFAULT_TCP_USER_TIMEOUT_SECS: u64 = 0;

/// Bound, on an accepted connection, how long data may stay **unacknowledged, or buffered but
/// untransmitted because the peer's window is zero**, before the kernel drops the connection
/// (`TCP_USER_TIMEOUT`, Linux; `0` = the kernel's own limits, about 15 minutes of retransmissions).
///
/// Keepalive cannot do the first half: it only probes an *idle* connection, and a connection with
/// data in flight is never idle, so a peer that vanishes mid-response (power loss, a dropped NAT
/// mapping, a yanked cable) keeps its file descriptor, connection slot, per-IP slot and buffers
/// until the retransmission limit gives up. The second half is the price: a client that stops
/// reading for longer than the timeout (a paused player with a full buffer, a very slow reader)
/// is dropped too, which is why this is opt-in. Other platforms have no such option; no-op there.
pub fn set_user_timeout(stream: &tokio::net::TcpStream, secs: u64) {
    #[cfg(target_os = "linux")]
    if secs > 0 {
        let _ = socket2::SockRef::from(stream)
            .set_tcp_user_timeout(Some(std::time::Duration::from_secs(secs)));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (stream, secs);
}

/// Default idle time before the kernel starts probing a silent connection.
pub const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 60;
/// Seconds between probes, and probes sent before the connection is declared dead.
// Each option exists on only some platforms (retries: not Windows), so the constants are
// unused elsewhere.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
const KEEPALIVE_INTERVAL_SECS: u64 = 10;
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const KEEPALIVE_RETRIES: u32 = 3;

/// Turn on kernel TCP keepalive: after `idle_secs` of silence the kernel probes every
/// 10 s and gives up after 3 unanswered probes, so a client or upstream that vanished
/// without a FIN (power loss, a NAT that dropped the mapping, a pulled cable) frees its
/// file descriptor and connection slot in `idle_secs + 30` s instead of holding it until
/// an application timeout. `0` leaves keepalive off. Best effort: a failure to set an
/// option is ignored, the connection still works.
pub fn set_keepalive(stream: &tokio::net::TcpStream, idle_secs: u64) {
    if idle_secs == 0 {
        return;
    }
    let ka = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(idle_secs));
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let ka = ka.with_interval(std::time::Duration::from_secs(
        KEEPALIVE_INTERVAL_SECS.min(idle_secs),
    ));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let ka = ka.with_retries(KEEPALIVE_RETRIES);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&ka);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected loopback pair; returns the client side.
    async fn connected() -> tokio::net::TcpStream {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (c, _srv) = tokio::join!(tokio::net::TcpStream::connect(addr), l.accept());
        c.unwrap()
    }

    #[tokio::test]
    async fn keepalive_is_off_by_default_and_on_after_set() {
        let s = connected().await;
        assert!(
            !socket2::SockRef::from(&s).keepalive().unwrap(),
            "control: a fresh socket has none"
        );
        set_keepalive(&s, 45);
        let sock = socket2::SockRef::from(&s);
        assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must be on");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                sock.tcp_keepalive_time().unwrap(),
                std::time::Duration::from_secs(45)
            );
            assert_eq!(
                sock.tcp_keepalive_interval().unwrap(),
                std::time::Duration::from_secs(10)
            );
            assert_eq!(sock.tcp_keepalive_retries().unwrap(), 3);
        }
    }

    // Compiled and run everywhere (the README test count comes from runtime output, so a
    // `#[cfg]`-gated test would make the macOS and Linux counts differ); only the part that needs
    // the Linux option is gated.
    #[tokio::test]
    async fn the_user_timeout_is_set_and_zero_leaves_the_kernel_default() {
        let s = connected().await;
        #[cfg(target_os = "linux")]
        {
            let sock = socket2::SockRef::from(&s);
            assert_eq!(
                sock.tcp_user_timeout().unwrap(),
                None,
                "control: a fresh socket has none"
            );
            set_user_timeout(&s, 0);
            assert_eq!(
                sock.tcp_user_timeout().unwrap(),
                None,
                "0 = leave the kernel default"
            );
            set_user_timeout(&s, 90);
            assert_eq!(
                sock.tcp_user_timeout().unwrap(),
                Some(std::time::Duration::from_secs(90))
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            // no such option here: the call must simply leave the connection alone
            set_user_timeout(&s, 90);
            assert!(s.peer_addr().is_ok());
        }
    }

    #[tokio::test]
    async fn the_user_timeout_never_breaks_a_connection_on_any_platform() {
        // a no-op off Linux; on Linux it must not disturb an established connection
        let s = connected().await;
        set_user_timeout(&s, 120);
        set_user_timeout(&s, 0);
        assert!(s.peer_addr().is_ok());
    }

    #[tokio::test]
    async fn zero_leaves_keepalive_off() {
        let s = connected().await;
        set_keepalive(&s, 0);
        assert!(!socket2::SockRef::from(&s).keepalive().unwrap());
    }

    #[tokio::test]
    async fn a_short_idle_time_shortens_the_probe_interval_too() {
        let s = connected().await;
        set_keepalive(&s, 5);
        #[cfg(target_os = "linux")]
        assert_eq!(
            socket2::SockRef::from(&s).tcp_keepalive_interval().unwrap(),
            std::time::Duration::from_secs(5),
            "the interval never exceeds the idle time"
        );
        assert!(socket2::SockRef::from(&s).keepalive().unwrap());
    }

    #[tokio::test]
    async fn binds_ipv4_ephemeral_port() {
        let l = bind_with_reuseport("127.0.0.1:0".parse().unwrap()).expect("bind v4");
        let addr = l.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0, "kernel must assign a real port");
    }

    #[tokio::test]
    async fn binds_ipv6_ephemeral_port() {
        // The domain-selection branch: an IPv6 addr must bind on an IPv6 socket.
        // Skip gracefully where the host has no IPv6 loopback configured.
        match bind_with_reuseport("[::1]:0".parse().unwrap()) {
            Ok(l) => {
                let addr = l.local_addr().unwrap();
                assert!(addr.is_ipv6());
                assert_ne!(addr.port(), 0);
            }
            Err(e) => eprintln!("skipping IPv6 bind test (no ::1?): {e}"),
        }
    }

    #[tokio::test]
    async fn two_listeners_share_a_port_via_reuseport() {
        // SO_REUSEPORT lets a second listener bind the SAME concrete port.
        // Without it (SO_REUSEADDR alone) the second bind would EADDRINUSE.
        // Runtime-skip (not #[cfg]) on non-Linux so the test still compiles and
        // is *counted* everywhere — keeping the README test-count SSOT platform-
        // independent — while only asserting where set_reuseport actually runs.
        if !cfg!(target_os = "linux") {
            eprintln!("skipping: SO_REUSEPORT same-port bind is Linux-only");
            return;
        }
        let first = bind_with_reuseport("127.0.0.1:0".parse().unwrap()).expect("first bind");
        let port = first.local_addr().unwrap().port();
        let same: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let second = bind_with_reuseport(same);
        assert!(
            second.is_ok(),
            "SO_REUSEPORT must allow a second bind on the same port: {:?}",
            second.err()
        );
    }

    #[tokio::test]
    async fn tune_accepted_is_safe_on_a_live_stream() {
        // Exercises the accept-side tuning FFI on a real connected socket.
        let listener = bind_with_reuseport("127.0.0.1:0".parse().unwrap()).expect("bind");
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        // Must not panic on either end.
        tune_accepted(&server);
        tune_accepted(&client);
    }
}

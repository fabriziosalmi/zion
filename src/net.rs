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

#[cfg(test)]
mod tests {
    use super::*;

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

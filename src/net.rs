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
        ) != 0 {
            eprintln!("  warning: TCP_DEFER_ACCEPT unavailable (may be in restricted container)");
        }

        // TCP_FASTOPEN: allow data in SYN for returning clients
        let tfo: i32 = 256;
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_FASTOPEN,
            &tfo as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        ) != 0 {
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

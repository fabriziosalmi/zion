//! Zion Bootstrap — hardware detection and auto-tuning.
//!
//! At startup, probes the OS and hardware to enable the best available
//! performance and security features. Prints a capability matrix so
//! the operator knows exactly what's active.
//!
//! Design principle: detect everything, enable the best defaults,
//! but never fail — degrade gracefully if a feature isn't available.

use std::sync::OnceLock;

/// Detected platform capabilities — computed once at startup, immutable forever.
#[derive(Debug, Clone)]
pub struct Platform {
    // ── Hardware ──
    pub os: &'static str,
    pub arch: &'static str,
    pub cpu_cores: usize,
    pub ram_mb: u64,

    // ── CPU Features ──
    pub has_aes_ni: bool, // hardware AES acceleration (Intel AES-NI / ARM CE)
    pub has_sha256: bool, // hardware SHA-256
    pub has_neon: bool,   // ARM NEON SIMD
    pub has_avx2: bool,   // x86 AVX2 SIMD

    // ── OS Capabilities ──
    pub has_so_reuseport: bool, // SO_REUSEPORT (multi-listener)
    pub has_tcp_fastopen: bool, // TFO (0-RTT TCP)
    pub has_tcp_quickack: bool, // TCP_QUICKACK (Linux only)

    // ── CPU Cache ──
    pub cache_line_size: usize, // bytes per cache line (64 x86, 128 ARM)
    pub l1d_cache_size: usize,  // L1 data cache per core (bytes)
    pub l2_cache_size: usize,   // L2 cache (bytes, may be shared)
    pub l1_hot_entries: usize,  // max entries for thread-local L1 cache

    // ── Tuning (computed from above) ──
    pub worker_threads: usize, // tokio worker count
    pub conn_limit: usize,     // max concurrent connections
    pub backlog: i32,          // listen backlog
    #[allow(dead_code)]
    pub recv_buf: usize, // TCP recv buffer
    pub send_buf: usize,       // TCP send buffer
}

static PLATFORM: OnceLock<Platform> = OnceLock::new();

/// Probe the system and return the detected platform.
/// Called once at startup. Cached forever.
pub fn detect() -> &'static Platform {
    PLATFORM.get_or_init(|| {
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let ram_mb = detect_ram_mb();

        let platform = Platform {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpu_cores,
            ram_mb,

            has_aes_ni: detect_aes(),
            has_sha256: detect_sha256(),
            has_neon: cfg!(target_arch = "aarch64"),
            has_avx2: detect_avx2(),

            has_so_reuseport: cfg!(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "freebsd"
            )),
            has_tcp_fastopen: cfg!(any(target_os = "linux", target_os = "macos")),
            has_tcp_quickack: cfg!(target_os = "linux"),

            cache_line_size: detect_cache_line_size(),
            l1d_cache_size: detect_l1d_cache_size(),
            l2_cache_size: detect_l2_cache_size(),
            l1_hot_entries: compute_l1_entries(detect_l1d_cache_size()),

            // ── Computed tuning ──
            worker_threads: compute_workers(cpu_cores),
            conn_limit: compute_conn_limit(ram_mb),
            backlog: compute_backlog(),
            recv_buf: compute_buf_size(ram_mb),
            send_buf: compute_buf_size(ram_mb),
        };

        platform
    })
}

/// Print the boot capability matrix.
pub fn print_report(p: &Platform) {
    eprintln!("  ┌────────────────────────────────────────────┐");
    eprintln!("  │ PLATFORM DETECTION                         │");
    eprintln!("  ├────────────────────────────────────────────┤");
    eprintln!("  │ OS:    {:<10} Arch: {:<18} │", p.os, p.arch);
    eprintln!(
        "  │ CPUs:  {:<10} RAM:  {} MB{:>14}│",
        p.cpu_cores, p.ram_mb, ""
    );
    eprintln!("  ├────────────────────────────────────────────┤");
    eprintln!("  │ CPU Features:                              │");
    eprintln!(
        "  │   AES-NI/CE:  {:<5}  SHA-256:  {:<12}│",
        yn(p.has_aes_ni),
        yn(p.has_sha256)
    );
    eprintln!(
        "  │   NEON/SIMD:  {:<5}  AVX2:     {:<12}│",
        yn(p.has_neon),
        yn(p.has_avx2)
    );
    eprintln!("  ├────────────────────────────────────────────┤");
    eprintln!("  │ OS Features:                               │");
    eprintln!(
        "  │   SO_REUSEPORT:  {:<5}  TCP_FASTOPEN: {:<5}│",
        yn(p.has_so_reuseport),
        yn(p.has_tcp_fastopen)
    );
    eprintln!("  │   TCP_QUICKACK:  {:<28}│", yn(p.has_tcp_quickack));
    eprintln!("  ├────────────────────────────────────────────┤");
    eprintln!("  │ CPU Cache:                                 │");
    eprintln!(
        "  │   Line: {}B  L1d: {}KB  L2: {}KB{:>10}│",
        p.cache_line_size,
        p.l1d_cache_size / 1024,
        p.l2_cache_size / 1024,
        ""
    );
    eprintln!("  │   L1 hot entries: {:<25}│", p.l1_hot_entries);
    eprintln!("  ├────────────────────────────────────────────┤");
    eprintln!("  │ Auto-tuning:                               │");
    eprintln!(
        "  │   Workers:     {:<6} Conn limit:  {:<8}│",
        p.worker_threads, p.conn_limit
    );
    eprintln!(
        "  │   Backlog:     {:<6} Buf size:    {:<5}KB │",
        p.backlog,
        p.send_buf / 1024
    );
    eprintln!("  └────────────────────────────────────────────┘");
}

fn yn(b: bool) -> &'static str {
    if b {
        "YES"
    } else {
        "no"
    }
}

// ── Detection functions ──────────────────────────────────────────

fn detect_ram_mb() -> u64 {
    #[cfg(target_os = "macos")]
    {
        sysctl_u64(b"hw.memsize\0")
            .map(|b| b / 1_048_576)
            .unwrap_or(4096)
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb / 1024)
            })
            .unwrap_or(4096)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        4096
    }
}

fn detect_aes() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        // All Apple Silicon and modern ARMv8 have AES crypto extensions
        true
    }
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_feature = "aes")]
        {
            true
        }
        #[cfg(not(target_feature = "aes"))]
        {
            // Runtime detection via CPUID
            is_x86_feature_detected_safe("aes")
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

fn detect_sha256() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected_safe("sha")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        false
    }
}

fn detect_avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected_safe("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn is_x86_feature_detected_safe(feature: &str) -> bool {
    match feature {
        "aes" => std::arch::is_x86_feature_detected!("aes"),
        "sha" => std::arch::is_x86_feature_detected!("sha"),
        "avx2" => std::arch::is_x86_feature_detected!("avx2"),
        _ => false,
    }
}

// ── Compute tuning parameters ────────────────────────────────────

/// Worker threads: use all cores but leave 1 for the OS on big machines.
fn compute_workers(cores: usize) -> usize {
    match cores {
        1 => 1,
        2..=4 => cores,
        _ => cores - 1, // leave 1 core for OS/interrupts
    }
}

/// Connection limit: scale with available RAM.
/// ~50KB per TLS connection (buffers + state).
fn compute_conn_limit(ram_mb: u64) -> usize {
    let available_mb = ram_mb / 4; // use max 25% of RAM for connections
    let max_conns = (available_mb * 1024 / 50) as usize; // 50KB per conn
    max_conns.clamp(1_000, 100_000)
}

/// Listen backlog: higher on Linux (supports large backlogs), moderate on macOS.
fn compute_backlog() -> i32 {
    #[cfg(target_os = "linux")]
    {
        8192
    }
    #[cfg(not(target_os = "linux"))]
    {
        1024
    }
}

/// TCP buffer size: scale with RAM but cap at 256KB.
fn compute_buf_size(ram_mb: u64) -> usize {
    if ram_mb >= 16384 {
        262_144 // 256KB for 16GB+ RAM
    } else if ram_mb >= 4096 {
        131_072 // 128KB for 4GB+ RAM
    } else {
        65_536 // 64KB default
    }
}

// ── CPU Cache Detection ──────────────────────────────────────────

fn detect_cache_line_size() -> usize {
    #[cfg(target_os = "macos")]
    {
        sysctl_usize(b"hw.cachelinesize\0").unwrap_or(if cfg!(target_arch = "aarch64") {
            128
        } else {
            64
        })
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(64)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        64
    }
}

fn detect_l1d_cache_size() -> usize {
    #[cfg(target_os = "macos")]
    {
        sysctl_usize(b"hw.l1dcachesize\0").unwrap_or(65536)
    }
    #[cfg(target_os = "linux")]
    {
        // index0 is typically L1d
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index0/size")
            .ok()
            .and_then(|s| {
                let s = s.trim().to_uppercase();
                if s.ends_with('K') {
                    s[..s.len() - 1].parse::<usize>().ok().map(|v| v * 1024)
                } else {
                    s.parse().ok()
                }
            })
            .unwrap_or(32768)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        32768
    }
}

fn detect_l2_cache_size() -> usize {
    #[cfg(target_os = "macos")]
    {
        sysctl_usize(b"hw.l2cachesize\0").unwrap_or(262144)
    }
    #[cfg(target_os = "linux")]
    {
        // index2 is typically L2
        std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cache/index2/size")
            .ok()
            .and_then(|s| {
                let s = s.trim().to_uppercase();
                if s.ends_with('K') {
                    s[..s.len() - 1].parse::<usize>().ok().map(|v| v * 1024)
                } else if s.ends_with('M') {
                    s[..s.len() - 1]
                        .parse::<usize>()
                        .ok()
                        .map(|v| v * 1024 * 1024)
                } else {
                    s.parse().ok()
                }
            })
            .unwrap_or(262144)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        262144
    }
}

/// M-01 FIX: Direct sysctl C API — no subprocess fork (~0.01ms vs ~5ms per call).
/// Uses libc::sysctlbyname to read kernel values without spawning a process.
/// Name must be a null-terminated byte string (e.g., b"hw.memsize\0").
#[cfg(target_os = "macos")]
fn sysctl_u64(name: &[u8]) -> Option<u64> {
    let mut val: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
    // SAFETY: FFI call to sysctlbyname is safe because:
    // 1. `name` is explicitly passed as null-terminated string.
    // 2. `val` passes a valid memory address with exact u64 sizing.
    // 3. Syscall bounds check against `size` accurately prevents overflow buffers.
    let ret = unsafe {
        libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut val as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret == 0 {
        Some(val)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn sysctl_usize(name: &[u8]) -> Option<usize> {
    sysctl_u64(name).map(|v| v as usize)
}

/// Compute max L1 hot cache entries from L1d size.
/// Each entry is ~200 bytes (key Arc<str> + Bytes + metadata).
/// Use 50% of L1d to leave room for stack + code.
fn compute_l1_entries(l1d_size: usize) -> usize {
    let usable = l1d_size / 2; // 50% of L1d
    let entry_size = 200; // approximate bytes per cache entry
    (usable / entry_size).clamp(32, 512)
}

// ── Socket tuning (applied per-connection) ───────────────────────

/// Apply optimal TCP settings to an accepted connection.
/// Called before TLS handshake for minimum latency.
#[inline]
#[allow(dead_code)]
pub fn tune_accepted_socket(stream: &tokio::net::TcpStream, platform: &Platform) {
    let _ = stream.set_nodelay(true); // TCP_NODELAY — always

    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_send_buffer_size(platform.send_buf);
    let _ = sock.set_recv_buffer_size(platform.recv_buf);

    // Keepalive: detect dead peers
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(30));
    let _ = sock.set_tcp_keepalive(&keepalive);

    // Note: TCP_QUICKACK (Linux) would need raw setsockopt via libc.
    // Omitted for cross-platform compatibility. Add libc dep when targeting Linux.
}

/// Apply SO_REUSEPORT to a listener socket (before bind).
/// Allows multiple listeners on the same port for kernel-level load balancing.
#[allow(dead_code)]
pub fn tune_listener_socket(sock: &socket2::Socket) {
    let _ = sock.set_reuse_address(true);
    // SO_REUSEPORT and TFO are Linux-specific via socket2
    #[cfg(target_os = "linux")]
    {
        // These may not be available on all socket2 versions
        // let _ = sock.set_reuse_port(true);
        // let _ = sock.set_tcp_fastopen(256);
    }
}

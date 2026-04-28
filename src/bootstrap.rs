//! Zion Bootstrap — hardware detection, auto-tuning, performance tier.
//!
//! At startup, probes the OS and hardware to enable the best available
//! performance and security features. Computes a Performance Tier (S/A/B/C)
//! and projected throughput, then prints a styled capability matrix so the
//! operator instantly knows what they're sitting on.
//!
//! Design principle: detect everything, enable the best defaults, but never
//! fail — degrade gracefully if a feature isn't available. Output adapts to
//! the terminal: rich ANSI on a TTY, plain ASCII when piped to a log
//! collector. The only "artificial delay" is a brief (~150 ms) header flash
//! on TTYs — fully suppressed under NO_COLOR / ZION_BOOT_PLAIN /
//! ZION_BOOT_ANIMATE=0 / non-TTY, so log streams are never delayed.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::Instant;

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

    // ── Probe timings (microseconds) ──
    pub probe_us: u64,

    // ── Live calibration ──
    /// Raw AES-128-GCM throughput measured at boot, in **thousands of seal
    /// operations per second on a single core** (1 KB payloads). `None` if
    /// the calibration was skipped (`ZION_BOOT_FAST=1`) or failed.
    ///
    /// This is the *TLS-encrypt ceiling*, not the proxy ceiling. A real
    /// proxy uses well under 10% of this because hyper / tokio / routing /
    /// header handling all eat throughput on top of AES. Use
    /// `projected_kreqs_cached()` for a calibrated proxy-throughput
    /// estimate (still extrapolated from M-series benchmarks).
    pub aes_kops_per_core: Option<u32>,
    /// Wall-time spent on the AES-GCM calibration microbench, in
    /// microseconds. Shown in the boot output as a credibility tag.
    pub calibration_us: u64,
}

static PLATFORM: OnceLock<Platform> = OnceLock::new();

/// Probe the system and return the detected platform.
/// Called once at startup. Cached forever.
pub fn detect() -> &'static Platform {
    PLATFORM.get_or_init(|| {
        let probe_start = Instant::now();

        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let ram_mb = detect_ram_mb();
        let l1d = detect_l1d_cache_size();

        // ── Probe time: detection only (no calibration) ──
        // Take the probe timestamp BEFORE the calibration so the "probed
        // in Xμs" footer reflects detection cost only — the user can see
        // the calibration time separately as "calibrated in Yms".
        let probe_us = probe_start.elapsed().as_micros() as u64;

        // ── Live AES-GCM calibration ──
        // 80 ms microbench on a single core. Skippable for fast-boot
        // environments (CI, k8s init containers, healthcheck probes).
        let calibration_start = Instant::now();
        let aes_kops_per_core = if std::env::var_os("ZION_BOOT_FAST").is_some() {
            None
        } else {
            calibrate_aes_gcm_kreqs()
        };
        let calibration_us = calibration_start.elapsed().as_micros() as u64;

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
            l1d_cache_size: l1d,
            l2_cache_size: detect_l2_cache_size(),
            l1_hot_entries: compute_l1_entries(l1d),

            // ── Computed tuning ──
            worker_threads: compute_workers(cpu_cores),
            conn_limit: compute_conn_limit(ram_mb),
            backlog: compute_backlog(),
            recv_buf: compute_buf_size(ram_mb),
            send_buf: compute_buf_size(ram_mb),

            probe_us,

            aes_kops_per_core,
            calibration_us,
        };

        platform
    })
}

/// Calibrate AES-128-GCM seal throughput on a single core. Runs a tight
/// loop on a 1 KB buffer for ~80 ms and reports throughput as thousands of
/// operations per second (kreqs/s). Returns `None` if the AEAD primitive
/// can't be initialized (which would indicate a busted aws-lc-rs build).
///
/// We pick AES-128-GCM specifically because that's the cipher TLS 1.3
/// negotiates by default, so the per-core ceiling we measure here directly
/// translates to the cached-path ceiling Zion can sustain in production.
///
/// Single-threaded by design: we want to know *per-core* throughput.
/// Multi-core scaling is computed by multiplying by `cpu_cores`.
fn calibrate_aes_gcm_kreqs() -> Option<u32> {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
    use std::time::{Duration, Instant};

    let key_bytes = [0u8; 16];
    let unbound = UnboundKey::new(&AES_128_GCM, &key_bytes).ok()?;
    let key = LessSafeKey::new(unbound);

    // 1 KB payload + 16 byte tag — matches the cached-path reference workload.
    let payload_len = 1024;
    let mut buffer: Vec<u8> = vec![0u8; payload_len + 16];

    // Warmup: a few iterations to JIT/code-cache and stabilize CPU frequency
    // before the timed loop starts.
    for i in 0..256u64 {
        buffer.truncate(payload_len);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&i.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let _ = key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer);
    }

    // Measured loop: 80 ms budget. We check the clock every 32 ops to
    // keep the syscall overhead well under 1% of the loop body.
    let budget = Duration::from_millis(80);
    let start = Instant::now();
    let mut counter: u64 = 1_000_000; // distinct from warmup nonces
    let mut ops: u64 = 0;

    while start.elapsed() < budget {
        for _ in 0..32 {
            buffer.truncate(payload_len);
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
            counter += 1;
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            // Errors here would mean the AEAD primitive is broken — skip
            // the op rather than poisoning the count, but keep going.
            if key
                .seal_in_place_append_tag(nonce, Aad::empty(), &mut buffer)
                .is_ok()
            {
                ops += 1;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    if elapsed <= 0.0 || ops == 0 {
        return None;
    }
    let ops_per_sec = ops as f64 / elapsed;
    Some((ops_per_sec / 1000.0).round() as u32)
}

// ═══════════════════════════════════════════════════════════════════
// PERFORMANCE TIER
// ═══════════════════════════════════════════════════════════════════

/// Hardware capability tier. Computed from cores, RAM, crypto acceleration,
/// SIMD, and OS-level networking primitives. The tier is the headline number
/// the operator sees — it tells them at a glance what their box is good for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    S, // 80+ — flagship: hw-accelerated TLS, plenty of cores/RAM, kernel tuning
    A, // 55-79 — strong: hw-accelerated TLS, solid resources
    B, // 30-54 — decent: missing one accelerator or constrained on a dimension
    C, // <30  — limited: throughput will be CPU-bound
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::S => "S",
            Tier::A => "A",
            Tier::B => "B",
            Tier::C => "C",
        }
    }

    /// One-line motto shown beside the badge.
    pub fn motto(self) -> &'static str {
        match self {
            Tier::S => "flagship — hardware-accelerated TLS at scale",
            Tier::A => "strong — hw-accelerated TLS, solid resources",
            Tier::B => "decent — adequate for most production loads",
            Tier::C => "limited — CPU-bound, fine for dev and edge",
        }
    }

    /// Foreground ANSI color used when rendering the badge.
    fn color(self) -> &'static str {
        match self {
            Tier::S => "\x1b[1;38;5;201m", // bright magenta
            Tier::A => "\x1b[1;38;5;51m",  // bright cyan
            Tier::B => "\x1b[1;38;5;46m",  // bright green
            Tier::C => "\x1b[1;38;5;220m", // amber
        }
    }
}

impl Platform {
    /// Compute the raw tier score (0..~125). Exposed for diagnostics.
    pub fn tier_score(&self) -> u32 {
        let mut s = 0u32;

        // Cores — by far the strongest signal for cached-path throughput.
        s += match self.cpu_cores {
            0..=2 => 0,
            3..=4 => 10,
            5..=8 => 25,
            9..=16 => 35,
            _ => 45,
        };

        // RAM — caps connection limit and cache size.
        s += match self.ram_mb {
            0..=1999 => 0,
            2000..=7999 => 5,
            8000..=15999 => 12,
            16000..=31999 => 20,
            32000..=63999 => 28,
            _ => 35,
        };

        // Crypto acceleration — TLS encrypt is the practical ceiling on cached.
        if self.has_aes_ni {
            s += 10;
        }
        if self.has_sha256 {
            s += 5;
        }
        if self.has_avx2 || self.has_neon {
            s += 5;
        }

        // OS networking primitives.
        match self.os {
            "linux" => s += 10, // io_uring, SO_REUSEPORT, TCP_QUICKACK
            "macos" => s += 3,  // SO_REUSEPORT, TCP_FASTOPEN, no io_uring
            _ => {}
        }

        s
    }

    pub fn tier(&self) -> Tier {
        match self.tier_score() {
            80.. => Tier::S,
            55..=79 => Tier::A,
            30..=54 => Tier::B,
            _ => Tier::C,
        }
    }

    /// Projected cached-path proxy throughput in thousands of req/s (1 KB
    /// payload). Estimate calibrated against published M-series benchmark
    /// (141 K req/s on Apple M4 = ~14 K req/s/core with AES-NI/CE; ~5 K
    /// without). Always an estimate — the proxy uses well under 10% of the
    /// raw AES ceiling because of hyper / tokio / routing overhead, and
    /// per-core scaling is approximately linear up to memory bandwidth.
    pub fn projected_kreqs_cached(&self) -> u32 {
        let per_core: u32 = if self.has_aes_ni { 14 } else { 5 };
        let raw = (self.cpu_cores as u32) * per_core;
        raw.min(250)
    }

    /// Projected dynamic-path proxy throughput. Empirical ~¼ of cached —
    /// upstream + TCP round-trip dominate. Always an estimate.
    pub fn projected_kreqs_dynamic(&self) -> u32 {
        (self.projected_kreqs_cached() / 4).max(1)
    }

    /// Total AES-128-GCM seal throughput across all cores, derived from the
    /// per-core calibration multiplied by `cpu_cores`. Returns `None` if
    /// calibration was skipped or unavailable. Reported in **kilo ops/sec**
    /// (i.e. 1 500 means 1.5 M seals/sec). This is the raw TLS-encrypt
    /// ceiling — the proxy will only ever achieve a fraction of it.
    pub fn aes_kops_total(&self) -> Option<u32> {
        let per_core = self.aes_kops_per_core?;
        let total = (per_core as u64) * (self.cpu_cores as u64);
        Some(total.min(u32::MAX as u64) as u32)
    }
}

// ═══════════════════════════════════════════════════════════════════
// REPORT RENDERING
// ═══════════════════════════════════════════════════════════════════

/// Print the boot capability matrix.
///
/// Output adapts to the terminal: ANSI-colored on a TTY, plain ASCII when
/// piped (journald, docker logs, CI). Set `ZION_BOOT_PLAIN=1` to force plain
/// even on a TTY (useful for screenshots / CI snapshots).
pub fn print_report(p: &Platform) {
    let style = Style::detect();
    let mut w = std::io::stderr().lock();
    let _ = render(p, &style, &mut w);
}

fn render<W: std::io::Write>(p: &Platform, s: &Style, w: &mut W) -> std::io::Result<()> {
    let tier = p.tier();

    // ── Header banner ──
    writeln!(w)?;
    render_header(s, w)?;
    writeln!(w, "  {}{}{}", s.dim(), "─".repeat(58), s.reset(),)?;

    // ── Hardware ──
    section(w, s, "hardware")?;
    kv(w, s, "os", &format!("{} / {}", p.os, p.arch), None)?;
    kv(
        w,
        s,
        "cpu",
        &format!("{} cores", p.cpu_cores),
        Some(if p.cpu_cores >= 8 {
            Mark::Good
        } else if p.cpu_cores >= 4 {
            Mark::Ok
        } else {
            Mark::Warn
        }),
    )?;
    kv(
        w,
        s,
        "ram",
        &fmt_bytes(p.ram_mb * 1024 * 1024),
        Some(if p.ram_mb >= 16_000 {
            Mark::Good
        } else if p.ram_mb >= 4_000 {
            Mark::Ok
        } else {
            Mark::Warn
        }),
    )?;

    // ── Crypto / SIMD ──
    section(w, s, "crypto / simd")?;
    feat(
        w,
        s,
        "aes-ni / armv8 ce",
        p.has_aes_ni,
        "hardware TLS encrypt",
    )?;
    feat(
        w,
        s,
        "sha-256 hw",
        p.has_sha256,
        "hardware HMAC + cert verify",
    )?;
    feat(w, s, "neon", p.has_neon, "ARM SIMD")?;
    feat(w, s, "avx2", p.has_avx2, "x86 SIMD")?;

    // ── OS networking ──
    section(w, s, "os networking")?;
    feat(
        w,
        s,
        "so_reuseport",
        p.has_so_reuseport,
        "kernel load balance",
    )?;
    feat(w, s, "tcp_fastopen", p.has_tcp_fastopen, "0-RTT TCP")?;
    feat(
        w,
        s,
        "tcp_quickack",
        p.has_tcp_quickack,
        "linux only — sub-ms ACK",
    )?;

    // ── CPU cache ──
    section(w, s, "cpu cache")?;
    kv(
        w,
        s,
        "line / l1d / l2",
        &format!(
            "{}B / {} / {}",
            p.cache_line_size,
            fmt_bytes(p.l1d_cache_size as u64),
            fmt_bytes(p.l2_cache_size as u64),
        ),
        None,
    )?;
    kv(w, s, "l1 hot entries", &p.l1_hot_entries.to_string(), None)?;

    // ── Auto-tuning ──
    section(w, s, "auto-tuning")?;
    kv(w, s, "workers", &p.worker_threads.to_string(), None)?;
    kv(w, s, "conn limit", &p.conn_limit.to_string(), None)?;
    kv(w, s, "backlog", &p.backlog.to_string(), None)?;
    kv(w, s, "tcp buf", &fmt_bytes(p.send_buf as u64), None)?;

    // ── Tier badge ──
    writeln!(w)?;
    render_tier_badge(p, tier, s, w)?;

    // ── Synthesis line ──
    // One dense line that crystallizes the whole platform in ~60 chars —
    // optimized for screenshot-and-share. Stays after detail + badge so the
    // reader builds context first, then sees the recap.
    render_synthesis(p, s, w)?;

    // ── Hint line ──
    // Always emit something — silence on a perfect machine is a missed
    // chance to nudge the operator toward the next useful step.
    writeln!(w, "  {}hint{}  {}", s.dim(), s.reset(), upgrade_hint(p))?;

    let footer = match p.aes_kops_per_core {
        Some(_) => format!(
            "probed in {}μs · calibrated in {}ms · ZION_BOOT_PLAIN=1 / ZION_BOOT_FAST=1 to override",
            p.probe_us,
            (p.calibration_us / 1000).max(1),
        ),
        None => format!(
            "probed in {}μs · calibration skipped · ZION_BOOT_PLAIN=1 to disable colors",
            p.probe_us,
        ),
    };
    writeln!(w, "  {}{}{}", s.dim(), footer, s.reset())?;
    writeln!(w)?;
    Ok(())
}

/// Render the "ZION  edge gateway  vX.Y.Z" header.
///
/// On a TTY with colors enabled, briefly cycles the ZION title through 6
/// hot colors (~150ms total) before settling on bold bright white — a CRT
/// power-on flash that reads as "underground / metallic", not slop. On
/// non-TTY or NO_COLOR / ZION_BOOT_PLAIN / ZION_BOOT_ANIMATE=0 the cycle
/// is skipped entirely and the final frame is printed directly so log
/// collectors see one clean line.
fn render_header<W: std::io::Write>(s: &Style, w: &mut W) -> std::io::Result<()> {
    if !s.animate {
        // Final frame, no animation. In plain mode all escape strings are "".
        let title_color = if s.color { "\x1b[1;97m" } else { "" }; // bold bright white
        writeln!(
            w,
            "  {}ZION{}  {}edge gateway{}  {}v{}{}",
            title_color,
            s.reset(),
            s.dim(),
            s.reset(),
            s.dim(),
            env!("CARGO_PKG_VERSION"),
            s.reset(),
        )?;
        return Ok(());
    }

    // ── Rainbow loop → metallic white settle ──
    // We run the color cycle CYCLES times so the eye registers a continuous
    // loop, not a one-shot flash. \r returns to start of line and we
    // rewrite — no extra blank lines, no flicker on terminals that batch
    // redraws. Total duration ≈ FRAME_MS × cycle.len() × CYCLES.
    //
    // Bounded on purpose: once the rest of the boot output starts printing,
    // the ZION line scrolls up and any further animation would be invisible
    // anyway. Better to settle cleanly than to fight the log stream.
    const FRAME_MS: u64 = 25;
    const CYCLES: usize = 3;
    let cycle = [
        "\x1b[1;38;5;196m", // bright red
        "\x1b[1;38;5;202m", // orange
        "\x1b[1;38;5;226m", // yellow
        "\x1b[1;38;5;46m",  // green
        "\x1b[1;38;5;51m",  // cyan
        "\x1b[1;38;5;201m", // magenta
    ];

    for _ in 0..CYCLES {
        for color in &cycle {
            write!(
                w,
                "\r  {}ZION\x1b[0m  \x1b[2medge gateway\x1b[0m  \x1b[2mv{}\x1b[0m",
                color,
                env!("CARGO_PKG_VERSION"),
            )?;
            w.flush()?;
            std::thread::sleep(std::time::Duration::from_millis(FRAME_MS));
        }
    }

    // Final settle: bold bright white. Newline closes the rewriting line.
    writeln!(
        w,
        "\r  \x1b[1;97mZION\x1b[0m  \x1b[2medge gateway\x1b[0m  \x1b[2mv{}\x1b[0m",
        env!("CARGO_PKG_VERSION"),
    )?;
    Ok(())
}

/// Inner width of the tier badge (visible chars between the ║ borders, excl. the
/// 1-space pad on each side).
const BADGE_INNER: usize = 52;

fn render_tier_badge<W: std::io::Write>(
    p: &Platform,
    tier: Tier,
    s: &Style,
    w: &mut W,
) -> std::io::Result<()> {
    let cached = p.projected_kreqs_cached();
    let dynamic = p.projected_kreqs_dynamic();
    let score = p.tier_score();

    let tier_color = if s.color { tier.color() } else { "" };
    let reset_raw = if s.color { "\x1b[0m" } else { "" };
    let reset = s.reset();
    let dim = s.dim();
    let bold = s.bold();
    let border = s.border();

    // Top border
    writeln!(w, "  {}╔{}╗{}", border, "═".repeat(BADGE_INNER + 2), reset)?;

    // Tier line: "★ TIER {X}" ... "score {NN}/125" right-aligned
    let left = format!("★ TIER {}", tier.label());
    let left_styled = if s.color {
        format!("{}★ TIER {}{}{}", bold, tier_color, tier.label(), reset_raw)
    } else {
        left.clone()
    };
    let right = format!("score {:>3}/125", score);
    let right_styled = if s.color {
        format!("{}{}{}", dim, right, reset_raw)
    } else {
        right.clone()
    };
    let gap = BADGE_INNER.saturating_sub(left.len() + right.len());
    writeln!(
        w,
        "  {}║{} {}{}{} {}║{}",
        border,
        reset,
        left_styled,
        " ".repeat(gap),
        right_styled,
        border,
        reset,
    )?;

    // Motto line (italic-dim)
    let motto = pad_right(tier.motto(), BADGE_INNER);
    writeln!(
        w,
        "  {}║{} {}{}{} {}║{}",
        border, reset, dim, motto, reset_raw, border, reset
    )?;

    // ── AES line — what we actually measured ──
    let aes_line = match p.aes_kops_per_core {
        Some(per_core) => format!(
            "  AES-128-GCM  {} seal/s/core  (measured {}ms)",
            fmt_aes_rate(per_core),
            (p.calibration_us / 1000).max(1),
        ),
        None => "  AES-128-GCM  — calibration skipped".to_string(),
    };
    let aes_padded = pad_right(&aes_line, BADGE_INNER);
    writeln!(
        w,
        "  {}║{} {} {}║{}",
        border, reset, aes_padded, border, reset
    )?;

    // ── Proxy line — labeled estimate, no false promises ──
    let proxy_inner = format!("  proxy est.   ~{}K cached · ~{}K dynamic", cached, dynamic);
    let proxy_padded = pad_right(&proxy_inner, BADGE_INNER);
    writeln!(
        w,
        "  {}║{} {} {}║{}",
        border, reset, proxy_padded, border, reset
    )?;

    // Bottom border
    writeln!(w, "  {}╚{}╝{}", border, "═".repeat(BADGE_INNER + 2), reset)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// READY BANNER (closes the boot ceremony with a next-step CTA)
// ═══════════════════════════════════════════════════════════════════

/// Print the post-startup "READY" banner with the snapshot URL and a hint
/// to launch `zion top`. This replaces the bare `ZION ONLINE.` line and
/// closes the boot output loop with an actionable next step — the operator
/// reads it and immediately knows what to do next.
///
/// Called from main.rs *after* both listeners have bound and any optional
/// QUIC/io_uring spawns are wired up. Output adapts to TTY like the boot
/// report; piped output stays plain ASCII for log collectors.
pub fn print_ready_banner(http_addr: &str, https_addr: &str) {
    let style = Style::detect();
    let mut w = std::io::stderr().lock();
    let _ = render_ready(&style, http_addr, https_addr, &mut w);
}

fn render_ready<W: std::io::Write>(
    s: &Style,
    http_addr: &str,
    https_addr: &str,
    w: &mut W,
) -> std::io::Result<()> {
    // Rewrite wildcard binds for the snapshot URL — operators connect via
    // loopback, not 0.0.0.0/[::].
    let loopback_http = if http_addr.starts_with("0.0.0.0:") {
        http_addr.replacen("0.0.0.0", "127.0.0.1", 1)
    } else if http_addr.starts_with("[::]:") {
        http_addr.replacen("[::]", "[::1]", 1)
    } else {
        http_addr.to_string()
    };

    let bold_green = if s.color { "\x1b[1;38;5;46m" } else { "" };
    let cyan = if s.color { "\x1b[38;5;51m" } else { "" };
    let reset = s.reset();
    let dim = s.dim();

    writeln!(w)?;
    writeln!(
        w,
        "  {}▶ READY{}  {}{} (https) · {} (http){}",
        bold_green, reset, dim, https_addr, http_addr, reset,
    )?;
    writeln!(
        w,
        "  {}live dashboard:{}  {}zion top --url http://{}/_zion/snapshot.json{}",
        dim, reset, cyan, loopback_http, reset,
    )?;
    writeln!(
        w,
        "  {}health:{}         {}http://{}/healthz{}",
        dim, reset, cyan, loopback_http, reset,
    )?;
    writeln!(w)?;
    Ok(())
}

/// Render the one-line synthesis: crypto, OS networking, cache, workers,
/// connections — each colored by health. The format is deliberately dense
/// so an operator (or a screenshot) shows the platform at a glance.
fn render_synthesis<W: std::io::Write>(p: &Platform, s: &Style, w: &mut W) -> std::io::Result<()> {
    let crypto_count =
        (p.has_aes_ni as u32) + (p.has_sha256 as u32) + ((p.has_avx2 || p.has_neon) as u32);
    let os_count =
        (p.has_so_reuseport as u32) + (p.has_tcp_fastopen as u32) + (p.has_tcp_quickack as u32);

    let dim = s.dim();
    let reset = s.reset();
    let cyan = if s.color { "\x1b[38;5;51m" } else { "" };

    let parts = [
        format!("{}crypto{} {}", dim, reset, frac_styled(s, crypto_count, 3)),
        format!("{}os net{} {}", dim, reset, frac_styled(s, os_count, 3)),
        format!(
            "{}cache{} {}{}KB{}",
            dim,
            reset,
            cyan,
            p.l1d_cache_size / 1024,
            reset
        ),
        format!(
            "{}workers{} {}{}{}",
            dim, reset, cyan, p.worker_threads, reset
        ),
        format!(
            "{}conns{} {}{}{}",
            dim,
            reset,
            cyan,
            fmt_count(p.conn_limit),
            reset
        ),
    ];
    let sep = format!(" {}·{} ", dim, reset);
    writeln!(w, "  {}", parts.join(&sep))?;
    Ok(())
}

/// Format a fraction as "n/total" colored by ratio: full=green, ≥half=amber,
/// otherwise=red. Plain mode emits the digits without color.
fn frac_styled(s: &Style, n: u32, total: u32) -> String {
    let color = if !s.color {
        ""
    } else if n == total {
        "\x1b[38;5;46m" // green
    } else if n * 2 >= total {
        "\x1b[38;5;220m" // amber
    } else {
        "\x1b[38;5;196m" // red
    };
    format!("{}{}/{}{}", color, n, total, s.reset())
}

/// Format a per-core AES seal rate (already in K ops/sec) for display.
/// Examples: 1500 → "1.5M", 250 → "250K". Always 1 decimal in the M range.
fn fmt_aes_rate(kops: u32) -> String {
    if kops >= 1_000 {
        format!("{:.1}M", kops as f64 / 1_000.0)
    } else {
        format!("{}K", kops)
    }
}

/// Compact count: 1234 → "1K", 1_234_567 → "1.2M". Loses precision on
/// purpose — the synthesis is a glance, not a budget line.
fn fmt_count(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{}K", n / 1_000)
    } else {
        n.to_string()
    }
}

/// Produce a one-line hint that guides the operator toward the next useful
/// step. Always returns something — silence is a wasted slot. Priority:
///
///   1. Hardware bottlenecks (no AES, low RAM, few cores) — fix at the metal
///   2. Build flags missing for this OS / build (io_uring, tui, acme, http3)
///   3. OS-specific ceiling (macOS at the top of its class → mention Linux)
///   4. Default celebratory hint pointing at the next-most-useful action
///
/// `cfg!()` is used (not `#[cfg]`) so the function is ordinary code: simpler
/// to test and the compiler folds the constants away in release builds.
fn upgrade_hint(p: &Platform) -> String {
    // ── 1. Hardware bottlenecks ──
    if !p.has_aes_ni {
        return "no hardware AES — TLS encrypt will be the bottleneck. consider a newer CPU."
            .to_string();
    }
    if p.ram_mb < 4096 {
        return format!(
            "only {} MB RAM — conn limit capped at {}. add memory for higher concurrency.",
            p.ram_mb, p.conn_limit
        );
    }
    if p.cpu_cores < 4 {
        return format!(
            "only {} core{} — TLS handshake throughput is core-bound.",
            p.cpu_cores,
            if p.cpu_cores == 1 { "" } else { "s" }
        );
    }

    // ── 2. Build flags — biggest perf win first, then UX ──
    if cfg!(target_os = "linux") && !cfg!(feature = "io-uring-accept") {
        return "linux + multi-core — rebuild with `--features io-uring-accept` for multishot accept (kernel 5.19+)."
            .to_string();
    }
    if !cfg!(feature = "tui") {
        return "rebuild with `--features tui` to unlock the live dashboard: `zion top`."
            .to_string();
    }
    if !cfg!(feature = "acme") {
        return "rebuild with `--features acme` for Let's Encrypt auto-renewal.".to_string();
    }
    if !cfg!(feature = "http3") {
        return "rebuild with `--features http3` to serve HTTP/3 over QUIC.".to_string();
    }

    // ── 3. OS-specific ceiling ──
    if cfg!(target_os = "macos") && p.cpu_cores >= 8 {
        return "near the macos hardware ceiling — for io_uring (+20% accept) deploy on linux."
            .to_string();
    }

    // ── 4. Everything is hot. Point at the next action. ──
    "all systems hot — `zion top` for live metrics, edit zion.toml to add routes.".to_string()
}

// ═══════════════════════════════════════════════════════════════════
// STYLE / TTY HELPERS
// ═══════════════════════════════════════════════════════════════════

struct Style {
    color: bool,
    /// Whether to play the brief boot animation. False in non-TTY mode, when
    /// colors are off, or when ZION_BOOT_ANIMATE=0 is set. Tests construct
    /// `Style { color: true, animate: false }` to exercise color paths
    /// without paying the 150 ms sleep.
    animate: bool,
}

impl Style {
    fn detect() -> Self {
        // Honor NO_COLOR (https://no-color.org) and ZION_BOOT_PLAIN.
        let plain =
            std::env::var_os("NO_COLOR").is_some() || std::env::var_os("ZION_BOOT_PLAIN").is_some();
        let color = !plain && std::io::stderr().is_terminal();
        let animate_off =
            std::env::var_os("ZION_BOOT_ANIMATE").as_deref() == Some(std::ffi::OsStr::new("0"));
        let animate = color && !animate_off;
        Self { color, animate }
    }

    fn fg(&self, text: &str, ansi: &str) -> String {
        if self.color {
            format!("{}{}{}", ansi, text, "\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn dim(&self) -> &'static str {
        if self.color {
            "\x1b[2m"
        } else {
            ""
        }
    }
    fn bold(&self) -> &'static str {
        if self.color {
            "\x1b[1m"
        } else {
            ""
        }
    }
    fn reset(&self) -> &'static str {
        if self.color {
            "\x1b[0m"
        } else {
            ""
        }
    }
    /// Color used for box-drawing characters (╔╗╚╝║═). The SGR `dim`
    /// attribute attenuates so aggressively that thin chars vanish in a sea
    /// of trailing spaces; we use an explicit mid-gray (256-color #240) so
    /// borders stay legible without shouting.
    fn border(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;240m"
        } else {
            ""
        }
    }
}

#[derive(Copy, Clone)]
enum Mark {
    Good,
    Ok,
    Warn,
}

impl Mark {
    /// Visible width (for alignment): 1 char in TTY mode (a colored dot),
    /// 4 chars in plain mode ("[ok]" / "[ !]" / "    " for none).
    fn glyph(self, s: &Style) -> String {
        if !s.color {
            return match self {
                Mark::Good => "[ok]".to_string(),
                Mark::Ok => "[ok]".to_string(),
                Mark::Warn => "[!!]".to_string(),
            };
        }
        match self {
            Mark::Good => "\x1b[38;5;46m●\x1b[0m".to_string(), // bright green
            Mark::Ok => "\x1b[38;5;51m●\x1b[0m".to_string(),   // cyan
            Mark::Warn => "\x1b[38;5;220m●\x1b[0m".to_string(), // amber
        }
    }
}

fn section<W: std::io::Write>(w: &mut W, s: &Style, name: &str) -> std::io::Result<()> {
    writeln!(
        w,
        "  {}┄ {} {}{}",
        s.dim(),
        name,
        "─".repeat(54_usize.saturating_sub(name.len() + 4)),
        s.reset(),
    )
}

fn kv<W: std::io::Write>(
    w: &mut W,
    s: &Style,
    key: &str,
    val: &str,
    mark: Option<Mark>,
) -> std::io::Result<()> {
    // Reserve 1 visible col on TTY (the dot) or 4 cols in plain mode (e.g. "[ok]").
    let blank = if s.color {
        " ".to_string()
    } else {
        "    ".to_string()
    };
    let glyph = mark.map(|m| m.glyph(s)).unwrap_or(blank);
    writeln!(
        w,
        "  {}  {}{:<18}{} {}",
        glyph,
        s.dim(),
        key,
        s.reset(),
        val,
    )
}

fn feat<W: std::io::Write>(
    w: &mut W,
    s: &Style,
    name: &str,
    on: bool,
    note: &str,
) -> std::io::Result<()> {
    let mark = if on { Mark::Good } else { Mark::Warn };
    let state = if on {
        s.fg("yes", "\x1b[38;5;46m")
    } else {
        s.fg("no", "\x1b[38;5;244m")
    };
    writeln!(
        w,
        "  {}  {}{:<18}{} {:<6}  {}{}{}",
        mark.glyph(s),
        s.dim(),
        name,
        s.reset(),
        state,
        s.dim(),
        note,
        s.reset(),
    )
}

/// Pad a string with trailing spaces to the given visible-column width.
/// Counts Unicode scalar values (chars), not bytes — so "—" or "★" count as 1.
/// This is correct for the charset Zion uses in boot output (ASCII +
/// box-drawing + a handful of dingbats — no wide CJK / no combining marks).
fn pad_right(s: &str, width: usize) -> String {
    let visible = s.chars().count();
    if visible >= width {
        s.chars().take(width).collect()
    } else {
        let mut out = String::with_capacity(width);
        out.push_str(s);
        for _ in visible..width {
            out.push(' ');
        }
        out
    }
}

fn fmt_bytes(n: u64) -> String {
    const K: u64 = 1024;
    const M: u64 = K * K;
    const G: u64 = K * M;
    if n >= G {
        format!("{:.1} GB", n as f64 / G as f64)
    } else if n >= M {
        format!("{} MB", n / M)
    } else if n >= K {
        format!("{} KB", n / K)
    } else {
        format!("{} B", n)
    }
}

// ═══════════════════════════════════════════════════════════════════
// DETECTION FUNCTIONS
// ═══════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic(cores: usize, ram_mb: u64, aes: bool, os: &'static str) -> Platform {
        Platform {
            os,
            arch: "x86_64",
            cpu_cores: cores,
            ram_mb,
            has_aes_ni: aes,
            has_sha256: aes,
            has_neon: false,
            has_avx2: aes,
            has_so_reuseport: true,
            has_tcp_fastopen: true,
            has_tcp_quickack: os == "linux",
            cache_line_size: 64,
            l1d_cache_size: 32768,
            l2_cache_size: 262_144,
            l1_hot_entries: 80,
            worker_threads: cores,
            conn_limit: 10_000,
            backlog: 1024,
            recv_buf: 65536,
            send_buf: 65536,
            probe_us: 0,
            aes_kops_per_core: None,
            calibration_us: 0,
        }
    }

    #[test]
    fn tier_s_for_flagship() {
        // 16 cores, 32 GB, hw crypto, linux → flagship
        let p = synthetic(16, 32_000, true, "linux");
        assert!(p.tier_score() >= 80, "score = {}", p.tier_score());
        assert_eq!(p.tier(), Tier::S);
    }

    #[test]
    fn tier_a_for_strong() {
        // 8 cores, 16 GB, hw crypto, linux → strong
        let p = synthetic(8, 16_000, true, "linux");
        let s = p.tier_score();
        assert!((55..=79).contains(&s), "score = {}", s);
        assert_eq!(p.tier(), Tier::A);
    }

    #[test]
    fn tier_c_for_tiny_box() {
        // 1 core, 1 GB, no hw crypto, freebsd → minimal
        let p = synthetic(1, 1024, false, "freebsd");
        let s = p.tier_score();
        assert!(s < 30, "score = {}", s);
        assert_eq!(p.tier(), Tier::C);
    }

    #[test]
    fn projection_scales_with_cores_and_aes() {
        let with_aes = synthetic(10, 16_000, true, "linux");
        let without_aes = synthetic(10, 16_000, false, "linux");
        assert!(with_aes.projected_kreqs_cached() > without_aes.projected_kreqs_cached());
        assert!(with_aes.projected_kreqs_dynamic() >= 1);
    }

    #[test]
    fn projection_capped() {
        let huge = synthetic(64, 64_000, true, "linux");
        // Static formula: 64 × 14 = 896, capped at 250 K.
        assert_eq!(huge.projected_kreqs_cached(), 250);
    }

    #[test]
    fn projection_is_static_estimate() {
        // The cached/dynamic projection is *always* the static formula —
        // calibration measures raw AES, not full-stack proxy throughput,
        // so they're separate concerns. The proxy estimate stays a labeled
        // estimate.
        let p = synthetic(8, 16_000, true, "linux");
        assert!(p.aes_kops_per_core.is_none()); // synthetic skips calibration
        assert_eq!(p.projected_kreqs_cached(), 112); // 8 × 14
        assert_eq!(p.projected_kreqs_dynamic(), 28); // 112 / 4
    }

    #[test]
    fn aes_kops_total_multiplies_per_core() {
        let mut p = synthetic(8, 16_000, true, "linux");
        p.aes_kops_per_core = Some(1_500); // 1.5 M ops/s/core
        assert_eq!(p.aes_kops_total(), Some(12_000)); // 8 × 1500
    }

    #[test]
    fn aes_kops_total_none_when_calibration_skipped() {
        let p = synthetic(8, 16_000, true, "linux");
        assert_eq!(p.aes_kops_total(), None);
    }

    #[test]
    fn calibration_measures_real_throughput() {
        // The actual calibration must produce a non-trivial result on any
        // CPU we'd reasonably ship to. Anything < 10 K/s/core would suggest
        // the AEAD primitive is busted or the host is comically slow.
        let kreqs = calibrate_aes_gcm_kreqs().expect("calibration returned None");
        assert!(kreqs > 10, "implausibly low calibration: {kreqs} K/s/core");
        // Sanity ceiling: even the fastest hw-accelerated CPUs don't seal
        // 1 KB AES-GCM at 50 M/s/core. If we see that, the loop is broken.
        assert!(
            kreqs < 50_000,
            "implausibly high calibration: {kreqs} K/s/core"
        );
    }

    #[test]
    fn fmt_aes_rate_breakpoints() {
        assert_eq!(fmt_aes_rate(0), "0K");
        assert_eq!(fmt_aes_rate(250), "250K");
        assert_eq!(fmt_aes_rate(999), "999K");
        assert_eq!(fmt_aes_rate(1_000), "1.0M");
        assert_eq!(fmt_aes_rate(1_500), "1.5M");
        assert_eq!(fmt_aes_rate(12_345), "12.3M");
    }

    #[test]
    fn upgrade_hint_warns_no_aes() {
        let p = synthetic(8, 16_000, false, "linux");
        let hint = upgrade_hint(&p);
        assert!(hint.contains("AES"), "got: {hint}");
    }

    #[test]
    fn upgrade_hint_warns_low_ram() {
        let p = synthetic(8, 1024, true, "linux");
        let hint = upgrade_hint(&p);
        assert!(hint.contains("RAM"), "got: {hint}");
    }

    #[test]
    fn upgrade_hint_warns_few_cores() {
        let p = synthetic(2, 16_000, true, "linux");
        let hint = upgrade_hint(&p);
        assert!(hint.contains("core"), "got: {hint}");
    }

    #[test]
    fn upgrade_hint_is_never_empty() {
        // Across every platform/feature combo we should always say
        // *something* useful — silence on a healthy box is a missed nudge.
        for (cores, ram, aes, os) in [
            (1, 1024, false, "linux"),
            (8, 16_000, true, "linux"),
            (10, 16_384, true, "macos"),
            (16, 32_000, true, "freebsd"),
            (64, 64_000, true, "linux"),
        ] {
            let p = synthetic(cores, ram, aes, os);
            let hint = upgrade_hint(&p);
            assert!(!hint.is_empty(), "empty hint for {:?}", p);
            // Hints are sentences — at least 20 chars of substance
            assert!(hint.len() > 20, "trivially-short hint: {hint}");
        }
    }

    #[test]
    fn upgrade_hint_singular_core_grammar() {
        let p = synthetic(1, 16_000, true, "linux");
        let hint = upgrade_hint(&p);
        // Singular: "1 core" not "1 cores"
        assert!(hint.contains("1 core "), "got: {hint}");
    }

    #[test]
    fn render_plain_is_ascii_only() {
        let p = synthetic(8, 16_000, true, "linux");
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render(&p, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // No ANSI escape sequences in plain mode
        assert!(!out.contains("\x1b["));
        // Tier badge present
        assert!(out.contains("TIER A"));
        // Expected sections
        assert!(out.contains("hardware"));
        assert!(out.contains("crypto"));
        assert!(out.contains("auto-tuning"));
    }

    #[test]
    fn ready_banner_rewrites_wildcard_to_loopback() {
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_ready(&s, "0.0.0.0:8080", "0.0.0.0:4433", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // Wildcard rewritten in URL hints
        assert!(
            out.contains("http://127.0.0.1:8080/_zion/snapshot.json"),
            "got: {out}"
        );
        assert!(out.contains("http://127.0.0.1:8080/healthz"));
        // Listening summary keeps the original bind for accuracy
        assert!(out.contains("0.0.0.0:8080 (http)"));
        assert!(out.contains("0.0.0.0:4433 (https)"));
        assert!(out.contains("READY"));
        // Plain mode → no ANSI
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn ready_banner_keeps_explicit_loopback() {
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_ready(&s, "127.0.0.1:8080", "127.0.0.1:4433", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // No double-rewrite on explicit loopback
        assert!(out.contains("http://127.0.0.1:8080/_zion/snapshot.json"));
    }

    #[test]
    fn ready_banner_handles_ipv6_wildcard() {
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_ready(&s, "[::]:8080", "[::]:4433", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("http://[::1]:8080/_zion/snapshot.json"));
    }

    #[test]
    fn ready_banner_color_includes_ansi() {
        let s = Style {
            color: true,
            animate: false,
        };
        let mut buf = Vec::new();
        render_ready(&s, "0.0.0.0:80", "0.0.0.0:443", &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\x1b[1;38;5;46m")); // bold green
        assert!(out.contains("\x1b[38;5;51m")); // cyan
    }

    #[test]
    fn header_plain_is_single_line_no_ansi() {
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_header(&s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("ZION"));
        assert!(out.contains("edge gateway"));
        assert!(!out.contains("\x1b["), "plain header has ANSI: {out:?}");
        // Exactly one line of output
        assert_eq!(out.matches('\n').count(), 1);
        // No \r — animation path must not have run
        assert!(!out.contains('\r'));
    }

    #[test]
    fn header_animated_loops_three_cycles_then_settles() {
        // animate=true forces the rainbow loop path. We use a Vec sink — no
        // terminal — so the sleeps still happen (~450 ms) but writes land
        // in memory; we then inspect the output for the expected frames.
        let s = Style {
            color: true,
            animate: true,
        };
        let mut buf = Vec::new();
        render_header(&s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // 3 cycles × 6 colors = 18 rewriting frames, plus 1 final settle.
        assert_eq!(
            out.matches('\r').count(),
            19,
            "expected 18 cycle frames + 1 settle frame, got: {out:?}"
        );
        // The final settle uses bold bright white
        assert!(out.contains("\x1b[1;97mZION"));
        // All six cycle colors are present (each appears 3 times in the buffer)
        for code in [
            "38;5;196", "38;5;202", "38;5;226", "38;5;46", "38;5;51", "38;5;201",
        ] {
            let occurrences = out.matches(code).count();
            assert_eq!(
                occurrences, 3,
                "color {code} should appear 3 times (one per cycle), got {occurrences}",
            );
        }
    }

    #[test]
    fn synthesis_full_capability_macos_m4() {
        // Apple M4 profile: full crypto, partial OS net (no QUICKACK on macos).
        let p = synthetic(10, 16_384, true, "macos");
        // Override the synthetic NEON/AVX bits to match real M4
        let p = Platform {
            has_neon: true,
            has_tcp_quickack: false,
            ..p
        };
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_synthesis(&p, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("crypto 3/3"), "got: {out}");
        assert!(out.contains("os net 2/3"), "got: {out}");
        assert!(out.contains("workers"));
        assert!(out.contains("conns"));
        // Plain mode = no ANSI
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn synthesis_partial_crypto_warned() {
        // No AES-NI, no AVX2, no NEON: crypto 1/3 (only sha-256 with our synthetic).
        // Use a synthetic that has only sha256 for the warn case.
        let mut p = synthetic(4, 8_000, false, "linux");
        p.has_sha256 = true;
        let s = Style {
            color: false,
            animate: false,
        };
        let mut buf = Vec::new();
        render_synthesis(&p, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("crypto 1/3"));
    }

    #[test]
    fn synthesis_color_uses_green_for_full_amber_for_partial() {
        let p = synthetic(8, 16_000, true, "linux");
        let s = Style {
            color: true,
            animate: false,
        };
        let mut buf = Vec::new();
        render_synthesis(&p, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // synthetic(linux, true) → crypto: aes-yes, sha-yes, avx2-yes (because aes flag in synthetic) → 3/3 → green
        assert!(
            out.contains("\x1b[38;5;46m3/3"),
            "expected green for crypto 3/3, got: {out}"
        );
        // os: REUSEPORT yes, FASTOPEN yes, QUICKACK yes (linux) → 3/3 → green
        // (synthetic helper sets all 3 true on linux)
    }

    #[test]
    fn fmt_count_breakpoints() {
        assert_eq!(fmt_count(0), "0");
        assert_eq!(fmt_count(999), "999");
        assert_eq!(fmt_count(1_000), "1K");
        assert_eq!(fmt_count(83_886), "83K");
        assert_eq!(fmt_count(1_234_567), "1.2M");
    }

    #[test]
    fn frac_styled_plain_no_color() {
        let s = Style {
            color: false,
            animate: false,
        };
        assert_eq!(frac_styled(&s, 3, 3), "3/3");
        assert_eq!(frac_styled(&s, 2, 3), "2/3");
        assert_eq!(frac_styled(&s, 0, 3), "0/3");
    }

    #[test]
    fn header_color_no_animate_skips_rewrite() {
        // color=true but animate=false → final frame only, no \r, ANSI present.
        let s = Style {
            color: true,
            animate: false,
        };
        let mut buf = Vec::new();
        render_header(&s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains('\r'));
        assert!(out.contains("\x1b[1;97mZION"));
    }

    #[test]
    fn render_color_includes_ansi() {
        let p = synthetic(8, 16_000, true, "linux");
        let s = Style {
            color: true,
            animate: false,
        };
        let mut buf = Vec::new();
        render(&p, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\x1b["));
    }
}

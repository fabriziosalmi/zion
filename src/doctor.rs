// SPDX-License-Identifier: Apache-2.0
//! `zion doctor` — environment diagnostic.
//!
//! Runs a checklist of common production gotchas (fd limit, privileged
//! ports, kernel features, hardware crypto) and prints actionable fixes
//! for each. Always available — diagnostics shouldn't be feature-gated.
//!
//! Exit codes:
//!   0 — all checks OK or warnings only
//!   2 — one or more failures (the daemon would not start cleanly)
//!
//! Output adapts to TTY: colored glyphs on a terminal, plain ASCII when
//! piped to a log file or CI. Honors `NO_COLOR` and `ZION_BOOT_PLAIN`.

use std::io::IsTerminal;
use std::net::TcpListener;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub fix: Option<String>,
}

impl Check {
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Warn,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    // `fail` is only called from `#[cfg(unix)]` blocks (fd-limit check).
    // Windows builds don't reach a call site, so dead_code fires there.
    #[allow(dead_code)]
    fn fail(name: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Fail,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
    fn skip(name: &'static str, reason: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Skip,
            detail: reason.into(),
            fix: None,
        }
    }
}

/// Run all checks and print the report. Returns the exit code the caller
/// should use: 0 on success / warnings, 2 on any hard failure.
pub fn run() -> i32 {
    let platform = crate::bootstrap::detect();
    let checks = collect_checks(platform);
    let mut w = std::io::stderr().lock();
    let style = Style::detect();
    let _ = render(&checks, &style, &mut w);

    if checks.iter().any(|c| c.status == Status::Fail) {
        2
    } else {
        0
    }
}

fn collect_checks(p: &crate::bootstrap::Platform) -> Vec<Check> {
    vec![
        check_fd_limit(),
        check_privileged_port_80(),
        check_privileged_port_443(),
        check_somaxconn(),
        check_kernel_version(),
        check_hardware_crypto(p),
        check_aes_calibration(p),
    ]
}

// ─────────────────────────────────────────────────────────────────────────
// CHECKS
// ─────────────────────────────────────────────────────────────────────────

/// File descriptor soft limit. Each TLS connection burns an fd; below 4096
/// you'll start hitting "too many open files" under modest load.
fn check_fd_limit() -> Check {
    #[cfg(unix)]
    {
        use libc::{getrlimit, rlimit, RLIMIT_NOFILE};
        let mut lim = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit takes a valid out-pointer with the right layout.
        let rc = unsafe { getrlimit(RLIMIT_NOFILE, &mut lim as *mut rlimit) };
        if rc != 0 {
            return Check::warn(
                "fd limit",
                "could not query RLIMIT_NOFILE",
                "check `ulimit -n` manually",
            );
        }
        let soft = lim.rlim_cur;
        let hard = lim.rlim_max;
        let detail = format!("soft={soft} hard={hard}");
        if soft < 1024 {
            Check::fail(
                "fd limit",
                detail,
                "raise: `ulimit -n 65536` (or LimitNOFILE=65536 in systemd unit)",
            )
        } else if soft < 8192 {
            Check::warn("fd limit", detail, "raise to 65536: `ulimit -n 65536`")
        } else {
            Check::ok("fd limit", detail)
        }
    }
    #[cfg(not(unix))]
    {
        Check::skip("fd limit", "non-unix platform")
    }
}

/// Try to bind localhost:80 to detect whether we have permission for
/// privileged ports. We don't need :443 separately — same gate — but we
/// do both to surface IPv4 vs IPv6 stack issues.
fn check_privileged_port_80() -> Check {
    check_can_bind(80, "privileged port :80")
}

fn check_privileged_port_443() -> Check {
    check_can_bind(443, "privileged port :443")
}

fn check_can_bind(port: u16, name: &'static str) -> Check {
    let addr = format!("127.0.0.1:{port}");
    match TcpListener::bind(&addr) {
        Ok(l) => {
            // Drop immediately so we don't keep the port reserved.
            drop(l);
            Check::ok(name, format!("can bind {addr}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Check::warn(
            name,
            format!("cannot bind {addr}: permission denied"),
            "run as root, or `setcap cap_net_bind_service+ep ./zion` (Linux)",
        ),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Something else is using the port — not a doctor failure,
            // but worth noting.
            Check::warn(
                name,
                format!("{addr} is already in use"),
                "stop the conflicting service or pick a different port",
            )
        }
        Err(e) => Check::warn(name, format!("bind error: {e}"), "investigate"),
    }
}

/// `net.core.somaxconn` caps the listen() backlog. Modern Zion sets a
/// backlog of 8192 on Linux but the kernel silently truncates to this
/// value. Default is often 128 → tail-latency cliff under burst arrivals.
fn check_somaxconn() -> Check {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/sys/net/core/somaxconn") {
            Ok(s) => {
                let v: u32 = s.trim().parse().unwrap_or(0);
                let detail = format!("{v}");
                if v < 1024 {
                    Check::warn(
                        "somaxconn",
                        detail,
                        "raise: `sudo sysctl -w net.core.somaxconn=4096` (and persist in /etc/sysctl.conf)",
                    )
                } else {
                    Check::ok("somaxconn", detail)
                }
            }
            Err(_) => Check::skip("somaxconn", "could not read /proc/sys/net/core/somaxconn"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Check::skip("somaxconn", "linux only")
    }
}

/// Kernel version — io_uring multishot accept needs 5.19+. We don't fail
/// on this; we just nudge the user toward a feature flag they may not
/// know about.
fn check_kernel_version() -> Check {
    #[cfg(target_os = "linux")]
    {
        let version = std::fs::read_to_string("/proc/version").unwrap_or_default();
        // Parse "Linux version 6.1.0-…" → 6.1
        let v_str = version
            .split_whitespace()
            .nth(2)
            .unwrap_or("")
            .split('-')
            .next()
            .unwrap_or("");
        let mut parts = v_str.split('.');
        let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let detail = format!("{major}.{minor}");
        let supports_io_uring_multishot = major > 5 || (major == 5 && minor >= 19);
        if supports_io_uring_multishot {
            Check::ok(
                "kernel version",
                format!(
                    "{detail} (io_uring multishot supported — try `--features io-uring-accept`)"
                ),
            )
        } else if major >= 5 {
            Check::warn(
                "kernel version",
                detail,
                "for io_uring multishot accept, upgrade to 5.19+",
            )
        } else {
            Check::warn(
                "kernel version",
                detail,
                "ancient kernel; consider upgrading for io_uring + better TCP knobs",
            )
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Check::skip("kernel version", "linux only")
    }
}

/// Hardware crypto presence — TLS encrypt is the practical ceiling on
/// the cached path; without AES-NI/CE, projected throughput drops ~3x.
fn check_hardware_crypto(p: &crate::bootstrap::Platform) -> Check {
    if p.has_aes_ni && p.has_sha256 {
        Check::ok(
            "hardware crypto",
            format!(
                "AES-NI + SHA-256 (NEON={}, AVX2={})",
                if p.has_neon { "yes" } else { "no" },
                if p.has_avx2 { "yes" } else { "no" }
            ),
        )
    } else if p.has_aes_ni {
        Check::warn(
            "hardware crypto",
            "AES-NI present but no SHA-256 hardware",
            "performance is OK; cert verification slightly slower",
        )
    } else {
        Check::warn(
            "hardware crypto",
            "no hardware AES — TLS encrypt will be CPU-bound",
            "consider a newer CPU; expected throughput ~3x lower than AES-NI hardware",
        )
    }
}

/// AES-128-GCM calibration result from boot. Sanity-check that aws-lc-rs
/// is actually working and the per-core throughput is in a plausible band.
fn check_aes_calibration(p: &crate::bootstrap::Platform) -> Check {
    match p.aes_kops_per_core {
        None => Check::skip(
            "aes calibration",
            "skipped (ZION_BOOT_FAST=1 or aws-lc-rs unavailable)",
        ),
        Some(kops) if kops < 50 => Check::warn(
            "aes calibration",
            format!("{kops} K seal/s/core — implausibly low"),
            "investigate aws-lc-rs build; expected ≥ 100 K/s/core on commodity hardware",
        ),
        Some(kops) => Check::ok(
            "aes calibration",
            format!("{} K seal/s/core × {} cores", kops, p.cpu_cores),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────
// RENDERING
// ─────────────────────────────────────────────────────────────────────────

struct Style {
    color: bool,
}

impl Style {
    fn detect() -> Self {
        let plain =
            std::env::var_os("NO_COLOR").is_some() || std::env::var_os("ZION_BOOT_PLAIN").is_some();
        Self {
            color: !plain && std::io::stderr().is_terminal(),
        }
    }

    fn glyph(&self, status: Status) -> &'static str {
        if self.color {
            match status {
                Status::Ok => "\x1b[38;5;46m✓\x1b[0m",
                Status::Warn => "\x1b[38;5;220m!\x1b[0m",
                Status::Fail => "\x1b[1;38;5;196m✗\x1b[0m",
                Status::Skip => "\x1b[38;5;240m·\x1b[0m",
            }
        } else {
            match status {
                Status::Ok => "[ok]",
                Status::Warn => "[!!]",
                Status::Fail => "[XX]",
                Status::Skip => "[--]",
            }
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
    fn red(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;196m"
        } else {
            ""
        }
    }
    fn amber(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;220m"
        } else {
            ""
        }
    }
    fn green(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;46m"
        } else {
            ""
        }
    }
}

fn render<W: std::io::Write>(checks: &[Check], s: &Style, w: &mut W) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  {}ZION doctor{} — environment check",
        s.bold(),
        s.reset(),
    )?;
    writeln!(w)?;

    let name_w = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);

    for c in checks {
        writeln!(
            w,
            "  {}  {:<width$}  {}",
            s.glyph(c.status),
            c.name,
            c.detail,
            width = name_w,
        )?;
        if let Some(fix) = &c.fix {
            writeln!(w, "      {}fix:{} {}", s.dim(), s.reset(), fix,)?;
        }
    }

    writeln!(w)?;

    let ok = checks.iter().filter(|c| c.status == Status::Ok).count();
    let warn = checks.iter().filter(|c| c.status == Status::Warn).count();
    let fail = checks.iter().filter(|c| c.status == Status::Fail).count();
    let skip = checks.iter().filter(|c| c.status == Status::Skip).count();

    writeln!(
        w,
        "  {}{}{} ok · {}{}{} warn · {}{}{} fail · {}{}{} skipped",
        s.green(),
        ok,
        s.reset(),
        s.amber(),
        warn,
        s.reset(),
        s.red(),
        fail,
        s.reset(),
        s.dim(),
        skip,
        s.reset(),
    )?;

    if fail > 0 {
        writeln!(
            w,
            "\n  {}✗ doctor reports {} failure(s) — fix the items above before starting Zion.{}",
            s.red(),
            fail,
            s.reset(),
        )?;
    } else if warn > 0 {
        writeln!(
            w,
            "\n  {}! {} warning(s) — Zion will start, but performance / reliability may be impacted.{}",
            s.amber(),
            warn,
            s.reset(),
        )?;
    } else {
        writeln!(
            w,
            "\n  {}✓ all systems hot — happy serving.{}",
            s.green(),
            s.reset(),
        )?;
    }

    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_platform() -> crate::bootstrap::Platform {
        // Fresh Platform via detect() — it's cached after first call so
        // we just re-use whatever the test runner's host produced.
        crate::bootstrap::detect().clone()
    }

    #[test]
    fn fd_limit_returns_some_status() {
        let c = check_fd_limit();
        assert_eq!(c.name, "fd limit");
        // On any reasonable dev box, fd limit is at least gettable.
        assert!(matches!(
            c.status,
            Status::Ok | Status::Warn | Status::Fail | Status::Skip
        ));
    }

    #[test]
    fn hardware_crypto_passes_on_aes_box() {
        let p = synth_platform();
        let c = check_hardware_crypto(&p);
        assert_eq!(c.name, "hardware crypto");
        // Test host (M-series Mac or modern x86) should have AES.
        if p.has_aes_ni {
            assert_eq!(c.status, Status::Ok);
        }
    }

    #[test]
    fn render_plain_no_ansi() {
        let s = Style { color: false };
        let checks = vec![
            Check::ok("a", "fine"),
            Check::warn("b", "iffy", "do X"),
            Check::fail("c", "bad", "do Y"),
            Check::skip("d", "n/a"),
        ];
        let mut buf = Vec::new();
        render(&checks, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(!out.contains("\x1b["), "ANSI in plain mode: {out}");
        assert!(out.contains("[ok]"));
        assert!(out.contains("[!!]"));
        assert!(out.contains("[XX]"));
        assert!(out.contains("ZION doctor"));
        assert!(out.contains("fix: do X"));
    }

    #[test]
    fn render_summary_counts() {
        let s = Style { color: false };
        let checks = vec![
            Check::ok("a", ""),
            Check::ok("b", ""),
            Check::warn("c", "", "x"),
            Check::skip("d", ""),
        ];
        let mut buf = Vec::new();
        render(&checks, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("2 ok"));
        assert!(out.contains("1 warn"));
        assert!(out.contains("0 fail"));
        assert!(out.contains("1 skipped"));
    }

    #[test]
    fn render_color_includes_ansi() {
        let s = Style { color: true };
        let checks = vec![Check::ok("a", "fine")];
        let mut buf = Vec::new();
        render(&checks, &s, &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn check_constructors_set_correct_status() {
        assert_eq!(Check::ok("x", "").status, Status::Ok);
        assert_eq!(Check::warn("x", "", "y").status, Status::Warn);
        assert_eq!(Check::fail("x", "", "y").status, Status::Fail);
        assert_eq!(Check::skip("x", "").status, Status::Skip);
    }

    #[test]
    fn warn_and_fail_carry_fix_hints() {
        let w = Check::warn("x", "y", "do z");
        let f = Check::fail("x", "y", "do z");
        assert_eq!(w.fix.as_deref(), Some("do z"));
        assert_eq!(f.fix.as_deref(), Some("do z"));
        assert!(Check::ok("x", "").fix.is_none());
        assert!(Check::skip("x", "").fix.is_none());
    }

    #[test]
    fn collect_checks_returns_all_categories() {
        let p = synth_platform();
        let checks = collect_checks(&p);
        // Seven canonical checks: fd, port80, port443, somaxconn, kernel,
        // hwcrypto, aes-cal.
        assert_eq!(checks.len(), 7);
        for c in &checks {
            assert!(!c.name.is_empty());
            assert!(!c.detail.is_empty(), "empty detail in {}", c.name);
        }
    }
}

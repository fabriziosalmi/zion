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

/// The host/environment checks — deterministic, no config or network I/O, so
/// they're stable to unit-test. Always present regardless of deployment.
fn host_checks(p: &crate::bootstrap::Platform) -> Vec<Check> {
    vec![
        check_fd_limit(),
        check_memory_introspection(),
        check_privileged_port_80(),
        check_privileged_port_443(),
        check_somaxconn(),
        check_kernel_version(),
        check_hardware_crypto(p),
        check_aes_calibration(p),
    ]
}

fn collect_checks(p: &crate::bootstrap::Platform) -> Vec<Check> {
    let mut checks = host_checks(p);

    // ── Deploy-time checks ──
    // The checks above validate the host; these validate the actual deployment,
    // so a bad config or an unreachable backend is caught by `zion doctor`
    // BEFORE start, not at first request.
    let path = std::env::var("ZION_CONFIG").unwrap_or_else(|_| "zion.toml".to_string());
    if !std::path::Path::new(&path).exists() {
        checks.push(Check::skip(
            "config",
            format!("no config at {path} — run `zion init` or set ZION_CONFIG"),
        ));
    } else {
        match crate::config::load_config(&path) {
            Ok(cfg) => {
                checks.push(Check::ok("config", format!("{path} parses and validates")));
                checks.push(check_upstreams_reachable(&cfg));
                checks.push(check_security_posture(&cfg));
            }
            Err(e) => checks.push(Check::fail(
                "config",
                format!("{path}: {e}"),
                "fix the config error above, then re-run `zion doctor`",
            )),
        }
    }

    checks
}

/// Derive the `host:port` to probe from an upstream URL, defaulting the port by
/// scheme (https→443, else 80). Pure + unit-tested. `None` when the URL has no
/// host (already reported by config validation).
fn upstream_socket_addr(url: &str) -> Option<String> {
    let uri = url.parse::<hyper::Uri>().ok()?;
    let host = uri.host()?;
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    Some(format!("{host}:{port}"))
}

/// Resolve + TCP-connect `host:port`, BOUNDED end-to-end. `connect_timeout`
/// only caps the connect; `to_socket_addrs` (blocking libc `getaddrinfo`) has no
/// timeout and stalls for the OS resolver budget on a slow/blackholed DNS. Run
/// the whole probe on a detached thread and cap it with a `recv_timeout` so
/// `zion doctor` can't hang (a leaked thread on a hung resolver is fine for a
/// short-lived CLI). Returns false on timeout / unresolved / refused.
fn probe_reachable(addr: String) -> bool {
    use std::net::ToSocketAddrs;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ok = addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .map(|sa| {
                std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_millis(500))
                    .is_ok()
            })
            .unwrap_or(false);
        let _ = tx.send(ok);
    });
    rx.recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or(false)
}

/// Probe each configured upstream with a short TCP connect. **Warn**, not fail,
/// on unreachable — a backend may simply be booting — but surface it so a
/// typo'd host:port or a down backend is visible before the first request.
fn check_upstreams_reachable(cfg: &crate::config::ZionConfig) -> Check {
    let mut urls: Vec<String> = cfg.upstreams.values().cloned().collect();
    for up in cfg.upstream.values() {
        urls.extend(up.get_urls());
    }
    if urls.is_empty() {
        return Check::skip("upstreams", "no upstreams configured");
    }
    let mut unreachable = Vec::new();
    for url in &urls {
        let Some(addr) = upstream_socket_addr(url) else {
            continue; // malformed URL already reported by config validation
        };
        if !probe_reachable(addr) {
            unreachable.push(url.clone());
        }
    }
    if unreachable.is_empty() {
        Check::ok("upstreams", format!("{} reachable", urls.len()))
    } else {
        Check::warn(
            "upstreams",
            format!("unreachable: {}", unreachable.join(", ")),
            "start the backend(s) or fix host:port — transient if they're still booting",
        )
    }
}

/// Surface the security-relevant defaults that are *silently off*, so they're
/// a conscious operator choice rather than a surprise: per-IP request-rate
/// limiting (`rate_limit_rps = 0` = disabled) and WAF coverage (no route with a
/// `waf_profile` / `waf = true`). **Warn**, not fail — a gateway may legitimately
/// run without either, but the operator should know.
fn check_security_posture(cfg: &crate::config::ZionConfig) -> Check {
    let rate_off = cfg.server.rate_limit_rps == 0;
    let waf_routes = cfg
        .route
        .iter()
        .filter(|r| r.waf_profile.is_some() || r.waf)
        .count();
    let total = cfg.route.len();

    let mut notes = Vec::new();
    if rate_off {
        notes.push("per-IP request-rate limiting is OFF (server.rate_limit_rps = 0)".to_string());
    }
    if total > 0 && waf_routes == 0 {
        notes.push("WAF is not assigned to any route".to_string());
    }

    if notes.is_empty() {
        Check::ok(
            "posture",
            format!("rate-limit on; WAF on {waf_routes}/{total} routes"),
        )
    } else {
        Check::warn(
            "posture",
            notes.join("; "),
            "intentional? set server.rate_limit_rps and/or a route waf_profile to harden",
        )
    }
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

/// Memory-introspection readiness. The daemon populates the
/// `zion_process_resident_memory_bytes` gauge by reading `/proc/self/status`
/// (`VmRSS`); this preflight confirms that source is actually readable on
/// the deployment host and reports the current resident set size. In a
/// hardened container that masks `/proc`, this warns up front that the RSS
/// gauge will read 0 — so an operator doesn't discover a blind metric only
/// while chasing a leak in production.
fn check_memory_introspection() -> Check {
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status) => match status
                .lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse::<u64>().ok())
            {
                Some(kib) => Check::ok(
                    "memory introspection",
                    format!("VmRSS readable ({} MB) — /metrics RSS gauge active", kib / 1024),
                ),
                None => Check::warn(
                    "memory introspection",
                    "/proc/self/status exposes no VmRSS line",
                    "the zion_process_resident_memory_bytes gauge will report 0 here",
                ),
            },
            Err(e) => Check::warn(
                "memory introspection",
                format!("/proc/self/status unreadable: {e}"),
                "unmask /proc so the RSS / open-fd gauges can populate (some hardened container runtimes mask it)",
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Check::skip(
            "memory introspection",
            "RSS / open-fd gauges are Linux-only (sourced from /proc/self)",
        )
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

/// Kernel version — io_uring accept needs 5.19+. We don't fail
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
        let supports_io_uring_accept = major > 5 || (major == 5 && minor >= 19);
        if supports_io_uring_accept {
            Check::ok(
                "kernel version",
                format!("{detail} (io_uring accept supported — try `--features io-uring-accept`)"),
            )
        } else if major >= 5 {
            Check::warn(
                "kernel version",
                detail,
                "for io_uring accept, upgrade to 5.19+",
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
    fn upstream_socket_addr_defaults_port_by_scheme() {
        assert_eq!(
            upstream_socket_addr("http://127.0.0.1:8000").as_deref(),
            Some("127.0.0.1:8000")
        );
        assert_eq!(
            upstream_socket_addr("http://backend").as_deref(),
            Some("backend:80")
        );
        assert_eq!(
            upstream_socket_addr("https://backend").as_deref(),
            Some("backend:443")
        );
        assert_eq!(
            upstream_socket_addr("https://backend:9443").as_deref(),
            Some("backend:9443")
        );
        // No host (malformed) → None; config validation reports it separately.
        assert_eq!(upstream_socket_addr("not a url"), None);
    }

    #[test]
    fn security_posture_warns_when_protections_off() {
        // rate-limit defaulted off + no WAF on any route → Warn.
        let off = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
[tls]
cert_path = "/c"
key_path = "/k"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/{*rest}"
upstream = "be"
"#;
        let cfg: crate::config::ZionConfig = toml::from_str(off).unwrap();
        assert_eq!(check_security_posture(&cfg).status, Status::Warn);

        // rate-limit on + a WAF-protected route → Ok.
        let hardened = r#"
[server]
listen_http = "0.0.0.0:80"
listen_https = "0.0.0.0:443"
rate_limit_rps = 100
[tls]
cert_path = "/c"
key_path = "/k"
[upstreams]
be = "http://127.0.0.1:8000"
[[route]]
path = "/{*rest}"
upstream = "be"
waf = true
"#;
        let cfg2: crate::config::ZionConfig = toml::from_str(hardened).unwrap();
        assert_eq!(check_security_posture(&cfg2).status, Status::Ok);
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
        // Test the host checks (deterministic, no config/network I/O). The
        // eight canonical checks: fd, memory-introspection, port80, port443,
        // somaxconn, kernel, hwcrypto, aes-cal. (collect_checks() also appends
        // deploy-time config/upstream checks, which depend on the environment.)
        let checks = host_checks(&p);
        assert_eq!(checks.len(), 8);
        for c in &checks {
            assert!(!c.name.is_empty());
            assert!(!c.detail.is_empty(), "empty detail in {}", c.name);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! `zion init` — interactive zion.toml wizard.
//!
//! From zero to a running daemon in 30 seconds. The wizard:
//!   1. Greets the operator and shows detected hardware
//!   2. Probes common dev ports (3000, 5173, 8000, …) to suggest upstreams
//!   3. Prompts for hostname, upstreams, listener ports, TLS, WAF
//!   4. Writes a commented zion.toml plus (optionally) a self-signed cert
//!   5. Prints the next-step commands (run daemon, `zion top`, `zion doctor`)
//!
//! Both interactive and non-interactive modes are supported. The latter
//! drives adoption: CI bootstrap, container init scripts, or scripted
//! provisioning never need a TTY.
//!
//! Self-signed certificate generation requires the `init` cargo feature
//! (which pulls `rcgen`). Without the feature, the wizard falls back to
//! printing the equivalent `openssl` command for the operator to run.

use crate::cli::{AutoOpts, InitOpts};
use std::io::{IsTerminal, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_millis(80);

/// A port we probed and found something listening on. The hint is a best
/// guess from the port number — we don't actually fingerprint the service.
#[derive(Debug, Clone)]
struct DetectedService {
    port: u16,
    hint: &'static str,
    suggested_name: &'static str,
}

/// Common dev/server ports to probe. Order matters — the first match
/// becomes the suggested catch-all upstream.
const COMMON_PORTS: &[(u16, &str, &str)] = &[
    (3000, "Node / Next.js / React dev", "frontend"),
    (5173, "Vite dev server", "frontend"),
    (4000, "Phoenix / Elixir", "backend"),
    (5000, "Flask / .NET / generic", "backend"),
    (8000, "Django / FastAPI / generic", "backend"),
    (8080, "generic HTTP / Tomcat", "backend"),
    (8081, "generic HTTP", "backend"),
    (9000, "PHP-FPM / SonarQube", "backend"),
    (3001, "alternate Node", "frontend"),
];

/// Resolved configuration the wizard writes out. Built from CLI flags,
/// detected services, and (in interactive mode) operator answers.
#[derive(Debug, Clone)]
struct ResolvedInit {
    output: String,
    force: bool,
    hostname: String,
    upstreams: Vec<(String, String)>, // (name, host:port)
    http_port: u16,
    https_port: u16,
    gen_tls: bool,
    cert_path: String,
    key_path: String,
    with_waf: bool,
}

/// Run the wizard. Returns the exit code the caller should use:
///   0 — config written successfully
///   1 — refused to overwrite (no --force) / user aborted
///   2 — fatal error (I/O, etc.)
pub fn run(opts: InitOpts) -> i32 {
    let style = Style::detect();
    let mut stderr = std::io::stderr().lock();
    let _ = print_header(&style, &mut stderr);

    let platform = crate::bootstrap::detect();
    let _ = print_platform_summary(platform, &style, &mut stderr);

    let detected = scan_local_ports();
    let _ = print_scan_results(&detected, &style, &mut stderr);

    let resolved = if opts.non_interactive {
        build_non_interactive(opts, &detected)
    } else {
        match build_interactive(opts, &detected, &style, &mut stderr) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("init: {e}");
                return 2;
            }
        }
    };

    // Existing-file gate. Default protective.
    if Path::new(&resolved.output).exists() && !resolved.force {
        eprintln!(
            "\n  {}error:{} {} already exists — pass --force to overwrite",
            style.red(),
            style.reset(),
            resolved.output,
        );
        return 1;
    }

    // Generate TLS cert (or print openssl fallback) before writing the
    // config so the config can reference paths that actually exist.
    if resolved.gen_tls {
        match generate_tls_cert(&resolved) {
            CertOutcome::Generated => {
                let _ = writeln!(
                    stderr,
                    "  {}✓{} wrote {} + {} (self-signed, valid 365 days, CN={})",
                    style.green(),
                    style.reset(),
                    resolved.cert_path,
                    resolved.key_path,
                    resolved.hostname,
                );
            }
            CertOutcome::FeatureMissing => {
                let _ = print_openssl_fallback(&resolved, &style, &mut stderr);
            }
            CertOutcome::Failed(e) => {
                eprintln!(
                    "  {}✗ cert generation failed:{} {}",
                    style.red(),
                    style.reset(),
                    e
                );
                let _ = print_openssl_fallback(&resolved, &style, &mut stderr);
            }
        }
    }

    let toml = render_toml(&resolved);
    if let Err(e) = std::fs::write(&resolved.output, &toml) {
        eprintln!("error: failed to write {}: {}", resolved.output, e);
        return 2;
    }

    let _ = writeln!(
        stderr,
        "  {}✓{} wrote {} ({} lines)",
        style.green(),
        style.reset(),
        resolved.output,
        toml.lines().count(),
    );
    let _ = print_next_steps(&resolved, &style, &mut stderr);
    0
}

// ─────────────────────────────────────────────────────────────────────────
// AUTO MODE — one-shot dev / demo with no config files on disk
// ─────────────────────────────────────────────────────────────────────────

/// Prepare an ephemeral TLS cert + zion.toml in the OS temp dir, set
/// `ZION_CONFIG` so the daemon entry point picks it up, and return the
/// config path. Caller (main) falls through to the normal daemon code.
///
/// Cert + config live in `$TMPDIR/zion-auto-{pid}/` and are NOT cleaned up
/// on shutdown — they're tiny, the OS will reclaim the tempdir, and
/// keeping them lets the operator re-run `zion auto` quickly without
/// regenerating certs.
#[cfg(feature = "init")]
pub fn run_auto(opts: AutoOpts) -> Result<PathBuf, String> {
    use rcgen::generate_simple_self_signed;

    let dir = std::env::temp_dir().join(format!("zion-auto-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir:?}: {e}"))?;

    let cert_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    let config_path = dir.join("zion.toml");

    // Self-signed cert with both the user-chosen hostname and `localhost`
    // as SANs so https://localhost:<port> works regardless of --hostname.
    let mut sans = vec![opts.hostname.clone()];
    if opts.hostname != "localhost" {
        sans.push("localhost".to_string());
    }
    let cert = generate_simple_self_signed(sans).map_err(|e| format!("rcgen: {e}"))?;
    std::fs::write(&cert_path, cert.cert.pem()).map_err(|e| format!("write {cert_path:?}: {e}"))?;
    std::fs::write(&key_path, cert.signing_key.serialize_pem())
        .map_err(|e| format!("write {key_path:?}: {e}"))?;

    let toml = format!(
        "# zion auto-mode — generated for one-shot dev / demo use.\n\
         # Tied to PID {pid}; regenerated on every `zion auto` invocation.\n\
         \n\
         [server]\n\
         listen_http  = \"0.0.0.0:{http_port}\"\n\
         listen_https = \"0.0.0.0:{https_port}\"\n\
         \n\
         [tls]\n\
         cert_path = \"{cert}\"\n\
         key_path  = \"{key}\"\n\
         hot_reload  = false\n\
         min_version = \"1.3\"\n\
         alpn        = [\"h2\", \"http/1.1\"]\n\
         \n\
         [upstream.backend]\n\
         url                = \"http://{upstream}\"\n\
         connect_timeout_ms = 3000\n\
         keepalive          = 32\n\
         \n\
         [[route]]\n\
         path     = \"/{{*rest}}\"\n\
         upstream = \"backend\"\n",
        pid = std::process::id(),
        http_port = opts.http_port,
        https_port = opts.https_port,
        cert = cert_path.display(),
        key = key_path.display(),
        upstream = opts.upstream,
    );
    std::fs::write(&config_path, &toml).map_err(|e| format!("write {config_path:?}: {e}"))?;

    // Set ZION_CONFIG so the existing daemon entry point picks it up
    // verbatim — no refactor of async_main needed.
    // SAFETY: process is single-threaded at this point (we run before the
    // tokio runtime is built), so set_var is safe. Any future change that
    // moves auto-mode prep behind multi-threaded code MUST revisit this.
    unsafe {
        std::env::set_var("ZION_CONFIG", &config_path);
    }

    Ok(config_path)
}

#[cfg(not(feature = "init"))]
pub fn run_auto(_opts: AutoOpts) -> Result<PathBuf, String> {
    Err(
        "zion auto requires the `init` feature for self-signed cert generation.\n  \
         rebuild with: cargo build --release --features init"
            .to_string(),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// PORT SCANNING
// ─────────────────────────────────────────────────────────────────────────

fn scan_local_ports() -> Vec<DetectedService> {
    let mut out = Vec::new();
    for &(port, hint, name) in COMMON_PORTS {
        if probe_port(port) {
            out.push(DetectedService {
                port,
                hint,
                suggested_name: name,
            });
        }
    }
    out
}

fn probe_port(port: u16) -> bool {
    let addr: SocketAddr = match format!("127.0.0.1:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────
// INTERACTIVE / NON-INTERACTIVE BUILDERS
// ─────────────────────────────────────────────────────────────────────────

fn build_interactive<W: Write>(
    opts: InitOpts,
    detected: &[DetectedService],
    style: &Style,
    w: &mut W,
) -> std::io::Result<ResolvedInit> {
    writeln!(w)?;

    // Hostname
    let default_host = opts.hostname.clone().unwrap_or_else(|| "localhost".into());
    let hostname = prompt("hostname Zion will serve", &default_host)?;

    // Upstreams: pre-declared via --upstream + interactively confirmed for each scan hit.
    let mut upstreams = opts.upstreams.clone();
    if !detected.is_empty() {
        writeln!(w)?;
        writeln!(
            w,
            "  {}for each detected port, accept it?{}",
            style.dim(),
            style.reset()
        )?;
        for d in detected {
            // Skip if a CLI --upstream already covers this port.
            let already = opts
                .upstreams
                .iter()
                .any(|(_, target)| target.ends_with(&format!(":{}", d.port)));
            if already {
                continue;
            }
            let label = format!(
                "    use :{} ({}) as upstream \"{}\"?",
                d.port, d.hint, d.suggested_name
            );
            if prompt_yn(&label, true)? {
                // Avoid duplicate names when the operator added one manually.
                let name = unique_name(&upstreams, d.suggested_name);
                upstreams.push((name, format!("127.0.0.1:{}", d.port)));
            }
        }
    }

    // Fallback: at least one upstream is required for a valid config.
    if upstreams.is_empty() {
        writeln!(w)?;
        writeln!(
            w,
            "  {}no upstreams chosen — need at least one to write a working config{}",
            style.amber(),
            style.reset()
        )?;
        let target = prompt("upstream target (host:port)", "127.0.0.1:8080")?;
        upstreams.push(("backend".into(), target));
    }

    writeln!(w)?;

    // Ports
    let http_port = parse_port(
        prompt("HTTP listen port", &port_default(opts.http_port, 80))?,
        80,
    );
    let https_port = parse_port(
        prompt("HTTPS listen port", &port_default(opts.https_port, 443))?,
        443,
    );

    // TLS
    let gen_tls = if !opts.with_tls {
        false
    } else {
        prompt_yn("generate self-signed TLS certificate?", true)?
    };

    // WAF
    let with_waf = if !opts.with_waf {
        false
    } else {
        let has_api_or_backend = upstreams.iter().any(|(n, _)| n == "api" || n == "backend");
        if has_api_or_backend {
            prompt_yn("enable WAF on /api/{*rest} routes?", true)?
        } else {
            // No /api route to attach to — silently skip.
            false
        }
    };

    Ok(ResolvedInit {
        output: opts.output,
        force: opts.force,
        hostname,
        upstreams,
        http_port,
        https_port,
        gen_tls,
        cert_path: "tls/server.crt".into(),
        key_path: "tls/server.key".into(),
        with_waf,
    })
}

fn build_non_interactive(opts: InitOpts, detected: &[DetectedService]) -> ResolvedInit {
    let hostname = opts.hostname.clone().unwrap_or_else(|| "localhost".into());

    let mut upstreams = opts.upstreams.clone();
    if upstreams.is_empty() {
        // Auto-add anything we detected, deduped by suggested name.
        for d in detected {
            let name = unique_name(&upstreams, d.suggested_name);
            upstreams.push((name, format!("127.0.0.1:{}", d.port)));
        }
        if upstreams.is_empty() {
            // Last-resort default so the file is at least valid.
            upstreams.push(("backend".into(), "127.0.0.1:8080".into()));
        }
    }

    ResolvedInit {
        output: opts.output,
        force: opts.force,
        hostname,
        upstreams,
        http_port: opts.http_port.unwrap_or(80),
        https_port: opts.https_port.unwrap_or(443),
        gen_tls: opts.with_tls,
        cert_path: "tls/server.crt".into(),
        key_path: "tls/server.key".into(),
        with_waf: opts.with_waf,
    }
}

fn unique_name(existing: &[(String, String)], proposed: &str) -> String {
    if !existing.iter().any(|(n, _)| n == proposed) {
        return proposed.to_string();
    }
    for i in 2..100 {
        let candidate = format!("{proposed}{i}");
        if !existing.iter().any(|(n, _)| n == &candidate) {
            return candidate;
        }
    }
    proposed.to_string()
}

fn parse_port(s: String, default: u16) -> u16 {
    s.parse().unwrap_or(default)
}

fn port_default(opt: Option<u16>, fallback: u16) -> String {
    opt.unwrap_or(fallback).to_string()
}

// ─────────────────────────────────────────────────────────────────────────
// PROMPTS
// ─────────────────────────────────────────────────────────────────────────

fn prompt(label: &str, default: &str) -> std::io::Result<String> {
    print!("  {label} [{default}]: ");
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let s = buf.trim();
    Ok(if s.is_empty() {
        default.to_string()
    } else {
        s.to_string()
    })
}

fn prompt_yn(label: &str, default_yes: bool) -> std::io::Result<bool> {
    let suffix = if default_yes { "Y/n" } else { "y/N" };
    print!("  {label} [{suffix}]: ");
    std::io::stdout().flush().ok();
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let s = buf.trim().to_lowercase();
    Ok(if s.is_empty() {
        default_yes
    } else {
        matches!(s.as_str(), "y" | "yes")
    })
}

// ─────────────────────────────────────────────────────────────────────────
// TOML RENDERING (hand-rolled for educational comments)
// ─────────────────────────────────────────────────────────────────────────

fn render_toml(r: &ResolvedInit) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str(&format!(
        "# zion.toml — generated by `zion init` on {}\n",
        ymd_today()
    ));
    out.push_str("# Hostname: ");
    out.push_str(&r.hostname);
    out.push_str(
        "\n# Edit freely. See zion.example.toml for the full reference.\n\n[server]\nlisten_http  = \"0.0.0.0:",
    );
    out.push_str(&r.http_port.to_string());
    out.push_str("\"\nlisten_https = \"0.0.0.0:");
    out.push_str(&r.https_port.to_string());
    out.push_str("\"\n\n[tls]\ncert_path = \"");
    out.push_str(&r.cert_path);
    out.push_str("\"\nkey_path  = \"");
    out.push_str(&r.key_path);
    out.push_str(
        "\"\nhot_reload  = true\nmin_version = \"1.3\"\nalpn        = [\"h2\", \"http/1.1\"]\n\n",
    );

    // Upstreams (modern named-section format)
    out.push_str("# ── Upstreams ────────────────────────────────────────────\n");
    for (name, target) in &r.upstreams {
        out.push_str(&format!(
            "[upstream.{name}]\nurl                = \"http://{target}\"\nconnect_timeout_ms = 3000\nkeepalive          = 32\n\n"
        ));
    }

    // Decide routing layout up-front so the WAF profile block is only
    // emitted when a route actually uses it.
    let catchall = r
        .upstreams
        .iter()
        .find(|(n, _)| n == "frontend")
        .unwrap_or(&r.upstreams[0]);
    let api_upstream = r
        .upstreams
        .iter()
        .find(|(n, _)| n == "api")
        .or_else(|| r.upstreams.iter().find(|(n, _)| n == "backend"));
    let split_api = match api_upstream {
        Some((api_name, _)) => api_name != &catchall.0,
        None => false,
    };
    let waf_attaches = r.with_waf && split_api;

    if waf_attaches {
        out.push_str("# ── WAF profile ──────────────────────────────────────────\n");
        out.push_str(
            "[waf_profile.strict]\nmax_body_mb                = 10\nmax_depth                  = 10\nmax_string_len             = 1048576\ndeny_unknown_content_types = true\nallowed_content_types      = [\"application/json\", \"multipart/form-data\"]\n\n",
        );
    }

    // Routes — always emit a catch-all so requests don't 404 by default.
    // Emit a dedicated /api/{*rest} route only when there are 2+ upstreams
    // and the api/backend upstream is distinct from the catch-all.
    out.push_str("# ── Routes (matched via radix tree, ~30 ns lookup) ──────\n");
    if split_api {
        let (api_name, _) = api_upstream.unwrap();
        out.push_str(&format!(
            "[[route]]\npath     = \"/api/{{*rest}}\"\nupstream = \"{api_name}\"\n"
        ));
        if waf_attaches {
            out.push_str("waf_profile = \"strict\"\n");
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "[[route]]\npath     = \"/{{*rest}}\"\nupstream = \"{}\"\n",
        catchall.0
    ));

    out
}

fn ymd_today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64 + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_val = doy - (153 * mp + 2) / 5 + 1;
    let m_val = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_val = if m_val <= 2 { y + 1 } else { y };
    format!("{y_val:04}-{m_val:02}-{d_val:02}")
}

// ─────────────────────────────────────────────────────────────────────────
// CERT GENERATION (gated behind `init` feature)
// ─────────────────────────────────────────────────────────────────────────

/// `Generated` and `Failed` are constructed only by `generate_tls_cert`,
/// which is `#[cfg(feature = "init")]`. Without the feature the enum is
/// still defined (the dispatch in `run_init` handles it shape-stable) but
/// only `FeatureMissing` is reachable.
#[allow(dead_code)]
enum CertOutcome {
    Generated,
    FeatureMissing,
    Failed(String),
}

#[cfg(feature = "init")]
fn generate_tls_cert(r: &ResolvedInit) -> CertOutcome {
    use rcgen::generate_simple_self_signed;

    let mut sans = vec![r.hostname.clone()];
    if r.hostname != "localhost" {
        sans.push("localhost".to_string());
    }

    let cert = match generate_simple_self_signed(sans) {
        Ok(c) => c,
        Err(e) => return CertOutcome::Failed(format!("rcgen: {e}")),
    };

    // Ensure parent dir exists for both files.
    if let Some(parent) = Path::new(&r.cert_path).parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return CertOutcome::Failed(format!("mkdir {parent:?}: {e}"));
        }
    }
    if let Some(parent) = Path::new(&r.key_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Err(e) = std::fs::write(&r.cert_path, cert.cert.pem()) {
        return CertOutcome::Failed(format!("write {}: {}", r.cert_path, e));
    }
    if let Err(e) = std::fs::write(&r.key_path, cert.signing_key.serialize_pem()) {
        return CertOutcome::Failed(format!("write {}: {}", r.key_path, e));
    }

    CertOutcome::Generated
}

#[cfg(not(feature = "init"))]
fn generate_tls_cert(_r: &ResolvedInit) -> CertOutcome {
    CertOutcome::FeatureMissing
}

// ─────────────────────────────────────────────────────────────────────────
// OUTPUT (rendering helpers)
// ─────────────────────────────────────────────────────────────────────────

fn print_header<W: Write>(s: &Style, w: &mut W) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  {}{}ZION init{}{} — let's get you running",
        s.bold(),
        s.cyan(),
        s.reset(),
        s.reset(),
    )
}

fn print_platform_summary<W: Write>(
    p: &crate::bootstrap::Platform,
    s: &Style,
    w: &mut W,
) -> std::io::Result<()> {
    writeln!(
        w,
        "  {}✓{} detected: {}{} / {} · {} cores · {} MB RAM{}",
        s.green(),
        s.reset(),
        s.dim(),
        p.os,
        p.arch,
        p.cpu_cores,
        p.ram_mb,
        s.reset(),
    )
}

fn print_scan_results<W: Write>(
    detected: &[DetectedService],
    s: &Style,
    w: &mut W,
) -> std::io::Result<()> {
    writeln!(w)?;
    if detected.is_empty() {
        writeln!(
            w,
            "  {}no listening services detected on common dev ports{}",
            s.dim(),
            s.reset(),
        )
    } else {
        writeln!(
            w,
            "  {}detected listening services on common dev ports:{}",
            s.dim(),
            s.reset()
        )?;
        for d in detected {
            writeln!(
                w,
                "    {}●{} :{:<5} {}({})",
                s.green(),
                s.reset(),
                d.port,
                s.dim(),
                d.hint,
            )?;
        }
        Ok(())
    }
}

fn print_next_steps<W: Write>(r: &ResolvedInit, s: &Style, w: &mut W) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(w, "  {}done.{} run with:", s.bold(), s.reset())?;
    writeln!(
        w,
        "    {}ZION_CONFIG={} ./zion{}",
        s.cyan(),
        r.output,
        s.reset()
    )?;
    writeln!(w)?;
    writeln!(w, "  also available:")?;
    writeln!(
        w,
        "    {}./zion top{}     {}— live dashboard{}",
        s.cyan(),
        s.reset(),
        s.dim(),
        s.reset()
    )?;
    writeln!(
        w,
        "    {}./zion doctor{}  {}— environment check{}",
        s.cyan(),
        s.reset(),
        s.dim(),
        s.reset()
    )?;
    writeln!(w)
}

fn print_openssl_fallback<W: Write>(r: &ResolvedInit, s: &Style, w: &mut W) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  {}!{} self-signed cert generation requires `--features init`",
        s.amber(),
        s.reset()
    )?;
    writeln!(
        w,
        "    rebuild zion with: cargo build --release --features init"
    )?;
    writeln!(w, "    or generate the cert externally:")?;
    writeln!(
        w,
        "      {}mkdir -p tls && openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \\\n        -keyout {} -out {} \\\n        -subj \"/CN={}\" -addext \"subjectAltName=DNS:{},DNS:localhost,IP:127.0.0.1\"{}",
        s.dim(),
        r.key_path,
        r.cert_path,
        r.hostname,
        r.hostname,
        s.reset(),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// STYLE
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
    fn bold(&self) -> &'static str {
        if self.color {
            "\x1b[1m"
        } else {
            ""
        }
    }
    fn dim(&self) -> &'static str {
        if self.color {
            "\x1b[2m"
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
    fn green(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;46m"
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
    fn red(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;196m"
        } else {
            ""
        }
    }
    fn cyan(&self) -> &'static str {
        if self.color {
            "\x1b[38;5;51m"
        } else {
            ""
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::InitOpts;

    fn opts_with_upstreams(pairs: &[(&str, &str)]) -> InitOpts {
        InitOpts {
            non_interactive: true,
            upstreams: pairs
                .iter()
                .map(|(n, t)| (n.to_string(), t.to_string()))
                .collect(),
            ..InitOpts::default()
        }
    }

    #[test]
    fn unique_name_dedupes() {
        let existing = vec![
            ("backend".into(), "x".into()),
            ("backend2".into(), "x".into()),
        ];
        assert_eq!(unique_name(&existing, "frontend"), "frontend");
        assert_eq!(unique_name(&existing, "backend"), "backend3");
    }

    #[test]
    fn build_non_interactive_uses_explicit_upstreams() {
        let opts = opts_with_upstreams(&[("backend", "127.0.0.1:8000")]);
        let r = build_non_interactive(opts, &[]);
        assert_eq!(r.upstreams.len(), 1);
        assert_eq!(r.upstreams[0].0, "backend");
        assert_eq!(r.http_port, 80);
        assert_eq!(r.https_port, 443);
        assert!(r.gen_tls);
        assert!(r.with_waf);
    }

    #[test]
    fn build_non_interactive_uses_detected_when_no_explicit() {
        let opts = InitOpts {
            non_interactive: true,
            ..InitOpts::default()
        };
        let detected = vec![DetectedService {
            port: 3000,
            hint: "Node",
            suggested_name: "frontend",
        }];
        let r = build_non_interactive(opts, &detected);
        assert_eq!(r.upstreams.len(), 1);
        assert_eq!(r.upstreams[0].0, "frontend");
        assert_eq!(r.upstreams[0].1, "127.0.0.1:3000");
    }

    #[test]
    fn build_non_interactive_falls_back_to_default() {
        let opts = InitOpts {
            non_interactive: true,
            ..InitOpts::default()
        };
        let r = build_non_interactive(opts, &[]);
        assert_eq!(r.upstreams.len(), 1);
        assert_eq!(r.upstreams[0].1, "127.0.0.1:8080");
    }

    #[test]
    fn render_toml_contains_essentials() {
        let r = ResolvedInit {
            output: "zion.toml".into(),
            force: false,
            hostname: "example.com".into(),
            upstreams: vec![
                ("frontend".into(), "127.0.0.1:3000".into()),
                ("backend".into(), "127.0.0.1:8000".into()),
            ],
            http_port: 80,
            https_port: 443,
            gen_tls: true,
            cert_path: "tls/server.crt".into(),
            key_path: "tls/server.key".into(),
            with_waf: true,
        };
        let toml = render_toml(&r);
        // Essentials
        assert!(toml.contains("listen_http  = \"0.0.0.0:80\""));
        assert!(toml.contains("listen_https = \"0.0.0.0:443\""));
        assert!(toml.contains("[upstream.frontend]"));
        assert!(toml.contains("[upstream.backend]"));
        assert!(toml.contains("url                = \"http://127.0.0.1:3000\""));
        assert!(toml.contains("url                = \"http://127.0.0.1:8000\""));
        // Routes
        assert!(toml.contains("path     = \"/api/{*rest}\""));
        assert!(toml.contains("upstream = \"backend\""));
        assert!(toml.contains("waf_profile = \"strict\""));
        assert!(toml.contains("path     = \"/{*rest}\""));
        assert!(toml.contains("upstream = \"frontend\""));
        // TLS
        assert!(toml.contains("cert_path = \"tls/server.crt\""));
        assert!(toml.contains("key_path  = \"tls/server.key\""));
    }

    #[test]
    fn render_toml_skips_waf_when_disabled() {
        let r = ResolvedInit {
            output: "zion.toml".into(),
            force: false,
            hostname: "x".into(),
            upstreams: vec![("backend".into(), "127.0.0.1:8000".into())],
            http_port: 80,
            https_port: 443,
            gen_tls: false,
            cert_path: "tls/server.crt".into(),
            key_path: "tls/server.key".into(),
            with_waf: false,
        };
        let toml = render_toml(&r);
        assert!(!toml.contains("waf_profile"));
        assert!(!toml.contains("[waf_profile.strict]"));
    }

    #[test]
    fn render_toml_single_backend_upstream_emits_only_catchall() {
        // With one upstream named "backend", /api/* and catch-all would
        // both target backend. We collapse to a single catch-all so there
        // are no redundant routes — and skip the WAF profile block since
        // no route would reference it.
        let r = ResolvedInit {
            output: "zion.toml".into(),
            force: false,
            hostname: "x".into(),
            upstreams: vec![("backend".into(), "127.0.0.1:8000".into())],
            http_port: 80,
            https_port: 443,
            gen_tls: false,
            cert_path: "tls/server.crt".into(),
            key_path: "tls/server.key".into(),
            with_waf: true,
        };
        let toml = render_toml(&r);
        assert!(
            !toml.contains("/api/"),
            "should not split /api/ on single upstream: {toml}"
        );
        assert!(
            !toml.contains("[waf_profile.strict]"),
            "should not emit WAF block: {toml}"
        );
        assert!(toml.contains("path     = \"/{*rest}\""));
        assert!(toml.contains("upstream = \"backend\""));
    }

    #[test]
    fn render_toml_skips_api_route_without_backend() {
        let r = ResolvedInit {
            output: "zion.toml".into(),
            force: false,
            hostname: "x".into(),
            upstreams: vec![("frontend".into(), "127.0.0.1:3000".into())],
            http_port: 80,
            https_port: 443,
            gen_tls: false,
            cert_path: "tls/server.crt".into(),
            key_path: "tls/server.key".into(),
            with_waf: true,
        };
        let toml = render_toml(&r);
        // Only frontend → no /api/* route to attach
        assert!(!toml.contains("/api/"));
        assert!(toml.contains("path     = \"/{*rest}\""));
        assert!(toml.contains("upstream = \"frontend\""));
    }

    #[test]
    fn ymd_today_is_iso_like() {
        let s = ymd_today();
        assert_eq!(s.len(), 10);
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
    }

    #[test]
    fn parse_port_falls_back_on_garbage() {
        assert_eq!(parse_port("not-a-number".into(), 80), 80);
        assert_eq!(parse_port("8080".into(), 80), 8080);
    }
}

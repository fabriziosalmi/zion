// SPDX-License-Identifier: Apache-2.0
//! Tiny zero-dep CLI dispatcher.
//!
//! Zion historically took zero positional arguments — everything was env-driven
//! (`ZION_CONFIG=zion.toml`). We keep that as the default behavior so existing
//! systemd units and Dockerfiles work untouched. New subcommands are additive:
//!
//!   zion              # run the daemon (default)
//!   zion top          # live TUI dashboard (requires --features tui)
//!   zion top --url http://10.0.0.5/_zion/snapshot.json --interval 250
//!   zion --version    # version
//!   zion --help       # help
//!
//! No clap, no structopt — argv parsing is trivial and the deps would dwarf
//! the logic.

#[derive(Debug, Clone)]
pub enum Command {
    /// Run the gateway daemon. The default.
    Daemon,
    /// Launch the live TUI dashboard.
    Top(TopOpts),
    /// Run environment diagnostic checks and exit.
    Doctor,
    /// Generate a `zion.toml` from prompts (or flags) and optional certs.
    Init(InitOpts),
    /// Print the detected platform capabilities as JSON to stdout and exit.
    /// Shape matches the `platform` field of `/_zion/snapshot.json` so a
    /// consumer can use the same schema for live runtime polling and
    /// boot-time provisioning.
    Bootstrap,
    /// One-shot dev / demo mode: generate a self-signed cert + ephemeral
    /// config in a temp dir and run the daemon, no `zion.toml` on disk.
    /// `zion --auto --upstream=:3000` is the fastest path from "I have a
    /// backend" to "TLS in front of it" with zero config files.
    Auto(AutoOpts),
    /// Synthesize a validated `zion.toml` from detected signals (a listening
    /// backend, or `--upstream` / `--domain` hints) and print it (or `--write`
    /// it). Deterministic, no ML, self-validated by the config parser (#133).
    Suggest(SuggestOpts),
    /// Convert a foreign proxy config (nginx) into a validated `zion.toml`
    /// with an honest findings report (ADR-0011). Self-validated like suggest.
    Import(ImportOpts),
    /// Print version and exit 0.
    Version,
    /// Print help and exit 0.
    Help,
    /// Drive a full ACME issue → renew → revoke cycle against the
    /// directory in `ZION_ACME_TEST_*` env vars and exit (issue #59).
    /// Hidden: only the soak workflow / CI invokes it. Requires the
    /// `acme` feature; without it the subcommand prints a hint and exits.
    AcmeSoak,
    /// Unknown subcommand — print help to stderr and exit 1.
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct TopOpts {
    /// Full URL of the snapshot endpoint. Defaults to the localhost HTTP port.
    pub url: String,
    /// Poll interval in milliseconds (TUI redraws on each poll).
    pub interval_ms: u64,
}

impl Default for TopOpts {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:80/_zion/snapshot.json".to_string(),
            interval_ms: 500,
        }
    }
}

/// Options for `zion suggest`. All optional — with none, it scans localhost
/// for a backend and emits a config to stdout.
#[derive(Debug, Clone, Default)]
pub struct SuggestOpts {
    /// Upstream hint: `:3000`, `3000`, `host:port`. None = scan localhost.
    pub upstream: Option<String>,
    /// Domain for the TLS cert path hint. None = "localhost".
    pub domain: Option<String>,
    /// Write the (validated) config to this path instead of stdout.
    pub write: Option<String>,
}

/// Options for `zion import <source> <input>` (ADR-0011).
#[derive(Debug, Clone, Default)]
pub struct ImportOpts {
    /// Source format: `nginx` or `traefik`; empty = usage error.
    pub source: String,
    /// Input config path, or `-` for stdin.
    pub input: Option<String>,
    /// Write the converted config here instead of stdout.
    pub output: Option<String>,
    /// Write the full findings report here (stderr always gets the summary).
    pub report: Option<String>,
    /// Exit non-zero when any partial/unsupported finding exists.
    pub strict: bool,
    /// `--var KEY=VALUE` overrides for `${...}` expansion (traefik front-end);
    /// these win over a `.env` next to the compose file.
    pub vars: Vec<(String, String)>,
}

/// Options for `zion init`. All flags are additive — the wizard fills in
/// anything the operator didn't specify, prompting interactively unless
/// `--non-interactive` is set.
#[derive(Debug, Clone)]
pub struct InitOpts {
    /// Where to write the config file. Defaults to `./zion.toml`.
    pub output: String,
    /// Overwrite an existing config without prompting.
    pub force: bool,
    /// Skip all prompts and use defaults / detected values.
    pub non_interactive: bool,
    /// Hostname Zion will serve. None = "localhost" or prompt-driven.
    pub hostname: Option<String>,
    /// Pre-declared upstream services as `name=host:port`. Empty = scan
    /// local ports and ask, or skip in non-interactive mode.
    pub upstreams: Vec<(String, String)>,
    /// HTTP listener port override. None = 80 default.
    pub http_port: Option<u16>,
    /// HTTPS listener port override. None = 443 default.
    pub https_port: Option<u16>,
    /// Generate a self-signed TLS certificate (requires `--features init`).
    /// Defaults to true; flip with `--no-tls`.
    pub with_tls: bool,
    /// Add a WAF-enabled `/api/{*rest}` route when an upstream named "api"
    /// or "backend" is configured. Flip with `--no-waf`.
    pub with_waf: bool,
    /// Automatic HTTPS via Let's Encrypt. `None` = heuristic (on for a public
    /// hostname, off for localhost / an IP); `Some` forced by `--acme` /
    /// `--no-acme`.
    pub acme: Option<bool>,
    /// Contact email for the Let's Encrypt account (required when ACME is on).
    pub acme_email: Option<String>,
    /// Domains to obtain a certificate for. Empty = the served hostname.
    pub acme_domains: Vec<String>,
}

/// Options for `zion auto` (no-config dev mode). Bare minimum to point Zion
/// at a backend and serve TLS in front of it. Defaults match a typical
/// `npm run dev` style local environment.
#[derive(Debug, Clone)]
pub struct AutoOpts {
    /// Backend to proxy to. Format: `host:port` (host defaults to 127.0.0.1
    /// if just `:port` is given, e.g. `:3000`). No scheme — auto mode is
    /// HTTP-to-upstream only by design.
    pub upstream: String,
    /// HTTP listener port. Default: 80 if running as root, else 8080.
    pub http_port: u16,
    /// HTTPS listener port. Default: 443 if running as root, else 8443.
    pub https_port: u16,
    /// SAN to bake into the self-signed cert. Default: `localhost`.
    pub hostname: String,
}

impl Default for AutoOpts {
    fn default() -> Self {
        // Default to unprivileged ports — auto mode is for dev / demo /
        // throwaway use, not production. A user with CAP_NET_BIND_SERVICE
        // (or root) who wants :443 explicitly can pass --https-port=443.
        Self {
            upstream: "127.0.0.1:3000".to_string(),
            http_port: 8080,
            https_port: 8443,
            hostname: "localhost".to_string(),
        }
    }
}

impl Default for InitOpts {
    fn default() -> Self {
        Self {
            output: "zion.toml".to_string(),
            force: false,
            non_interactive: false,
            hostname: None,
            upstreams: Vec::new(),
            http_port: None,
            https_port: None,
            with_tls: true,
            with_waf: true,
            acme: None,
            acme_email: None,
            acme_domains: Vec::new(),
        }
    }
}

/// Parse `std::env::args()`. Returns the resolved Command.
pub fn parse() -> Command {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_argv(&args)
}

pub(crate) fn parse_argv(args: &[String]) -> Command {
    let Some(first) = args.first() else {
        return Command::Daemon;
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Command::Help,
        "-V" | "--version" | "version" => Command::Version,
        "top" => Command::Top(parse_top_opts(&args[1..])),
        "doctor" => Command::Doctor,
        "init" => Command::Init(parse_init_opts(&args[1..])),
        "bootstrap" => Command::Bootstrap,
        "auto" => Command::Auto(parse_auto_opts(&args[1..])),
        "suggest" => Command::Suggest(parse_suggest_opts(&args[1..])),
        "import" => Command::Import(parse_import_opts(&args[1..])),
        "acme-soak" => Command::AcmeSoak,
        other => {
            // Anything else: surface as Unknown — caller prints help and exits 1.
            // Note: legacy invocations passed nothing, so this only triggers on
            // a genuine typo or new tool.
            Command::Unknown(other.to_string())
        }
    }
}

fn parse_auto_opts(args: &[String]) -> AutoOpts {
    let mut opts = AutoOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--upstream" if i + 1 < args.len() => {
                opts.upstream = normalize_upstream(&args[i + 1]);
                i += 2;
            }
            "--http-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    opts.http_port = p;
                }
                i += 2;
            }
            "--https-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    opts.https_port = p;
                }
                i += 2;
            }
            "--hostname" if i + 1 < args.len() => {
                opts.hostname = args[i + 1].clone();
                i += 2;
            }
            _ => i += 1,
        }
    }
    opts
}

// A value for a value-taking flag must not itself look like a flag — this is
// what makes `zion import nginx x.conf -o --strict` keep `--strict` as the
// flag it is instead of writing a file literally named "--strict".
fn flag_value(args: &[String], i: usize) -> Option<&String> {
    args.get(i + 1).filter(|v| !v.starts_with('-'))
}

fn parse_import_opts(args: &[String]) -> ImportOpts {
    let mut opts = ImportOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" if flag_value(args, i).is_some() => {
                opts.output = flag_value(args, i).cloned();
                i += 2;
            }
            "--report" if flag_value(args, i).is_some() => {
                opts.report = flag_value(args, i).cloned();
                i += 2;
            }
            "--strict" => {
                opts.strict = true;
                i += 1;
            }
            "--var" if flag_value(args, i).is_some() => {
                if let Some((k, v)) = flag_value(args, i).and_then(|kv| kv.split_once('=')) {
                    opts.vars.push((k.to_string(), v.to_string()));
                }
                i += 2;
            }
            // Positionals: first the source format, then the input path
            // (`-` = stdin, so a leading dash alone is not a flag).
            arg if !arg.starts_with('-') || arg == "-" => {
                if opts.source.is_empty() {
                    opts.source = arg.to_string();
                } else if opts.input.is_none() {
                    opts.input = Some(arg.to_string());
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    opts
}

fn parse_suggest_opts(args: &[String]) -> SuggestOpts {
    let mut opts = SuggestOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--upstream" if i + 1 < args.len() => {
                opts.upstream = Some(args[i + 1].clone());
                i += 2;
            }
            "-d" | "--domain" if i + 1 < args.len() => {
                opts.domain = Some(args[i + 1].clone());
                i += 2;
            }
            "-w" | "--write" if i + 1 < args.len() => {
                opts.write = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    opts
}

/// Allow `--upstream=:3000` as shorthand for `127.0.0.1:3000` so the
/// happy path (`zion auto --upstream=:3000`) is as terse as possible.
fn normalize_upstream(s: &str) -> String {
    if let Some(port_str) = s.strip_prefix(':') {
        format!("127.0.0.1:{port_str}")
    } else {
        s.to_string()
    }
}

fn parse_init_opts(args: &[String]) -> InitOpts {
    let mut opts = InitOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" if i + 1 < args.len() => {
                opts.output = args[i + 1].clone();
                i += 2;
            }
            "-f" | "--force" => {
                opts.force = true;
                i += 1;
            }
            "-y" | "--non-interactive" => {
                opts.non_interactive = true;
                i += 1;
            }
            "--hostname" if i + 1 < args.len() => {
                opts.hostname = Some(args[i + 1].clone());
                i += 2;
            }
            "--upstream" if i + 1 < args.len() => {
                // Format: name=host:port  e.g. "backend=127.0.0.1:8000"
                if let Some((name, target)) = args[i + 1].split_once('=') {
                    opts.upstreams
                        .push((name.trim().to_string(), target.trim().to_string()));
                }
                i += 2;
            }
            "--http-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    opts.http_port = Some(p);
                }
                i += 2;
            }
            "--https-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    opts.https_port = Some(p);
                }
                i += 2;
            }
            "--no-tls" => {
                opts.with_tls = false;
                i += 1;
            }
            "--no-waf" => {
                opts.with_waf = false;
                i += 1;
            }
            "--acme" => {
                opts.acme = Some(true);
                i += 1;
            }
            "--no-acme" => {
                opts.acme = Some(false);
                i += 1;
            }
            "--email" if i + 1 < args.len() => {
                opts.acme_email = Some(args[i + 1].clone());
                i += 2;
            }
            "--domain" if i + 1 < args.len() => {
                opts.acme_domains.push(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }
    opts
}

fn parse_top_opts(args: &[String]) -> TopOpts {
    let mut opts = TopOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-u" | "--url" if i + 1 < args.len() => {
                opts.url = args[i + 1].clone();
                i += 2;
            }
            "-i" | "--interval" if i + 1 < args.len() => {
                if let Ok(n) = args[i + 1].parse::<u64>() {
                    opts.interval_ms = n.clamp(100, 10_000);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    opts
}

pub fn print_version() {
    println!("zion {}", env!("CARGO_PKG_VERSION"));
}

pub fn print_help() {
    let bin = std::env::args()
        .next()
        .unwrap_or_else(|| "zion".to_string());
    let bin = std::path::Path::new(&bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("zion");
    println!(
        "zion {}\n\
        High-performance TLS reverse proxy with built-in WAF.\n\
        \n\
        USAGE:\n  \
            {bin}                        run the gateway daemon (default)\n  \
            {bin} auto --upstream :3000  one-shot dev mode: TLS in front of upstream, no config files\n  \
            {bin} top [opts]             live TUI dashboard\n  \
            {bin} init [opts]            generate zion.toml from prompts (or flags)\n  \
            {bin} suggest [opts]         synthesize a validated zion.toml from a detected/declared backend\n  \
            {bin} import <nginx|traefik> convert an nginx or Traefik-compose config to a validated zion.toml (honest findings)\n  \
            {bin} doctor                 run environment diagnostic checks\n  \
            {bin} bootstrap              dump detected platform as JSON (for CI / automation)\n  \
            {bin} --version              print version\n  \
            {bin} --help                 show this help\n\
        \n\
        TOP OPTIONS:\n  \
            -u, --url <URL>              snapshot endpoint (default http://127.0.0.1:80/_zion/snapshot.json)\n  \
            -i, --interval <MS>          poll interval in ms (default 500, range 100..10000)\n\
        \n\
        AUTO OPTIONS:\n  \
            -u, --upstream HOST:PORT     backend to proxy to (`:3000` shorthand → 127.0.0.1:3000)\n  \
                --http-port <N>          HTTP port (default 8080)\n  \
                --https-port <N>         HTTPS port (default 8443)\n  \
                --hostname <H>           SAN for the self-signed cert (default localhost)\n\
        \n\
        INIT OPTIONS:\n  \
            -o, --output <PATH>          output config path (default zion.toml)\n  \
            -f, --force                  overwrite an existing config\n  \
            -y, --non-interactive        skip prompts; use defaults + flags\n  \
                --hostname <H>           hostname Zion will serve\n  \
                --upstream NAME=HOST:PORT  declare an upstream (multi-allowed)\n  \
                --http-port <N>          override HTTP port (default 80)\n  \
                --https-port <N>         override HTTPS port (default 443)\n  \
                --no-tls                 skip self-signed cert generation\n  \
                --no-waf                 skip WAF on /api/* routes\n  \
                --acme / --no-acme       force automatic HTTPS on/off (default: on for a public hostname)\n  \
                --email <ADDR>           Let's Encrypt contact email (required when ACME is on)\n  \
                --domain <NAME>          domain to obtain a cert for (repeatable; default: the hostname)\n\
        \n\
        IMPORT OPTIONS:\n  \
            {bin} import nginx <PATH|->  input config (`-` = stdin; `include` resolves relative to it)\n  \
            -o, --output <PATH>          write the converted config (default stdout)\n  \
                --report <PATH>          write the full findings report (stderr shows partial/unsupported)\n  \
                --strict                 exit 2 if any partial/unsupported finding exists\n\
        \n\
        ENVIRONMENT:\n  \
            ZION_CONFIG=zion.toml        config path for the daemon\n  \
            ZION_BOOT_PLAIN=1            disable ANSI colors in boot output\n  \
            NO_COLOR=1                   honored — same as ZION_BOOT_PLAIN\n",
        env!("CARGO_PKG_VERSION"),
        bin = bin
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_argv_is_daemon() {
        assert!(matches!(parse_argv(&argv(&[])), Command::Daemon));
    }

    #[test]
    fn parse_suggest_flags() {
        match parse_argv(&argv(&[
            "suggest",
            "--upstream",
            ":3000",
            "--domain",
            "x.example.com",
            "--write",
            "out.toml",
        ])) {
            Command::Suggest(o) => {
                assert_eq!(o.upstream.as_deref(), Some(":3000"));
                assert_eq!(o.domain.as_deref(), Some("x.example.com"));
                assert_eq!(o.write.as_deref(), Some("out.toml"));
            }
            _ => panic!("expected Suggest"),
        }
        // Bare `suggest` → all None (scan localhost, print to stdout).
        match parse_argv(&argv(&["suggest"])) {
            Command::Suggest(o) => {
                assert!(o.upstream.is_none() && o.domain.is_none() && o.write.is_none())
            }
            _ => panic!("expected Suggest"),
        }
    }

    #[test]
    fn parse_import_flags() {
        match parse_argv(&argv(&[
            "import",
            "nginx",
            "site.conf",
            "-o",
            "zion.toml",
            "--report",
            "report.txt",
            "--strict",
        ])) {
            Command::Import(o) => {
                assert_eq!(o.source, "nginx");
                assert_eq!(o.input.as_deref(), Some("site.conf"));
                assert_eq!(o.output.as_deref(), Some("zion.toml"));
                assert_eq!(o.report.as_deref(), Some("report.txt"));
                assert!(o.strict);
            }
            _ => panic!("expected Import"),
        }
        // `-` is stdin, not a flag.
        match parse_argv(&argv(&["import", "nginx", "-"])) {
            Command::Import(o) => {
                assert_eq!(o.source, "nginx");
                assert_eq!(o.input.as_deref(), Some("-"));
                assert!(!o.strict);
            }
            _ => panic!("expected Import"),
        }
        // A value-taking flag never swallows a following flag: here `-o` is
        // dangling, so output stays stdout and --strict is still honored.
        match parse_argv(&argv(&["import", "nginx", "x.conf", "-o", "--strict"])) {
            Command::Import(o) => {
                assert_eq!(o.output, None);
                assert!(o.strict);
                assert_eq!(o.input.as_deref(), Some("x.conf"));
            }
            _ => panic!("expected Import"),
        }
        // Bare `import` → empty source; run() prints usage and exits 1.
        match parse_argv(&argv(&["import"])) {
            Command::Import(o) => assert!(o.source.is_empty() && o.input.is_none()),
            _ => panic!("expected Import"),
        }
    }

    #[test]
    fn top_default_opts() {
        match parse_argv(&argv(&["top"])) {
            Command::Top(o) => {
                assert_eq!(o.interval_ms, 500);
                assert!(o.url.contains("snapshot.json"));
            }
            _ => panic!("expected Top"),
        }
    }

    #[test]
    fn top_custom_url_and_interval() {
        match parse_argv(&argv(&[
            "top",
            "-u",
            "http://1.2.3.4:9000/_zion/snapshot.json",
            "-i",
            "250",
        ])) {
            Command::Top(o) => {
                assert_eq!(o.url, "http://1.2.3.4:9000/_zion/snapshot.json");
                assert_eq!(o.interval_ms, 250);
            }
            _ => panic!("expected Top"),
        }
    }

    #[test]
    fn interval_clamped() {
        match parse_argv(&argv(&["top", "-i", "10"])) {
            Command::Top(o) => assert_eq!(o.interval_ms, 100),
            _ => panic!(),
        }
        match parse_argv(&argv(&["top", "-i", "999999"])) {
            Command::Top(o) => assert_eq!(o.interval_ms, 10_000),
            _ => panic!(),
        }
    }

    #[test]
    fn version_and_help() {
        assert!(matches!(
            parse_argv(&argv(&["--version"])),
            Command::Version
        ));
        assert!(matches!(parse_argv(&argv(&["-V"])), Command::Version));
        assert!(matches!(parse_argv(&argv(&["--help"])), Command::Help));
        assert!(matches!(parse_argv(&argv(&["-h"])), Command::Help));
    }

    #[test]
    fn unknown_subcommand() {
        match parse_argv(&argv(&["nope"])) {
            Command::Unknown(s) => assert_eq!(s, "nope"),
            _ => panic!(),
        }
    }

    #[test]
    fn doctor_subcommand() {
        assert!(matches!(parse_argv(&argv(&["doctor"])), Command::Doctor));
    }

    #[test]
    fn bootstrap_subcommand() {
        assert!(matches!(
            parse_argv(&argv(&["bootstrap"])),
            Command::Bootstrap
        ));
    }

    #[test]
    fn auto_subcommand_defaults_to_unprivileged() {
        match parse_argv(&argv(&["auto"])) {
            Command::Auto(o) => {
                assert_eq!(o.upstream, "127.0.0.1:3000");
                assert_eq!(o.http_port, 8080);
                assert_eq!(o.https_port, 8443);
                assert_eq!(o.hostname, "localhost");
            }
            _ => panic!("expected Auto"),
        }
    }

    #[test]
    fn auto_upstream_short_form_normalized() {
        // `:3000` → `127.0.0.1:3000` (the happy-path one-liner)
        match parse_argv(&argv(&["auto", "--upstream", ":3000"])) {
            Command::Auto(o) => assert_eq!(o.upstream, "127.0.0.1:3000"),
            _ => panic!(),
        }
    }

    #[test]
    fn auto_full_flags() {
        match parse_argv(&argv(&[
            "auto",
            "-u",
            "10.0.0.5:8000",
            "--http-port",
            "80",
            "--https-port",
            "443",
            "--hostname",
            "dev.example.com",
        ])) {
            Command::Auto(o) => {
                assert_eq!(o.upstream, "10.0.0.5:8000");
                assert_eq!(o.http_port, 80);
                assert_eq!(o.https_port, 443);
                assert_eq!(o.hostname, "dev.example.com");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn init_default_opts() {
        match parse_argv(&argv(&["init"])) {
            Command::Init(o) => {
                assert_eq!(o.output, "zion.toml");
                assert!(!o.force);
                assert!(!o.non_interactive);
                assert!(o.with_tls);
                assert!(o.with_waf);
                assert!(o.upstreams.is_empty());
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn init_full_flags() {
        let cmd = parse_argv(&argv(&[
            "init",
            "-o",
            "custom.toml",
            "-f",
            "-y",
            "--hostname",
            "example.com",
            "--upstream",
            "backend=127.0.0.1:8000",
            "--upstream",
            "frontend=127.0.0.1:3000",
            "--http-port",
            "8080",
            "--https-port",
            "8443",
            "--no-tls",
            "--no-waf",
        ]));
        match cmd {
            Command::Init(o) => {
                assert_eq!(o.output, "custom.toml");
                assert!(o.force);
                assert!(o.non_interactive);
                assert_eq!(o.hostname.as_deref(), Some("example.com"));
                assert_eq!(o.upstreams.len(), 2);
                assert_eq!(o.upstreams[0], ("backend".into(), "127.0.0.1:8000".into()));
                assert_eq!(o.upstreams[1], ("frontend".into(), "127.0.0.1:3000".into()));
                assert_eq!(o.http_port, Some(8080));
                assert_eq!(o.https_port, Some(8443));
                assert!(!o.with_tls);
                assert!(!o.with_waf);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn init_malformed_upstream_skipped() {
        match parse_argv(&argv(&["init", "--upstream", "no-equals-sign"])) {
            Command::Init(o) => assert!(o.upstreams.is_empty()),
            _ => panic!(),
        }
    }
}

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
    /// Offline audit-log tooling: `zion audit verify <segment>...`.
    Audit(Vec<String>),
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
    /// A subcommand was given an argument it cannot honour (unknown flag, missing or
    /// unparsable value). The caller prints `message` and exits with `exit`: running with
    /// defaults instead would do something other than what was asked.
    Usage { message: String, exit: i32 },
}

/// Exit code of a usage error: the same as a config error, the daemon's other "you asked for
/// something I cannot do" outcome.
const USAGE_EXIT: i32 = 2;
/// `zion import` keeps 2 for "converted, but `--strict` found partial/unsupported directives"
/// (ADR-0011), so its usage errors are the fatal 1: nothing was emitted.
const IMPORT_USAGE_EXIT: i32 = 1;

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
    /// Source format: `nginx`, `traefik`, or `caddy`; empty = usage error.
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
    /// `--acme-email EMAIL`: emit a `[tls.acme]` block for automatic HTTPS when
    /// the source uses ACME (Traefik certresolver / Caddy auto-HTTPS). Without
    /// it, ACME-managed TLS imports to a placeholder cert + a partial finding.
    pub acme_email: Option<String>,
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
    let rest = &args[1..];
    // `zion init --help` asks for help, it does not start the wizard. (`audit` reads its own
    // arguments.) A flag's value never starts with `-`, so this cannot swallow one.
    if first != "audit" && rest.iter().any(|a| a == "-h" || a == "--help") {
        return Command::Help;
    }
    let usage = |exit: i32| move |message: String| Command::Usage { message, exit };
    match first.as_str() {
        "-h" | "--help" | "help" => Command::Help,
        "-V" | "--version" | "version" => Command::Version,
        "top" => parse_top_opts(rest).map_or_else(usage(USAGE_EXIT), Command::Top),
        "doctor" => no_args("doctor", rest).map_or_else(usage(USAGE_EXIT), |()| Command::Doctor),
        "init" => parse_init_opts(rest).map_or_else(usage(USAGE_EXIT), Command::Init),
        "bootstrap" => {
            no_args("bootstrap", rest).map_or_else(usage(USAGE_EXIT), |()| Command::Bootstrap)
        }
        "auto" => parse_auto_opts(rest).map_or_else(usage(USAGE_EXIT), Command::Auto),
        "suggest" => parse_suggest_opts(rest).map_or_else(usage(USAGE_EXIT), Command::Suggest),
        "import" => parse_import_opts(rest).map_or_else(usage(IMPORT_USAGE_EXIT), Command::Import),
        "audit" => Command::Audit(rest.to_vec()),
        "acme-soak" => Command::AcmeSoak,
        other => {
            // Anything else: surface as Unknown — caller prints help and exits 1.
            // Note: legacy invocations passed nothing, so this only triggers on
            // a genuine typo or new tool.
            Command::Unknown(other.to_string())
        }
    }
}

/// Walks one subcommand's arguments. Every parser goes through it, so the rules are the same
/// everywhere: `--flag value` and `--flag=value` both work, and an unknown flag, a missing
/// value or a value that does not parse is an error, never a silent default.
struct Flags<'a> {
    cmd: &'static str,
    args: &'a [String],
    i: usize,
    /// The flag `next` returned last, for the error messages.
    flag: &'a str,
    /// The `value` of a `--flag=value` argument, until the flag's arm takes it.
    inline: Option<&'a str>,
}

impl<'a> Flags<'a> {
    fn new(cmd: &'static str, args: &'a [String]) -> Self {
        Self {
            cmd,
            args,
            i: 0,
            flag: "",
            inline: None,
        }
    }

    /// The next argument, with the `=value` of a long flag split off. An `=value` the previous
    /// flag did not take (`--force=yes`) is an error.
    fn next(&mut self) -> Result<Option<&'a str>, String> {
        if let Some(v) = self.inline.take() {
            return Err(format!(
                "zion {}: {} takes no value (got `{v}`)",
                self.cmd, self.flag
            ));
        }
        let Some(arg) = self.args.get(self.i) else {
            return Ok(None);
        };
        self.i += 1;
        self.flag = arg;
        if arg.starts_with("--") {
            if let Some((name, value)) = arg.split_once('=') {
                self.flag = name;
                self.inline = Some(value);
            }
        }
        Ok(Some(self.flag))
    }

    /// The value of the flag `next` just returned. The following argument is not taken when it
    /// looks like a flag itself: `import x.conf -o --strict` must not write a file named
    /// `--strict`. (`-`, stdin/stdout by convention, is a value.)
    fn value(&mut self) -> Result<&'a str, String> {
        if let Some(v) = self.inline.take() {
            return Ok(v);
        }
        let (cmd, flag) = (self.cmd, self.flag);
        match self.args.get(self.i) {
            Some(v) if !v.starts_with('-') || v == "-" => {
                self.i += 1;
                Ok(v)
            }
            Some(v) => Err(format!(
                "zion {cmd}: {flag} needs a value, but `{v}` follows it (if that is the value, write {flag}={v})"
            )),
            None => Err(format!("zion {cmd}: {flag} needs a value")),
        }
    }

    /// The flag's value parsed as `T`; `what` names the expected form in the error.
    fn parsed<T: std::str::FromStr>(&mut self, what: &str) -> Result<T, String> {
        let (cmd, flag) = (self.cmd, self.flag);
        let v = self.value()?;
        v.parse()
            .map_err(|_| format!("zion {cmd}: {flag} expects {what}, got `{v}`"))
    }

    /// The flag's value split at its first `=` (`--var KEY=VALUE`); `what` names the form.
    fn pair(&mut self, what: &str) -> Result<(&'a str, &'a str), String> {
        let (cmd, flag) = (self.cmd, self.flag);
        let v = self.value()?;
        match v.split_once('=') {
            Some((k, val)) if !k.trim().is_empty() => Ok((k, val)),
            _ => Err(format!("zion {cmd}: {flag} expects {what}, got `{v}`")),
        }
    }

    /// The error for an argument no arm matched, with the nearest known flag when the
    /// argument looks like a typo of one.
    fn unknown(&self, arg: &str, known: &[&str]) -> String {
        let cmd = self.cmd;
        if !arg.starts_with('-') {
            return format!("zion {cmd}: unexpected argument `{arg}`");
        }
        let nearest = known
            .iter()
            .map(|k| (edit_distance(arg, k), *k))
            .filter(|(d, _)| *d <= 2)
            .min();
        match nearest {
            Some((_, k)) => format!("zion {cmd}: unknown flag `{arg}` (did you mean `{k}`?)"),
            None => format!("zion {cmd}: unknown flag `{arg}`"),
        }
    }
}

/// Levenshtein distance, for the "did you mean" hint. Flags are a few ASCII bytes long.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut diag = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = diag + usize::from(ca != cb);
            diag = row[j + 1];
            row[j + 1] = cost.min(row[j] + 1).min(diag + 1);
        }
    }
    row[b.len()]
}

/// For the subcommands that take no arguments at all.
fn no_args(cmd: &'static str, args: &[String]) -> Result<(), String> {
    match args.first() {
        None => Ok(()),
        Some(arg) => Err(format!("zion {cmd}: takes no arguments, got `{arg}`")),
    }
}

const AUTO_FLAGS: &[&str] = &[
    "-u",
    "--upstream",
    "--http-port",
    "--https-port",
    "--hostname",
];

fn parse_auto_opts(args: &[String]) -> Result<AutoOpts, String> {
    let mut opts = AutoOpts::default();
    let mut f = Flags::new("auto", args);
    while let Some(arg) = f.next()? {
        match arg {
            "-u" | "--upstream" => opts.upstream = normalize_upstream(f.value()?),
            "--http-port" => opts.http_port = f.parsed("a port (0-65535)")?,
            "--https-port" => opts.https_port = f.parsed("a port (0-65535)")?,
            "--hostname" => opts.hostname = f.value()?.to_string(),
            other => return Err(f.unknown(other, AUTO_FLAGS)),
        }
    }
    Ok(opts)
}

const IMPORT_FLAGS: &[&str] = &[
    "-o",
    "--output",
    "--report",
    "--strict",
    "--var",
    "--acme-email",
];

fn parse_import_opts(args: &[String]) -> Result<ImportOpts, String> {
    let mut opts = ImportOpts::default();
    let mut f = Flags::new("import", args);
    while let Some(arg) = f.next()? {
        match arg {
            "-o" | "--output" => opts.output = Some(f.value()?.to_string()),
            "--report" => opts.report = Some(f.value()?.to_string()),
            "--strict" => opts.strict = true,
            "--var" => {
                let (k, v) = f.pair("KEY=VALUE")?;
                opts.vars.push((k.to_string(), v.to_string()));
            }
            "--acme-email" => opts.acme_email = Some(f.value()?.to_string()),
            // Positionals: first the source format, then the input path
            // (`-` = stdin, so a leading dash alone is not a flag).
            arg if !arg.starts_with('-') || arg == "-" => {
                if opts.source.is_empty() {
                    opts.source = arg.to_string();
                } else if opts.input.is_none() {
                    opts.input = Some(arg.to_string());
                } else {
                    return Err(f.unknown(arg, IMPORT_FLAGS));
                }
            }
            other => return Err(f.unknown(other, IMPORT_FLAGS)),
        }
    }
    Ok(opts)
}

const SUGGEST_FLAGS: &[&str] = &["-u", "--upstream", "-d", "--domain", "-w", "--write"];

fn parse_suggest_opts(args: &[String]) -> Result<SuggestOpts, String> {
    let mut opts = SuggestOpts::default();
    let mut f = Flags::new("suggest", args);
    while let Some(arg) = f.next()? {
        match arg {
            "-u" | "--upstream" => opts.upstream = Some(f.value()?.to_string()),
            "-d" | "--domain" => opts.domain = Some(f.value()?.to_string()),
            "-w" | "--write" => opts.write = Some(f.value()?.to_string()),
            other => return Err(f.unknown(other, SUGGEST_FLAGS)),
        }
    }
    Ok(opts)
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

const INIT_FLAGS: &[&str] = &[
    "-o",
    "--output",
    "-f",
    "--force",
    "-y",
    "--non-interactive",
    "--hostname",
    "--upstream",
    "--http-port",
    "--https-port",
    "--no-tls",
    "--no-waf",
    "--acme",
    "--no-acme",
    "--email",
    "--domain",
];

fn parse_init_opts(args: &[String]) -> Result<InitOpts, String> {
    let mut opts = InitOpts::default();
    let mut f = Flags::new("init", args);
    while let Some(arg) = f.next()? {
        match arg {
            "-o" | "--output" => opts.output = f.value()?.to_string(),
            "-f" | "--force" => opts.force = true,
            "-y" | "--non-interactive" => opts.non_interactive = true,
            "--hostname" => opts.hostname = Some(f.value()?.to_string()),
            // Format: name=host:port  e.g. "backend=127.0.0.1:8000"
            "--upstream" => {
                let (name, target) = f.pair("NAME=HOST:PORT")?;
                opts.upstreams
                    .push((name.trim().to_string(), target.trim().to_string()));
            }
            "--http-port" => opts.http_port = Some(f.parsed("a port (0-65535)")?),
            "--https-port" => opts.https_port = Some(f.parsed("a port (0-65535)")?),
            "--no-tls" => opts.with_tls = false,
            "--no-waf" => opts.with_waf = false,
            "--acme" => opts.acme = Some(true),
            "--no-acme" => opts.acme = Some(false),
            "--email" => opts.acme_email = Some(f.value()?.to_string()),
            "--domain" => opts.acme_domains.push(f.value()?.to_string()),
            other => return Err(f.unknown(other, INIT_FLAGS)),
        }
    }
    Ok(opts)
}

const TOP_FLAGS: &[&str] = &["-u", "--url", "-i", "--interval"];

fn parse_top_opts(args: &[String]) -> Result<TopOpts, String> {
    let mut opts = TopOpts::default();
    let mut f = Flags::new("top", args);
    while let Some(arg) = f.next()? {
        match arg {
            "-u" | "--url" => opts.url = f.value()?.to_string(),
            "-i" | "--interval" => {
                opts.interval_ms = f.parsed::<u64>("milliseconds")?.clamp(100, 10_000);
            }
            other => return Err(f.unknown(other, TOP_FLAGS)),
        }
    }
    Ok(opts)
}

pub fn print_version() {
    // git sha + commit date are stamped by build.rs. `option_env!` (not `env!`)
    // so the binary still COMPILES when build.rs did not run — e.g. a Docker
    // build whose context omits build.rs — degrading to "unknown" rather than a
    // hard compile error. build.rs is present in the normal build and in the
    // release/container builds (which also pass the sha via a build-arg).
    println!(
        "zion {} ({} {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("ZION_GIT_SHA").unwrap_or("unknown"),
        option_env!("ZION_COMMIT_DATE").unwrap_or("unknown"),
    );
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
            {bin} import <nginx|traefik|caddy> convert an nginx / Traefik-compose / Caddyfile config to a validated zion.toml (honest findings)\n  \
            {bin} doctor                 run environment diagnostic checks\n  \
            {bin} audit verify <file>... verify the HMAC chain of audit log segments (--key-env, --previous-key-env)\n  \
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
            {bin} import nginx <PATH|->  nginx config (`-` = stdin; `include` resolves relative to it)\n  \
            {bin} import traefik <PATH>  docker-compose file with Traefik labels (`.env` next to it is read)\n  \
            {bin} import caddy <PATH|->  Caddyfile (`.env` next to it is read)\n  \
            -o, --output <PATH>          write the converted config (default stdout)\n  \
                --report <PATH>          write the full findings report (stderr shows partial/unsupported)\n  \
                --strict                 exit 2 if any partial/unsupported finding exists\n  \
                --var KEY=VALUE          value for a `${{KEY}}` / `{{$KEY}}` in the source (repeatable; wins over `.env`)\n  \
                --acme-email <ADDR>      emit `[tls.acme]` with this contact when the source uses automatic HTTPS\n\
        \n\
        Every flag also takes the form --flag=value. An unknown flag, a missing value or a value\n\
        that does not parse is an error (exit 2; exit 1 for import).\n\
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
        // A value-taking flag never swallows a following flag: `-o --strict` does not write a
        // file named "--strict". It is an error, not a silent "output stays stdout".
        let msg = usage(
            &["import", "nginx", "x.conf", "-o", "--strict"],
            IMPORT_USAGE_EXIT,
        );
        assert!(
            msg.contains("-o needs a value") && msg.contains("-o=--strict"),
            "{msg}"
        );
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

    /// The message of the usage error `args` must produce, with the exit code checked.
    fn usage(args: &[&str], exit: i32) -> String {
        match parse_argv(&argv(args)) {
            Command::Usage { message, exit: got } => {
                assert_eq!(got, exit, "exit code of `zion {}`", args.join(" "));
                message
            }
            other => panic!(
                "`zion {}` must be a usage error, got {other:?}",
                args.join(" ")
            ),
        }
    }

    /// Every subcommand, every way of getting an argument wrong: each used to run with a
    /// default instead of what was asked (ZION-API-02).
    #[test]
    fn a_wrong_argument_is_an_error_in_every_subcommand() {
        // (args, exit code, what the message must name)
        let cases: &[(&[&str], i32, &[&str])] = &[
            // Unknown flag, with the nearest known one.
            (
                &["init", "-y", "--ouput", "x.toml"],
                2,
                &["zion init", "`--ouput`", "`--output`"],
            ),
            (
                &["auto", "--upsteam", ":3000"],
                2,
                &["zion auto", "`--upsteam`", "`--upstream`"],
            ),
            (
                &["suggest", "--domian", "a.example"],
                2,
                &["zion suggest", "`--domian`", "`--domain`"],
            ),
            (
                &["top", "--intervall", "250"],
                2,
                &["zion top", "`--intervall`", "`--interval`"],
            ),
            (
                &["import", "nginx", "a.conf", "--strct"],
                1,
                &["zion import", "`--strct`", "`--strict`"],
            ),
            // Unknown flag with nothing near it: no hint is invented.
            (
                &["init", "--frobnicate"],
                2,
                &["unknown flag `--frobnicate`"],
            ),
            // Missing value.
            (&["init", "--output"], 2, &["--output needs a value"]),
            (&["auto", "--upstream"], 2, &["--upstream needs a value"]),
            (&["suggest", "-w"], 2, &["-w needs a value"]),
            (&["top", "--url"], 2, &["--url needs a value"]),
            (
                &["import", "nginx", "a.conf", "--report"],
                1,
                &["--report needs a value"],
            ),
            (
                &["init", "--hostname", "--no-tls"],
                2,
                &["--hostname needs a value", "`--no-tls`"],
            ),
            // A value that does not parse.
            (
                &["init", "--https-port", "70000"],
                2,
                &["--https-port expects a port", "`70000`"],
            ),
            (
                &["init", "--http-port", "abc"],
                2,
                &["--http-port expects a port", "`abc`"],
            ),
            (
                &["auto", "--https-port", "-1"],
                2,
                &["--https-port needs a value"],
            ),
            (
                &["auto", "--http-port=eighty"],
                2,
                &["--http-port expects a port", "`eighty`"],
            ),
            (
                &["top", "-i", "fast"],
                2,
                &["-i expects milliseconds", "`fast`"],
            ),
            (
                &["init", "--upstream", "no-equals-sign"],
                2,
                &["--upstream expects NAME=HOST:PORT"],
            ),
            (
                &["init", "--upstream", "=127.0.0.1:1"],
                2,
                &["--upstream expects NAME=HOST:PORT"],
            ),
            (
                &["import", "traefik", "c.yml", "--var", "FOO"],
                1,
                &["--var expects KEY=VALUE", "`FOO`"],
            ),
            // A value given to a flag that takes none.
            (
                &["init", "--force=yes"],
                2,
                &["--force takes no value", "`yes`"],
            ),
            (
                &["import", "nginx", "a.conf", "--strict=1"],
                1,
                &["--strict takes no value"],
            ),
            // A stray positional.
            (
                &["init", "zion.toml"],
                2,
                &["unexpected argument `zion.toml`"],
            ),
            (&["auto", ":3000"], 2, &["unexpected argument `:3000`"]),
            (
                &["import", "nginx", "a.conf", "b.conf"],
                1,
                &["unexpected argument `b.conf`"],
            ),
            (
                &["doctor", "--json"],
                2,
                &["zion doctor: takes no arguments", "`--json`"],
            ),
            (
                &["bootstrap", "x"],
                2,
                &["zion bootstrap: takes no arguments"],
            ),
        ];
        for (args, exit, needles) in cases {
            let msg = usage(args, *exit);
            for needle in *needles {
                assert!(
                    msg.contains(needle),
                    "`zion {}` → `{msg}` lacks `{needle}`",
                    args.join(" ")
                );
            }
        }
    }

    /// `--flag=value` is the form the docs use for the shortest path (`auto --upstream=:3000`).
    /// It used to be an unrecognised argument, skipped: it only "worked" because the default
    /// upstream is also :3000.
    #[test]
    fn a_long_flag_takes_its_value_after_an_equals_sign() {
        match parse_argv(&argv(&["auto", "--upstream=:9000", "--https-port=9443"])) {
            Command::Auto(o) => {
                assert_eq!(o.upstream, "127.0.0.1:9000");
                assert_eq!(o.https_port, 9443);
            }
            other => panic!("{other:?}"),
        }
        match parse_argv(&argv(&[
            "init",
            "--upstream=api=10.0.0.1:8000",
            "--output=out.toml",
        ])) {
            Command::Init(o) => {
                assert_eq!(
                    o.upstreams,
                    [("api".to_string(), "10.0.0.1:8000".to_string())]
                );
                assert_eq!(o.output, "out.toml");
            }
            other => panic!("{other:?}"),
        }
        // The explicit form is how a value that starts with a dash is given.
        match parse_argv(&argv(&[
            "import",
            "nginx",
            "a.conf",
            "--var=FLAGS=-O2",
            "--output=-",
        ])) {
            Command::Import(o) => {
                assert_eq!(o.vars, [("FLAGS".to_string(), "-O2".to_string())]);
                assert_eq!(o.output.as_deref(), Some("-"));
            }
            other => panic!("{other:?}"),
        }
    }

    /// The `*_FLAGS` lists feed the "did you mean" hint; a flag missing from its list would
    /// never be suggested. Each listed flag must be one its parser accepts.
    #[test]
    fn every_listed_flag_is_accepted_by_its_parser() {
        let lists: &[(&str, &[&str], &[&str])] = &[
            ("auto", AUTO_FLAGS, &[]),
            ("suggest", SUGGEST_FLAGS, &[]),
            ("top", TOP_FLAGS, &[]),
            ("init", INIT_FLAGS, &[]),
            ("import", IMPORT_FLAGS, &["nginx", "a.conf"]),
        ];
        for (cmd, flags, prefix) in lists {
            for flag in *flags {
                let mut args = vec![*cmd];
                args.extend_from_slice(prefix);
                args.push(flag);
                if let Command::Usage { message, .. } = parse_argv(&argv(&args)) {
                    assert!(
                        !message.contains("unknown flag"),
                        "{cmd}: listed flag {flag} is not accepted: {message}"
                    );
                }
            }
        }
    }

    #[test]
    fn help_inside_a_subcommand_is_help() {
        for args in [
            &["init", "--help"][..],
            &["auto", "-h"],
            &["import", "nginx", "--help"],
        ] {
            assert!(matches!(parse_argv(&argv(args)), Command::Help), "{args:?}");
        }
        // `audit` reads its own arguments.
        assert!(matches!(
            parse_argv(&argv(&["audit", "--help"])),
            Command::Audit(_)
        ));
    }

    #[test]
    fn edit_distance_counts_single_edits() {
        assert_eq!(edit_distance("--output", "--output"), 0);
        assert_eq!(edit_distance("--ouput", "--output"), 1);
        assert_eq!(edit_distance("--upsteam", "--upstream"), 1);
        assert_eq!(edit_distance("--strct", "--strict"), 1);
        assert_eq!(edit_distance("", "-o"), 2);
    }
}

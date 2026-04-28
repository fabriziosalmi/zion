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
    /// Print version and exit 0.
    Version,
    /// Print help and exit 0.
    Help,
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
        other => {
            // Anything else: surface as Unknown — caller prints help and exits 1.
            // Note: legacy invocations passed nothing, so this only triggers on
            // a genuine typo or new tool.
            Command::Unknown(other.to_string())
        }
    }
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
            {bin} top [opts]             live TUI dashboard\n  \
            {bin} --version              print version\n  \
            {bin} --help                 show this help\n\
        \n\
        TOP OPTIONS:\n  \
            -u, --url <URL>              snapshot endpoint (default http://127.0.0.1:80/_zion/snapshot.json)\n  \
            -i, --interval <MS>          poll interval in ms (default 500, range 100..10000)\n\
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
}

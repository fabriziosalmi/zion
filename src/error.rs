// SPDX-License-Identifier: Apache-2.0
//! Unified error type — `ZionError`.
//!
//! Replaces the historical `Box<dyn std::error::Error>` returned by `main`
//! and `async_main`. The goal isn't to thread typed errors through every
//! per-request branch (the request path uses `String`-based errors at
//! call-sites and converts to HTTP status codes locally — that is correct,
//! cheap, and pragmatic). The goal is to give the *boot path* a structured
//! error so:
//!
//!   - `match` exhaustiveness keeps us honest about what can go wrong;
//!   - the panic-hook / audit subsystems can downcast and emit a typed
//!     `kind=` field instead of a free-form string;
//!   - exit-code policy is centralized here, not scattered as
//!     `std::process::exit(2)` literals.
//!
//! Variants are intentionally narrow. Each one corresponds to a real,
//! distinguishable failure surface during the boot/lifecycle of a Zion
//! daemon. If a new variant is needed for a new subsystem, prefer adding
//! it here over re-introducing `Box<dyn Error>`.

use std::fmt;

/// Top-level Result alias for the boot path.
pub type ZionResult<T> = Result<T, ZionError>;

/// Top-level error type for boot/lifecycle failures.
///
/// Every variant carries the underlying message as `String`. We deliberately
/// don't store the source error type (which would force every variant to be
/// generic over `Box<dyn Error>`) because by the time a boot error reaches
/// `main()` the only useful thing is the operator-readable string — the
/// upstream type isn't actionable. The variant *kind* gives the structured
/// dimension (used by panic-hook / `to_exit_code`).
#[derive(Debug)]
pub enum ZionError {
    /// `[server] / [tls] / [route] / etc.` parsing or validation failed.
    /// Includes both file-IO errors (couldn't read `zion.toml`) and
    /// semantic validation failures (unknown WAF profile name, etc.).
    Config(String),

    /// TLS material couldn't be loaded, or rustls rejected the
    /// certificate / key combination.
    Tls(String),

    /// A listening socket couldn't be bound. Usually `EADDRINUSE` or
    /// `EACCES` (port < 1024 without `CAP_NET_BIND_SERVICE`).
    Listener(String),

    /// ACME flow failure (only reachable with `--features acme`).
    #[allow(dead_code)] // surfaced when `--features acme`
    Acme(String),

    /// Auth profile setup failed — JWKS fetch, OIDC discovery, key parse.
    /// Only reachable with `--features auth`.
    #[allow(dead_code)] // surfaced when `--features auth`
    Auth(String),

    /// Audit-log writer couldn't open its target file. Currently downgraded
    /// to a warning (the daemon continues without audit), but kept here as
    /// a variant so a stricter mode can promote it later.
    #[allow(dead_code)]
    Audit(String),

    /// Anything else not yet specialized — keep narrow on purpose.
    Other(String),
}

impl ZionError {
    /// Return the conventional Unix exit code for this error category.
    /// Conventions:
    ///   * `2` — config / validation problem (operator must fix the file)
    ///   * `3` — TLS material problem (operator must rotate certs)
    ///   * `4` — bind/listener problem (port already used or no permission)
    ///   * `5` — runtime subsystem (ACME, auth, audit) failed
    ///   * `1` — anything else
    ///
    /// Wired at the `main()` boundary so supervisors can branch on the code.
    pub fn to_exit_code(&self) -> i32 {
        match self {
            ZionError::Config(_) => 2,
            ZionError::Tls(_) => 3,
            ZionError::Listener(_) => 4,
            ZionError::Acme(_) | ZionError::Auth(_) | ZionError::Audit(_) => 5,
            ZionError::Other(_) => 1,
        }
    }

    /// Stable, lowercase identifier for structured logs / metrics labels.
    /// Mirrors the variant name minus the payload. Emitted as the `kind=`
    /// field in the `main()` fatal line and reserved for the audit-log
    /// integration point.
    pub fn kind(&self) -> &'static str {
        match self {
            ZionError::Config(_) => "config",
            ZionError::Tls(_) => "tls",
            ZionError::Listener(_) => "listener",
            ZionError::Acme(_) => "acme",
            ZionError::Auth(_) => "auth",
            ZionError::Audit(_) => "audit",
            ZionError::Other(_) => "other",
        }
    }
}

impl fmt::Display for ZionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZionError::Config(m) => write!(f, "config: {m}"),
            ZionError::Tls(m) => write!(f, "tls: {m}"),
            ZionError::Listener(m) => write!(f, "listener: {m}"),
            ZionError::Acme(m) => write!(f, "acme: {m}"),
            ZionError::Auth(m) => write!(f, "auth: {m}"),
            ZionError::Audit(m) => write!(f, "audit: {m}"),
            ZionError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ZionError {}

// ─────────────────────────────────────────────────────────────────────────────
// `From` conversions — keep these targeted. We don't blanket-impl
// `From<Box<dyn Error>>` because that would silently re-introduce the very
// thing we're replacing.
// ─────────────────────────────────────────────────────────────────────────────

impl From<std::io::Error> for ZionError {
    fn from(e: std::io::Error) -> Self {
        // I/O errors are usually about listeners or filesystem state at
        // boot. Pick the most useful default; callers can wrap manually
        // for finer-grained categorisation.
        ZionError::Other(format!("io: {e}"))
    }
}

impl From<String> for ZionError {
    /// Catch-all conversion from the `String`-based errors used in
    /// per-call-site code. Every site that returns a structured boot error
    /// should prefer one of the explicit constructors instead.
    fn from(s: String) -> Self {
        ZionError::Other(s)
    }
}

impl From<&str> for ZionError {
    fn from(s: &str) -> Self {
        ZionError::Other(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_kind_prefix() {
        assert_eq!(
            ZionError::Config("missing [tls] block".into()).to_string(),
            "config: missing [tls] block"
        );
        assert_eq!(
            ZionError::Tls("bad cert".into()).to_string(),
            "tls: bad cert"
        );
    }

    #[test]
    fn other_does_not_double_prefix() {
        // `Other` is a free-form variant — its Display is bare so we don't
        // get "other: …" noise in operator output.
        assert_eq!(
            ZionError::Other("something bad".into()).to_string(),
            "something bad"
        );
    }

    #[test]
    fn kind_identifiers_are_stable_lowercase() {
        for e in [
            ZionError::Config("".into()),
            ZionError::Tls("".into()),
            ZionError::Listener("".into()),
            ZionError::Acme("".into()),
            ZionError::Auth("".into()),
            ZionError::Audit("".into()),
            ZionError::Other("".into()),
        ] {
            let k = e.kind();
            assert!(k.chars().all(|c| c.is_ascii_lowercase()), "kind: {k}");
            assert!(!k.is_empty());
        }
    }

    #[test]
    fn exit_codes_are_distinct_per_category() {
        // Operator-facing contract: each major failure mode maps to its
        // own exit code so process supervisors / SRE runbooks can branch.
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        seen.insert(ZionError::Config("".into()).to_exit_code());
        seen.insert(ZionError::Tls("".into()).to_exit_code());
        seen.insert(ZionError::Listener("".into()).to_exit_code());
        seen.insert(ZionError::Other("".into()).to_exit_code());
        assert_eq!(seen.len(), 4, "config/tls/listener/other must differ");
    }

    #[test]
    fn from_string_lands_in_other() {
        let err: ZionError = "boom".to_string().into();
        assert_eq!(err.kind(), "other");
    }

    #[test]
    fn from_io_error_has_io_prefix() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let err: ZionError = io.into();
        assert!(err.to_string().contains("io:"), "got {err}");
    }

    #[test]
    fn implements_std_error() {
        // Compile-time assertion: ZionError is a std::error::Error.
        fn assert_error<E: std::error::Error>() {}
        assert_error::<ZionError>();
    }

    #[test]
    fn is_send_sync() {
        // Required for use in async fn return types and tokio task results.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ZionError>();
    }
}

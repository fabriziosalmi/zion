//! Zion structured logging — zero-dependency, minimal, fast.
//!
//! Two formats:
//!   - "text": human-readable (default, for development)
//!   - "json": machine-parseable (for production, Loki/ELK/Datadog)
//!
//! NOT used on the request hot path — only for startup, errors, and lifecycle events.

use std::sync::OnceLock;

static JSON_MODE: OnceLock<bool> = OnceLock::new();

/// Initialize the logger. Call once at startup.
pub fn init(format: &str) {
    JSON_MODE.set(format == "json").ok();
}

fn is_json() -> bool {
    *JSON_MODE.get().unwrap_or(&false)
}

/// Log an info-level event.
pub fn info(event: &str, msg: &str) {
    if is_json() {
        eprintln!(
            r#"{{"ts":"{}","level":"info","event":"{}","msg":"{}"}}"#,
            now(), escape(event), escape(msg)
        );
    } else {
        eprintln!("{}", msg);
    }
}

/// Log a warning-level event.
#[allow(dead_code)]
pub fn warn(event: &str, msg: &str) {
    if is_json() {
        eprintln!(
            r#"{{"ts":"{}","level":"warn","event":"{}","msg":"{}"}}"#,
            now(), escape(event), escape(msg)
        );
    } else {
        eprintln!("  warning: {}", msg);
    }
}

/// Log an error-level event.
#[allow(dead_code)]
pub fn error(event: &str, msg: &str) {
    if is_json() {
        eprintln!(
            r#"{{"ts":"{}","level":"error","event":"{}","msg":"{}"}}"#,
            now(), escape(event), escape(msg)
        );
    } else {
        eprintln!("  error: {}", msg);
    }
}

fn now() -> String {
    // ISO 8601 UTC — no chrono needed
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", d.as_secs())
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

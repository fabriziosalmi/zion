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
            now(),
            escape(event),
            escape(msg)
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
            now(),
            escape(event),
            escape(msg)
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
            now(),
            escape(event),
            escape(msg)
        );
    } else {
        eprintln!("  error: {}", msg);
    }
}

fn now() -> String {
    // ISO 8601 UTC with microsecond precision — no chrono needed
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let micros = d.subsec_micros();
    // Decompose epoch seconds into date-time components
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    // Days since 1970-01-01 → year/month/day (civil calendar)
    // Algorithm from Howard Hinnant (public domain)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d_val = doy - (153 * mp + 2) / 5 + 1;
    let m_val = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_val = if m_val <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        y_val, m_val, d_val, hours, minutes, seconds, micros
    )
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_returns_iso8601_format() {
        let ts = now();
        // Format: YYYY-MM-DDTHH:MM:SS.mmmmmmZ
        assert_eq!(ts.len(), 27, "timestamp length should be 27: {}", ts);
        assert!(ts.ends_with('Z'), "should end with Z: {}", ts);
        assert_eq!(&ts[4..5], "-", "YYYY-MM separator: {}", ts);
        assert_eq!(&ts[7..8], "-", "MM-DD separator: {}", ts);
        assert_eq!(&ts[10..11], "T", "date-time separator: {}", ts);
        assert_eq!(&ts[13..14], ":", "HH:MM separator: {}", ts);
        assert_eq!(&ts[16..17], ":", "MM:SS separator: {}", ts);
        assert_eq!(&ts[19..20], ".", "SS.mmmmmm separator: {}", ts);
    }

    #[test]
    fn now_year_is_reasonable() {
        let ts = now();
        let year: u32 = ts[..4].parse().unwrap();
        assert!((2024..=2100).contains(&year), "year out of range: {}", year);
    }

    #[test]
    fn escape_handles_quotes_and_backslashes() {
        assert_eq!(escape(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(escape(r"back\slash"), r"back\\slash");
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Zion structured logging — zero-dependency, minimal, fast.
//!
//! Two formats:
//!   - "text": human-readable (default, for development)
//!   - "json": machine-parseable (for production, Loki/ELK/Datadog)
//!
//! In text mode when stderr is NOT a terminal (journald, `docker logs`, a file,
//! a pipe) every line carries a UTC timestamp, a level and the event key
//! (`2026-09-30T06:26:36.771169Z WARN upstream: ...`), so incident logs can be
//! ordered and filtered by subsystem without a wrapper adding timestamps. On a
//! TTY the human-oriented format below is unchanged.
//!
//! In text mode on a TTY, warnings and errors get a colored glyph prefix
//! (`⚠` amber for warn, `✖` red for error) so they don't drown in the rest
//! of the boot output. ANSI is suppressed when stderr is not a terminal,
//! when `NO_COLOR` is set, or when the logger is in JSON mode.
//!
//! NOT used on the request hot path — only for startup, errors, and
//! lifecycle events.

use std::io::IsTerminal;
use std::sync::OnceLock;

static JSON_MODE: OnceLock<bool> = OnceLock::new();
static COLOR_TTY: OnceLock<bool> = OnceLock::new();
/// True in text mode when stderr is not a terminal: lines get ts + level + event.
static STAMPED: OnceLock<bool> = OnceLock::new();

/// Initialize the logger. Call once at startup.
pub fn init(format: &str) {
    JSON_MODE.set(format == "json").ok();
    let plain =
        std::env::var_os("NO_COLOR").is_some() || std::env::var_os("ZION_BOOT_PLAIN").is_some();
    let color = !plain && std::io::stderr().is_terminal();
    COLOR_TTY.set(color).ok();
    STAMPED.set(!std::io::stderr().is_terminal()).ok();
}

fn is_stamped() -> bool {
    *STAMPED.get().unwrap_or(&false)
}

/// One machine-friendly text line: `<ts> <LEVEL> <event>: <msg>`.
fn format_stamped(ts: &str, level: &str, event: &str, msg: &str) -> String {
    format!("{ts} {level:<5} {event}: {msg}")
}

fn is_json() -> bool {
    *JSON_MODE.get().unwrap_or(&false)
}

fn want_color() -> bool {
    *COLOR_TTY.get().unwrap_or(&false)
}

/// One output line: through the non-blocking queue once it is installed (so a stalled stderr
/// cannot stall the request that logged), straight to stderr during boot.
fn emit(line: &str) {
    crate::logq::line(line);
}

/// Log an info-level event.
pub fn info(event: &str, msg: &str) {
    if is_json() {
        emit(&format!(
            r#"{{"ts":"{}","level":"info","event":"{}","msg":"{}"}}"#,
            now(),
            escape(event),
            escape(msg)
        ));
    } else if is_stamped() {
        emit(&format_stamped(&now(), "INFO", event, msg));
    } else {
        emit(msg);
    }
}

/// Log a warning-level event. In text+TTY mode the line is prefixed with
/// a bold amber `⚠ warning:` so operators spot it amid the boot stream.
pub fn warn(event: &str, msg: &str) {
    if !is_json() && is_stamped() {
        emit(&format_stamped(&now(), "WARN", event, msg));
    } else {
        emit(&format_warn(is_json(), want_color(), event, msg));
    }
}

/// Log an error-level event. In text+TTY mode prefixed with a bold red
/// `✖ error:` for maximum salience.
pub fn error(event: &str, msg: &str) {
    if !is_json() && is_stamped() {
        emit(&format_stamped(&now(), "ERROR", event, msg));
    } else {
        emit(&format_error(is_json(), want_color(), event, msg));
    }
}

/// Build the warning-line string. Extracted from `warn()` so tests can
/// exercise all four combinations of (json, color) without touching the
/// global OnceLock state.
fn format_warn(json: bool, color: bool, event: &str, msg: &str) -> String {
    if json {
        format!(
            r#"{{"ts":"{}","level":"warn","event":"{}","msg":"{}"}}"#,
            now(),
            escape(event),
            escape(msg)
        )
    } else if color {
        format!("  \x1b[1;38;5;220m⚠ warning:\x1b[0m  {msg}")
    } else {
        format!("  warning: {msg}")
    }
}

fn format_error(json: bool, color: bool, event: &str, msg: &str) -> String {
    if json {
        format!(
            r#"{{"ts":"{}","level":"error","event":"{}","msg":"{}"}}"#,
            now(),
            escape(event),
            escape(msg)
        )
    } else if color {
        format!("  \x1b[1;38;5;196m✖ error:\x1b[0m  {msg}")
    } else {
        format!("  error: {msg}")
    }
}

/// Lets at most `burst` messages through per `window_secs`, so a log line that a
/// client can trigger (a broken upload, a reset stream) cannot be turned into a
/// flood. One `static` per call site; lock-free.
pub struct Throttle {
    window_secs: u64,
    burst: u32,
    /// `window index << 24 | messages let through in that window`.
    state: std::sync::atomic::AtomicU64,
}

impl Throttle {
    pub const fn new(burst: u32, window_secs: u64) -> Self {
        Self {
            window_secs,
            burst,
            state: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn allow(&self) -> bool {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.allow_at(secs)
    }

    fn allow_at(&self, now_secs: u64) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let window = now_secs / self.window_secs.max(1);
        let mut cur = self.state.load(Relaxed);
        loop {
            let (cur_window, n) = (cur >> 24, (cur & 0xff_ffff) as u32);
            let next = if cur_window != window {
                (window << 24) | 1
            } else if n < self.burst {
                cur + 1
            } else {
                return false;
            };
            if self.burst == 0 {
                return false;
            }
            match self
                .state
                .compare_exchange_weak(cur, next, Relaxed, Relaxed)
            {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }
}

pub(crate) fn now() -> String {
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
    format!("{y_val:04}-{m_val:02}-{d_val:02}T{hours:02}:{minutes:02}:{seconds:02}.{micros:06}Z")
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_throttle_lets_a_burst_through_per_window_and_then_nothing() {
        let t = Throttle::new(3, 10);
        assert!([100, 101, 109].iter().all(|&s| t.allow_at(s)));
        assert!(!t.allow_at(109), "the fourth in the window is held back");
        assert!(!t.allow_at(100), "and so is any later one in it");
        assert!(t.allow_at(110), "the next window starts again");
        assert!(t.allow_at(119) && t.allow_at(119));
        assert!(!t.allow_at(119));
        assert!(!Throttle::new(0, 10).allow_at(5), "a burst of 0 is silence");
    }

    #[test]
    fn stamped_text_line_has_timestamp_level_and_event() {
        // ZION-OBS-04: a non-TTY text log must be orderable and filterable.
        let line = format_stamped(&now(), "WARN", "upstream", "http://b:1 is DOWN");
        let (ts, rest) = line.split_once(' ').unwrap();
        assert_eq!(ts.len(), 27, "ISO-8601 UTC with microseconds: {ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T');
        assert_eq!(rest, "WARN  upstream: http://b:1 is DOWN");
        // levels align on a fixed column
        assert!(format_stamped("t", "INFO", "e", "m").starts_with("t INFO  e: m"));
        assert!(format_stamped("t", "ERROR", "e", "m").starts_with("t ERROR e: m"));
    }

    #[test]
    fn now_returns_iso8601_format() {
        let ts = now();
        // Format: YYYY-MM-DDTHH:MM:SS.mmmmmmZ
        assert_eq!(ts.len(), 27, "timestamp length should be 27: {ts}");
        assert!(ts.ends_with('Z'), "should end with Z: {ts}");
        assert_eq!(&ts[4..5], "-", "YYYY-MM separator: {ts}");
        assert_eq!(&ts[7..8], "-", "MM-DD separator: {ts}");
        assert_eq!(&ts[10..11], "T", "date-time separator: {ts}");
        assert_eq!(&ts[13..14], ":", "HH:MM separator: {ts}");
        assert_eq!(&ts[16..17], ":", "MM:SS separator: {ts}");
        assert_eq!(&ts[19..20], ".", "SS.mmmmmm separator: {ts}");
    }

    #[test]
    fn now_year_is_reasonable() {
        let ts = now();
        let year: u32 = ts[..4].parse().unwrap();
        assert!((2024..=2100).contains(&year), "year out of range: {year}");
    }

    #[test]
    fn escape_handles_quotes_and_backslashes() {
        assert_eq!(escape(r#"hello "world""#), r#"hello \"world\""#);
        assert_eq!(escape(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn warn_plain_text_no_color() {
        let out = format_warn(false, false, "health", "upstream is DOWN");
        assert_eq!(out, "  warning: upstream is DOWN");
    }

    #[test]
    fn warn_text_color_prefixes_amber_glyph() {
        let out = format_warn(false, true, "health", "upstream is DOWN");
        // Bold + 256-color amber sequence
        assert!(out.starts_with("  \x1b[1;38;5;220m⚠ warning:\x1b[0m"));
        assert!(out.ends_with("upstream is DOWN"));
    }

    #[test]
    fn warn_json_mode_unchanged_by_color_flag() {
        // JSON output must never carry ANSI escapes — log collectors parse
        // it. We can't compare timestamps (they differ across calls), so we
        // verify structural fields and absence of ANSI on both branches.
        for color in [false, true] {
            let out = format_warn(true, color, "health", "upstream is DOWN");
            assert!(out.contains(r#""level":"warn""#), "color={color}: {out}");
            assert!(out.contains(r#""event":"health""#), "color={color}: {out}");
            assert!(
                out.contains(r#""msg":"upstream is DOWN""#),
                "color={color}: {out}"
            );
            assert!(!out.contains("\x1b["), "color={color}: ANSI in JSON: {out}");
        }
    }

    #[test]
    fn error_plain_text_no_color() {
        let out = format_error(false, false, "tls", "handshake failed");
        assert_eq!(out, "  error: handshake failed");
    }

    #[test]
    fn error_text_color_prefixes_red_glyph() {
        let out = format_error(false, true, "tls", "handshake failed");
        assert!(out.starts_with("  \x1b[1;38;5;196m✖ error:\x1b[0m"));
        assert!(out.ends_with("handshake failed"));
    }

    #[test]
    fn error_json_mode_unchanged_by_color_flag() {
        for color in [false, true] {
            let out = format_error(true, color, "tls", "handshake failed");
            assert!(out.contains(r#""level":"error""#), "color={color}: {out}");
            assert!(!out.contains("\x1b["), "color={color}: ANSI in JSON: {out}");
        }
    }

    #[test]
    fn json_escapes_quotes_in_message() {
        let out = format_warn(true, false, "evt", r#"got "quoted" payload"#);
        assert!(out.contains(r#""msg":"got \"quoted\" payload""#));
    }
}

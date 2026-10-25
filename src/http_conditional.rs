// SPDX-License-Identifier: Apache-2.0
//! Shared HTTP conditional-request helpers (RFC 9110 §13): weak-ETag comparison,
//! the `If-None-Match` / `If-Modified-Since` → 304 decision, and RFC 9110 §5.6.7
//! `IMF-fixdate` formatting.
//!
//! Two callers with different validator *sources* share one comparison:
//!  - the cache revalidation path (dispatch) echoes the origin's `ETag` /
//!    `Last-Modified`;
//!  - the static file server derives them from filesystem metadata.
//!
//! Keeping the decision in one place means the 304 semantics can never drift
//! between the two.

use hyper::header::{HeaderMap, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH};

/// Strip a weak-ETag `W/` prefix for the weak comparison `If-None-Match` uses
/// (RFC 9110 §8.8.3.2).
pub fn strip_weak(etag: &str) -> &str {
    etag.strip_prefix("W/").unwrap_or(etag)
}

/// Can this conditional request be answered `304 Not Modified`? RFC 9110 §13.1:
/// `If-None-Match` takes precedence (weak comparison; `*` matches any current
/// representation); otherwise `If-Modified-Since` is honored as an exact echo of
/// the current `Last-Modified` (the dominant browser revalidation pattern — full
/// HTTP-date range comparison is a deliberate follow-up).
pub fn is_not_modified(
    req_headers: &HeaderMap,
    etag: Option<&HeaderValue>,
    last_modified: Option<&HeaderValue>,
) -> bool {
    if let Some(inm) = req_headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        let inm = inm.trim();
        if inm == "*" {
            return true;
        }
        let stored = match etag.and_then(|e| e.to_str().ok()) {
            Some(e) => strip_weak(e.trim()),
            None => return false,
        };
        return inm.split(',').any(|t| strip_weak(t.trim()) == stored);
    }
    if let (Some(ims), Some(lm)) = (
        req_headers
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok()),
        last_modified.and_then(|v| v.to_str().ok()),
    ) {
        let (ims, lm) = (ims.trim(), lm.trim());
        // RFC 9110 13.1.3: not modified when the representation's last modification time is at or
        // before the If-Modified-Since date. Parse both as IMF-fixdate and compare; fall back to an
        // exact-string match only if either side is not a parseable IMF-fixdate (e.g. one of the
        // obsolete date formats), which keeps the common echo-back case working (#744).
        return match (parse_imf_fixdate(ims), parse_imf_fixdate(lm)) {
            (Some(ims_secs), Some(lm_secs)) => lm_secs <= ims_secs,
            _ => ims == lm,
        };
    }
    false
}

/// Format a UNIX timestamp (seconds since the epoch, UTC) as an RFC 9110 §5.6.7
/// `IMF-fixdate` — e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
///
/// Dependency-free on purpose: the `time` crate is an optional feature and
/// `mode=static` lives in the lean default build, so this uses Howard Hinnant's
/// `civil_from_days` algorithm rather than pulling a date crate into core.
pub fn fmt_imf_fixdate(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let sod = unix_secs % 86_400;
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);

    // Epoch day 0 (1970-01-01) was a Thursday; index the table from there.
    const WKD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let wkd = WKD[days.rem_euclid(7) as usize];

    // civil_from_days: days since 1970-01-01 → (year, month, day). See
    // https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day-of-era  [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day-of-year [0, 365]
    let mp = (5 * doy + 2) / 153; // month, shifted so March = 0  [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day-of-month [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // real month [1, 12]
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };

    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{wkd}, {d:02} {mon} {y:04} {hh:02}:{mm:02}:{ss:02} GMT",
        mon = MON[(m - 1) as usize],
    )
}

/// Parse an RFC 9110 §5.6.7 `IMF-fixdate` (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`) to a UNIX
/// timestamp (seconds since the epoch, UTC). Returns `None` for anything that is not an
/// IMF-fixdate, including the two obsolete HTTP date formats; the caller treats a non-parse as a
/// reason to fall back to exact-string comparison. Dependency-free (Howard Hinnant's
/// `days_from_civil`), matching `fmt_imf_fixdate`.
fn parse_imf_fixdate(s: &str) -> Option<i64> {
    // "Sun, 06 Nov 1994 08:49:37 GMT" -> ["Sun,","06","Nov","1994","08:49:37","GMT"]
    let mut it = s.split_whitespace();
    let _wkd = it.next()?;
    let day: i64 = it.next()?.parse().ok()?;
    let month = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;
    if it.next()? != "GMT" {
        return None;
    }
    let mut tp = time.split(':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss: i64 = tp.next()?.parse().ok()?;
    if tp.next().is_some() || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant). Inverse of the `civil_from_days` used
/// in [`fmt_imf_fixdate`]. See https://howardhinnant.github.io/date_algorithms.html
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }
    fn headers(pairs: &[(hyper::header::HeaderName, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(k.clone(), hv(v));
        }
        h
    }

    // ── fmt_imf_fixdate ──────────────────────────────────────────────────────

    #[test]
    fn imf_fixdate_canonical_vectors() {
        // The classic RFC example.
        assert_eq!(
            fmt_imf_fixdate(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        // The epoch itself (a Thursday).
        assert_eq!(fmt_imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // A leap-day (2000-02-29 was a Tuesday) — exercises the century rule.
        assert_eq!(
            fmt_imf_fixdate(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        // End-of-year rollover, zero-padded day.
        assert_eq!(
            fmt_imf_fixdate(978_307_199),
            "Sun, 31 Dec 2000 23:59:59 GMT"
        );
    }

    #[test]
    fn imf_fixdate_is_stable_and_round_trippable_as_a_header() {
        // Whatever it emits must be a valid header value (no panics downstream).
        let s = fmt_imf_fixdate(1_700_000_000);
        assert!(HeaderValue::from_str(&s).is_ok());
        assert!(s.ends_with(" GMT"));
    }

    // ── is_not_modified ──────────────────────────────────────────────────────

    #[test]
    fn inm_exact_and_weak_match_is_304() {
        let et = hv("W/\"abc\"");
        let h = headers(&[(IF_NONE_MATCH, "W/\"abc\"")]);
        assert!(is_not_modified(&h, Some(&et), None));
        // Weak/strong prefixes are compared weakly: a strong INM still matches a
        // weak stored tag on the same opaque value.
        let h2 = headers(&[(IF_NONE_MATCH, "\"abc\"")]);
        assert!(is_not_modified(&h2, Some(&et), None));
    }

    #[test]
    fn inm_mismatch_is_not_304() {
        let et = hv("W/\"abc\"");
        let h = headers(&[(IF_NONE_MATCH, "W/\"xyz\"")]);
        assert!(!is_not_modified(&h, Some(&et), None));
    }

    #[test]
    fn inm_star_matches_any_representation() {
        let et = hv("W/\"whatever\"");
        let h = headers(&[(IF_NONE_MATCH, "*")]);
        assert!(is_not_modified(&h, Some(&et), None));
        // `*` matches even when we somehow have no stored ETag.
        assert!(is_not_modified(&h, None, None));
    }

    #[test]
    fn inm_list_matches_any_member() {
        let et = hv("W/\"abc\"");
        let h = headers(&[(IF_NONE_MATCH, "\"p\", W/\"abc\" , \"q\"")]);
        assert!(is_not_modified(&h, Some(&et), None));
    }

    #[test]
    fn inm_without_stored_etag_is_not_304() {
        let h = headers(&[(IF_NONE_MATCH, "\"abc\"")]);
        assert!(!is_not_modified(&h, None, None));
    }

    #[test]
    fn ims_exact_echo_is_304_and_ims_takes_a_back_seat_to_inm() {
        let lm = hv("Sun, 06 Nov 1994 08:49:37 GMT");
        let h = headers(&[(IF_MODIFIED_SINCE, "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert!(is_not_modified(&h, None, Some(&lm)));
        // #744: a LATER If-Modified-Since date now 304s (last-modified <= date), per RFC 9110.
        let later = headers(&[(IF_MODIFIED_SINCE, "Mon, 07 Nov 1994 00:00:00 GMT")]);
        assert!(is_not_modified(&later, None, Some(&lm)));
        // An EARLIER date means the resource was modified since: not a 304.
        let earlier = headers(&[(IF_MODIFIED_SINCE, "Sat, 05 Nov 1994 00:00:00 GMT")]);
        assert!(!is_not_modified(&earlier, None, Some(&lm)));

        // When both are present, INM wins: a matching INM 304s regardless of IMS,
        // and a mismatching INM blocks the 304 even if IMS would have echoed.
        let et = hv("W/\"abc\"");
        let both_inm_hit = headers(&[
            (IF_NONE_MATCH, "W/\"abc\""),
            (IF_MODIFIED_SINCE, "Mon, 07 Nov 1994 00:00:00 GMT"),
        ]);
        assert!(is_not_modified(&both_inm_hit, Some(&et), Some(&lm)));
        let both_inm_miss = headers(&[
            (IF_NONE_MATCH, "W/\"nope\""),
            (IF_MODIFIED_SINCE, "Sun, 06 Nov 1994 08:49:37 GMT"),
        ]);
        assert!(!is_not_modified(&both_inm_miss, Some(&et), Some(&lm)));
    }

    #[test]
    fn parse_imf_fixdate_roundtrips_and_orders() {
        for secs in [0u64, 784_111_777, 951_782_400, 1_700_000_000] {
            let s = fmt_imf_fixdate(secs);
            assert_eq!(
                parse_imf_fixdate(&s),
                Some(secs as i64),
                "round-trip of {s}"
            );
        }
        let a = parse_imf_fixdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let b = parse_imf_fixdate("Mon, 07 Nov 1994 00:00:00 GMT").unwrap();
        assert!(a < b, "later date must compare greater");
        // The obsolete RFC 850 / asctime formats and garbage are not parsed (None).
        assert_eq!(parse_imf_fixdate("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(parse_imf_fixdate("garbage"), None);
    }

    #[test]
    fn ims_unparseable_date_falls_back_to_exact_equality() {
        let lm = hv("Sun, 06 Nov 1994 08:49:37 GMT");
        // An IMS we cannot parse falls back to exact-string comparison with Last-Modified.
        let garbage = headers(&[(IF_MODIFIED_SINCE, "not a date")]);
        assert!(!is_not_modified(&garbage, None, Some(&lm)));
        let obsolete_exact = headers(&[(IF_MODIFIED_SINCE, "Sun, 06 Nov 1994 08:49:37 GMT")]);
        assert!(is_not_modified(&obsolete_exact, None, Some(&lm)));
    }

    #[test]
    fn no_conditional_headers_is_not_304() {
        assert!(!is_not_modified(
            &HeaderMap::new(),
            Some(&hv("W/\"a\"")),
            None
        ));
    }
}

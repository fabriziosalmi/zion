// SPDX-License-Identifier: Apache-2.0
//! When a certificate revocation list says it will be replaced (`nextUpdate`).
//!
//! The verifier (rustls) knows the `nextUpdate` of the lists it is given but does not say it,
//! and by default keeps applying a list whose `nextUpdate` is past. This reads that one field
//! so zion can report it: a gauge for the alert, a warning at load. The list's signature is
//! not checked here (the verifier does that, when a handshake uses it); this only reads dates.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Which listener a CRL belongs to: the data plane (`[tls]`) or the admin API (`[admin]`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Listener {
    Tls,
    Admin,
}

impl Listener {
    fn label(self) -> &'static str {
        match self {
            Listener::Tls => "tls",
            Listener::Admin => "admin",
        }
    }

    fn gauge(self) -> &'static AtomicU64 {
        static TLS: AtomicU64 = AtomicU64::new(0);
        static ADMIN: AtomicU64 = AtomicU64::new(0);
        match self {
            Listener::Tls => &TLS,
            Listener::Admin => &ADMIN,
        }
    }
}

/// A list this close to its `nextUpdate` is worth a warning.
const WARN_BEFORE_SECS: u64 = 7 * 86_400;

/// Where a list stands against its `nextUpdate`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Freshness {
    /// More than a week left, or no `nextUpdate` to go by.
    Fine,
    /// Expires in this many seconds.
    Soon(u64),
    /// Expired this many seconds ago.
    Expired(u64),
}

fn freshness(next_update: Option<u64>, now: u64) -> Freshness {
    match next_update {
        None => Freshness::Fine,
        Some(t) if t <= now => Freshness::Expired(now - t),
        Some(t) if t - now <= WARN_BEFORE_SECS => Freshness::Soon(t - now),
        Some(_) => Freshness::Fine,
    }
}

fn human(secs: u64) -> String {
    match secs {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 2 * 86_400 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

/// The warning for a list in this state, if it deserves one. Names the file, never its content.
fn warning(listener: Listener, path: &str, state: Freshness, enforce: bool) -> Option<String> {
    let who = listener.label();
    match state {
        Freshness::Fine => None,
        Freshness::Soon(left) => Some(format!(
            "client CRL {path} ([{who}]): its nextUpdate is in {} — publish the next list before then",
            human(left)
        )),
        Freshness::Expired(ago) if enforce => Some(format!(
            "client CRL {path} ([{who}]): expired {} ago (its nextUpdate has passed) and client_crl_enforce_next_update is set — every client certificate is refused until a fresh list is published",
            human(ago)
        )),
        Freshness::Expired(ago) => Some(format!(
            "client CRL {path} ([{who}]): expired {} ago (its nextUpdate has passed). The list is out of date but keeps being applied; publish a fresh one, or set client_crl_enforce_next_update = true to refuse every client until then",
            human(ago)
        )),
    }
}

/// Note the CRLs just loaded for `listener`: the earliest `nextUpdate` among them goes to the
/// gauge (`0` when none has one), and a list that is expired or close to it is warned about.
/// Called at every load and reload, so the gauge follows a file that is replaced.
pub fn report<T: AsRef<[u8]>>(listener: Listener, path: &str, crls: &[T], enforce: bool) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let earliest = crls.iter().filter_map(|c| next_update(c.as_ref())).min();
    listener.gauge().store(earliest.unwrap_or(0), Relaxed);
    if let Some(w) = warning(listener, path, freshness(earliest, now), enforce) {
        crate::logging::warn("tls", &w);
    }
}

/// The CRL gauge in Prometheus text format; nothing when no listener has a CRL with a date.
pub fn render(out: &mut bytes::BytesMut) {
    let values = [Listener::Tls, Listener::Admin].map(|l| (l, l.gauge().load(Relaxed)));
    if values.iter().all(|(_, v)| *v == 0) {
        return;
    }
    out.extend_from_slice(
        b"# HELP zion_tls_client_crl_next_update_timestamp_seconds Unix time of the earliest nextUpdate among the client CRLs a listener loaded. time() minus this above zero means the list is out of date.\n\
          # TYPE zion_tls_client_crl_next_update_timestamp_seconds gauge\n",
    );
    for (listener, value) in values {
        if value != 0 {
            out.extend_from_slice(
                format!(
                    "zion_tls_client_crl_next_update_timestamp_seconds{{listener=\"{}\"}} {value}\n",
                    listener.label()
                )
                .as_bytes(),
            );
        }
    }
}

/// `nextUpdate` of a DER-encoded `CertificateList`, in seconds since the Unix epoch. `None`
/// when the list has none (it is optional) or is not shaped as a CRL.
///
/// ```text
/// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
/// TBSCertList ::= SEQUENCE {
///     version Version OPTIONAL,            -- INTEGER
///     signature AlgorithmIdentifier,       -- SEQUENCE
///     issuer Name,                         -- SEQUENCE
///     thisUpdate Time,                     -- UTCTime | GeneralizedTime
///     nextUpdate Time OPTIONAL, ... }
/// ```
pub fn next_update(der: &[u8]) -> Option<u64> {
    let (_, list) = tlv(der, 0x30)?;
    let (_, tbs) = tlv(list, 0x30)?;
    let mut rest = tbs;
    // version (optional), signature, issuer
    if rest.first() == Some(&0x02) {
        rest = tlv(rest, 0x02)?.0;
    }
    rest = tlv(rest, 0x30)?.0;
    rest = tlv(rest, 0x30)?.0;
    // thisUpdate, then nextUpdate when the next element is a time
    rest = time(rest)?.1;
    time(rest).map(|(secs, _)| secs)
}

/// One DER element with tag `tag`: `(what follows it, its content)`.
fn tlv(buf: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = buf.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((&rest[len..], &rest[..len]))
}

/// A `UTCTime` or `GeneralizedTime` at the start of `buf`: `(seconds since the epoch, what
/// follows it)`. Both are required to be UTC (`Z`) and to carry seconds, as RFC 5280 says.
fn time(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (rest, text) = match buf.first()? {
        0x17 => tlv(buf, 0x17)?,
        0x18 => tlv(buf, 0x18)?,
        _ => return None,
    };
    let text = std::str::from_utf8(text).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |from: usize, len: usize| digits.get(from..from + len)?.parse::<u64>().ok();
    let (year, at) = if buf[0] == 0x17 {
        if digits.len() != 12 {
            return None;
        }
        let yy = n(0, 2)?;
        (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
    } else {
        if digits.len() != 14 {
            return None;
        }
        (n(0, 4)?, 4)
    };
    let (month, day) = (n(at, 2)?, n(at + 2, 2)?);
    let (hour, minute, second) = (n(at + 4, 2)?, n(at + 6, 2)?, n(at + 8, 2)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = days_from_civil(year as i64, month as i64, day as i64);
    let secs = days.checked_mul(86_400)? + (hour * 3600 + minute * 60 + second) as i64;
    u64::try_from(secs).ok().map(|s| (s, rest))
}

/// Days from 1970-01-01 to the given civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DER `tag len content`, with the long form of the length when it is needed.
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend(content);
        out
    }

    fn utc(s: &str) -> Vec<u8> {
        der(0x17, s.as_bytes())
    }
    fn general(s: &str) -> Vec<u8> {
        der(0x18, s.as_bytes())
    }

    /// A CRL-shaped blob: `version` and the times as given, an empty issuer and algorithm,
    /// no revoked list. The signature is not real; nothing here reads it.
    fn crl(version: bool, times: &[Vec<u8>]) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(der(0x02, &[1]));
        }
        tbs.extend(der(0x30, &[0x06, 0x01, 0x2a])); // signature AlgorithmIdentifier
        tbs.extend(der(0x30, &[0x31, 0x00])); // issuer
        for t in times {
            tbs.extend(t);
        }
        let mut list = der(0x30, &tbs);
        list.extend(der(0x30, &[0x06, 0x01, 0x2a])); // signatureAlgorithm
        list.extend(der(0x03, &[0x00, 0xff])); // signatureValue
        der(0x30, &list)
    }

    #[test]
    fn it_reads_next_update_as_utc_and_generalized_time() {
        // 2026-10-07 13:44:49 UTC, checked against `date -u -r`.
        let want = Some(1_791_380_689);
        let this = utc("261007134448Z");
        assert_eq!(
            next_update(&crl(true, &[this.clone(), utc("261007134449Z")])),
            want
        );
        assert_eq!(
            next_update(&crl(false, &[this.clone(), utc("261007134449Z")])),
            want
        );
        assert_eq!(
            next_update(&crl(true, &[this, general("20261007134449Z")])),
            want
        );
        assert_eq!(
            next_update(&crl(
                true,
                &[general("20261007134448Z"), general("20261007134449Z")]
            )),
            want
        );
    }

    #[test]
    fn utc_time_years_pivot_at_fifty() {
        // 2049-12-31 23:59:59 and 1950-01-01 00:00:00.
        assert_eq!(
            next_update(&crl(true, &[utc("200101000000Z"), utc("491231235959Z")])),
            Some(2_524_607_999)
        );
        assert_eq!(
            next_update(&crl(true, &[utc("200101000000Z"), utc("500101000000Z")])),
            None,
            "before 1970 is not a time a CRL has"
        );
    }

    #[test]
    fn leap_days_and_month_ends_are_counted() {
        // 2028-02-29 12:00:00 and 2100-03-01 00:00:00 (2100 is not a leap year).
        assert_eq!(
            next_update(&crl(true, &[utc("280101000000Z"), utc("280229120000Z")])),
            Some(1_835_438_400)
        );
        assert_eq!(
            next_update(&crl(
                true,
                &[general("20000101000000Z"), general("21000301000000Z")]
            )),
            Some(4_107_542_400)
        );
    }

    #[test]
    fn a_list_without_next_update_has_none() {
        assert_eq!(next_update(&crl(true, &[utc("261007134448Z")])), None);
    }

    #[test]
    fn lengths_in_the_long_form_are_followed() {
        // An issuer of 200 bytes makes the tbsCertList and the list use 0x81/0x82 lengths.
        let mut tbs = der(0x02, &[1]);
        tbs.extend(der(0x30, &[0x06, 0x01, 0x2a]));
        tbs.extend(der(0x30, &[0u8; 200]));
        tbs.extend(utc("261007134448Z"));
        tbs.extend(utc("261007134449Z"));
        let mut list = der(0x30, &tbs);
        list.extend(der(0x03, &[0u8; 300]));
        assert_eq!(next_update(&der(0x30, &list)), Some(1_791_380_689));
    }

    #[test]
    fn what_is_not_a_crl_has_no_next_update_and_never_panics() {
        for bad in [
            &[][..],
            &[0x30],
            &[0x30, 0x00],
            &[0x30, 0x03, 0x01, 0x02, 0x03],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            &[0x30, 0x80],
            b"-----BEGIN X509 CRL-----",
        ] {
            assert_eq!(next_update(bad), None, "{bad:?}");
        }
        // Times that are not UTC, not digits, out of range, or the wrong length.
        for t in [
            utc("261007134449+0000"),
            utc("26100713444Z"),
            utc("2610071344aaZ"),
            utc("261307134449Z"),
            utc("261032134449Z"),
            utc("261007254449Z"),
            general("261007134449Z"),
        ] {
            assert_eq!(next_update(&crl(true, &[utc("261007134448Z"), t])), None);
        }
        // Every prefix of a good list is rejected, none panics.
        let good = crl(true, &[utc("261007134448Z"), utc("261007134449Z")]);
        for end in 0..good.len() {
            assert_eq!(next_update(&good[..end]), None, "prefix of {end} bytes");
        }
    }

    #[test]
    fn freshness_is_judged_against_next_update() {
        let now = 1_000_000;
        assert_eq!(freshness(None, now), Freshness::Fine);
        assert_eq!(freshness(Some(now - 5), now), Freshness::Expired(5));
        assert_eq!(
            freshness(Some(now), now),
            Freshness::Expired(0),
            "a list is out of date at its nextUpdate"
        );
        assert_eq!(freshness(Some(now + 1), now), Freshness::Soon(1));
        assert_eq!(
            freshness(Some(now + WARN_BEFORE_SECS), now),
            Freshness::Soon(WARN_BEFORE_SECS)
        );
        assert_eq!(
            freshness(Some(now + WARN_BEFORE_SECS + 1), now),
            Freshness::Fine
        );
    }

    #[test]
    fn warnings_name_the_file_and_say_what_happens() {
        let w = |state, enforce| warning(Listener::Admin, "/etc/zion/crl.pem", state, enforce);
        assert_eq!(w(Freshness::Fine, false), None);
        let soon = w(Freshness::Soon(3 * 86_400), false).unwrap();
        assert!(
            soon.contains("/etc/zion/crl.pem")
                && soon.contains("[admin]")
                && soon.contains("3 days"),
            "{soon}"
        );
        let expired = w(Freshness::Expired(90), false).unwrap();
        assert!(
            expired.contains("expired 90 s ago") && expired.contains("keeps being applied"),
            "{expired}"
        );
        assert!(
            expired.contains("client_crl_enforce_next_update = true"),
            "{expired}"
        );
        let enforced = w(Freshness::Expired(3 * 3600), true).unwrap();
        assert!(
            enforced.contains("expired 3 h ago") && enforced.contains("refused"),
            "{enforced}"
        );
        assert!(!enforced.contains("keeps being applied"), "{enforced}");
    }

    #[test]
    fn durations_read_in_the_unit_that_matters() {
        assert_eq!(human(0), "0 s");
        assert_eq!(human(119), "119 s");
        assert_eq!(human(120), "2 min");
        assert_eq!(human(7199), "119 min");
        assert_eq!(human(7200), "2 h");
        assert_eq!(human(2 * 86_400 - 1), "47 h");
        assert_eq!(human(2 * 86_400), "2 days");
    }

    /// The gauge takes the earliest date, follows a reload, and falls back to nothing.
    #[test]
    fn the_gauge_holds_the_earliest_next_update_and_follows_the_last_load() {
        let list = |next: &str| crl(true, &[utc("261007134448Z"), utc(next)]);
        let render_now = || {
            let mut out = bytes::BytesMut::new();
            render(&mut out);
            String::from_utf8(out.to_vec()).unwrap()
        };
        report(
            Listener::Admin,
            "/c",
            &[list("301007134449Z"), list("291007134449Z")],
            false,
        );
        let text = render_now();
        assert!(
            text.contains("# TYPE zion_tls_client_crl_next_update_timestamp_seconds gauge"),
            "{text}"
        );
        assert!(
            text.contains("{listener=\"admin\"} 1886075089\n"),
            "the earlier of the two (2029-10-07 13:44:49): {text}"
        );
        assert!(
            !text.contains("listener=\"tls\""),
            "a listener without a CRL has no series: {text}"
        );
        // A new load replaces it.
        report(Listener::Admin, "/c", &[list("320101000000Z")], false);
        assert!(render_now().contains("{listener=\"admin\"} 1956528000\n"));
        // A list with no nextUpdate leaves nothing to report.
        report(
            Listener::Admin,
            "/c",
            &[crl(true, &[utc("261007134448Z")])],
            false,
        );
        assert!(!render_now().contains("listener=\"admin\""));
    }

    /// A list as OpenSSL writes it (revoking one certificate; throwaway CA, nothing secret):
    /// `lastUpdate=Oct  7 13:44:48 2026 GMT`, `nextUpdate=Oct  7 13:44:49 2026 GMT`.
    #[test]
    fn it_reads_a_list_openssl_wrote() {
        const PEM: &str = "-----BEGIN X509 CRL-----
MIIBgDBqAgEBMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB3Rlc3QtY2EXDTI2
MTAwNzEzNDQ0OFoXDTI2MTAwNzEzNDQ0OVowFDASAgECFw0yNjEwMDcxMzQ0NDha
oA4wDDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAn4uVfCJXTFrCqF5W
EYlZbNbCF1tSNEJg/k9LUpBWRyZ8K2KLx71P2c0EdbzZLJk05Nw4VxO39JeMloix
2F3FsAfi+CWyb8aQc8dpE06ZsYHipTcWkN4L8X0dTj4nDqRAsOOA49zLe+SaNDuu
HruV/rrTMcHvHgOBtSx3IUYQ8aF5eWQofExA6ivi7WFe/SPkhdvPdRlZHIfR/+no
LGjD25HjJwcYfR4vMJYT25WsG0Y0rBg+4OSb1IiwOt+f1mG++WCfJos86IJH0l2e
2djc1uTC5O41ELzogJjzA2xakRRUMl51HxE4WwaSkGn6gkxj1ZSicehl11b4qO7Y
eyOjnQ==
-----END X509 CRL-----\n";
        let ders = crate::pem::crls(PEM.as_bytes()).unwrap();
        assert_eq!(ders.len(), 1);
        assert_eq!(next_update(ders[0].as_ref()), Some(1_791_380_689));
    }
}

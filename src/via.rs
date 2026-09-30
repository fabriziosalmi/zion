// SPDX-License-Identifier: Apache-2.0
//! `Via` (RFC 9110 §7.6.3) and loop detection.
//!
//! A proxy SHOULD add itself to `Via` on what it forwards, and a request that comes
//! back to a proxy already listed in its `Via` has looped: a misconfigured upstream
//! that points at this proxy (or at something that does) would otherwise bounce the
//! request between hops until a connection or file-descriptor limit stops it.
//!
//! Each process takes a random pseudonym at first use (`zion-` plus 8 hex digits) and
//! appends `<protocol> <pseudonym>` to the `Via` of every request it forwards. A request
//! whose `Via` already names THIS pseudonym is refused with `508 Loop Detected`.
//!
//! The pseudonym is per process on purpose: a fixed name would make two legitimate Zion
//! tiers in a chain (an edge Zion in front of an origin Zion) look like a loop.

use std::sync::OnceLock;

/// This process's pseudonym in `Via`.
pub fn pseudonym() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let mut b = [0u8; 4];
        // A failure of the system RNG is not worth failing a request over: fall back to
        // the process id, which still distinguishes processes on one host.
        if aws_lc_rs::rand::fill(&mut b).is_err() {
            b = std::process::id().to_be_bytes();
        }
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        format!("zion-{hex}")
    })
}

/// The `received-protocol` of a `Via` entry for a message that arrived over `v`.
pub fn received_protocol(v: hyper::Version) -> &'static str {
    match v {
        hyper::Version::HTTP_09 => "0.9",
        hyper::Version::HTTP_10 => "1.0",
        hyper::Version::HTTP_2 => "2",
        hyper::Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

/// Append this proxy to `Via`, keeping what earlier hops wrote.
pub fn append(headers: &mut hyper::HeaderMap, received: hyper::Version) {
    let entry = format!("{} {}", received_protocol(received), pseudonym());
    if let Ok(v) = hyper::header::HeaderValue::from_str(&entry) {
        headers.append(hyper::header::VIA, v);
    }
}

/// Does any `Via` entry name `pseudonym` as its `received-by`? Entries look like
/// `1.1 name`, `HTTP/1.0 name:8080` or `1.1 name (comment)`, comma separated; only an
/// exact, case-insensitive match of the name counts, so `zion-ab12cd34-x` is not us.
pub fn names(headers: &hyper::HeaderMap, pseudonym: &str) -> bool {
    headers
        .get_all(hyper::header::VIA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|entry| entry.split_whitespace().nth(1))
        .map(|by| by.split(':').next().unwrap_or(by))
        .any(|by| by.eq_ignore_ascii_case(pseudonym))
}

/// Has this request already passed through this process?
pub fn is_loop(headers: &hyper::HeaderMap) -> bool {
    names(headers, pseudonym())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn via(lines: &[&str]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for l in lines {
            h.append(hyper::header::VIA, HeaderValue::from_str(l).unwrap());
        }
        h
    }

    #[test]
    fn the_pseudonym_is_stable_and_distinct_in_form() {
        let p = pseudonym();
        assert_eq!(p, pseudonym());
        assert!(p.starts_with("zion-") && p.len() == 13, "{p}");
        assert!(p[5..].chars().all(|c| c.is_ascii_hexdigit()), "{p}");
    }

    #[test]
    fn names_matches_the_received_by_exactly() {
        let me = "zion-deadbeef";
        assert!(names(&via(&["1.1 zion-deadbeef"]), me));
        assert!(
            names(&via(&["1.0 edge, 1.1 zion-deadbeef, 1.1 b"]), me),
            "in the middle"
        );
        assert!(
            names(&via(&["1.1 a", "HTTP/2 ZION-DEADBEEF"]), me),
            "second line, any case"
        );
        assert!(
            names(&via(&["1.1 zion-deadbeef:8443 (Zion)"]), me),
            "port and comment"
        );
        for not in [
            "1.1 zion-deadbeef-2",
            "1.1 zion-deadbee",
            "1.1 other",
            "1.1 edge (zion-deadbeef)",
            "zion-deadbeef",
            "",
        ] {
            assert!(!names(&via(&[not]), me), "{not:?}");
        }
        assert!(!names(&hyper::HeaderMap::new(), me));
    }

    #[test]
    fn append_keeps_earlier_hops_and_names_the_protocol() {
        let mut h = via(&["1.0 edge"]);
        append(&mut h, hyper::Version::HTTP_2);
        let all: Vec<&str> = h
            .get_all(hyper::header::VIA)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(all[0], "1.0 edge");
        assert_eq!(all[1], format!("2 {}", pseudonym()));
        assert!(
            is_loop(&h),
            "after appending, the request names this process"
        );
        for (v, p) in [
            (hyper::Version::HTTP_10, "1.0"),
            (hyper::Version::HTTP_11, "1.1"),
            (hyper::Version::HTTP_2, "2"),
            (hyper::Version::HTTP_3, "3"),
        ] {
            assert_eq!(received_protocol(v), p);
        }
    }
}

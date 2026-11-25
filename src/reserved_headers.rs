// SPDX-License-Identifier: Apache-2.0
//! Request headers an upstream reads as a statement *about* the request, and who may make
//! that statement. One table, so "what must a client never be able to set" has one answer
//! and one test can walk it over every listener.
//!
//! A header is the same header under any case and with any byte that is neither a letter nor a
//! digit for any `-` ([`same_name`]). An upstream that names headers the CGI way (RFC 3875: upper
//! case, `-` as `_`; WSGI and Rack do the same) turns `X_Client_Cert_Fingerprint` and
//! `X-Client-Cert-Fingerprint` into the one variable `HTTP_X_CLIENT_CERT_FINGERPRINT`, and PHP
//! also turns `.` into `_` when it files that variable, so its built-in server reads
//! `X.Client.Cert.Fingerprint` as the same one. A scrub that drops only the dashed spelling lets
//! a client hand such an upstream a forged value under another.
//!
//! No dependency on the rest of the crate: the table is also what the real-socket tests
//! iterate.

/// Who is entitled to put a reserved header on a request that reaches an upstream. A copy
/// from anyone else is a forgery and is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asserter {
    /// Zion's TLS layer: what the handshake verified (the client certificate, the JA4
    /// identity). Every listener strips inbound copies before the pipeline; only the HTTPS
    /// listener puts back the values it verified.
    Transport,
    /// Zion's request pipeline: the authenticated identity (`X-Auth-*`, set by the auth
    /// gate) and the mesh reputation (`X-Zion-Mesh-Score`, set by the mesh gate). Dropped
    /// by the first pre-routing gate, whoever the peer is.
    Pipeline,
    /// A configured trusted proxy: where the request "really" goes or came from. Dropped
    /// unless the peer is in `[server] trusted_proxies`.
    TrustedProxy,
}

/// Every reserved header (lower-case, as hyper stores names) with its asserter.
///
/// `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto` and `X-Forwarded-Host` are not here:
/// Zion sets or drops them when it forwards, and drops their other spellings there
/// ([`FORWARDING_HEADERS`]).
pub const RESERVED_HEADERS: [(&str, Asserter); 16] = [
    // What the TLS handshake verified.
    ("x-client-cert-fingerprint", Asserter::Transport),
    ("x-client-cert-dn", Asserter::Transport),
    ("x-client-tls-ja4", Asserter::Transport),
    ("x-client-tls-allowlisted", Asserter::Transport),
    // What the pipeline established.
    ("x-auth-subject", Asserter::Pipeline),
    ("x-auth-email", Asserter::Pipeline),
    ("x-zion-mesh-score", Asserter::Pipeline),
    // The path (`X-Original-URL` / `X-Rewrite-URL`, honoured by IIS, Symfony and others over
    // the real request line), the host or scheme, and RFC 7239 `Forwarded` (Zion generates
    // `X-Forwarded-*`, never `Forwarded`, so an upstream that prefers it would read the
    // client's own claim). From a client these are route/policy bypass and cache-poisoning
    // inputs.
    ("x-original-url", Asserter::TrustedProxy),
    ("x-rewrite-url", Asserter::TrustedProxy),
    ("forwarded", Asserter::TrustedProxy),
    ("x-forwarded-server", Asserter::TrustedProxy),
    ("x-forwarded-scheme", Asserter::TrustedProxy),
    ("x-forwarded-prefix", Asserter::TrustedProxy),
    ("x-host", Asserter::TrustedProxy),
    ("x-http-host-override", Asserter::TrustedProxy),
    ("x-original-host", Asserter::TrustedProxy),
];

/// The forwarding headers Zion sets or drops on every request it forwards (`proxy.rs`,
/// `apply_forwarding_hygiene`), under the dashed name: `X-Forwarded-Proto` is always set,
/// `X-Real-IP` when the client address is known, `X-Forwarded-Host` when the request names a
/// host, and `X-Forwarded-For` as `xff_mode` says (extended in `append`, replaced in `rewrite`,
/// removed in `drop`). Another spelling of one ([`same_name`]) is a second copy that Zion neither
/// overwrites nor reads, and that the upstream reads as the same header: behind Python's
/// `wsgiref`, `X_Real_IP: 1.2.3.4` makes `HTTP_X_REAL_IP` `1.2.3.4,<client>`, and behind PHP's
/// built-in server an `X.Real.IP: 1.2.3.4` sent after `X-Real-IP` makes it `1.2.3.4`. So
/// [`drop_other_spellings`] removes it from every forwarded request.
pub const FORWARDING_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// The reserved headers `asserter` owns.
pub fn reserved(asserter: Asserter) -> impl Iterator<Item = &'static str> {
    RESERVED_HEADERS
        .iter()
        .filter(move |(_, a)| *a == asserter)
        .map(|(name, _)| *name)
}

/// `name`, a request header name (lower-case, as hyper stores it), is the header `dashed`
/// (lower-case letters, digits and `-`) with any byte that is neither a letter nor a digit read as
/// a `-`. A CGI-style upstream reads `_` as `-`, and PHP also `.` (its built-in server reads
/// `X.Real.IP` as `HTTP_X_REAL_IP`). The other bytes a header name may hold
/// (`` !#$%&'*+^`|~ ``) are read as `-` too, although PHP's built-in server keeps them: a name
/// that differs from `dashed` only there has no use but to pass for it.
pub fn same_name(dashed: &str, name: &str) -> bool {
    dashed.len() == name.len()
        && dashed
            .bytes()
            .zip(name.bytes())
            .all(|(d, n)| d == n || (d == b'-' && !n.is_ascii_alphanumeric()))
}

/// Drop every copy of the headers `asserter` owns, under every spelling [`same_name`] reads as
/// that header: any case (hyper lower-cases names), and any byte that is neither a letter nor a
/// digit (`_`, `.`) for any `-`.
///
/// A request almost never carries one. So only the names the request *does* carry are looked at
/// (a handful, and all but `forwarded` and the ones that start with `x` and a byte that is
/// neither a letter nor a digit are dismissed by their first two bytes), and a name is collected
/// and removed only when it matches: a request that carries none allocates nothing and is not
/// touched.
pub fn scrub(headers: &mut hyper::HeaderMap, asserter: Asserter) {
    let mut hits: Vec<hyper::header::HeaderName> = Vec::new();
    for k in headers.keys() {
        let name = k.as_str();
        let maybe_reserved = name == "forwarded"
            || matches!(name.as_bytes(), [b'x', sep, ..] if !sep.is_ascii_alphanumeric());
        if maybe_reserved && reserved(asserter).any(|r| same_name(r, name)) {
            hits.push(k.clone());
        }
    }
    for name in hits {
        headers.remove(&name);
    }
}

/// Drop every header that is one of `names` (lower-case, dashed) spelled with another byte for at
/// least one `-` ([`same_name`]): `X_Real_IP`, `X.Real.IP`. The dashed spelling itself stays: the
/// caller sets or extends it.
pub fn drop_other_spellings(headers: &mut hyper::HeaderMap, names: &[&str]) {
    let mut hits: Vec<hyper::header::HeaderName> = Vec::new();
    for k in headers.keys() {
        let name = k.as_str();
        if names.iter().any(|n| *n != name && same_name(n, name)) {
            hits.push(k.clone());
        }
    }
    for name in hits {
        headers.remove(&name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_lower_case_and_names_each_header_once() {
        let mut seen = std::collections::HashSet::new();
        for (name, _) in RESERVED_HEADERS {
            assert_eq!(
                name,
                name.to_ascii_lowercase(),
                "hyper stores names lower-case"
            );
            assert!(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).is_ok(),
                "{name} is not a header name"
            );
            assert!(seen.insert(name), "{name} is listed twice");
        }
        for asserter in [
            Asserter::Transport,
            Asserter::Pipeline,
            Asserter::TrustedProxy,
        ] {
            assert!(reserved(asserter).count() > 0, "{asserter:?} owns nothing");
        }
    }

    #[test]
    fn a_request_with_none_of_them_is_left_exactly_as_it_was() {
        // the common case, taken on the fast path: nothing to find, nothing touched
        let mut h = hyper::HeaderMap::new();
        for (k, v) in [
            ("host", "a.example"),
            ("user-agent", "t"),
            ("x-request-id", "1"),
            ("x-custom", "kept"),
            ("accept", "*/*"),
        ] {
            h.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let before = h.clone();
        for asserter in [
            Asserter::Transport,
            Asserter::Pipeline,
            Asserter::TrustedProxy,
        ] {
            scrub(&mut h, asserter);
        }
        assert_eq!(h, before);
    }

    /// The spellings of `name` a client would try: as written, upper case, every `-` as `_`,
    /// only the first `-` as `_`, every `-` as `.` (PHP reads `.` as `_`), and every `-` as `~`.
    fn spellings(name: &str) -> Vec<String> {
        vec![
            name.to_string(),
            name.to_ascii_uppercase(),
            name.replace('-', "_"),
            name.replacen('-', "_", 1),
            name.replace('-', "."),
            name.replace('-', "~"),
        ]
    }

    #[test]
    fn a_scrub_removes_every_copy_of_its_class_and_nothing_else() {
        for asserter in [
            Asserter::Transport,
            Asserter::Pipeline,
            Asserter::TrustedProxy,
        ] {
            let mut h = hyper::HeaderMap::new();
            for (name, _) in RESERVED_HEADERS {
                // Mixed case, `_` or `.` for `-`, and repeated, as a client would try.
                for spelling in spellings(name) {
                    h.append(
                        hyper::header::HeaderName::from_bytes(spelling.as_bytes()).unwrap(),
                        "forged".parse().unwrap(),
                    );
                }
            }
            h.insert("authorization", "Bearer t".parse().unwrap());
            scrub(&mut h, asserter);
            for (name, owner) in RESERVED_HEADERS {
                for spelling in spellings(name) {
                    assert_eq!(
                        h.contains_key(spelling.to_ascii_lowercase().as_str()),
                        owner != asserter,
                        "{spelling} after scrubbing {asserter:?}"
                    );
                }
            }
            assert!(h.contains_key("authorization"), "unrelated headers stay");
        }
    }

    #[test]
    fn a_scrub_removes_the_underscore_spelling_of_a_reserved_header() {
        // A CGI-style upstream reads `X_Client_Cert_Fingerprint` as
        // `X-Client-Cert-Fingerprint` (both become HTTP_X_CLIENT_CERT_FINGERPRINT).
        let mut h = hyper::HeaderMap::new();
        h.insert(
            hyper::header::HeaderName::from_bytes(b"X_Client_Cert_Fingerprint").unwrap(),
            "sha256:forged".parse().unwrap(),
        );
        scrub(&mut h, Asserter::Transport);
        assert!(
            !h.contains_key("x_client_cert_fingerprint"),
            "underscore alias survived the Transport scrub: {h:?}"
        );
    }

    /// PHP files a request header under `HTTP_` + its name upper-cased with `-` and `.` as `_`, so
    /// its built-in server reads `X.Client.Cert.Fingerprint` as `HTTP_X_CLIENT_CERT_FINGERPRINT`.
    #[test]
    fn a_scrub_removes_the_dotted_spelling_php_reads_as_a_reserved_header() {
        for (name, asserter) in [
            ("X.Client.Cert.Fingerprint", Asserter::Transport),
            ("X.Auth.Subject", Asserter::Pipeline),
            ("X.Original.URL", Asserter::TrustedProxy),
            ("X_Forwarded.Prefix", Asserter::TrustedProxy),
        ] {
            let mut h = hyper::HeaderMap::new();
            h.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "forged".parse().unwrap(),
            );
            scrub(&mut h, asserter);
            assert!(
                h.is_empty(),
                "{name} survived the {asserter:?} scrub: {h:?}"
            );
        }
    }

    #[test]
    fn a_name_that_only_looks_like_a_reserved_one_is_kept() {
        let mut h = hyper::HeaderMap::new();
        for name in [
            "x-client-cert-fingerprints",
            "x_client_cert",
            "x-client-cert-fingerprint-x",
            "x0client0cert0fingerprint",
            "xclient-cert-fingerprint",
            "x.client.cert.fingerprint.",
            "forwarded_",
        ] {
            h.insert(
                hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                "kept".parse().unwrap(),
            );
        }
        let before = h.clone();
        for asserter in [
            Asserter::Transport,
            Asserter::Pipeline,
            Asserter::TrustedProxy,
        ] {
            scrub(&mut h, asserter);
        }
        assert_eq!(h, before);
    }

    #[test]
    fn another_spelling_of_a_forwarding_header_is_dropped_and_the_dashed_one_kept() {
        let mut h = hyper::HeaderMap::new();
        for name in FORWARDING_HEADERS {
            for spelling in spellings(name) {
                h.append(
                    hyper::header::HeaderName::from_bytes(spelling.as_bytes()).unwrap(),
                    "v".parse().unwrap(),
                );
            }
        }
        h.insert("x_request_id", "kept".parse().unwrap());
        h.insert("x.request.id", "kept".parse().unwrap());
        drop_other_spellings(&mut h, &FORWARDING_HEADERS);
        for name in FORWARDING_HEADERS {
            // The dashed spelling (as written and upper-cased: one name to hyper) stays, twice.
            assert_eq!(h.get_all(name).iter().count(), 2, "{name}: {h:?}");
            for spelling in spellings(name) {
                let spelling = spelling.to_ascii_lowercase();
                assert!(
                    spelling == name || !h.contains_key(spelling.as_str()),
                    "{spelling} survived: {h:?}"
                );
            }
        }
        assert!(h.contains_key("x_request_id"), "unrelated headers stay");
        assert!(h.contains_key("x.request.id"), "unrelated headers stay");
    }

    // A counterexample here is a spelling of a reserved header that reaches the upstream.
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn every_case_and_separator_spelling_of_a_reserved_header_is_scrubbed(
            index in 0..RESERVED_HEADERS.len(),
            mask in any::<u64>(),
            seps in prop::collection::vec(
                prop::sample::select(b"_.!#$%&'*+^`|~".to_vec()),
                64,
            ),
        ) {
            let (name, owner) = RESERVED_HEADERS[index];
            let spelling: String = name
                .bytes()
                .enumerate()
                .map(|(i, b)| {
                    let flip = (mask >> (i % 64)) & 1 == 1;
                    match b {
                        b'-' if flip => seps.get(i).copied().unwrap_or(b'_') as char,
                        b if flip => b.to_ascii_uppercase() as char,
                        b => b as char,
                    }
                })
                .collect();
            let mut h = hyper::HeaderMap::new();
            h.insert(
                hyper::header::HeaderName::from_bytes(spelling.as_bytes()).unwrap(),
                "forged".parse().unwrap(),
            );
            scrub(&mut h, owner);
            prop_assert!(h.is_empty(), "{} survived as {:?}", name, spelling);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Request headers an upstream reads as a statement *about* the request, and who may make
//! that statement. One table, so "what must a client never be able to set" has one answer
//! and one test can walk it over every listener.
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
/// Zion always overwrites (or, for a trusted proxy, extends) them when it forwards.
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

/// The reserved headers `asserter` owns.
pub fn reserved(asserter: Asserter) -> impl Iterator<Item = &'static str> {
    RESERVED_HEADERS
        .iter()
        .filter(move |(_, a)| *a == asserter)
        .map(|(name, _)| *name)
}

/// Drop every copy of the headers `asserter` owns (hyper lower-cases names, so one `remove`
/// per name clears repeated and mixed-case copies).
pub fn scrub(headers: &mut hyper::HeaderMap, asserter: Asserter) {
    for name in reserved(asserter) {
        headers.remove(name);
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
    fn a_scrub_removes_every_copy_of_its_class_and_nothing_else() {
        for asserter in [
            Asserter::Transport,
            Asserter::Pipeline,
            Asserter::TrustedProxy,
        ] {
            let mut h = hyper::HeaderMap::new();
            for (name, _) in RESERVED_HEADERS {
                // Mixed case and repeated, as a client would try.
                let upper = name.to_ascii_uppercase();
                for spelling in [name, upper.as_str()] {
                    h.append(
                        hyper::header::HeaderName::from_bytes(spelling.as_bytes()).unwrap(),
                        "forged".parse().unwrap(),
                    );
                }
            }
            h.insert("authorization", "Bearer t".parse().unwrap());
            scrub(&mut h, asserter);
            for (name, owner) in RESERVED_HEADERS {
                assert_eq!(
                    h.contains_key(name),
                    owner != asserter,
                    "{name} after scrubbing {asserter:?}"
                );
            }
            assert!(h.contains_key("authorization"), "unrelated headers stay");
        }
    }
}

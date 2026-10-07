// SPDX-License-Identifier: Apache-2.0
//! PEM files, read through `rustls::pki_types` (the same parser `rustls-pemfile` wrapped,
//! which is archived: RUSTSEC-2025-0134).
//!
//! Three functions with the shape the callers had: certificates in file order, the first
//! private key of any kind (`None` when there is none), and certificate revocation lists.
//! A section of another kind is skipped; a malformed section is an error. Each takes the
//! file's bytes, so a caller that already read the file to hash it does not read it twice.

use rustls::pki_types::pem::{Error, PemObject};
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

/// Every `CERTIFICATE` section, in order. Empty when there is none.
pub fn certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    CertificateDer::pem_slice_iter(pem).collect()
}

/// The first private key (`PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`), `None` when
/// the file holds no key of those kinds.
pub fn private_key(pem: &[u8]) -> Result<Option<PrivateKeyDer<'static>>, Error> {
    match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => Ok(Some(key)),
        Err(Error::NoItemsFound) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Every `X509 CRL` section, in order. Empty when there is none.
pub fn crls(pem: &[u8]) -> Result<Vec<CertificateRevocationListDer<'static>>, Error> {
    CertificateRevocationListDer::pem_slice_iter(pem).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PEM section with `body` bytes as its content (the parsers read the framing and the
    /// base64, not the DER, so the content need not be a real key).
    fn section(label: &str, body: &[u8]) -> String {
        use std::fmt::Write;
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut text = String::new();
        for chunk in body.chunks(3) {
            let n = chunk.len();
            let v = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for (i, shift) in [18, 12, 6, 0].iter().enumerate() {
                if i <= n {
                    text.push(B64[((v >> shift) & 63) as usize] as char);
                } else {
                    text.push('=');
                }
            }
        }
        let mut out = format!("-----BEGIN {label}-----\n");
        for line in text.as_bytes().chunks(64) {
            writeln!(out, "{}", std::str::from_utf8(line).unwrap()).unwrap();
        }
        writeln!(out, "-----END {label}-----").unwrap();
        out
    }

    /// Distinct, recognisable content per section.
    fn body(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(7))
            .collect()
    }

    /// The inputs both parsers are run on. Good files of every shape zion is given, and the
    /// ways a file goes wrong.
    fn corpus() -> Vec<(&'static str, Vec<u8>)> {
        let cert = |n: u8| section("CERTIFICATE", &body(n, 90 + usize::from(n)));
        let pkcs8 = section("PRIVATE KEY", &body(1, 120));
        let pkcs1 = section("RSA PRIVATE KEY", &body(2, 200));
        let sec1 = section("EC PRIVATE KEY", &body(3, 60));
        let crl = section("X509 CRL", &body(4, 150));
        let mut c: Vec<(&'static str, Vec<u8>)> = vec![
            ("one certificate", cert(1).into_bytes()),
            (
                "a chain of three",
                [cert(1), cert(2), cert(3)].concat().into_bytes(),
            ),
            ("pkcs8 key", pkcs8.clone().into_bytes()),
            ("pkcs1 key", pkcs1.clone().into_bytes()),
            ("sec1 key", sec1.clone().into_bytes()),
            (
                "two keys: the first wins",
                [sec1.clone(), pkcs8.clone()].concat().into_bytes(),
            ),
            (
                "key then certificate",
                [pkcs8.clone(), cert(1)].concat().into_bytes(),
            ),
            (
                "certificate then key",
                [cert(1), pkcs1.clone()].concat().into_bytes(),
            ),
            (
                "certificates around a key",
                [cert(1), pkcs8.clone(), cert(2)].concat().into_bytes(),
            ),
            ("a crl", crl.clone().into_bytes()),
            (
                "two crls",
                [crl.clone(), section("X509 CRL", &body(5, 80))]
                    .concat()
                    .into_bytes(),
            ),
            (
                "a certificate and a crl",
                [cert(1), crl.clone()].concat().into_bytes(),
            ),
            (
                "a public key only",
                section("PUBLIC KEY", &body(6, 70)).into_bytes(),
            ),
            (
                "an encrypted key only",
                section("ENCRYPTED PRIVATE KEY", &body(7, 90)).into_bytes(),
            ),
            (
                "a csr only",
                section("CERTIFICATE REQUEST", &body(8, 90)).into_bytes(),
            ),
            (
                "parameters then a key",
                [section("EC PARAMETERS", &body(9, 10)), sec1.clone()]
                    .concat()
                    .into_bytes(),
            ),
            ("an empty file", Vec::new()),
            ("only whitespace", b"  \n\t\n\n".to_vec()),
            (
                "text that is not pem",
                b"hello, this is not a certificate\n".to_vec(),
            ),
            (
                "text before and between",
                format!("# issued by\n{}\nnotes\n{}\ntrailer\n", cert(1), cert(2)).into_bytes(),
            ),
            (
                "crlf line endings",
                cert(1).replace('\n', "\r\n").into_bytes(),
            ),
            (
                "no newline at the end",
                cert(1).trim_end().as_bytes().to_vec(),
            ),
            (
                "a byte order mark first",
                [b"\xef\xbb\xbf".as_slice(), cert(1).as_bytes()].concat(),
            ),
            (
                "trailing spaces after the begin line",
                cert(1)
                    .replacen("CERTIFICATE-----", "CERTIFICATE----- ", 1)
                    .into_bytes(),
            ),
            (
                "an empty certificate section",
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "a very long line",
                format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                    "QUJD".repeat(5000)
                )
                .into_bytes(),
            ),
            (
                "a begin with no end",
                cert(1)
                    .replace("-----END CERTIFICATE-----\n", "")
                    .into_bytes(),
            ),
            (
                "an end with no begin",
                cert(1)
                    .replace("-----BEGIN CERTIFICATE-----\n", "")
                    .into_bytes(),
            ),
            (
                "mismatched labels",
                cert(1)
                    .replace("END CERTIFICATE", "END PRIVATE KEY")
                    .into_bytes(),
            ),
            ("lower case label", cert(1).to_lowercase().into_bytes()),
            (
                "a bad base64 character",
                cert(1).replacen('A', "*", 1).into_bytes(),
            ),
            (
                "truncated base64",
                cert(1)
                    .replacen("=\n", "\n", 1)
                    .replace("-----END", "QQ\n-----END")
                    .into_bytes(),
            ),
            (
                "a good block after a bad one",
                [cert(1).replacen('A', "*", 1), cert(2)]
                    .concat()
                    .into_bytes(),
            ),
            (
                "a bad block after a good one",
                [cert(1), cert(2).replacen('A', "*", 1)]
                    .concat()
                    .into_bytes(),
            ),
            (
                "a key whose body is not base64",
                "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"
                    .as_bytes()
                    .to_vec(),
            ),
            (
                "a der file",
                vec![0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00],
            ),
            ("binary garbage", (0..=255u8).collect()),
            ("nul bytes", vec![0; 64]),
            (
                "a nested begin",
                format!("-----BEGIN CERTIFICATE-----\n{}", cert(1)).into_bytes(),
            ),
            (
                "five hundred certificates",
                (0..500u32)
                    .map(|i| cert((i % 200) as u8))
                    .collect::<String>()
                    .into_bytes(),
            ),
        ];
        c.push((
            "every kind at once",
            [cert(1), crl, pkcs8, pkcs1, sec1].concat().into_bytes(),
        ));
        c
    }

    /// What one parser made of one input, comparable across parsers: how many items and a
    /// digest of their bytes, or that it was refused. (The error text is not compared: it is
    /// for the operator, and the two crates word it differently.)
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Items(Vec<(usize, u64)>),
        Key(Option<(&'static str, usize, u64)>),
        Refused,
    }

    fn digest(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf29ce484222325u64, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
    }

    fn kind_of(key: &PrivateKeyDer<'_>) -> (&'static str, usize, u64) {
        match key {
            PrivateKeyDer::Pkcs1(k) => (
                "pkcs1",
                k.secret_pkcs1_der().len(),
                digest(k.secret_pkcs1_der()),
            ),
            PrivateKeyDer::Pkcs8(k) => (
                "pkcs8",
                k.secret_pkcs8_der().len(),
                digest(k.secret_pkcs8_der()),
            ),
            PrivateKeyDer::Sec1(k) => (
                "sec1",
                k.secret_sec1_der().len(),
                digest(k.secret_sec1_der()),
            ),
            _ => ("other", 0, 0),
        }
    }

    fn new_certs(pem: &[u8]) -> Outcome {
        certs(pem).map_or(Outcome::Refused, |v| {
            Outcome::Items(v.iter().map(|c| (c.len(), digest(c))).collect())
        })
    }
    fn new_crls(pem: &[u8]) -> Outcome {
        crls(pem).map_or(Outcome::Refused, |v| {
            Outcome::Items(v.iter().map(|c| (c.len(), digest(c))).collect())
        })
    }
    fn new_key(pem: &[u8]) -> Outcome {
        private_key(pem).map_or(Outcome::Refused, |k| Outcome::Key(k.as_ref().map(kind_of)))
    }

    /// What `rustls-pemfile` 2.2.0 made of each input of `corpus()`, as a digest of the
    /// outcome for certificates, key and CRLs together. Recorded by running both parsers over
    /// the corpus while the crate was still a dependency (they agreed on every input), then
    /// kept here so that nothing needs the archived crate to prove it. A change in this table
    /// is a change in what zion accepts as a certificate, a key or a CRL.
    const RECORDED: &[(&str, u64)] = &[
        ("one certificate", 13735250170367152698),
        ("a chain of three", 12614549480812674335),
        ("pkcs8 key", 5856121713950469042),
        ("pkcs1 key", 6230808213748110309),
        ("sec1 key", 6439124982290363099),
        ("two keys: the first wins", 6439124982290363099),
        ("key then certificate", 1632705742499061627),
        ("certificate then key", 9010685197473556864),
        ("certificates around a key", 1221084591850379636),
        ("a crl", 11335546349197399601),
        ("two crls", 17059253623223111018),
        ("a certificate and a crl", 2056781657163928874),
        ("a public key only", 17491199989910252345),
        ("an encrypted key only", 17491199989910252345),
        ("a csr only", 17491199989910252345),
        ("parameters then a key", 6439124982290363099),
        ("an empty file", 17491199989910252345),
        ("only whitespace", 17491199989910252345),
        ("text that is not pem", 17491199989910252345),
        ("text before and between", 6500020977082414803),
        ("crlf line endings", 13735250170367152698),
        ("no newline at the end", 13735250170367152698),
        ("a byte order mark first", 17491199989910252345),
        ("trailing spaces after the begin line", 13735250170367152698),
        ("an empty certificate section", 7859597806383895435),
        ("a very long line", 110026014674360131),
        ("a begin with no end", 13991669570033771399),
        ("an end with no begin", 17491199989910252345),
        ("mismatched labels", 13991669570033771399),
        ("lower case label", 17491199989910252345),
        ("a bad base64 character", 13991669570033771399),
        ("truncated base64", 13991669570033771399),
        ("a good block after a bad one", 13991669570033771399),
        ("a bad block after a good one", 13991669570033771399),
        ("a key whose body is not base64", 13991669570033771399),
        ("a der file", 17491199989910252345),
        ("binary garbage", 17491199989910252345),
        ("nul bytes", 17491199989910252345),
        ("a nested begin", 13735250170367152698),
        ("five hundred certificates", 5147912943267400775),
        ("every kind at once", 8001477398051595283),
    ];

    #[test]
    fn the_parser_reads_every_input_as_rustls_pemfile_did() {
        let corpus = corpus();
        assert_eq!(
            corpus.len(),
            RECORDED.len(),
            "the corpus and the record differ in size"
        );
        for ((name, pem), (recorded_name, recorded)) in corpus.iter().zip(RECORDED) {
            assert_eq!(name, recorded_name);
            let outcome = format!("{:?}{:?}{:?}", new_certs(pem), new_key(pem), new_crls(pem));
            // The message names the input and leaves the outcome out: it is derived from key
            // bytes, and a test log is not a place for those (even synthetic ones).
            assert_eq!(
                digest(outcome.as_bytes()),
                *recorded,
                "{name:?} is read differently from before"
            );
        }
    }

    /// The behaviours callers rely on, stated out loud (the record above would also catch a
    /// change, but not say what it was).
    #[test]
    fn what_callers_rely_on() {
        let find = |name: &str| corpus().into_iter().find(|(n, _)| *n == name).unwrap().1;
        // Several certificates come back in file order; other kinds are skipped.
        match new_certs(&find("certificates around a key")) {
            Outcome::Items(v) => assert_eq!(v.len(), 2),
            _ => panic!("the certificates around a key were not read as a list"),
        }
        // The first key wins, whatever its kind; a file with no key is `None`, not an error.
        assert!(matches!(
            new_key(&find("two keys: the first wins")),
            Outcome::Key(Some(("sec1", ..)))
        ));
        assert_eq!(new_key(&find("an encrypted key only")), Outcome::Key(None));
        assert_eq!(new_key(&find("an empty file")), Outcome::Key(None));
        // A file that is not PEM at all has no items; a damaged section is an error, and it
        // refuses the whole file, whichever kind was asked for.
        assert_eq!(
            new_certs(&find("text that is not pem")),
            Outcome::Items(vec![])
        );
        for name in [
            "a bad base64 character",
            "a begin with no end",
            "mismatched labels",
        ] {
            let pem = find(name);
            assert_eq!(
                [new_certs(&pem), new_key(&pem), new_crls(&pem)],
                [Outcome::Refused, Outcome::Refused, Outcome::Refused],
                "{name}"
            );
        }
        // A bad section after a good one still refuses the file: a half-read chain is never used.
        assert_eq!(
            new_certs(&find("a bad block after a good one")),
            Outcome::Refused
        );
    }
}

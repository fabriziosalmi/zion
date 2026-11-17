#![no_main]
//! Fuzz target — `uri_norm::try_normalize_path` / `without_path_params`.
//!
//! zion routes, checks policy on and forwards the normalized path, and the upstream decodes it
//! once more. If the two can read one path differently, a request matches a permissive route
//! and reaches a protected resource. On every path the normalizer accepts, the fuzzer checks
//! what the module promises:
//!   1. the result is canonical: normalizing it again changes nothing;
//!   2. no `.` or `..` segment, also after the upstream decodes each segment once;
//!   3. no empty segment (a `//` run) after the root;
//!   4. none of the bytes no route accepts: `\`, `%5C`, `%00`;
//!   5. a path with `;` stripped by `without_path_params` has no `;` and no dot segment.
//!
//! An encoded slash (`%2F`) decoding into `/` upstream is a documented choice (a route can
//! refuse it with `refuse_encoded_slash`), so segments are decoded one by one, not re-split.

use libfuzzer_sys::fuzz_target;
use zion::uri_norm::{try_normalize_path, without_path_params};

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// One full percent-decoding pass, as an upstream does.
fn decode_once(seg: &str) -> Vec<u8> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn assert_clean_segments(path: &str, what: &str) {
    for (n, seg) in path.split('/').enumerate() {
        assert!(seg != "." && seg != "..", "{what}: dot segment in {path:?}");
        let decoded = decode_once(seg);
        assert!(
            decoded != b"." && decoded != b"..",
            "{what}: segment {seg:?} decodes to a dot segment upstream in {path:?}"
        );
        // An empty segment after the root and before the last one is a `//` run.
        let last = n == path.split('/').count() - 1;
        assert!(
            n == 0 || last || !seg.is_empty(),
            "{what}: repeated slash in {path:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    let path = format!("/{input}");

    if let Some(out) = try_normalize_path(&path) {
        let out = out.into_owned();
        assert_eq!(
            try_normalize_path(&out).as_deref(),
            Some(out.as_str()),
            "not canonical: {path:?} -> {out:?}"
        );
        assert_clean_segments(&out, "try_normalize_path");
        let b = out.as_bytes();
        for i in 0..b.len() {
            assert!(b[i] != b'\\', "backslash kept: {path:?} -> {out:?}");
            if b[i] == b'%' {
                let esc = b.get(i + 1..i + 3);
                assert!(
                    esc != Some(b"5C") && esc != Some(b"00"),
                    "refused escape kept: {path:?} -> {out:?}"
                );
            }
        }
    }

    if let Some(stripped) = without_path_params(&path) {
        assert!(
            !stripped.contains(';'),
            "';' left: {path:?} -> {stripped:?}"
        );
        for seg in stripped.split('/') {
            assert!(
                seg != "." && seg != "..",
                "dot segment left: {path:?} -> {stripped:?}"
            );
        }
    }
});

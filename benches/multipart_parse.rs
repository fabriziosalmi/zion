// SPDX-License-Identifier: Apache-2.0
//! Microbench: the #694 multipart structure parser (`waf::multipart_structure`).
//!
//! Measures the parse cost per MiB of a well-formed `multipart/form-data` body.
//! That is the work zion does on every upload and, more to the point, the cost
//! of walking a large body before it can refuse an oversized or malformed one —
//! the number the #694 "done when" asks for.
//!
//! The parser is O(body length): `memchr::memmem` (SIMD) finds each CRLF
//! dash-boundary, and a large upload's bytes are one file part scanned once.
//! This isolates the parse from `validate_request`'s other gates (the
//! Aho-Corasick scan, entropy, JSON structure), which a full-body
//! `validate_request` bench would fold in.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use zion::waf::{multipart_structure, WafProfile, WafVerdict};

const KB_1: usize = 1024;
const KB_256: usize = 256 * 1024;
const MB_1: usize = 1_048_576;
const MB_10: usize = 10 * 1_048_576;

const BOUNDARY: &str = "ZbWafBench";

fn profile() -> WafProfile {
    // Generous limits so a well-formed body is Allowed: we measure the parse of a
    // valid body, not the early exit of a rejection.
    WafProfile {
        max_parts: 100_000,
        max_file_parts: 100_000,
        max_part_headers: 1024,
        max_part_header_bytes: 1 << 20,
        ..WafProfile::default()
    }
}

fn content_type() -> String {
    format!("multipart/form-data; boundary={BOUNDARY}")
}

/// A well-formed `multipart/form-data` body of about `n` bytes: a small text field
/// plus one file part whose content is padded to make up the size. The filler is
/// never the boundary, so the parser walks the whole content once to find the next
/// delimiter — the realistic shape of a large upload (a few fields + one big file).
fn multipart_body(n: usize) -> Vec<u8> {
    let dash = format!("--{BOUNDARY}");
    let mut out = Vec::with_capacity(n + 256);
    // one small text field
    out.extend_from_slice(dash.as_bytes());
    out.extend_from_slice(
        b"\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue one\r\n",
    );
    // one file part, header then padded content
    out.extend_from_slice(dash.as_bytes());
    out.extend_from_slice(
        b"\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n\
          Content-Type: application/octet-stream\r\n\r\n",
    );
    let tail = dash.len() + 2 /* \r\n before close */ + 2 /* -- close */;
    let pad = n.saturating_sub(out.len() + tail);
    out.resize(out.len() + pad, b'x');
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(dash.as_bytes());
    out.extend_from_slice(b"--");
    out
}

fn bench(c: &mut Criterion) {
    let p = profile();
    let ct = content_type();
    let mut g = c.benchmark_group("waf/multipart_parse");
    for &size in &[KB_1, KB_256, MB_1, MB_10] {
        let body = multipart_body(size);
        // Sanity: a well-formed body must be Allowed, or we would be timing a reject.
        assert_eq!(
            multipart_structure(&ct, &body, &p),
            WafVerdict::Allow,
            "size {size} should parse clean"
        );
        if size == MB_10 {
            g.sample_size(30); // keep the 10 MB case under the wall-clock budget
        }
        g.throughput(Throughput::Bytes(body.len() as u64));
        let id = match size {
            KB_1 => "1KB",
            KB_256 => "256KB",
            MB_1 => "1MB",
            _ => "10MB",
        };
        g.bench_function(id, |b| {
            b.iter(|| {
                black_box(multipart_structure(
                    black_box(&ct),
                    black_box(&body),
                    black_box(&p),
                ))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

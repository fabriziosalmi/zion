//! JA4 TLS client fingerprinting — Phase 3a (#27).
//!
//! Compile with `--features tls-fingerprint`.
//!
//! This module is a **pure library**: given the bytes of a TLS `ClientHello`
//! handshake message, it computes the canonical [FoxIO JA4] client fingerprint
//! (`ja4_a_ja4_b_ja4_c`, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`). It does
//! nothing else — no socket peeking, no allowlist, no config, no metrics. Those
//! land in later commits (see #27). The parser is hand-rolled and every read is
//! bounds-checked, so arbitrary/adversarial input yields a typed `Err`, never a
//! panic.
//!
//! JA4 is deliberately reproducible across TLS libraries: GREASE values are
//! stripped everywhere, ciphers and extension types are sorted, and only the
//! signature-algorithms list keeps its wire order.
//!
//! [FoxIO JA4]: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

// Phase 3a commit 1 ships this as a standalone library — its only consumers are
// this module's own tests. The allowlist gate, config, and pre-handshake peek
// hook (later #27 commits) are what wire `ja4_from_client_hello`/`Ja4`/
// `TlsFpError` into the binary; until then they read as dead code. Drop this
// allow when the hook lands.
#![allow(dead_code)]

use sha2::{Digest, Sha256};

/// A computed JA4 client fingerprint, e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
///
/// Wraps the canonical `String`. Cheap `Hash`/`Eq` so a later commit can key an
/// allowlist `HashSet<Ja4>` on it directly.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Ja4(pub String);

impl Ja4 {
    /// The fingerprint as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Ja4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a `ClientHello` could not be fingerprinted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TlsFpError {
    /// The buffer ended mid-field (short read).
    Truncated,
    /// First handshake byte was not `0x01` (ClientHello).
    NotClientHello,
    /// A length field was internally inconsistent (e.g. odd cipher-list length).
    Malformed,
}

impl std::fmt::Display for TlsFpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            TlsFpError::Truncated => "truncated ClientHello",
            TlsFpError::NotClientHello => "not a ClientHello",
            TlsFpError::Malformed => "malformed ClientHello",
        };
        f.write_str(s)
    }
}

impl std::error::Error for TlsFpError {}

/// The 16 GREASE code points (RFC 8701). Stripped from ciphers, extension
/// types, `supported_versions`, and `signature_algorithms` before counting,
/// sorting, or hashing.
///
/// Predicate form (used directly): the two bytes are equal and the low nibble
/// is `0xa` — i.e. `0x0a0a, 0x1a1a, … 0xfafa`.
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0x00ff) && (v & 0x000f) == 0x000a
}

/// A forward-only, bounds-checked cursor over a byte slice. Every accessor
/// returns `Err(Truncated)` rather than panicking on a short read.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsFpError> {
        let end = self.pos.checked_add(n).ok_or(TlsFpError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(TlsFpError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, TlsFpError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TlsFpError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

/// Parse a `[u16]` list packed big-endian; the slice length must be even.
fn u16_list(bytes: &[u8]) -> Result<Vec<u16>, TlsFpError> {
    if bytes.len() % 2 != 0 {
        return Err(TlsFpError::Malformed);
    }
    Ok(bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

/// Map a TLS version code point to its 2-char JA4 token. TLS-over-TCP only:
/// DTLS (`d1`/`d2`/`d3`) is out of scope for Phase 3a — the transport char is
/// hardcoded `t` and this parser doesn't understand the DTLS ClientHello layout,
/// so DTLS code points fall through to the `00` unknown token like anything else.
fn version_token(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn hex_nibble(n: u8) -> char {
    char::from_digit((n & 0x0f) as u32, 16).unwrap_or('0')
}

/// JA4 ALPN token from the first advertised protocol id: first+last byte if both
/// are alphanumeric (`h2` → `h2`, `http/1.1` → `h1`), else `hex(hi nibble of
/// first) + hex(lo nibble of last)`. `00` when ALPN is absent/empty.
fn alpn_token(first: &[u8]) -> (char, char) {
    match (first.first(), first.last()) {
        (Some(&f), Some(&l)) if is_alnum(f) && is_alnum(l) => (f as char, l as char),
        (Some(&f), Some(&l)) => (hex_nibble(f >> 4), hex_nibble(l)),
        _ => ('0', '0'),
    }
}

/// First 12 lowercase-hex chars (6 bytes) of `SHA256(input)`.
fn sha256_12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(12);
    for b in digest.iter().take(6) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Comma-joined 4-char zero-padded lowercase hex of a code-point slice, in the
/// slice's current order. Callers sort (ciphers, extension types) or preserve
/// wire order (signature_algorithms) beforehand. Formats once — no per-element
/// `String` allocation — and zero-padded 4-hex sorts identically to numeric u16
/// order, so sorting the `u16`s is equivalent to sorting the hex strings.
fn csv_hex(vals: &[u16]) -> String {
    let mut out = String::with_capacity(vals.len() * 5);
    for (i, v) in vals.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!("{v:04x}"));
    }
    out
}

/// Fields extracted from a `ClientHello` that JA4 needs.
struct ClientHelloParts {
    legacy_version: u16,
    ciphers: Vec<u16>,
    ext_types: Vec<u16>,
    sni_present: bool,
    /// Whether the `supported_versions` (0x002b) extension was present — the JA4
    /// version rule branches on presence, not on whether a non-GREASE value
    /// survives.
    sv_present: bool,
    supported_versions: Vec<u16>,
    sig_algs: Vec<u16>,
    first_alpn: Vec<u8>,
}

/// Walk a `ClientHello` handshake-message body (starting at the `0x01` msg_type)
/// and pull out the JA4-relevant fields.
fn parse_client_hello(bytes: &[u8]) -> Result<ClientHelloParts, TlsFpError> {
    let mut r = Reader::new(bytes);

    if r.u8()? != 0x01 {
        return Err(TlsFpError::NotClientHello);
    }
    // 24-bit handshake body length. Clamp the whole walk to it so a hostile
    // length field can never make an extension read spill past the declared
    // message into trailing bytes (a second record, or record framing, is the
    // peek/hook commit's concern). The buffer must actually contain the message.
    let blen = r.take(3)?;
    let body_len = ((blen[0] as usize) << 16) | ((blen[1] as usize) << 8) | (blen[2] as usize);
    let body_end = 4usize.checked_add(body_len).ok_or(TlsFpError::Malformed)?;
    let body = bytes.get(4..body_end).ok_or(TlsFpError::Truncated)?;
    let mut r = Reader::new(body);

    let legacy_version = r.u16()?;
    let _random = r.take(32)?;
    let sid_len = r.u8()? as usize;
    let _session_id = r.take(sid_len)?;

    let cs_len = r.u16()? as usize;
    let ciphers = u16_list(r.take(cs_len)?)?;

    let comp_len = r.u8()? as usize;
    let _compression = r.take(comp_len)?;

    let mut parts = ClientHelloParts {
        legacy_version,
        ciphers,
        ext_types: Vec::new(),
        sni_present: false,
        sv_present: false,
        supported_versions: Vec::new(),
        sig_algs: Vec::new(),
        first_alpn: Vec::new(),
    };

    // Extensions are optional (a bare TLS 1.2 hello may omit the block).
    if r.remaining() == 0 {
        return Ok(parts);
    }
    let ext_total = r.u16()? as usize;
    let mut ext = Reader::new(r.take(ext_total)?);

    while ext.remaining() >= 4 {
        let ext_type = ext.u16()?;
        let ext_len = ext.u16()? as usize;
        let data = ext.take(ext_len)?;
        parts.ext_types.push(ext_type);

        match ext_type {
            0x0000 => parts.sni_present = true,
            0x0010 => {
                // ALPN: [list_len u16][ {proto_len u8, proto bytes} … ]. Keep the
                // first protocol. Best-effort: a well-formed but EMPTY list (body
                // [0x00,0x00]) is valid and must yield the "00" token, not fail
                // the whole fingerprint (which would drop a legitimate client).
                let mut a = Reader::new(data);
                if a.u16().is_ok() {
                    if let Ok(plen) = a.u8() {
                        if let Ok(proto) = a.take(plen as usize) {
                            parts.first_alpn = proto.to_vec();
                        }
                    }
                }
            }
            0x000d => {
                // signature_algorithms: [list_len u16][ u16 … ] — WIRE order.
                let mut s = Reader::new(data);
                let list_len = s.u16()? as usize;
                parts.sig_algs = u16_list(s.take(list_len)?)?;
            }
            0x002b => {
                // supported_versions: [list_len u8][ u16 … ].
                parts.sv_present = true;
                let mut s = Reader::new(data);
                let list_len = s.u8()? as usize;
                parts.supported_versions = u16_list(s.take(list_len)?)?;
            }
            _ => {}
        }
    }

    Ok(parts)
}

/// Compute the JA4 client fingerprint from a `ClientHello` handshake-message
/// body (the buffer must start at the `0x01` msg_type byte; a later peek/hook
/// commit strips the 5-byte TLS record header before calling).
///
/// Always TLS-over-TCP (`t`); QUIC (`q`) is out of scope for Phase 3a.
pub fn ja4_from_client_hello(bytes: &[u8]) -> Result<Ja4, TlsFpError> {
    let p = parse_client_hello(bytes)?;

    // GREASE-stripped working sets (used for both the counts and the hashes).
    let ciphers: Vec<u16> = p
        .ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let ext_types: Vec<u16> = p
        .ext_types
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();

    // ── JA4_a ─────────────────────────────────────────────────────────────
    // Version: the JA4 rule branches on whether supported_versions is PRESENT.
    // If so, use the highest non-GREASE entry (or "00" when the list is empty /
    // all-GREASE); otherwise use the legacy record version.
    let version = if p.sv_present {
        p.supported_versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .map_or("00", version_token)
    } else {
        version_token(p.legacy_version)
    };

    let sni = if p.sni_present { 'd' } else { 'i' };
    // The extension count includes SNI + ALPN — they are only removed from JA4_c.
    let cipher_ct = ciphers.len().min(99);
    let ext_ct = ext_types.len().min(99);
    let (alpn0, alpn1) = alpn_token(&p.first_alpn);
    let ja4_a = format!("t{version}{sni}{cipher_ct:02}{ext_ct:02}{alpn0}{alpn1}");

    // ── JA4_b: sorted ciphers, hashed ─────────────────────────────────────
    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    let ja4_b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha256_12(&csv_hex(&sorted_ciphers))
    };

    // ── JA4_c: sorted ext types (minus SNI+ALPN) + wire-order sig-algs ─────
    let mut sorted_exts: Vec<u16> = ext_types
        .into_iter()
        .filter(|v| *v != 0x0000 && *v != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let ja4_c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        let sig_algs: Vec<u16> = p
            .sig_algs
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .collect();
        // No sig-algs → NO trailing underscore (a classic JA4 off-by-one).
        let combined = if sig_algs.is_empty() {
            csv_hex(&sorted_exts)
        } else {
            format!("{}_{}", csv_hex(&sorted_exts), csv_hex(&sig_algs))
        };
        sha256_12(&combined)
    };

    Ok(Ja4(format!("{ja4_a}_{ja4_b}_{ja4_c}")))
}

/// Compute JA4 from a raw TLS record buffer as `MSG_PEEK`'d off the socket — the
/// buffer starts at the 5-byte TLS record header (`content_type`, legacy
/// version, length). Strips the header and fingerprints the ClientHello in the
/// first handshake record.
///
/// Only the first record is inspected. A ClientHello fragmented across multiple
/// TLS records (rare, and something a peek may also simply not have buffered
/// yet) yields `Truncated` — the shadow-mode caller treats that as "not
/// fingerprinted this time" rather than an error to act on. Bytes beyond the
/// first record (a coalesced second record) are ignored.
pub fn ja4_from_tls_record(bytes: &[u8]) -> Result<Ja4, TlsFpError> {
    let mut r = Reader::new(bytes);
    // TLS record: content_type(1) = 22 handshake, legacy_version(2), length(2).
    if r.u8()? != 0x16 {
        return Err(TlsFpError::NotClientHello);
    }
    let _legacy_version = r.u16()?;
    let rec_len = r.u16()? as usize;
    // The handshake message (starting at the 0x01 ClientHello msg_type) is the
    // record payload. ja4_from_client_hello clamps to the handshake's own 24-bit
    // length, so a short/fragmented payload comes back as Truncated.
    let payload = r.take(rec_len)?;
    ja4_from_client_hello(payload)
}

/// Runtime-resolved fingerprint state, read on the accept path. Built once per
/// config load from `[tls.fingerprint]`; the resolver returns `None` for
/// `mode = off` so the hot path pays nothing when the feature is unused.
#[derive(Clone, Debug)]
pub struct TlsFpRuntime {
    pub mode: crate::config::FingerprintMode,
    on_unknown: crate::config::OnUnknown,
    on_unfingerprintable: crate::config::OnUnfingerprintable,
    /// JA4 string → allowlist entry name (for the known/unknown metric split).
    allowed: std::collections::HashMap<String, String>,
}

impl TlsFpRuntime {
    /// Resolve from config; `None` for `mode = off` (zero hot-path cost).
    pub fn from_config(cfg: &crate::config::FingerprintConfig) -> Option<Self> {
        if cfg.mode == crate::config::FingerprintMode::Off {
            return None;
        }
        let allowed = cfg
            .allowed
            .iter()
            .map(|a| (a.ja4.clone(), a.name.clone()))
            .collect();
        Some(TlsFpRuntime {
            mode: cfg.mode.clone(),
            on_unknown: cfg.on_unknown,
            on_unfingerprintable: cfg.on_unfingerprintable,
            allowed,
        })
    }

    /// The allowlist entry name for a fingerprint, if it is known.
    pub fn known_name(&self, ja4: &Ja4) -> Option<&str> {
        self.allowed.get(ja4.as_str()).map(String::as_str)
    }

    /// Verdict for an unknown fingerprint. Rejects only in `allowlist` mode with
    /// `on_unknown = drop`; `shadow` and `log_only` observe without blocking.
    fn unknown_decision(&self, ja4: &Ja4) -> GateDecision {
        use crate::config::{FingerprintMode, OnUnknown};
        if self.mode == FingerprintMode::Allowlist && self.on_unknown == OnUnknown::Drop {
            tracing::warn!(ja4 = %ja4, "tls-fp: rejecting connection — fingerprint not on allowlist");
            crate::metrics::METRICS
                .tls_fp_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            GateDecision::Reject
        } else {
            tracing::info!(ja4 = %ja4, "tls-fp: unknown ClientHello fingerprint");
            GateDecision::Proceed
        }
    }

    /// Verdict for a connection whose ClientHello could not be fingerprinted.
    /// Availability-first: proceed unless `allowlist` + `on_unfingerprintable =
    /// drop`.
    fn unfingerprintable_decision(&self) -> GateDecision {
        use crate::config::{FingerprintMode, OnUnfingerprintable};
        if self.mode == FingerprintMode::Allowlist
            && self.on_unfingerprintable == OnUnfingerprintable::Drop
        {
            crate::metrics::METRICS
                .tls_fp_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            GateDecision::Reject
        } else {
            GateDecision::Proceed
        }
    }
}

/// Bytes peeked to cover a full ClientHello — big enough for a TLS 1.3 hybrid
/// post-quantum key share (X25519MLKEM768 pushes the record past ~1.5 KB); a
/// 1 KB buffer would silently truncate exactly the modern browsers we most want
/// to fingerprint.
const PEEK_CAP: usize = 4096;

/// Upper bound on the pre-handshake peek. A real ClientHello is the first thing
/// sent after TCP connect, so this only bites a client that connects and stalls.
const PEEK_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Does the buffer already hold a complete first TLS record (5-byte header +
/// its declared payload)?
fn first_record_complete(buf: &[u8]) -> bool {
    buf.len() >= 5 && buf.len() >= 5 + (((buf[3] as usize) << 8) | buf[4] as usize)
}

/// `MSG_PEEK` the first TLS record (the ClientHello) without consuming it,
/// waiting — up to `PEEK_BUDGET` — for the rest of a ClientHello that arrives
/// split across TCP segments (a TLS 1.3 hybrid post-quantum ClientHello exceeds
/// one MSS, so its first peek is otherwise a partial record and gets dropped).
/// Returns the peeked length, or `None` on timeout / EOF / error. Every byte is
/// left in the kernel buffer for rustls to re-read.
///
/// This runs BEFORE the 10s-bounded rustls accept, while already holding the
/// connection permit + per-IP slot, so it MUST be bounded: an unbounded wait on
/// a client that connects and sends nothing is a slow-loris amplification.
async fn peek_client_hello(stream: &tokio::net::TcpStream, buf: &mut [u8]) -> Option<usize> {
    let deadline = tokio::time::Instant::now() + PEEK_BUDGET;
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.peek(buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return None,
        };
        // Not a handshake record (don't wait on non-TLS/garbage), the whole
        // first record is here, or the buffer is full → classify what we have.
        if buf[0] != 0x16 || first_record_complete(&buf[..n]) || n == buf.len() {
            return Some(n);
        }
        // Partial handshake record — briefly wait for the rest, bounded by the
        // deadline. Sleeping (not spinning): the next TCP segment arrives within
        // an RTT, and a stalled client is capped by PEEK_BUDGET.
        if tokio::time::timeout_at(
            deadline,
            tokio::time::sleep(std::time::Duration::from_millis(2)),
        )
        .await
        .is_err()
        {
            return Some(n); // deadline hit — classify what we have (likely Truncated → skip)
        }
    }
}

/// The accept-path gate's verdict: proceed into the TLS handshake, or reject
/// (the caller closes the socket before the handshake starts).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateDecision {
    Proceed,
    Reject,
}

/// The accept-path JA4 gate: `MSG_PEEK` the ClientHello (leaving the bytes in
/// the kernel buffer for rustls to re-read), compute JA4, count it known vs
/// unknown, and return whether the connection may proceed.
///
/// - `mode = off` (runtime `None`) → `Proceed`, no peek, no syscall.
/// - `mode = shadow` → always `Proceed`; only observes (counts + logs).
/// - `mode = allowlist` → `Reject` an unknown fingerprint iff `on_unknown =
///   drop`, and a ClientHello that couldn't be fingerprinted iff
///   `on_unfingerprintable = drop`; otherwise `Proceed`.
pub async fn fingerprint_gate(
    stream: &tokio::net::TcpStream,
    state: &crate::AppState,
) -> GateDecision {
    // Clone the resolved runtime out (a cheap Arc clone) and DROP the arc-swap
    // Guard before awaiting — never hold a config Guard across an await point.
    let fp = {
        let cfg = state.config.load();
        match cfg.tls_fingerprint.as_ref() {
            Some(fp) => fp.clone(),
            None => return GateDecision::Proceed, // mode = off → no peek, no syscall
        }
    };
    let mut buf = [0u8; PEEK_CAP];
    let Some(n) = peek_client_hello(stream, &mut buf).await else {
        // Timeout / EOF / stalled client — could not fingerprint.
        return fp.unfingerprintable_decision();
    };
    match ja4_from_tls_record(&buf[..n]) {
        Ok(ja4) => {
            if fp.known_name(&ja4).is_some() {
                crate::metrics::METRICS
                    .tls_fp_known
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                GateDecision::Proceed
            } else {
                crate::metrics::METRICS
                    .tls_fp_unknown
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                fp.unknown_decision(&ja4)
            }
        }
        // A not-a-ClientHello / truncated-beyond-budget peek: couldn't fingerprint.
        Err(_) => fp.unfingerprintable_decision(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a TLS extension `[type u16][len u16][data]`.
    fn push_ext(out: &mut Vec<u8>, etype: u16, data: &[u8]) {
        out.extend_from_slice(&etype.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    /// Build a canonical modern-Chrome `ClientHello` (handshake-message body)
    /// whose GREASE-stripped, sorted cipher/extension/sig-alg lists reproduce
    /// the FoxIO reference fingerprint `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    /// The two sub-hashes were verified independently with `shasum -a 256`.
    fn chrome_client_hello() -> Vec<u8> {
        // 16 ciphers = 1 GREASE + 15 real (post-GREASE count = 15).
        let ciphers: [u16; 16] = [
            0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ];

        // 17 extensions = 1 GREASE + 16 real (post-GREASE count = 16, incl SNI+ALPN).
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0a0a, &[]); // GREASE

        // SNI (0x0000): server_name_list = [list_len u16][type u8=0][name_len u16][name]
        let host = b"example.com";
        let mut snl = vec![0x00];
        snl.extend_from_slice(&(host.len() as u16).to_be_bytes());
        snl.extend_from_slice(host);
        let mut sni = (snl.len() as u16).to_be_bytes().to_vec();
        sni.extend_from_slice(&snl);
        push_ext(&mut ext, 0x0000, &sni);

        push_ext(&mut ext, 0x0017, &[]); // extended_master_secret
        push_ext(&mut ext, 0xff01, &[0x00]); // renegotiation_info
        push_ext(&mut ext, 0x000a, &[0x00, 0x02, 0x00, 0x1d]); // supported_groups
        push_ext(&mut ext, 0x000b, &[0x01, 0x00]); // ec_point_formats
        push_ext(&mut ext, 0x0023, &[]); // session_ticket

        // ALPN (0x0010): [list_len u16][proto_len u8=2]["h2"]
        let mut alpn = 3u16.to_be_bytes().to_vec();
        alpn.push(0x02);
        alpn.extend_from_slice(b"h2");
        push_ext(&mut ext, 0x0010, &alpn);

        push_ext(&mut ext, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request

        // signature_algorithms (0x000d): WIRE order preserved in ja4_c.
        let sig_algs: [u16; 8] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut sa = ((sig_algs.len() * 2) as u16).to_be_bytes().to_vec();
        for s in sig_algs {
            sa.extend_from_slice(&s.to_be_bytes());
        }
        push_ext(&mut ext, 0x000d, &sa);

        push_ext(&mut ext, 0x0012, &[]); // signed_certificate_timestamp
        push_ext(&mut ext, 0x0033, &[0x00, 0x00]); // key_share (unparsed by JA4)
        push_ext(&mut ext, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes

        // supported_versions (0x002b): [len u8=6][GREASE 0x0a0a][0x0304 TLS1.3][0x0303]
        push_ext(
            &mut ext,
            0x002b,
            &[0x06, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03],
        );

        push_ext(&mut ext, 0x0015, &[]); // padding
        push_ext(&mut ext, 0x001b, &[0x02, 0x00, 0x02]); // compress_certificate
        push_ext(&mut ext, 0x4469, &[0x00, 0x00]); // application_settings (ALPS)

        assemble_body(0x0303, &ciphers, &ext)
    }

    /// Wrap fields into a full ClientHello handshake-message body.
    fn assemble_body(legacy_version: u16, ciphers: &[u16], ext: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&legacy_version.to_be_bytes());
        inner.extend_from_slice(&[0u8; 32]); // random
        inner.push(0x00); // session_id len = 0
        inner.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            inner.extend_from_slice(&c.to_be_bytes());
        }
        inner.extend_from_slice(&[0x01, 0x00]); // 1 compression method: null
        inner.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        inner.extend_from_slice(ext);

        let mut body = vec![0x01]; // ClientHello msg_type
        body.extend_from_slice(&(inner.len() as u32).to_be_bytes()[1..]); // 24-bit length
        body.extend_from_slice(&inner);
        body
    }

    #[test]
    fn chrome_reference_fingerprint() {
        let hello = chrome_client_hello();
        let ja4 = ja4_from_client_hello(&hello).expect("parse");
        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    /// Wrap a handshake-message body in a TLS handshake record header
    /// (`0x16`, legacy version 0x0301, length).
    fn wrap_record(body: &[u8]) -> Vec<u8> {
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(body);
        rec
    }

    #[test]
    fn tls_record_wrapper_matches_reference() {
        // The record-framed ClientHello (as MSG_PEEK'd off the socket) yields the
        // same fingerprint as the bare handshake body.
        let rec = wrap_record(&chrome_client_hello());
        let ja4 = ja4_from_tls_record(&rec).expect("record parse");
        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn first_record_complete_boundary() {
        // Drives the peek-completion loop: keep waiting until the whole first
        // record is buffered (so a multi-segment PQ ClientHello isn't dropped).
        let rec = wrap_record(&chrome_client_hello());
        assert!(first_record_complete(&rec));
        assert!(!first_record_complete(&rec[..rec.len() - 1])); // one byte short
        assert!(!first_record_complete(&[0x16, 0x03, 0x01])); // header not even complete
    }

    #[test]
    fn tls_record_ignores_a_coalesced_second_record() {
        // A peek that also grabbed the start of a second record must not corrupt
        // the fingerprint — only the first record's payload is read.
        let mut rec = wrap_record(&chrome_client_hello());
        rec.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]); // app-data record
        let ja4 = ja4_from_tls_record(&rec).unwrap();
        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn non_handshake_record_is_rejected() {
        // 0x17 = application_data, not a handshake record.
        let mut rec = vec![0x17, 0x03, 0x03];
        rec.extend_from_slice(&4u16.to_be_bytes());
        rec.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(ja4_from_tls_record(&rec), Err(TlsFpError::NotClientHello));
    }

    #[test]
    fn fragmented_record_payload_is_truncated_not_a_panic() {
        // A record whose declared length exceeds the buffer (peek caught only a
        // fragment) → Truncated, never a panic.
        let rec = wrap_record(&chrome_client_hello());
        for n in 0..rec.len() {
            let _ = ja4_from_tls_record(&rec[..n]); // must not panic
        }
        // A record header claiming more payload than present.
        let hello = chrome_client_hello();
        let mut rec = wrap_record(&hello);
        let inflated = (hello.len() as u16 + 50).to_be_bytes();
        rec[3] = inflated[0];
        rec[4] = inflated[1];
        assert_eq!(ja4_from_tls_record(&rec), Err(TlsFpError::Truncated));
    }

    #[test]
    fn ja4_a_fields_decompose() {
        let ja4 = ja4_from_client_hello(&chrome_client_hello()).unwrap();
        let a = ja4.as_str().split('_').next().unwrap();
        assert_eq!(a, "t13d1516h2");
        // t=TCP, 13=TLS1.3, d=SNI, 15 ciphers, 16 exts, h2 ALPN.
    }

    #[test]
    fn grease_is_stripped_from_counts_and_hashes() {
        // The fixture carries GREASE in ciphers, extensions, and
        // supported_versions; the reference JA4 only matches if all are stripped.
        let ja4 = ja4_from_client_hello(&chrome_client_hello()).unwrap();
        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn gate_decisions_by_mode_and_policy() {
        use crate::config::{FingerprintMode, OnUnfingerprintable, OnUnknown};
        let ja4 = Ja4("t13d1516h2_8daaf6152771_e5627efa2ab1".into());
        let mk = |mode, on_unknown, on_unfingerprintable| TlsFpRuntime {
            mode,
            on_unknown,
            on_unfingerprintable,
            allowed: std::collections::HashMap::new(),
        };
        // shadow NEVER rejects, whatever the policy knobs say.
        let sh = mk(
            FingerprintMode::Shadow,
            OnUnknown::Drop,
            OnUnfingerprintable::Drop,
        );
        assert_eq!(sh.unknown_decision(&ja4), GateDecision::Proceed);
        assert_eq!(sh.unfingerprintable_decision(), GateDecision::Proceed);
        // allowlist + log_only: observe, don't block.
        let al_log = mk(
            FingerprintMode::Allowlist,
            OnUnknown::LogOnly,
            OnUnfingerprintable::Allow,
        );
        assert_eq!(al_log.unknown_decision(&ja4), GateDecision::Proceed);
        // allowlist + drop: unknown is rejected; unfingerprintable stays fail-open
        // by default (service first).
        let al_drop = mk(
            FingerprintMode::Allowlist,
            OnUnknown::Drop,
            OnUnfingerprintable::Allow,
        );
        assert_eq!(al_drop.unknown_decision(&ja4), GateDecision::Reject);
        assert_eq!(al_drop.unfingerprintable_decision(), GateDecision::Proceed);
        // opting into strict unfingerprintable handling rejects those too.
        let strict = mk(
            FingerprintMode::Allowlist,
            OnUnknown::LogOnly,
            OnUnfingerprintable::Drop,
        );
        assert_eq!(strict.unfingerprintable_decision(), GateDecision::Reject);
    }

    #[test]
    fn runtime_resolves_off_to_none_and_classifies() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        // mode = off → None, so the accept path pays nothing.
        let off = FingerprintConfig {
            mode: FingerprintMode::Off,
            allowed: vec![],
            ..Default::default()
        };
        assert!(TlsFpRuntime::from_config(&off).is_none());

        // shadow with an allowlist → Some; known_name classifies known vs unknown.
        let cfg = FingerprintConfig {
            mode: FingerprintMode::Shadow,
            allowed: vec![AllowedFingerprint {
                name: "chrome".into(),
                ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(),
            }],
            ..Default::default()
        };
        let rt = TlsFpRuntime::from_config(&cfg).expect("shadow resolves to Some");
        let known = ja4_from_client_hello(&chrome_client_hello()).unwrap();
        assert_eq!(rt.known_name(&known), Some("chrome"));
        let unknown = Ja4("t00i0000_000000000000_000000000000".into());
        assert_eq!(rt.known_name(&unknown), None);
    }

    #[test]
    fn sub_hashes_match_independent_sha256() {
        // ja4_b = sha256_12 of the sorted GREASE-stripped cipher CSV.
        assert_eq!(
            sha256_12("002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"),
            "8daaf6152771"
        );
        // ja4_c = sha256_12 of "sorted exts (no SNI/ALPN)_wire-order sigalgs".
        assert_eq!(
            sha256_12("0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"),
            "e5627efa2ab1"
        );
    }

    #[test]
    fn empty_ciphers_yield_zero_hash() {
        // All ciphers GREASE → nothing remains → ja4_b is the literal zero hash.
        let ciphers: [u16; 2] = [0x0a0a, 0x1a1a];
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x002b, &[0x02, 0x03, 0x04]); // supported_versions = TLS1.3
        let hello = assemble_body(0x0303, &ciphers, &ext);
        let ja4 = ja4_from_client_hello(&hello).unwrap();
        let b = ja4.as_str().split('_').nth(1).unwrap();
        assert_eq!(b, "000000000000");
    }

    #[test]
    fn no_sigalgs_has_no_trailing_underscore() {
        // One non-SNI/ALPN extension (0x0017), no signature_algorithms: the
        // hashed ja4_c input must be the ext CSV alone — no trailing '_'.
        let ciphers: [u16; 1] = [0x1301];
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0017, &[]);
        let hello = assemble_body(0x0303, &ciphers, &ext);
        let ja4 = ja4_from_client_hello(&hello).unwrap();
        let c = ja4.as_str().split('_').nth(2).unwrap();
        assert_eq!(c, sha256_12("0017"));
    }

    #[test]
    fn sni_and_alpn_counted_in_a_but_removed_from_c() {
        // ja4_a ext count includes SNI(0000)+ALPN(0010); ja4_c hashes neither.
        let ciphers: [u16; 1] = [0x1301];
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0000, &[0x00, 0x00]); // SNI (empty list)
        push_ext(&mut ext, 0x0010, &[0x00, 0x03, 0x02, b'h', b'2']); // ALPN h2
        push_ext(&mut ext, 0x0017, &[]); // one real ext left for ja4_c
        let hello = assemble_body(0x0303, &ciphers, &ext);
        let ja4 = ja4_from_client_hello(&hello).unwrap();
        let a = ja4.as_str().split('_').next().unwrap();
        // 1 cipher, 3 exts counted, SNI present, ALPN h2.
        assert_eq!(a, "t12d0103h2");
        // ja4_c hashes only 0017 (SNI+ALPN removed).
        let c = ja4.as_str().split('_').nth(2).unwrap();
        assert_eq!(c, sha256_12("0017"));
    }

    #[test]
    fn empty_alpn_list_yields_00_token_not_error() {
        // A well-formed but EMPTY ALPN ProtocolNameList (body [0x00,0x00]) is
        // valid and must fingerprint with ALPN token "00" — not error out, which
        // would fail-open by dropping a legitimate client at the gate.
        let ciphers: [u16; 1] = [0x1301];
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0000, &[0x00, 0x00]); // SNI
        push_ext(&mut ext, 0x0010, &[0x00, 0x00]); // ALPN: empty ProtocolNameList
        push_ext(&mut ext, 0x0017, &[]);
        let hello = assemble_body(0x0303, &ciphers, &ext);
        let ja4 = ja4_from_client_hello(&hello).expect("empty ALPN must not error");
        let a = ja4.as_str().split('_').next().unwrap();
        assert_eq!(a, "t12d010300"); // 1 cipher, 3 exts, SNI, ALPN token "00"
    }

    #[test]
    fn all_grease_supported_versions_yields_00() {
        // supported_versions PRESENT but only GREASE → version token "00", not a
        // silent fall-back to the legacy record version.
        let ciphers: [u16; 1] = [0x1301];
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x002b, &[0x02, 0x0a, 0x0a]); // [len=2][GREASE 0x0a0a]
        let hello = assemble_body(0x0303, &ciphers, &ext);
        let ja4 = ja4_from_client_hello(&hello).unwrap();
        assert_eq!(&ja4.as_str()[1..3], "00");
    }

    #[test]
    fn body_len_larger_than_buffer_is_truncated() {
        // The 24-bit handshake length claims more than the buffer holds → the
        // clamp rejects it up front instead of walking a short buffer.
        let mut hello = chrome_client_hello();
        hello[1] = 0xff; // inflate the high byte of the 24-bit body length
        assert_eq!(ja4_from_client_hello(&hello), Err(TlsFpError::Truncated));
    }

    #[test]
    fn trailing_bytes_after_message_are_ignored() {
        // Extra bytes beyond the declared handshake message (a second record, or
        // peek slack) do not corrupt the fingerprint — the clamp keeps the walk
        // inside body_len.
        let mut hello = chrome_client_hello();
        hello.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let ja4 = ja4_from_client_hello(&hello).unwrap();
        assert_eq!(ja4.as_str(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn not_a_client_hello_is_rejected() {
        // 0x02 = ServerHello.
        assert_eq!(
            ja4_from_client_hello(&[0x02, 0x00, 0x00, 0x00]),
            Err(TlsFpError::NotClientHello)
        );
    }

    #[test]
    fn truncated_buffers_never_panic() {
        // Every prefix of a valid hello must return Err, never index-panic.
        let hello = chrome_client_hello();
        for n in 0..hello.len() {
            let _ = ja4_from_client_hello(&hello[..n]); // must not panic
        }
        // A lone msg_type byte with no length is truncated.
        assert_eq!(ja4_from_client_hello(&[0x01]), Err(TlsFpError::Truncated));
        // Empty input is truncated, not a panic.
        assert_eq!(ja4_from_client_hello(&[]), Err(TlsFpError::Truncated));
    }

    #[test]
    fn odd_cipher_list_is_malformed() {
        // cipher_suites length = 3 (odd) → Malformed, not a partial parse.
        let mut body = vec![0x01, 0x00, 0x00, 0x00];
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session_id len
        body.extend_from_slice(&3u16.to_be_bytes()); // cipher list len = 3 (odd)
        body.extend_from_slice(&[0x13, 0x01, 0x13]);
        body.extend_from_slice(&[0x01, 0x00]); // compression
                                               // fix the 24-bit length to cover what we wrote
        let inner_len = (body.len() - 4) as u32;
        body[1..4].copy_from_slice(&inner_len.to_be_bytes()[1..]);
        assert_eq!(ja4_from_client_hello(&body), Err(TlsFpError::Malformed));
    }
}

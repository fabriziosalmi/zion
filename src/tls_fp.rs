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

/// Cheap shape check for a configured JA4 string: `<10-char a>_<12 hex b>_<12
/// hex c>`. Catches a typo / wrong case / truncation at config load rather than
/// as a silent never-matches outage (a malformed allowlist entry matches nothing,
/// which under `on_unknown = drop` is a total outage the empty-list guard misses).
/// Case is not enforced here — [`TlsFpRuntime::from_config`] lowercases entries.
pub fn looks_like_ja4(s: &str) -> bool {
    let mut parts = s.trim().split('_');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(b), Some(c), None) => {
            a.len() == 10
                && a.bytes().all(|x| x.is_ascii_alphanumeric())
                && b.len() == 12
                && b.bytes().all(|x| x.is_ascii_hexdigit())
                && c.len() == 12
                && c.bytes().all(|x| x.is_ascii_hexdigit())
        }
        _ => false,
    }
}

/// Per-fingerprint fixed-window (1 s) connection-rate state. Shared across
/// connections through the `Arc<TlsFpRuntime>` — the window and count are
/// packed into one `AtomicU64` and advanced by CAS, the same idiom as
/// `security::RateEntry`, so the hot path takes no lock. Reset on config
/// reload (the state spans one second; losing it at a reload is noise).
#[derive(Debug)]
struct FpRate {
    /// Connections admitted per one-second window; always > 0 here (a
    /// configured 0 resolves to "no limit" = no `FpRate` at all).
    cps: u32,
    /// `(unix_second as u32) << 32 | count` — window + count in one CAS.
    packed: std::sync::atomic::AtomicU64,
}

impl FpRate {
    fn new(cps: u32) -> Self {
        FpRate {
            cps,
            packed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Admit one connection at `now_secs` (unix seconds).
    ///
    /// `FirstDenial` marks the ONE connection per window that crosses the cap
    /// (the successful CAS from `count == cps` to `cps + 1` happens exactly
    /// once) — the caller logs on that and stays silent on every later
    /// `Denied`, so a flood against a rate-limited fingerprint produces at
    /// most one log line per second instead of one per connection.
    fn admit(&self, now_secs: u64) -> Admit {
        use std::sync::atomic::Ordering::Relaxed;
        let window = now_secs as u32;
        loop {
            let old = self.packed.load(Relaxed);
            let (old_window, old_count) = ((old >> 32) as u32, old as u32);
            let (new, verdict) = if old_window == window {
                // Same window — increment; saturate so a flood can't wrap the
                // counter back under the cap.
                (
                    ((window as u64) << 32) | u64::from(old_count.saturating_add(1)),
                    match old_count.cmp(&self.cps) {
                        std::cmp::Ordering::Less => Admit::Granted,
                        std::cmp::Ordering::Equal => Admit::FirstDenial,
                        std::cmp::Ordering::Greater => Admit::Denied,
                    },
                )
            } else {
                // New window — this connection is its first.
                (((window as u64) << 32) | 1, Admit::Granted)
            };
            if self
                .packed
                .compare_exchange_weak(old, new, Relaxed, Relaxed)
                .is_ok()
            {
                return verdict;
            }
        }
    }
}

/// Verdict of [`FpRate::admit`] for one connection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Admit {
    /// Under the cap — proceed.
    Granted,
    /// The connection that crossed the cap: denied, and the one worth logging.
    FirstDenial,
    /// Over the cap, already reported this window: denied silently.
    Denied,
}

/// One resolved allowlist entry: the human label plus the optional
/// per-fingerprint connection-rate limit.
#[derive(Debug)]
struct AllowedEntry {
    name: String,
    rate: Option<FpRate>,
    /// Compiled `allowed_routes` matcher (#27 follow-up); `None` = no
    /// restriction. Same pattern semantics as the request router — built by
    /// `config::compile_path_set`.
    routes: Option<matchit::Router<()>>,
}

/// Runtime-resolved fingerprint state, read on the accept path. Built once per
/// config load from `[tls.fingerprint]`; the resolver returns `None` for
/// `mode = off` so the hot path pays nothing when the feature is unused.
/// Shared as `Arc<TlsFpRuntime>` (not cloned per connection): the per-entry
/// rate atomics must be one instance across all connections.
#[derive(Debug)]
pub struct TlsFpRuntime {
    pub mode: crate::config::FingerprintMode,
    on_unknown: crate::config::OnUnknown,
    on_unfingerprintable: crate::config::OnUnfingerprintable,
    /// TTL of the unknown-fingerprint ban fast path; zero = bans disabled.
    ban_ttl: std::time::Duration,
    /// JA4 string → allowlist entry (name + optional rate limit).
    allowed: std::collections::HashMap<String, AllowedEntry>,
}

impl TlsFpRuntime {
    /// Resolve from config; `None` for `mode = off` (zero hot-path cost).
    pub fn from_config(cfg: &crate::config::FingerprintConfig) -> Option<Self> {
        if cfg.mode == crate::config::FingerprintMode::Off {
            return None;
        }
        // Normalize entries (trim + lowercase) so a configured JA4 that differs
        // only in case/whitespace from the computed (lowercase) fingerprint still
        // matches instead of silently never matching.
        let allowed = cfg
            .allowed
            .iter()
            .map(|a| {
                (
                    a.ja4.trim().to_ascii_lowercase(),
                    AllowedEntry {
                        name: a.name.clone(),
                        rate: (a.rate_limit_cps > 0).then(|| FpRate::new(a.rate_limit_cps)),
                        routes: if a.allowed_routes.is_empty() {
                            None
                        } else {
                            match crate::config::compile_path_set(&a.allowed_routes) {
                                Ok(r) => Some(r),
                                // Validation refuses bad patterns at load, so
                                // this arm is unreachable in practice — but if
                                // it ever fires, fail OPEN (unrestricted) and
                                // say so loudly: a silent total deny for an
                                // allowlisted client is the worse failure.
                                Err(e) => {
                                    tracing::error!(
                                        name = %a.name, error = %e,
                                        "tls-fp: allowed_routes failed to compile past validation — entry left UNRESTRICTED"
                                    );
                                    None
                                }
                            }
                        },
                    },
                )
            })
            .collect();
        Some(TlsFpRuntime {
            mode: cfg.mode.clone(),
            on_unknown: cfg.on_unknown,
            on_unfingerprintable: cfg.on_unfingerprintable,
            ban_ttl: std::time::Duration::from_secs(cfg.ban_ttl_secs),
            allowed,
        })
    }

    /// The complete per-request route gate (#27 follow-up): restriction
    /// lookup, mode policy, metric, and (debug) logging in one place, so the
    /// dispatch wiring stays a dumb two-liner and the mode branch is
    /// unit-testable here. `Reject` ONLY in `allowlist` mode for a restricted
    /// fingerprint outside its list; `shadow` observes (counts
    /// `zion_tls_fp_route_denied`, never blocks). Deny logging is debug-level on purpose: a JA4 is replayable
    /// client-controlled input, and the metric is the operator signal — the
    /// access log never sees early-gate denials (same as the sovereign gate).
    pub fn route_gate(&self, ja4: &str, path: &str) -> GateDecision {
        use crate::config::FingerprintMode;
        let Some(name) = self.route_denied(ja4, path) else {
            return GateDecision::Proceed;
        };
        crate::metrics::METRICS
            .tls_fp_route_denied
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.mode == FingerprintMode::Allowlist {
            tracing::debug!(
                ja4,
                name,
                path,
                "tls-fp: route not in allowed_routes for this fingerprint — 403"
            );
            GateDecision::Reject
        } else {
            tracing::debug!(
                ja4,
                name,
                path,
                "tls-fp: route not in allowed_routes (shadow — proceeding)"
            );
            GateDecision::Proceed
        }
    }

    /// Per-fingerprint route restriction (#27 follow-up): `Some(entry name)`
    /// when `ja4` is allowlisted with an `allowed_routes` list that does NOT
    /// cover `path`. `None` = unrestricted entry, path covered, or `ja4` not
    /// on the allowlist at all (unknowns are the gate's business, not this).
    pub fn route_denied(&self, ja4: &str, path: &str) -> Option<&str> {
        let entry = self.allowed.get(ja4)?;
        let routes = entry.routes.as_ref()?;
        if routes.at(path).is_ok() {
            None
        } else {
            Some(entry.name.as_str())
        }
    }

    /// The allowlist entry name for a fingerprint, if it is known.
    pub fn known_name(&self, ja4: &Ja4) -> Option<&str> {
        self.allowed.get(ja4.as_str()).map(|e| e.name.as_str())
    }

    /// The enforcement posture as one comparable value: mode alone doesn't
    /// tell the story — within `allowlist`, flipping `on_unknown` from
    /// `log_only` to `drop` is exactly the moment enforcement (and the ban
    /// machinery) begins. The reload announcer compares postures, not modes.
    pub fn posture(
        &self,
    ) -> (
        crate::config::FingerprintMode,
        crate::config::OnUnknown,
        crate::config::OnUnfingerprintable,
    ) {
        (
            self.mode.clone(),
            self.on_unknown,
            self.on_unfingerprintable,
        )
    }

    /// Verdict for a KNOWN (allowlisted) fingerprint: admit unless its
    /// per-fingerprint connection-rate limit says the current second is full.
    /// Over-cap in `allowlist` mode drops the connection pre-handshake; in
    /// `shadow` it is counted (`zion_tls_fp_rate_limited`) but never blocks —
    /// shadow observes, whatever the knobs say.
    ///
    /// Only the window's FIRST denial is logged: a JA4 is replayable
    /// client-controlled input, so a per-connection log line here would hand an
    /// attacker unbounded log amplification (the same hazard the ban fast path
    /// closes for unknown fingerprints). Every denial still counts in the
    /// metrics.
    /// `now_secs` is a closure so the common unlimited entry pays no clock
    /// read: it is only invoked once a rate limit actually exists.
    fn known_decision(
        &self,
        ja4: &Ja4,
        entry: &AllowedEntry,
        now_secs: impl FnOnce() -> u64,
    ) -> GateDecision {
        use crate::config::FingerprintMode;
        let Some(rate) = &entry.rate else {
            return GateDecision::Proceed;
        };
        let verdict = rate.admit(now_secs());
        if verdict == Admit::Granted {
            return GateDecision::Proceed;
        }
        crate::metrics::METRICS
            .tls_fp_rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.mode == FingerprintMode::Allowlist {
            if verdict == Admit::FirstDenial {
                tracing::warn!(
                    ja4 = %ja4, name = %entry.name, limit_cps = rate.cps,
                    "tls-fp: per-fingerprint connection rate exceeded — dropping over-cap connections this second"
                );
            }
            crate::metrics::METRICS
                .tls_fp_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            GateDecision::Reject
        } else {
            if verdict == Admit::FirstDenial {
                tracing::info!(
                    ja4 = %ja4, name = %entry.name, limit_cps = rate.cps,
                    "tls-fp: per-fingerprint connection rate exceeded (shadow — connections proceed)"
                );
            }
            GateDecision::Proceed
        }
    }

    /// Would this runtime drop an unknown fingerprint? (The only combination
    /// that rejects — and therefore the only one where the ban set applies.)
    fn drops_unknown(&self) -> bool {
        self.mode == crate::config::FingerprintMode::Allowlist
            && self.on_unknown == crate::config::OnUnknown::Drop
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
            tracing::warn!(
                "tls-fp: rejecting connection — ClientHello could not be fingerprinted \
                 (on_unfingerprintable = drop)"
            );
            crate::metrics::METRICS
                .tls_fp_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            GateDecision::Reject
        } else {
            GateDecision::Proceed
        }
    }
}

/// Ceiling on tracked bans. An attacker rotating a UNIQUE JA4 per connection
/// would otherwise grow the map without bound. At the cap, expired entries are
/// swept; if the map is still full the insert is skipped — a ban is only the
/// fast path, the slow path still rejects every unknown connection one by one.
const MAX_BAN_ENTRIES: usize = 4096;

/// Minimum spacing between full-map sweeps of the ban set. A sweep is a
/// `retain` that write-locks every DashMap shard and walks all entries; at
/// capacity, doing that per connection would put O(MAX_BAN_ENTRIES) work on
/// the accept path of the exact flood the cap defends against.
const BAN_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Ban set for rejected unknown fingerprints (#27 commit 4): JA4 → banned
/// until. Owned by `AppState` — like the per-IP `rate_map`, it tracks client
/// behaviour, not config, so it survives hot-reloads (an operator tweaking an
/// unrelated knob mid-attack must not amnesty every banned fingerprint).
#[derive(Debug, Default)]
pub struct BanSet {
    map: dashmap::DashMap<String, std::time::Instant>,
    /// Elapsed-milliseconds-since-first-use timestamp before which no full-map
    /// sweep may run (amortizes the at-capacity `retain` to one per
    /// `BAN_SWEEP_INTERVAL` process-wide; a CAS elects the single sweeper).
    next_sweep_ms: std::sync::atomic::AtomicU64,
    /// Fixed origin for `next_sweep_ms` (set on first use).
    epoch: std::sync::OnceLock<std::time::Instant>,
}

impl BanSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds from the set's fixed epoch to `now`. Monotonic; saturates
    /// at 0 for a `now` predating the epoch (only synthetic test clocks).
    fn elapsed_ms(&self, now: std::time::Instant) -> u64 {
        let epoch = *self.epoch.get_or_init(|| now);
        now.saturating_duration_since(epoch).as_millis() as u64
    }

    /// Is `ja4` actively banned at `now`? An expired entry is removed on the way.
    fn hit(&self, ja4: &str, now: std::time::Instant) -> bool {
        // The read guard from `get` MUST be dropped before `remove` touches the
        // same key — holding it across the removal deadlocks the DashMap shard.
        {
            let Some(until) = self.map.get(ja4) else {
                return false;
            };
            if *until > now {
                return true;
            }
        }
        drop(self.map.remove(ja4));
        false
    }

    /// Record a ban for `ja4` until `now + ttl`. At capacity, sweep expired
    /// entries — but at most once per `BAN_SWEEP_INTERVAL` across the whole
    /// process (CAS elects one sweeper; everyone else skips the insert) — and
    /// give up on the insert if the map is still full of live bans.
    fn insert(&self, ja4: &str, now: std::time::Instant, ttl: std::time::Duration) {
        use std::sync::atomic::Ordering::Relaxed;
        if self.map.len() >= MAX_BAN_ENTRIES {
            let now_ms = self.elapsed_ms(now);
            let next = self.next_sweep_ms.load(Relaxed);
            if now_ms < next {
                return; // a sweep just ran and the map is still full — skip
            }
            if self
                .next_sweep_ms
                .compare_exchange(
                    next,
                    now_ms + BAN_SWEEP_INTERVAL.as_millis() as u64,
                    Relaxed,
                    Relaxed,
                )
                .is_err()
            {
                return; // another connection won the sweep election — skip
            }
            self.map.retain(|_, until| *until > now);
            if self.map.len() >= MAX_BAN_ENTRIES {
                return; // full of LIVE bans — skip; the slow path still rejects
            }
        }
        // Validation caps ban_ttl_secs at one year, so this add cannot
        // overflow in practice — checked anyway: a skipped ban is safe, an
        // abort (release panics abort) is not.
        if let Some(until) = now.checked_add(ttl) {
            self.map.insert(ja4.to_owned(), until);
        }
    }

    /// Number of tracked bans (tests / introspection).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
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

/// The fingerprint identity of one accepted connection (#27 commit 5):
/// computed pre-handshake by the gate, stashed on the connection, and turned
/// into the `X-Client-TLS-JA4` / `X-Client-TLS-Allowlisted` upstream headers
/// by [`apply_headers`] — the same lifecycle as the mTLS
/// `X-Client-Cert-Fingerprint`.
#[derive(Clone, Debug)]
pub struct TlsFpIdentity {
    /// The computed JA4.
    pub ja4: Ja4,
    /// The matching allowlist entry's `name`, when the fingerprint is known.
    pub allowed_name: Option<String>,
}

/// What the accept-path gate concluded about one connection.
pub struct GateOutcome {
    pub decision: GateDecision,
    /// `Some` whenever a JA4 was actually computed — including for a shadow
    /// or log-only connection that proceeds unknown. `None` when
    /// fingerprinting is off or the ClientHello couldn't be fingerprinted.
    pub identity: Option<TlsFpIdentity>,
}

impl GateOutcome {
    fn proceed_anonymous() -> Self {
        GateOutcome {
            decision: GateDecision::Proceed,
            identity: None,
        }
    }
}

/// The post-peek decision tree, factored out of the async gate so the whole
/// mode × allowlist × ban × rate matrix is unit-testable without sockets.
fn classify(fp: &TlsFpRuntime, bans: &BanSet, parsed: Result<Ja4, TlsFpError>) -> GateOutcome {
    match parsed {
        Ok(ja4) => {
            // The allowlist is consulted BEFORE the ban set: an operator who
            // hot-reloads a previously-unknown fingerprint onto the allowlist
            // must win over a stale ban immediately.
            if let Some(entry) = fp.allowed.get(ja4.as_str()) {
                crate::metrics::METRICS
                    .tls_fp_known
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let decision = fp.known_decision(&ja4, entry, || {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                });
                GateOutcome {
                    decision,
                    identity: Some(TlsFpIdentity {
                        allowed_name: Some(entry.name.clone()),
                        ja4,
                    }),
                }
            } else {
                crate::metrics::METRICS
                    .tls_fp_unknown
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Ban fast path (#27 commit 4): only meaningful when unknowns
                // are dropped — everywhere else nothing is ever banned.
                if fp.drops_unknown() && !fp.ban_ttl.is_zero() {
                    let now = std::time::Instant::now();
                    if bans.hit(ja4.as_str(), now) {
                        crate::metrics::METRICS
                            .tls_fp_banned_hits
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        crate::metrics::METRICS
                            .tls_fp_rejected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        // debug, not warn: the first offense already warned when
                        // the ban was recorded — this keeps a flood readable.
                        tracing::debug!(ja4 = %ja4, "tls-fp: rejecting banned fingerprint (fast path)");
                        return GateOutcome {
                            decision: GateDecision::Reject,
                            identity: Some(TlsFpIdentity {
                                ja4,
                                allowed_name: None,
                            }),
                        };
                    }
                    bans.insert(ja4.as_str(), now, fp.ban_ttl);
                }
                GateOutcome {
                    decision: fp.unknown_decision(&ja4),
                    identity: Some(TlsFpIdentity {
                        ja4,
                        allowed_name: None,
                    }),
                }
            }
        }
        // A not-a-ClientHello / truncated-beyond-budget peek: couldn't fingerprint.
        Err(_) => GateOutcome {
            decision: fp.unfingerprintable_decision(),
            identity: None,
        },
    }
}

/// The accept-path JA4 gate: `MSG_PEEK` the ClientHello (leaving the bytes in
/// the kernel buffer for rustls to re-read), compute JA4, count it known vs
/// unknown, and return whether the connection may proceed — plus the computed
/// identity for the upstream headers (see [`TlsFpIdentity`]).
///
/// - `mode = off` (runtime `None`) → `Proceed`, no peek, no syscall.
/// - `mode = shadow` → always `Proceed`; only observes (counts + logs).
/// - `mode = allowlist` → `Reject` an unknown fingerprint iff `on_unknown =
///   drop`, and a ClientHello that couldn't be fingerprinted iff
///   `on_unfingerprintable = drop`; otherwise `Proceed`.
pub async fn fingerprint_gate(
    stream: &tokio::net::TcpStream,
    state: &crate::AppState,
) -> GateOutcome {
    // Clone the resolved runtime out (a cheap Arc clone) and DROP the arc-swap
    // Guard before awaiting — never hold a config Guard across an await point.
    let fp = {
        let cfg = state.config.load();
        match cfg.tls_fingerprint.as_ref() {
            Some(fp) => fp.clone(),
            None => return GateOutcome::proceed_anonymous(), // mode = off → no peek, no syscall
        }
    };
    let mut buf = [0u8; PEEK_CAP];
    let Some(n) = peek_client_hello(stream, &mut buf).await else {
        // Timeout / EOF / stalled client — could not fingerprint.
        return GateOutcome {
            decision: fp.unfingerprintable_decision(),
            identity: None,
        };
    };
    classify(&fp, &state.tls_fp_bans, ja4_from_tls_record(&buf[..n]))
}

/// The upstream header carrying the connection's JA4. Zion's attestation — a
/// client must never be able to set it (see [`apply_headers`]).
pub const HDR_JA4: &str = "X-Client-TLS-JA4";
/// The upstream header carrying the matching allowlist entry's name.
pub const HDR_ALLOWLISTED: &str = "X-Client-TLS-Allowlisted";

/// Strip any inbound `X-Client-TLS-JA4` / `X-Client-TLS-Allowlisted`
/// unconditionally, THEN re-inject the verified values when the gate computed
/// an identity — exactly the mTLS `X-Client-Cert-Fingerprint` discipline:
/// without the strip-first, a forged header would survive to the upstream as a
/// fake fingerprint identity.
///
/// Call sites, precisely: the :443 service closure is the ONLY caller —
/// `Some` when the gate computed an identity, `None` when fingerprinting is
/// off or the ClientHello couldn't be fingerprinted. The plaintext :80 path
/// and feature-off builds do NOT call this — the module is compiled out
/// without the feature — they strip by string literal in main.rs instead
/// (`header_name_consts_match_the_feature_off_literals` pins the names).
/// Deleting those literal strips in favour of "deduplicating" through this
/// function would break exactly those two paths.
pub fn apply_headers<B>(req: &mut hyper::Request<B>, identity: Option<&TlsFpIdentity>) {
    req.headers_mut().remove(HDR_JA4);
    req.headers_mut().remove(HDR_ALLOWLISTED);
    let Some(id) = identity else { return };
    // A computed JA4 is always header-safe (lowercase alnum + '_'); the entry
    // name is operator-controlled, so from_str guards it.
    if let Ok(v) = hyper::header::HeaderValue::from_str(id.ja4.as_str()) {
        req.headers_mut().insert(HDR_JA4, v);
    }
    if let Some(name) = &id.allowed_name {
        if let Ok(v) = hyper::header::HeaderValue::from_str(name) {
            req.headers_mut().insert(HDR_ALLOWLISTED, v);
        }
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
            ban_ttl: std::time::Duration::from_secs(600),
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
    fn looks_like_ja4_accepts_valid_rejects_garbage() {
        assert!(looks_like_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1"));
        // case + surrounding whitespace tolerated (from_config lowercases).
        assert!(looks_like_ja4("  T13D1516H2_8DAAF6152771_E5627EFA2AB1  "));
        assert!(!looks_like_ja4("t13d1516h2_8daaf6152771")); // 2 parts
        assert!(!looks_like_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1_x")); // 4 parts
        assert!(!looks_like_ja4("short_8daaf6152771_e5627efa2ab1")); // a not 10 chars
        assert!(!looks_like_ja4("t13d1516h2_zzzz6152771_e5627efa2ab1")); // b not hex
        assert!(!looks_like_ja4("t13d1516h2_8daaf615277_e5627efa2ab1")); // b is 11 chars
    }

    #[test]
    fn from_config_normalizes_case_so_uppercase_matches() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        let cfg = FingerprintConfig {
            mode: FingerprintMode::Allowlist,
            allowed: vec![AllowedFingerprint {
                name: "chrome".into(),
                ja4: "  T13D1516H2_8DAAF6152771_E5627EFA2AB1  ".into(), // upper + spaces
                rate_limit_cps: 0,
                allowed_routes: vec![],
            }],
            ..Default::default()
        };
        let rt = TlsFpRuntime::from_config(&cfg).unwrap();
        // The computed JA4 is lowercase; the normalized entry must still match.
        let computed = ja4_from_client_hello(&chrome_client_hello()).unwrap();
        assert_eq!(rt.known_name(&computed), Some("chrome"));
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
                rate_limit_cps: 0,
                allowed_routes: vec![],
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

    // ── #27 commit 4: per-fingerprint rate limit + ban fast path ──────────────

    #[test]
    fn fp_rate_admits_up_to_cps_within_one_second() {
        let rate = FpRate::new(3);
        let t = 1_000_000u64;
        assert_eq!(rate.admit(t), Admit::Granted);
        assert_eq!(rate.admit(t), Admit::Granted);
        assert_eq!(rate.admit(t), Admit::Granted);
        // 4th connection in the same second crosses the cap — the ONE worth
        // logging; every later denial in the window is silent.
        assert_eq!(rate.admit(t), Admit::FirstDenial);
        assert_eq!(rate.admit(t), Admit::Denied);
        assert_eq!(rate.admit(t), Admit::Denied);
    }

    #[test]
    fn fp_rate_resets_on_a_new_second() {
        let rate = FpRate::new(1);
        let t = 1_000_000u64;
        assert_eq!(rate.admit(t), Admit::Granted);
        assert_eq!(rate.admit(t), Admit::FirstDenial);
        assert_eq!(rate.admit(t + 1), Admit::Granted); // next window starts fresh
        assert_eq!(rate.admit(t + 1), Admit::FirstDenial); // and logs once again
    }

    #[test]
    fn fp_rate_count_saturates_instead_of_wrapping() {
        // A u32::MAX-sized flood must not wrap the counter back under the cap.
        let rate = FpRate::new(1);
        let t = 42u64;
        rate.packed.store(
            ((t as u32 as u64) << 32) | u64::from(u32::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        assert_eq!(rate.admit(t), Admit::Denied);
        assert_eq!(rate.admit(t), Admit::Denied); // saturated, still over, still silent
    }

    #[test]
    fn known_decision_drops_over_cap_in_allowlist_but_only_observes_in_shadow() {
        use crate::config::{FingerprintMode, OnUnfingerprintable, OnUnknown};
        let ja4 = Ja4("t13d1516h2_8daaf6152771_e5627efa2ab1".into());
        let mk = |mode| TlsFpRuntime {
            mode,
            on_unknown: OnUnknown::Drop,
            on_unfingerprintable: OnUnfingerprintable::Allow,
            ban_ttl: std::time::Duration::from_secs(600),
            allowed: std::collections::HashMap::new(),
        };
        let entry = AllowedEntry {
            name: "chrome".into(),
            rate: Some(FpRate::new(1)),
            routes: None,
        };
        let t = 7_777u64;
        // allowlist: first admitted, second dropped.
        let al = mk(FingerprintMode::Allowlist);
        assert_eq!(al.known_decision(&ja4, &entry, || t), GateDecision::Proceed);
        assert_eq!(al.known_decision(&ja4, &entry, || t), GateDecision::Reject);
        // shadow: over cap is observed, never blocked.
        let entry_sh = AllowedEntry {
            name: "chrome".into(),
            rate: Some(FpRate::new(1)),
            routes: None,
        };
        let sh = mk(FingerprintMode::Shadow);
        assert_eq!(
            sh.known_decision(&ja4, &entry_sh, || t),
            GateDecision::Proceed
        );
        assert_eq!(
            sh.known_decision(&ja4, &entry_sh, || t),
            GateDecision::Proceed
        );
        // no rate configured: always Proceed.
        let unlimited = AllowedEntry {
            name: "curl".into(),
            rate: None,
            routes: None,
        };
        assert_eq!(
            al.known_decision(&ja4, &unlimited, || unreachable!(
                "no rate limit — the clock must not be read"
            )),
            GateDecision::Proceed
        );
    }

    #[test]
    fn ban_hit_respects_ttl_and_removes_expired() {
        let bans = BanSet::new();
        let now = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(600);
        bans.insert("fp-a", now, ttl);
        assert!(bans.hit("fp-a", now)); // inside the TTL
        assert!(!bans.hit("fp-b", now)); // never banned
                                         // Past the TTL the entry no longer bans — and is removed on the way.
        assert!(!bans.hit("fp-a", now + ttl + std::time::Duration::from_secs(1)));
        assert!(bans.map.get("fp-a").is_none());
    }

    #[test]
    fn ban_insert_at_capacity_sweeps_expired_then_skips_when_full_of_live() {
        let bans = BanSet::new();
        let now = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(600);
        // Fill to the cap with entries that are already expired at `later`.
        for i in 0..MAX_BAN_ENTRIES {
            bans.map.insert(format!("old-{i}"), now); // banned_until = now → expired after now
        }
        let later = now + std::time::Duration::from_secs(2);
        // The sweep clears the expired entries and the insert lands.
        bans.insert("fresh", later, ttl);
        assert!(bans.hit("fresh", later));
        assert!(bans.len() < MAX_BAN_ENTRIES);
        // Now fill to the cap with LIVE bans: the next insert is skipped
        // (once the sweep interval has passed, so the sweep itself runs).
        for i in 0..MAX_BAN_ENTRIES {
            bans.map.insert(format!("live-{i}"), later + ttl);
        }
        let much_later = later + BAN_SWEEP_INTERVAL + std::time::Duration::from_millis(1);
        bans.insert("overflow", much_later, ttl);
        assert!(!bans.hit("overflow", much_later));
    }

    #[test]
    fn ban_sweep_is_amortized_one_full_retain_per_interval() {
        let bans = BanSet::new();
        let now = std::time::Instant::now();
        let ttl = std::time::Duration::from_secs(600);
        // Cap the map with entries that are EXPIRED at `later` — sweepable.
        for i in 0..MAX_BAN_ENTRIES {
            bans.map.insert(format!("old-{i}"), now);
        }
        let later = now + std::time::Duration::from_secs(2);
        // First at-capacity insert runs the sweep and lands.
        bans.insert("first", later, ttl);
        assert!(bans.hit("first", later));
        // Re-cap with expired entries again, WITHIN the sweep interval: the
        // sweep must NOT run again — the insert is skipped even though every
        // entry is sweepable. This is the amortization: O(n) retain at most
        // once per BAN_SWEEP_INTERVAL, not per connection.
        for i in 0..MAX_BAN_ENTRIES {
            bans.map.insert(format!("re-{i}"), now);
        }
        let within = later + std::time::Duration::from_millis(10);
        bans.insert("second", within, ttl);
        assert!(!bans.hit("second", within));
        // After the interval the sweep is allowed again and the insert lands.
        let after = later + BAN_SWEEP_INTERVAL + std::time::Duration::from_millis(1);
        bans.insert("third", after, ttl);
        assert!(bans.hit("third", after));
    }

    #[test]
    fn ban_insert_skips_on_instant_overflow_instead_of_panicking() {
        // Validation caps ban_ttl_secs at one year, but the insert must stay
        // panic-free regardless (release panics abort the proxy).
        let bans = BanSet::new();
        let now = std::time::Instant::now();
        bans.insert("fp-x", now, std::time::Duration::from_secs(u64::MAX));
        assert!(!bans.hit("fp-x", now)); // skipped, not aborted
    }

    // ── #27 commit 5: identity stash + upstream headers ───────────────────────

    /// Runtime with one allowlisted entry, for the classify/headers tests.
    fn runtime_with_chrome(mode: crate::config::FingerprintMode) -> TlsFpRuntime {
        use crate::config::{OnUnfingerprintable, OnUnknown};
        let mut allowed = std::collections::HashMap::new();
        allowed.insert(
            "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
            AllowedEntry {
                name: "chrome".into(),
                rate: None,
                routes: None,
            },
        );
        TlsFpRuntime {
            mode,
            on_unknown: OnUnknown::Drop,
            on_unfingerprintable: OnUnfingerprintable::Allow,
            ban_ttl: std::time::Duration::from_secs(600),
            allowed,
        }
    }

    #[test]
    fn classify_carries_identity_for_known_and_unknown_but_not_unfingerprintable() {
        use crate::config::FingerprintMode;
        let fp = runtime_with_chrome(FingerprintMode::Shadow);
        let bans = BanSet::new();
        // Known: identity with the allowlist entry's name.
        let out = classify(
            &fp,
            &bans,
            Ok(Ja4("t13d1516h2_8daaf6152771_e5627efa2ab1".into())),
        );
        assert_eq!(out.decision, GateDecision::Proceed);
        let id = out.identity.expect("known carries identity");
        assert_eq!(id.allowed_name.as_deref(), Some("chrome"));
        // Unknown in shadow: proceeds, identity present, no name.
        let out = classify(
            &fp,
            &bans,
            Ok(Ja4("t00i0000_000000000000_000000000000".into())),
        );
        assert_eq!(out.decision, GateDecision::Proceed);
        let id = out.identity.expect("unknown still carries identity");
        assert!(id.allowed_name.is_none());
        // Unfingerprintable: no identity at all.
        let out = classify(&fp, &bans, Err(TlsFpError::Truncated));
        assert_eq!(out.decision, GateDecision::Proceed); // on_unfingerprintable = allow
        assert!(out.identity.is_none());
    }

    #[test]
    fn classify_allowlist_beats_a_stale_ban() {
        use crate::config::FingerprintMode;
        // The documented un-ban path: an operator hot-reloads a banned
        // fingerprint onto the allowlist and it must be admitted IMMEDIATELY —
        // the allowlist lookup runs before the ban set. A "check the cheap ban
        // map first" refactor would break exactly this; this test is the pin.
        let fp = runtime_with_chrome(FingerprintMode::Allowlist); // on_unknown = Drop
        let bans = BanSet::new();
        let chrome = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        bans.insert(
            chrome,
            std::time::Instant::now(),
            std::time::Duration::from_secs(600),
        );
        let out = classify(&fp, &bans, Ok(Ja4(chrome.into())));
        assert_eq!(out.decision, GateDecision::Proceed);
        assert_eq!(
            out.identity.unwrap().allowed_name.as_deref(),
            Some("chrome")
        );
    }

    #[test]
    fn posture_reflects_enforcement_knobs_not_just_mode() {
        use crate::config::{FingerprintMode, OnUnknown};
        let log_only = TlsFpRuntime {
            on_unknown: OnUnknown::LogOnly,
            ..runtime_with_chrome(FingerprintMode::Allowlist)
        };
        let drop = runtime_with_chrome(FingerprintMode::Allowlist); // on_unknown = Drop
                                                                    // Same mode, different posture — the reload announcer must see it.
        assert_ne!(log_only.posture(), drop.posture());
    }

    #[test]
    fn classify_ban_fast_path_rejects_and_still_reports_identity() {
        use crate::config::FingerprintMode;
        let fp = runtime_with_chrome(FingerprintMode::Allowlist); // on_unknown = Drop
        let bans = BanSet::new();
        let unknown = || Ok(Ja4("t00i0000_000000000000_000000000000".into()));
        // First offense: rejected via unknown_decision, ban recorded.
        let out = classify(&fp, &bans, unknown());
        assert_eq!(out.decision, GateDecision::Reject);
        assert!(out.identity.is_some());
        // Second offense: rejected via the ban fast path — identity still there.
        let out = classify(&fp, &bans, unknown());
        assert_eq!(out.decision, GateDecision::Reject);
        let id = out.identity.expect("banned fast path keeps the identity");
        assert!(id.allowed_name.is_none());
    }

    #[test]
    fn apply_headers_strips_forgeries_and_injects_the_verified_identity() {
        let mut req = hyper::Request::builder()
            .header(HDR_JA4, "t13dforged_aaaaaaaaaaaa_bbbbbbbbbbbb")
            .header(HDR_ALLOWLISTED, "forged-name")
            .body(())
            .unwrap();
        let id = TlsFpIdentity {
            ja4: Ja4("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            allowed_name: Some("chrome".into()),
        };
        apply_headers(&mut req, Some(&id));
        assert_eq!(
            req.headers().get(HDR_JA4).unwrap(),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        assert_eq!(req.headers().get(HDR_ALLOWLISTED).unwrap(), "chrome");
    }

    #[test]
    fn apply_headers_without_identity_strips_only() {
        let mut req = hyper::Request::builder()
            .header(HDR_JA4, "t13dforged_aaaaaaaaaaaa_bbbbbbbbbbbb")
            .header(HDR_ALLOWLISTED, "forged-name")
            .body(())
            .unwrap();
        apply_headers::<()>(&mut req, None);
        assert!(req.headers().get(HDR_JA4).is_none());
        assert!(req.headers().get(HDR_ALLOWLISTED).is_none());
    }

    #[test]
    fn apply_headers_skips_an_unsafe_allowlist_name() {
        // The entry name is operator-controlled; a value HeaderValue rejects
        // must be skipped, not panic — and must not leave the forged one.
        let mut req = hyper::Request::builder()
            .header(HDR_ALLOWLISTED, "forged")
            .body(())
            .unwrap();
        let id = TlsFpIdentity {
            ja4: Ja4("t13d1516h2_8daaf6152771_e5627efa2ab1".into()),
            allowed_name: Some("bad\nname".into()),
        };
        apply_headers(&mut req, Some(&id));
        assert!(req.headers().get(HDR_JA4).is_some());
        assert!(req.headers().get(HDR_ALLOWLISTED).is_none());
    }

    #[test]
    fn header_name_consts_match_the_feature_off_literals() {
        // main.rs strips these by string literal on builds where this module
        // is compiled out — the consts and the literals must never drift.
        assert_eq!(HDR_JA4, "X-Client-TLS-JA4");
        assert_eq!(HDR_ALLOWLISTED, "X-Client-TLS-Allowlisted");
    }

    #[test]
    fn route_denied_matrix_with_router_alias_semantics() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        let chrome = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        let curl = "t13d1516h2_000000000000_000000000000";
        let cfg = FingerprintConfig {
            mode: FingerprintMode::Allowlist,
            allowed: vec![
                AllowedFingerprint {
                    name: "api-agent".into(),
                    ja4: chrome.into(),
                    rate_limit_cps: 0,
                    allowed_routes: vec!["/api/{*rest}".into(), "/healthz".into()],
                },
                AllowedFingerprint {
                    name: "unrestricted".into(),
                    ja4: curl.into(),
                    rate_limit_cps: 0,
                    allowed_routes: vec![],
                },
            ],
            ..Default::default()
        };
        let rt = TlsFpRuntime::from_config(&cfg).unwrap();
        // Covered paths — including the catch-all's BARE prefix (router alias
        // semantics: /api/{*rest} also serves /api) and the trailing-slash
        // variant of an explicit path.
        assert_eq!(rt.route_denied(chrome, "/api/v1/users"), None);
        assert_eq!(rt.route_denied(chrome, "/api"), None);
        assert_eq!(rt.route_denied(chrome, "/healthz"), None);
        assert_eq!(rt.route_denied(chrome, "/healthz/"), None);
        // Outside the list → denied, reporting the entry name.
        assert_eq!(rt.route_denied(chrome, "/admin"), Some("api-agent"));
        assert_eq!(rt.route_denied(chrome, "/"), Some("api-agent"));
        // No restriction list → never denied.
        assert_eq!(rt.route_denied(curl, "/anything"), None);
        // Not on the allowlist at all → not this check's business.
        assert_eq!(
            rt.route_denied("t00i0000_000000000000_000000000000", "/admin"),
            None
        );
    }

    #[test]
    fn route_gate_mode_matrix_allowlist_rejects_shadow_observes() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        let chrome = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        let mk = |mode| {
            let cfg = FingerprintConfig {
                mode,
                allowed: vec![AllowedFingerprint {
                    name: "api-agent".into(),
                    ja4: chrome.into(),
                    rate_limit_cps: 0,
                    allowed_routes: vec!["/api/{*rest}".into()],
                }],
                ..Default::default()
            };
            TlsFpRuntime::from_config(&cfg).unwrap()
        };
        // allowlist: outside the list → Reject (the dispatch 403); inside → Proceed.
        let al = mk(FingerprintMode::Allowlist);
        assert_eq!(al.route_gate(chrome, "/admin"), GateDecision::Reject);
        assert_eq!(al.route_gate(chrome, "/api/v1"), GateDecision::Proceed);
        // shadow: NEVER rejects, even outside the list (observe-only rollout).
        let sh = mk(FingerprintMode::Shadow);
        assert_eq!(sh.route_gate(chrome, "/admin"), GateDecision::Proceed);
        // unknown ja4 / unrestricted: not this gate's business.
        assert_eq!(
            al.route_gate("t00i0000_000000000000_000000000000", "/admin"),
            GateDecision::Proceed
        );
    }

    #[test]
    fn route_gate_counts_denials_in_both_modes() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        let chrome = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        let cfg = FingerprintConfig {
            mode: FingerprintMode::Shadow,
            allowed: vec![AllowedFingerprint {
                name: "api-agent".into(),
                ja4: chrome.into(),
                rate_limit_cps: 0,
                allowed_routes: vec!["/api/{*rest}".into()],
            }],
            ..Default::default()
        };
        let rt = TlsFpRuntime::from_config(&cfg).unwrap();
        let before = crate::metrics::METRICS
            .tls_fp_route_denied
            .load(std::sync::atomic::Ordering::Relaxed);
        rt.route_gate(chrome, "/admin"); // shadow denial: counted, not blocked
        rt.route_gate(chrome, "/api/ok"); // allowed: NOT counted
        let after = crate::metrics::METRICS
            .tls_fp_route_denied
            .load(std::sync::atomic::Ordering::Relaxed);
        // >= 1 rather than == 1: the metric is a global atomic shared with
        // parallel tests — only the delta from THIS test's denial is asserted.
        assert!(after > before, "denial must increment the metric");
    }

    #[test]
    fn from_config_resolves_rate_limit_only_when_positive() {
        use crate::config::{AllowedFingerprint, FingerprintConfig, FingerprintMode};
        let cfg = FingerprintConfig {
            mode: FingerprintMode::Allowlist,
            allowed: vec![
                AllowedFingerprint {
                    name: "limited".into(),
                    ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(),
                    rate_limit_cps: 50,
                    allowed_routes: vec![],
                },
                AllowedFingerprint {
                    name: "unlimited".into(),
                    ja4: "t13d1516h2_000000000000_000000000000".into(),
                    rate_limit_cps: 0, // 0 = no limit, same as [server] rate_limit_rps
                    allowed_routes: vec![],
                },
            ],
            ban_ttl_secs: 0,
            ..Default::default()
        };
        let rt = TlsFpRuntime::from_config(&cfg).unwrap();
        let limited = rt
            .allowed
            .get("t13d1516h2_8daaf6152771_e5627efa2ab1")
            .unwrap();
        assert_eq!(limited.rate.as_ref().map(|r| r.cps), Some(50));
        let unlimited = rt
            .allowed
            .get("t13d1516h2_000000000000_000000000000")
            .unwrap();
        assert!(unlimited.rate.is_none());
        assert!(rt.ban_ttl.is_zero()); // ban_ttl_secs = 0 disables the ban set
    }

    #[test]
    fn fingerprint_config_default_and_serde_default_agree_on_ban_ttl() {
        use crate::config::FingerprintConfig;
        // The manual Default impl and a TOML block omitting ban_ttl_secs must
        // both say 600 — a derived Default would silently disagree (0).
        assert_eq!(FingerprintConfig::default().ban_ttl_secs, 600);
        let parsed: FingerprintConfig = toml::from_str("mode = \"shadow\"").unwrap();
        assert_eq!(parsed.ban_ttl_secs, 600);
    }
}

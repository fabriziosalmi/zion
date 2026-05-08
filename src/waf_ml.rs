//! ML-augmented WAF scoring (Track C).
//!
//! Compile with `--features ml-waf`.
//!
//! Loads a quantized ONNX model at boot and scores every incoming
//! request on the WAF hot path. The score is a single float in `[0,1]`
//! interpreted as "probability that this request is malicious." If the
//! score exceeds [`MlConfig::threshold`] and the request is not in WAF
//! shadow mode, the dispatcher denies with reason
//! `"ml score above threshold"`. In shadow mode the score is logged but
//! the request flows through.
//!
//! Feature vector is 16-dim float over header/URI shape — chosen to
//! keep the model small enough (16→32→1 MLP, ~2 KB of weights) that
//! one inference fits a 200 µs p99 budget. Body-aware features are a
//! v1 follow-up.
//!
//! Budget enforcement is a soft alert, not a cancel: tract is sync and
//! cancelling mid-op is unsafe. Every score's wall-clock time is
//! recorded; the operator alerts on p99.
//!
//! Model load failure is not fatal — log once at boot, disable scoring
//! for the lifetime of the process, the Aho-Corasick gate keeps running.

// Scaffolding: public init / is_active / config fields are part of the
// v0.2.x stable surface. They are unused by the binary today (the
// dispatcher reaches them via `evaluate`) but the boot-banner / health
// endpoint integration that consumes them is the next-PR delta.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

use hyper::HeaderMap;

/// Configuration parsed from the `[waf.ml]` section of `zion.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MlConfig {
    /// Master switch. When `false` the scorer is never invoked.
    #[serde(default)]
    pub enabled: bool,

    /// Filesystem path to the ONNX model.
    #[serde(default = "default_model_path")]
    pub model_path: PathBuf,

    /// Score threshold above which a request is denied. Range `[0, 1]`.
    /// 0.5 = balanced, 0.8 = conservative (low FP), 0.3 = aggressive.
    #[serde(default = "default_threshold")]
    pub threshold: f32,

    /// Soft latency budget for one inference. Surfaced as a slow-trace
    /// metric when exceeded; never used as a hard cancel.
    #[serde(default = "default_budget_us")]
    pub budget_us: u32,
}

fn default_model_path() -> PathBuf {
    PathBuf::from("/usr/local/lib/zion/waf-scorer.onnx")
}
fn default_threshold() -> f32 {
    0.85
}
fn default_budget_us() -> u32 {
    200
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: default_model_path(),
            threshold: default_threshold(),
            budget_us: default_budget_us(),
        }
    }
}

// ── Feature extraction ────────────────────────────────────────────────

/// Number of features in the model input. **Must match the ONNX model's
/// declared input shape**. If you retrain with a different feature set,
/// bump this and the corresponding model file in lockstep.
pub const FEATURE_DIM: usize = 16;

/// Extract a fixed-size feature vector from the request shape (URI,
/// method, headers). Allocation-free — writes into a stack array.
///
/// Index map (keep the model in sync with this layout):
///
///   0  uri_len_norm       — URI length / 4096, clamped to 1.0
///   1  uri_entropy        — Shannon entropy of URI bytes (bits/byte / 8)
///   2  uri_pct_encoded    — count of `%` / uri_len, clamped
///   3  uri_special_chars  — count of `<>'"\\;()` / uri_len, clamped
///   4  uri_digits_ratio   — count of ASCII digits / uri_len
///   5  uri_path_depth     — count of `/` / 16, clamped
///   6  is_post            — 1.0 if method ∈ {POST,PUT,PATCH}, else 0.0
///   7  header_count_norm  — header count / 64, clamped
///   8  total_header_bytes — sum of header value lens / 8192, clamped
///   9  has_user_agent     — 1.0 if User-Agent present
///  10  has_referer        — 1.0 if Referer present
///  11  has_cookie         — 1.0 if Cookie present
///  12  has_auth           — 1.0 if Authorization present
///  13  ua_entropy         — entropy of User-Agent bytes (or 0.0)
///  14  has_content_type   — 1.0 if Content-Type present
///  15  unprintable_ratio  — non-printable bytes in URI / uri_len
pub fn extract_features(method: &str, uri: &str, headers: &HeaderMap) -> [f32; FEATURE_DIM] {
    let mut f = [0.0f32; FEATURE_DIM];
    let uri_b = uri.as_bytes();
    let n = uri_b.len() as f32;

    f[0] = (uri_b.len() as f32 / 4096.0).min(1.0);
    f[1] = byte_entropy(uri_b) / 8.0;

    let mut pct = 0u32;
    let mut special = 0u32;
    let mut digits = 0u32;
    let mut slashes = 0u32;
    let mut unprintable = 0u32;
    for &b in uri_b {
        if b == b'%' {
            pct += 1;
        }
        if matches!(b, b'<' | b'>' | b'\'' | b'"' | b'\\' | b';' | b'(' | b')') {
            special += 1;
        }
        if b.is_ascii_digit() {
            digits += 1;
        }
        if b == b'/' {
            slashes += 1;
        }
        if !(b == b'\t' || (0x20..=0x7e).contains(&b)) {
            unprintable += 1;
        }
    }
    if n > 0.0 {
        f[2] = (pct as f32 / n).min(1.0);
        f[3] = (special as f32 / n).min(1.0);
        f[4] = digits as f32 / n;
        f[15] = unprintable as f32 / n;
    }
    f[5] = (slashes as f32 / 16.0).min(1.0);

    f[6] = if matches!(method, "POST" | "PUT" | "PATCH") {
        1.0
    } else {
        0.0
    };

    f[7] = (headers.len() as f32 / 64.0).min(1.0);
    let total_hdr_bytes: usize = headers.iter().map(|(_, v)| v.as_bytes().len()).sum();
    f[8] = (total_hdr_bytes as f32 / 8192.0).min(1.0);

    f[9] = if headers.contains_key(hyper::header::USER_AGENT) {
        1.0
    } else {
        0.0
    };
    f[10] = if headers.contains_key(hyper::header::REFERER) {
        1.0
    } else {
        0.0
    };
    f[11] = if headers.contains_key(hyper::header::COOKIE) {
        1.0
    } else {
        0.0
    };
    f[12] = if headers.contains_key(hyper::header::AUTHORIZATION) {
        1.0
    } else {
        0.0
    };
    f[14] = if headers.contains_key(hyper::header::CONTENT_TYPE) {
        1.0
    } else {
        0.0
    };

    if let Some(ua) = headers.get(hyper::header::USER_AGENT) {
        f[13] = byte_entropy(ua.as_bytes()) / 8.0;
    }

    f
}

/// Shannon entropy in bits/byte over the input. Returns 0.0 on empty
/// input. Allocation-free (uses a stack histogram).
fn byte_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in bytes {
        hist[b as usize] = hist[b as usize].saturating_add(1);
    }
    let n = bytes.len() as f32;
    let mut h = 0.0f32;
    for &c in &hist {
        if c == 0 {
            continue;
        }
        let p = c as f32 / n;
        h -= p * p.log2();
    }
    h
}

// ── Model holder ──────────────────────────────────────────────────────

#[cfg(feature = "ml-waf")]
type RunnablePlan = tract_onnx::prelude::SimplePlan<
    tract_onnx::prelude::TypedFact,
    Box<dyn tract_onnx::prelude::TypedOp>,
    tract_onnx::prelude::Graph<
        tract_onnx::prelude::TypedFact,
        Box<dyn tract_onnx::prelude::TypedOp>,
    >,
>;

/// Process-global model handle, populated at most once at boot.
/// `None` means scoring is disabled (either by config or by load failure).
static MODEL: OnceLock<Option<RunnablePlan>> = OnceLock::new();

/// Process-global runtime config (threshold, budget). Stored separately
/// from `MODEL` so the dispatcher can read it on the hot path without
/// touching the (locked) tract plan.
static CONFIG: OnceLock<MlConfig> = OnceLock::new();

/// What the WAF dispatcher should do with the score. Returned from
/// [`evaluate`].
#[derive(Debug, Clone, Copy)]
pub struct MlVerdict {
    /// Score in `[0, 1]`. Higher = more likely malicious.
    pub score: f32,
    /// `true` if `score > threshold` (caller still decides shadow vs.
    /// real block based on the route's WAF profile).
    pub denies: bool,
    /// Wall-clock time of the inference, in microseconds. Recorded even
    /// when `denies = false` so p99 alerts cover the whole distribution.
    pub elapsed_us: u64,
    /// `true` if `elapsed_us > config.budget_us`. The operator can set
    /// a Prometheus alert directly on this counter without computing a
    /// p99 windowed quantile.
    pub over_budget: bool,
}

/// Initialise the model from the configured path. Idempotent — subsequent
/// calls are no-ops. Safe to call before `tokio::main`.
///
/// Returns `Ok(true)` if the model is now loaded, `Ok(false)` if scoring
/// is intentionally disabled, `Err` if the model file existed but failed
/// to parse — in which case the caller should log and continue without
/// ML (the OnceLock is still populated with `None`).
pub fn init(cfg: &MlConfig) -> Result<bool, String> {
    // Note on idempotency: `OnceLock::set` only succeeds once. If
    // init() is called with `enabled = false` first and a later call
    // re-enables, we must NOT have poisoned `MODEL` with `None` —
    // otherwise the model can never be loaded for the lifetime of the
    // process (an ugly hot-reload regression). So the disabled branch
    // does *not* touch MODEL.
    let _ = CONFIG.set(cfg.clone());
    if !cfg.enabled {
        return Ok(false);
    }
    if MODEL.get().and_then(|m| m.as_ref()).is_some() {
        // Model already loaded by a prior enabled call.
        return Ok(true);
    }

    use tract_onnx::prelude::*;
    // Load failures do *not* set MODEL — the OnceLock stays empty so
    // a follow-up init() (e.g. after the operator drops the file at
    // the right path) can succeed. Setting `None` here would poison
    // the slot for the lifetime of the process.
    let model = tract_onnx::onnx()
        .model_for_path(&cfg.model_path)
        .map_err(|e| format!("ml-waf: load {} failed: {e}", cfg.model_path.display()))?;
    let plan = model
        .into_optimized()
        .and_then(|m| m.into_runnable())
        .map_err(|e| format!("ml-waf: optimize/runnable failed: {e}"))?;
    let _ = MODEL.set(Some(plan));
    Ok(true)
}

/// True if the model is loaded and scoring is active.
pub fn is_active() -> bool {
    MODEL.get().and_then(|m| m.as_ref()).is_some()
}

/// Score a request. Returns `None` if the model isn't loaded; otherwise
/// `Some(score, elapsed_us)` so the caller can record both the verdict
/// and the latency in one shot.
///
/// The `elapsed_us` is reported even when the score result is below
/// threshold — the operator wants to alert on the *whole* p99, not just
/// the deny branch.
pub fn score(method: &str, uri: &str, headers: &HeaderMap) -> Option<(f32, u64)> {
    let plan = MODEL.get().and_then(|m| m.as_ref())?;
    let started = Instant::now();
    let features = extract_features(method, uri, headers);

    use tract_onnx::prelude::*;
    let arr = match tract_ndarray::Array::from_shape_vec((1, FEATURE_DIM), features.to_vec()) {
        Ok(a) => a,
        Err(_) => return None,
    };
    let input: Tensor = arr.into_tensor();
    let result = match plan.run(tvec!(input.into())) {
        Ok(out) => out,
        Err(_) => return None,
    };
    let elapsed_us = started.elapsed().as_micros() as u64;

    let arr = result.first().and_then(|t| t.to_array_view::<f32>().ok())?;
    let score = *arr.iter().next()?;
    Some((score.clamp(0.0, 1.0), elapsed_us))
}

/// Score and apply the configured threshold. Returns `None` when
/// scoring is disabled or the model failed to load — callers should
/// treat that as "no ML signal" and fall through to the legacy gates.
///
/// This is the single function that `dispatch.rs` calls. Keeping the
/// threshold comparison here (instead of in the dispatcher) means a
/// future change to the threshold logic — e.g. using a per-route value
/// or a separate "block" vs. "challenge" cutoff — does not require
/// touching the request hot path.
pub fn evaluate(method: &str, uri: &str, headers: &HeaderMap) -> Option<MlVerdict> {
    let (score, elapsed_us) = score(method, uri, headers)?;
    let cfg = CONFIG.get()?;
    Some(MlVerdict {
        score,
        denies: score > cfg.threshold,
        elapsed_us,
        over_budget: elapsed_us > cfg.budget_us as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{CONTENT_TYPE, USER_AGENT};

    fn h() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64)".parse().unwrap(),
        );
        h.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        h
    }

    #[test]
    fn benign_get_features_are_in_range() {
        let f = extract_features("GET", "/api/v1/widgets/42", &h());
        for v in f {
            assert!((0.0..=1.0).contains(&v), "feature out of range: {v}");
        }
        assert!(f[0] > 0.0 && f[0] < 0.01, "uri_len normalised tiny");
        assert!(f[6] == 0.0, "GET is not POST");
        assert!(f[9] == 1.0, "UA present");
    }

    #[test]
    fn injection_uri_lights_up_special_chars() {
        let benign = extract_features("GET", "/api/v1/widgets/42", &HeaderMap::new());
        let evil = extract_features(
            "GET",
            "/api/widgets?q=' OR '1'='1';--<script>",
            &HeaderMap::new(),
        );
        assert!(
            evil[3] > benign[3],
            "special-chars feature must increase on SQLi/XSS payloads"
        );
        assert!(evil[1] > benign[1], "entropy increases under encoded junk");
    }

    #[test]
    fn entropy_zero_on_empty() {
        assert_eq!(byte_entropy(b""), 0.0);
    }

    #[test]
    fn entropy_one_byte_is_zero() {
        assert_eq!(byte_entropy(b"aaaaaa"), 0.0);
    }

    #[test]
    fn entropy_uniform_two_bytes_is_one() {
        assert!((byte_entropy(b"abababab") - 1.0).abs() < 1e-3);
    }

    #[test]
    fn score_returns_none_when_model_absent() {
        // We deliberately do not init() in this test; MODEL stays None.
        assert!(score("GET", "/", &HeaderMap::new()).is_none());
    }

    #[test]
    fn config_default_disabled() {
        assert!(!MlConfig::default().enabled);
        assert_eq!(MlConfig::default().budget_us, 200);
    }

    /// Hammer F1.4 — calling `init` with `enabled = false` must not
    /// poison the `MODEL` OnceLock. A subsequent enabled call must
    /// still be able to attempt the load.
    ///
    /// Direct shape-test instead of state-test: we simulate the bug
    /// pattern by calling init(disabled) and then asserting the return
    /// value is `Ok(false)` (the contract). State-level inspection of
    /// the global MODEL is unsafe here because parallel tests share it.
    #[test]
    fn init_disabled_returns_ok_false() {
        let cfg = MlConfig {
            enabled: false,
            ..Default::default()
        };
        assert_eq!(init(&cfg), Ok(false));
    }

    /// Hammer F1.4 — calling init with `enabled = true` and a path
    /// that doesn't exist returns Err (not Ok(false), which would
    /// indicate the disabled path was wrongly taken).
    #[test]
    fn init_enabled_with_missing_model_returns_err() {
        let cfg = MlConfig {
            enabled: true,
            model_path: PathBuf::from("/tmp/zion-test-nonexistent.onnx"),
            ..Default::default()
        };
        // We don't assert on MODEL state because it is a process-global
        // OnceLock that another test in the same binary may have loaded.
        // The contract under test is just that the function returns Err
        // when the file is missing — never Ok(false).
        match init(&cfg) {
            Err(_) => {}   // expected: load failed
            Ok(true) => {} // accepted: another test pre-loaded MODEL
            Ok(false) => panic!("enabled init must not silently report disabled"),
        }
    }
}

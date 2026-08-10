# Model card — Zion ML-WAF scorer

> **Status: NOT SHIPPED.** This card documents the *reference baseline* produced
> by `ml/` (ADR-0023). No model is published while the corpus is synthetic. When
> a model is approved for release, this card ships alongside the `.onnx`.

## Intended use

- **Advisory** attack-likelihood scoring on Zion's WAF hot path (`--features
  ml-waf`). The score is exposed as a metric/header and, above a configurable
  `threshold`, can inform a decision — but it is **never the sole hard gate**; the
  rule engine (`waf.rs`) remains the authority. The scorer *complements* the rules.
- Out of scope: a standalone IDS, a replacement for signature rules, or any
  use as the only line of defense.

## Model

- **Architecture**: MLP 16 → 24 → 12 → 1, ReLU + final Sigmoid (Gemm/ReLU/Sigmoid
  — all tract-supported). ~3.8 KB ONNX.
- **Input**: `(1, 16)` float32 — the features below, in order.
- **Output**: one float32 in `[0,1]` (production clamps).
- **Runtime**: tract-onnx, in-process. **p99 8 µs / avg 4.7 µs** (release), against
  a 200 µs budget.

## Features (16) — see `src/waf_ml.rs` / `ml/features.py`

`uri_len_norm, uri_entropy, uri_pct_encoded, uri_special_chars, uri_digits_ratio,
uri_path_depth, is_post, header_count_norm, total_header_bytes, has_user_agent,
has_referer, has_cookie, has_auth, ua_entropy, has_content_type,
unprintable_ratio`. All request-shape / metadata — **no body inspection, no PII**.

## Training data

- **100% synthetic.** Attacks seeded from Zion's own 276 WAF signatures embedded
  into varied request shapes; benign from realistic API/static/page templates.
  Deterministic (seeded). **No captured or client traffic — ever.**
- Provenance + generator: `ml/generate_corpus.py`, `ml/testdata/waf_signatures.json`.

## Metrics (reference baseline, synthetic hold-out)

| metric | value |
|--------|-------|
| ROC-AUC | 0.9997 |
| precision | 1.00 |
| recall | 0.98 |
| mean score benign / attack | 0.011 / 0.967 |

## Limitations & honest caveats

- **The metrics overstate real-world skill.** The synthetic classes are separable
  by *template artifacts* (header-presence distributions, digit ratios, encoding),
  not deep attack semantics. Transferable signal lives in the **URI-content**
  features; the **header-presence** features are artifact-prone (a first corpus
  had a `has_auth` benign-only leak, since fixed).
- **Evasion**: because it is advisory and rule-complementary, evasion of the
  *scorer* does not bypass the WAF's signature rules. Still, do not treat the score
  as authoritative.
- **A production model requires richer data** (vetted public corpora and/or
  adversarial de-biasing) before it should be shipped or trusted.

## Threshold guidance

`threshold` (default 0.85, conservative/low-FP). 0.5 balanced, 0.3 aggressive.
Because the reference baseline overstates skill, **re-calibrate the threshold on
real traffic in shadow mode** before acting on the score.

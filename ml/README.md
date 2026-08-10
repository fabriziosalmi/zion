# ML-WAF training pipeline

Reproducible pipeline for the `--features ml-waf` scorer (see
[ADR-0023](../docs/adr/0023-ml-waf-training-pipeline.md) and
[`src/waf_ml.rs`](../src/waf_ml.rs)). It trains a tiny ONNX model that scores a
request's *attack-likelihood* in `[0,1]` on Zion's WAF hot path — **advisory
only, never a hard gate**.

> **Nothing here ships automatically.** Model artifacts are gitignored; a model
> is published only after a human reviews the corpus and metrics (the review
> gate). This directory is the *pipeline*, not a released model.

## Layout

| file | role |
|------|------|
| `features.py` | the 16-feature extractor — a **byte-exact** port of `waf_ml::extract_features` |
| `test_parity.py` | asserts `features.py` == golden vectors from Rust (`testdata/golden_features.json`) |
| `generate_corpus.py` | synthetic labeled corpus: attacks seeded from Zion's 276 WAF signatures + realistic benign |
| `train.py` | trains a tiny MLP (16→24→12→1) and exports ONNX `(1,16)→(1,1)` f32 |
| `validate.py` | onnxruntime interface + sanity check (the authoritative latency check is in Rust) |
| `testdata/` | `golden_features.json` (parity fixture) + `waf_signatures.json` (dumped from `waf.rs`) |

## Reproduce

```bash
pip install -r ml/requirements.txt

# 1. (only if the Rust extractor or signatures changed) refresh the fixtures:
cargo test --features ml-waf gen_golden_features -- --ignored --nocapture
cargo test dump_waf_signatures            -- --ignored --nocapture

# 2. verify the Python extractor still matches Rust byte-for-byte:
python3 ml/test_parity.py

# 3. generate a corpus, train, export:
python3 ml/generate_corpus.py --n 6000 --seed 1337
python3 ml/train.py           --epochs 120
python3 ml/validate.py

# 4. THE feasibility gate — tract latency vs the 200µs p99 budget (release):
ZION_ML_MODEL=ml/waf-scorer.onnx \
  cargo test --release --features ml-waf ml_scorer_latency -- --ignored --nocapture
```

## Status (2026-08-03)

- **Parity**: verified, max |Δ| = 9.6e-08.
- **Latency**: **p99 = 8 µs** release (avg 4.7 µs) — 25× under the 200 µs budget.
- **Model quality**: on the *synthetic* corpus AUC ≈ 0.9997 / precision 1.00 /
  recall 0.98 — but that reflects separability of the generator's **template
  artifacts**, not real-world robustness. The header-presence features are
  artifact-prone; the URI-content features carry the transferable signal. See the
  ADR. **A production model needs richer data** (public corpora / de-biasing) — a
  deferred, explicit-go follow-up.

## Hard rules

- **Confidentiality**: the corpus is 100% synthetic. Never train on captured or
  client traffic.
- **Parity**: if you change `waf_ml::extract_features`, regenerate the golden file
  and keep `features.py` in lockstep — `test_parity.py` is the guard.
- **Wiring**: production inference is **tract**, not onnxruntime. `validate.py` is
  a fast Python pre-flight; the Rust `ml_scorer_latency` bench is authoritative.

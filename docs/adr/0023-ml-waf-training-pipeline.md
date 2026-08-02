# ADR-0023: ML-WAF training pipeline (reproducible, synthetic-first, review-gated)

- **Status**: accepted
- **Date**: 2026-08-03
- **Deciders**: fabriziosalmi
- **Tags**: ml-waf, security, tract, reproducibility, data

## Context

`--features ml-waf` ships a fully-specified but **inert** capability: a 16-feature
extractor (`waf_ml::extract_features`) feeding a tract-onnx scorer on the WAF hot
path (advisory only, never a hard gate), with **no bundled model**. So the flag
does nothing out of the box, and every operator would have to invent a training
pipeline — features, data, export format, latency budget — from the source.

This ADR records the decision to build a **reproducible, in-repo training
pipeline** (`ml/`) so a model can be trained, validated, and — once reviewed —
shipped, and so anyone can retrain it. It deliberately does **not** ship a model
yet: the first corpus is synthetic and its quality is the open question.

## Decision

### A `ml/` pipeline, not a committed model (the review gate)

`ml/` holds the whole pipeline — `features.py`, `generate_corpus.py`, `train.py`,
`validate.py` — plus a tiny parity fixture. Model artifacts (`*.onnx`, `*.pt`),
the generated corpus, and CSVs are **gitignored**. No model is committed or
published (GitHub Release / HuggingFace) until a human reviews the corpus and the
metrics. The pipeline is the deliverable; the model is a reviewed output of it.

### Feature parity is pinned cross-language

`ml/features.py` is a byte-exact port of the Rust extractor. It is pinned by
`ml/test_parity.py` against golden vectors emitted from the Rust code itself
(`gen_golden_features`, an `#[ignore]` generator in `waf_ml.rs`). Verified: max
absolute Δ = 9.6e-08 over the corpus (pure f32-vs-f64 rounding). Training features
therefore equal inference features — the failure mode that silently poisons an
ML-WAF is designed out.

### Attacks are seeded from Zion's own signatures

`generate_corpus.py` seeds the attack class from the **276 real WAF signatures**
(`BALANCED_PATTERNS` + `AGGRESSIVE_EXTRA_PATTERNS`, dumped by `dump_waf_signatures`)
embedded into varied request shapes; benign is realistic API/static/page traffic.
The model thus learns to *agree with and generalize around* the deployed rule
engine — the sane target for an advisory scorer that complements, not replaces,
the rules. It is 100% synthetic — **no captured traffic, ever** (a hard
confidentiality rule).

### The model is deliberately tiny; tract latency is the gate

A 16→24→12→1 MLP (Gemm/ReLU/Sigmoid only — all tract-supported), input `(1,16)`
f32, one `[0,1]` output, matching `waf_ml::score`. The single feasibility gate is
the **200 µs p99 budget**, measured in Rust with tract (not onnxruntime), release
build: **avg 4.7 µs, p50 4 µs, p90 5 µs, p99 8 µs, max 181 µs — 25× under
budget.** Latency is a solved problem; the scorer is effectively free on the hot
path.

## Consequences

- **Positive**: the inert feature becomes usable; a model can be trained,
  latency-proven, and shipped with a reproducible provenance. Feature parity and
  the confidentiality rule are enforced mechanically.
- **The open problem — data quality.** On the synthetic corpus a properly-trained
  model reaches AUC ≈ 0.9997, precision 1.00 / recall 0.98. **This overstates
  real-world skill**: the generator's benign and attack classes are separable by
  *template artifacts* (header-presence distributions, digit ratios, encoding),
  not deep attack semantics. Observed live: the header-presence features
  (`has_auth`, `has_cookie`) are artifact-prone; the URI-content features
  (`pct_encoded`, `special`, entropy, `unprintable`) carry the transferable
  signal. A first pass had a `has_auth` data-leak (benign-only auth) that was
  caught in review and fixed. A production-grade model needs richer data.
- **Neutral**: shipping remains a human decision; nothing auto-publishes.

## Alternatives considered

- **Ship a model now off the synthetic corpus** — rejected: its metrics do not
  reflect real robustness, and shipping it would imply a quality it doesn't have.
- **Public web-attack datasets (CSIC 2010 / PKDD-2007) from the start** — deferred
  (not rejected): higher realism, but licensing review, download, and quality
  vetting. This is the recommended next step *if* the model is to ship, and needs
  an explicit go.
- **On-the-fly / larger model** — rejected: the 200 µs budget and the "advisory,
  not a gate" role favor a tiny net; latency headroom (25×) confirms the tiny net
  is right.
- **Committing the model into the repo / binary** — rejected: models are large,
  churny, and review-gated; distribute via GitHub Release / HuggingFace with a
  model card, pointed to by `model_path`.

## Open follow-ups (require an explicit go)

1. **Data escalation** — fold in vetted public corpora and/or add adversarial
   de-biasing so the model can't lean on template artifacts.
2. **Ship** — train on the improved corpus, publish the `.onnx` + model card to a
   GitHub Release / HuggingFace, and document `model_path` wiring (optionally in
   the dist bundle).

## References

- `src/waf_ml.rs` (`extract_features`, `score`, `gen_golden_features`,
  `ml_scorer_latency`), `src/waf.rs` (`dump_waf_signatures`)
- `ml/` (pipeline), `ml/README.md`, `ml/MODEL_CARD.md`
- ADR-0007 (MSRV — the pipeline adds no runtime dep; tract-onnx already ships
  under `ml-waf`)

## Update — real tool-traffic escalation (2026-08-03)

The synthetic model was tested cross-source against a real HTTP-DATASET-CSIC-2010
fragment (the only real data reachable in-sandbox — the canonical host is down;
mirrors are stubs/pre-featurized/oversized): it detected **0 of 9** real attacks
(scored them 0.000, same as benign) — the artifact-overfitting predicted above,
now measured.

Following that, an in-sandbox **attack-traffic lab** (`ml/attack_lab/`) was built
to train on *real* traffic instead of synthetic payloads: point real tools
(sqlmap with WAF-evasion `--tamper`, dalfox for XSS, SecLists payload replay) at
a local capture server and record the requests they emit; label a realistic
benign generator's traffic 0. Result:

- **Capturing real tool traffic works** — the retrained model reaches AUC ≈ 0.9999
  in-distribution and, unlike the synthetic one, actually recognizes
  payload-bearing attacks (SQLi/XSS/LFI/cmd). The synthetic→real transfer gap is
  the point: real traffic is required.
- **The ceiling moved off the data.** It is now (a) the **URI+header feature set**
  (no POST body, no value-semantics), so subtle parameter-tampering — much of the
  CSIC "anomalous" fragment, which is structurally identical to benign e-commerce
  — is invisible by construction; and (b) the **lack of a full real eval corpus**
  (9 attacks is too few — the fragment metric swings 0↔44% on noise, skewed to
  exactly that blind spot).

Confirmed follow-up levers (explicit-go): **body-aware features** and a **full,
diverse real eval corpus**. More scanners are diminishing returns. Still nothing
shipped; the lab's captured traffic and models are gitignored. See
`ml/attack_lab/README.md`.

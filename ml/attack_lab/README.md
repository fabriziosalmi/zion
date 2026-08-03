# ML-WAF attack-traffic lab

Generate a **real** training corpus for the WAF scorer by pointing real attack
tools at a local capture server and recording the requests they emit — instead
of hand-writing synthetic payloads. Fully local + defensive: the only target is
our own `127.0.0.1` loopback, the goal is training a defensive WAF model.

> All captured traffic + trained models are **gitignored** (`ml/corpus/`,
> `*.onnx`). This directory holds only the reproducible *method*.

## Pieces

| file | role |
|------|------|
| `capture_server.py` | 127.0.0.1 HTTP server that logs every request (method/uri/headers/**body**) to JSONL and answers 200 |
| `generate_traffic.py` | `--mode attack` replays SecLists payloads (LFI/cmdi/XSS) into varied shapes (query/path/header/**POST body**); `--mode benign` emits realistic traffic (incl. matched POST bodies) |
| `train_from_traffic.py` | featurizes the captured JSONL, trains the MLP, exports ONNX, and cross-source-evals on the CSIC sample |
| `features_body.py` | body-aware extension: the 16 URI+header features **+ 6 structural body features** → a 22-dim vector |
| `train_body.py` | A/B: trains 16-dim vs 22-dim on the same traffic, evals both on CSIC, + a **matched-cohort** isolation test (body is the only signal) |

## Reproduce

```bash
pip install -r ml/requirements.txt   # + requests

# 1. capture SQLi from a real tool (sqlmap) with WAF-evasion tampers
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap
CAPTURE_OUT=ml/corpus/traffic/attack.jsonl CAPTURE_LABEL=attack \
  python3 ml/attack_lab/capture_server.py &     # then run sqlmap at 127.0.0.1:9099
python3 /tmp/sqlmap/sqlmap.py -u "http://127.0.0.1:9099/i.php?id=1&cat=x" \
  --batch --level=4 --risk=2 --tamper=space2comment,charencode -p id,cat

# 2. add XSS (dalfox) + SecLists breadth, then benign
python3 ml/attack_lab/generate_traffic.py --mode attack --n 9000
python3 ml/attack_lab/generate_traffic.py --mode benign --n 40000   # server → benign.jsonl

# 3. train + cross-source eval
python3 ml/attack_lab/train_from_traffic.py
```

## Findings (2026-08-03) — honest

The escalation from synthetic → real tool-traffic, measured cross-source on a
real CSIC fragment (the only real data reachable in-sandbox):

| model | in-distribution AUC | real-CSIC attack detection |
|-------|:---:|:---:|
| **synthetic** (Zion's 276 signatures) | 0.9997 | **0/9 (0%)** |
| **tool-traffic** (sqlmap+tampers, dalfox, SecLists) | 0.9999 | strong on payload attacks; **noisy on the fragment** |

Two solid conclusions:

1. **Capturing real tool traffic works** — it produces a strong detector of
   payload-bearing attacks (SQLi/XSS/LFI/cmd), which the synthetic model utterly
   failed to transfer to real data.
2. **The remaining ceiling is not the traffic.** It is (a) the **URI+header
   feature set** — it does not see POST bodies or value-semantics, so *subtle
   parameter-tampering* (much of the CSIC "anomalous" fragment, which looks like
   ordinary e-commerce) is invisible by construction; and (b) the **absence of a
   proper real eval set** — a 9-attack fragment is too small to judge, and it is
   skewed toward exactly that blind spot (the cross-source number swings 0↔44%
   on 9 samples — noise).

Next real levers (each an explicit-go follow-up): **body-aware features**, and a
**full, diverse real eval corpus**. More scanners alone are diminishing returns.
Nothing here is shipped; see [ADR-0023](../../docs/adr/0023-ml-waf-training-pipeline.md).

## Body-aware features (2026-08-03) — proven in isolation, blocked on data

Follow-up lever #1, built and A/B-tested (`features_body.py` + `train_body.py`):
6 structural body features (length, byte-entropy, special/`%`/digit/unprintable
ratios) → a 22-dim extractor. Verdict:

| test | 16 (URI+header) | 22 (+body) |
|------|:---:|:---:|
| in-distribution AUC | 0.992 | 0.999 |
| CSIC anomalous detected | 0/9 | 0/9 |
| **matched cohort** (body is the *only* signal) | **AUC 0.49** (chance) | **AUC 0.93** |

The **matched cohort** is the decisive test: method+URI+headers held identical
across classes, only the body varies. There the 22-dim model separates attack from
benign (AUC 0.93) while the 16-dim model is at chance (0.49, body-blind by
construction) — so **the body features carry real signal**. Yet they add nothing on
captured/CSIC traffic, because those classes differ in a *non-body* dimension
(endpoint, then `Authorization`-header presence) the model shortcuts on, never
weighting the body. This is the **third instance** of the same root cause: the
ceiling is **data realism**, not features. Body features only contribute when
training data is structurally matched and differs in the payload — i.e. **real
production traffic self-labeled by the deployed rule engine**. The 22-dim extractor
is proven and ready to port to Rust *once such data exists*; the shipped scorer
stays 16-dim (no model ships regardless).

```bash
python3 ml/attack_lab/train_body.py   # runs the A/B + the matched-cohort isolation
```

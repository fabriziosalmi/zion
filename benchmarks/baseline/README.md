# Zion edge baseline — benchmark + RFC conformance

A reproducible harness that measures zion's data-path throughput/latency and
its HTTP/2 + TLS protocol conformance against independent external tools, then
renders a tracked PDF report. Used to establish the "minimum bar" for a release
and to catch regressions across versions on identical hardware.

## What it runs

| Dimension | Tool | What it checks |
|---|---|---|
| HTTP/2 conformance | [`h2spec`](https://github.com/summerwind/h2spec) | RFC 9113 / 7540 |
| TLS conformance | [`testssl.sh`](https://testssl.sh) | protocols, ciphers, FS, CVE probes |
| Throughput (cache hit) | `oha`, `h2load`, `wrk` | RAM cache-hit serve (H1/TLS, H2, H1) |
| Throughput (proxy) | `oha` | reverse-proxy passthrough (no cache) |
| Functional | `curl` | the v0.4.2 cache fix emits an `Age` header |

Lab topology: `client → zion (TLS :4432, min 1.2, memory cache) → Go bench-backend (:9090)`.
Config: [`zion-lab.toml`](zion-lab.toml). It mirrors the production edge profile
(TLS floor 1.2, memory cache, no WAF) so the verdicts are representative.

## Reproduce

```bash
# from repo root
bash benchmarks/baseline/run-baseline.sh
# → benchmarks/baseline/zion-<version>-baseline.pdf
```

Pinned parameters live at the top of `run-baseline.sh` (duration, connections,
h2load request/stream counts) and can be overridden via env vars, e.g.
`DURATION=30s CONNS=100 bash benchmarks/baseline/run-baseline.sh`.

The harness builds zion `--release`, generates self-signed lab certs, starts the
backend + zion, runs every test with captured raw output, and renders the PDF.
It tears the lab down on exit.

### Prerequisites

```bash
# macOS
brew install oha nghttp2 wrk testssl jq weasyprint
# h2spec (no brew formula): download a release binary into ~/http-tools/
#   https://github.com/summerwind/h2spec/releases
```

`go`, `cargo`, `openssl`, `python3` are also required. Tool versions are recorded
into the report — pin them there, not here.

## Rigor notes

- **Loopback numbers** measure server-side efficiency (no network RTT, self-signed
  TLS). They are an upper bound for the data path and a cross-version regression
  baseline — *not* a WAN figure.
- **Self-signed cert artifacts**: testssl flags chain-of-trust / revocation /
  overall-grade as HIGH/CRITICAL because the lab cert is self-signed. The report
  separates these from genuine crypto/protocol findings. The production edge
  serves a CA-issued cert.
- Every figure in the PDF is parsed from a raw tool output that is embedded
  verbatim in the report Appendix — nothing is hand-entered.

## Files

- `run-baseline.sh` — orchestrator (pinned params, env capture, run, render).
- `build-report.py` — parses `results/` → `report.html` (PDF via WeasyPrint CLI).
- `zion-lab.toml` — lab config (tracked).
- `zion-<version>-baseline.pdf` — the tracked deliverable.
- `results/` — raw tool outputs + intermediate `report.html` (gitignored; the
  PDF appendix already embeds the raw evidence).

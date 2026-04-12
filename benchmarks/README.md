# Benchmarks

## Active Scripts

| Script | Purpose | Duration |
|---|---|---|
| `bench-matrix.sh` | Payload × concurrency grid (36 cells). Main benchmark. | ~15 min |
| `bench-matrix.sh --quick` | Quick mode: 1 round × 3s per cell | ~2 min |
| `bench-scientific.sh` | Zion vs nginx (Docker, 5 runs, CI95) | ~20 min |
| `bench-profile.sh` | CPU flamegraph profiling via `samply` | ~3 min |

## Usage

```bash
# Full matrix (recommended for release validation)
bash benchmarks/bench-matrix.sh

# Quick smoke test
bash benchmarks/bench-matrix.sh --quick

# Docker comparison with nginx
bash benchmarks/bench-scientific.sh

# CPU profiling (requires samply)
bash benchmarks/bench-profile.sh
```

## Results

Results are saved to `results/matrix-history.json` with automatic delta comparison.

Live dashboard: `cd benchmarks && python3 -m http.server 8888` → `http://localhost:8888/dashboard.html`

## Configuration Files

| File | Description |
|---|---|
| `zion-bench-tls.toml` | TLS only (no WAF, no cache) |
| `zion-bench-tls-waf.toml` | TLS + WAF |
| `zion-bench-tls-cache.toml` | TLS + cache |
| `zion-bench-tls-waf-cache.toml` | TLS + WAF + cache (full stack) |
| `zion-docker.toml` | Docker container config |
| `zion-docker-waf.toml` | Docker + WAF |
| `zion-docker-full.toml` | Docker full stack |

## Archive

Superseded scripts are preserved in `archive/` for reference.

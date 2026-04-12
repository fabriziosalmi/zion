# Zion Configuration Profiles

Ready-to-use configuration templates. Copy one to `zion.toml` and adjust upstreams.

| Profile | File | Features |
|---|---|---|
| **Basic** | `basic.toml` | TLS proxy only — minimal, no WAF, no cache |
| **WAF Strict** | `waf-strict.toml` | TLS + strict WAF on API routes |
| **Full Stack** | `full-stack.toml` | TLS + WAF + cache + rate limiting + ACME + CSP |

## Usage

```bash
# Pick a profile
cp configs/full-stack.toml zion.toml

# Edit upstreams, domains, cert paths
vim zion.toml

# Run
ZION_CONFIG=zion.toml ./target/release/zion
```

For the complete reference with all options documented, see [zion.example.toml](../zion.example.toml).

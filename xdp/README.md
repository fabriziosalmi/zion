# Zion XDP Pre-Filter

Drops blacklisted source IPs at the NIC driver layer, before the kernel
network stack sees them.

## What is here

| Path                          | Purpose                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| `zion-xdp-prog/`              | The eBPF program (no_std, target `bpfel-unknown-none`)         |
| `zion-xdp-prog/src/main.rs`   | XDP entry point + LpmTrie lookup + stats                       |
| `build.sh`                    | Builds the eBPF object via nightly + `bpf-linker`              |

The userspace loader lives in **`src/xdp.rs`** of the main crate (gated on
`--features xdp`, Linux only).

## Maps

| Map name      | Type                | Purpose                                  |
| ------------- | ------------------- | ---------------------------------------- |
| `BLOCKED_V4`  | `LpmTrie<[u8;4],u32>` (max 65k entries) | CIDR-prefix blacklist; presence ⇒ drop  |
| `STATS`       | `Array<u64>` (size 2)                    | `[0]` = drops, `[1]` = passes            |

## Building

```bash
# Once:
rustup toolchain install nightly-2026-01-15
cargo install bpf-linker

# Each time the eBPF source changes:
./xdp/build.sh
```

The build artifact lands at:

```
xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog
```

## Loading

The userspace loader reads `ZION_XDP_OBJECT` (env) or the configured
path in `zion.toml`:

```toml
[xdp]
enabled    = true
interface  = "eth0"
object_path = "/usr/local/lib/zion/zion-xdp-prog.o"
```

Attaches in **driver mode** when supported, falling back to **SKB mode**
(generic XDP) automatically. SKB mode is a few-Mpps slower but works on
every Linux NIC including virtio inside an LXC container.

## Why a separate cargo project

eBPF requires a different target (`bpfel-unknown-none`), a different
toolchain (nightly with `-Z build-std=core`), and a different linker
(`bpf-linker`). Keeping the eBPF program out of zion's main workspace
means the standard `cargo build` of zion still works on macOS, Windows,
and Linux without any of those tools — the userspace loader is gated on
`--features xdp` and only compiled when explicitly requested.

## v0 scope

* IPv4 only.
* Single drop action (no rate-limit, no redirect).
* No fragmented-packet support (XDP_PASS for IP_MF/IP_OFFSET ≠ 0).

## v1 plan

* Parallel `BLOCKED_V6` LpmTrie keyed by `[u8; 16]`.
* Per-CPU rate-limit map (token bucket) → `XDP_DROP` only above threshold.
* `AF_XDP` socket attach for selective userspace handover.

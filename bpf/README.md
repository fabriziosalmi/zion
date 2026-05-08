# Zion BPF demux (issue #53)

`SK_REUSEPORT` eBPF program for the `:443` listener group. Lets a
fleet of Zion workers share a single TCP port and have userspace
control connection-to-worker routing — for NUMA affinity,
gossip-driven load shedding, or QUIC-vs-TCP partitioning logic. The
operator-facing rationale lives in the [issue spec](https://github.com/fabriziosalmi/zion/issues/53)
and in [docs/perf/roadmap.md](../docs/perf/roadmap.md).

## What is here

| Path                          | Purpose                                                                  |
| ----------------------------- | ------------------------------------------------------------------------ |
| `zion-bpf-demux/`             | The eBPF program (no_std, target `bpfel-unknown-none`)                   |
| `zion-bpf-demux/src/main.rs`  | `SK_REUSEPORT` entry point + `WORKERS` SOCKARRAY                         |
| `build.sh`                    | Builds the eBPF object via nightly + `bpf-linker` (mirrors `xdp/build.sh`) |

The userspace counterpart lives in **`src/bpf_demux.rs`** of the main
crate (gated on `--features bpf-demux`, Linux only). Today it ships
the kernel-version + capability probe and the structured boot log
line; the runtime loader that actually attaches the program to
listening sockets is **deferred** — see [Status](#status) below.

## Building

```bash
# Once:
rustup toolchain install nightly-2026-01-15
cargo install bpf-linker

# Per change:
bash bpf/build.sh
# → bpf/zion-bpf-demux/target/bpfel-unknown-none/release/zion-bpf-demux
```

The build script is **deliberately separate** from `cargo build`,
matching the `xdp/` precedent. `bpf-linker` + nightly + `build-std`
are not part of the regular dev toolchain; pulling them into every
`cargo build` would slow the inner loop without payoff for the
99 % of contributors who never touch the eBPF surface.

## Status

| Layer | Status | Tracking |
|-------|--------|----------|
| Feature gate `bpf-demux` | ✅ shipped (#95) | — |
| Kernel ≥ 5.7 + `CAP_BPF`/`CAP_SYS_ADMIN` probe + boot log | ✅ shipped (#95) | — |
| eBPF program source committed (`SK_PASS` body) | ✅ shipped (#95) | — |
| Build script `bpf/build.sh` | ✅ shipped (#95) | — |
| Integration test: TCP + QUIC coexist on `:443` | ✅ shipped — `t30_unified_port_*` in `tests/integration.rs` | — |
| Userspace loader: `Ebpf::load_file` + `setsockopt(SO_ATTACH_REUSEPORT_EBPF)` | ⛔ **deferred** | [#100](https://github.com/fabriziosalmi/zion/issues/100) |
| Multi-socket `SO_REUSEPORT` worker affinity | ⛔ deferred (v3) | [#100](https://github.com/fabriziosalmi/zion/issues/100) |
| Bench: no regression on TCP-only workload | ⛔ deferred (depends on loader) | [#100](https://github.com/fabriziosalmi/zion/issues/100) |

## Why the loader is deferred

The userspace half of this feature requires attaching a program of
type `BPF_PROG_TYPE_SK_REUSEPORT` to a listening socket via
`setsockopt(SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd)`. The
runtime crate we already depend on for XDP — [`aya`](https://github.com/aya-rs/aya)
— recognises the program type in its `bpf_prog_type` enum
([aya 0.13 `programs/info.rs`](https://github.com/aya-rs/aya/blob/main/aya/src/programs/info.rs))
**but does not yet ship a typed program handle** for it: the
`programs/` directory has `xdp.rs`, `sk_lookup.rs`, `sk_skb.rs`,
`sk_msg.rs`, … but no `sk_reuseport.rs`. Without the typed handle:

- We can `Ebpf::load_file` to parse the ELF, but
- `bpf.program_mut("zion_bpf_demux").try_into::<SkReuseport>()` does
  not compile (no such type), and
- `Program::load()` on the untyped handle would set the wrong
  `expected_attach_type`, so the kernel would reject the program at
  `bpf(BPF_PROG_LOAD)` time even before we got to the setsockopt.

Three viable paths to close the gap:

1. **Upstream contribution to aya** — add `programs::SkReuseport`
   alongside the existing `SkLookup` / `SkSkb` / `SkMsg` helpers.
   ~50 lines of Rust mirroring `sk_lookup.rs`. Track at the
   follow-up issue below.
2. **Switch to `libbpf-rs`** — has full SK_REUSEPORT support today.
   Adds a second BPF runtime to Zion's dependency closure (XDP path
   stays on aya) which we don't want.
3. **Hand-roll `bpf(BPF_PROG_LOAD)` + `setsockopt`** — pure-libc, no
   high-level BPF helpers. ~150 lines of unsafe FFI plus our own
   ELF section parsing. Doable but the surface is exactly what
   `aya` exists to encapsulate.

Path **(1)** is the rigorous choice and is tracked at
[#100](https://github.com/fabriziosalmi/zion/issues/100) so the work
flows through aya's review process rather than living as a
zion-private fork.

## Maps

| Map name   | Type                                | Purpose                                  |
| ---------- | ----------------------------------- | ---------------------------------------- |
| `WORKERS`  | `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` (max 256 entries) | Per-worker fd table populated by the userspace loader; the program returns an index into this table. |

In v1 the eBPF program body returns `SK_PASS` — falls through to the
kernel's default `SO_REUSEPORT` hash. The map is allocated but
unused; the program's value is being a *hook point* the v3 PR can
replace with real routing logic without re-attaching anything.

## References

- Issue: <https://github.com/fabriziosalmi/zion/issues/53>
- Cloudflare Pingora demux pattern (operator goal):
  <https://github.com/cloudflare/pingora>
- Linux kernel `SO_ATTACH_REUSEPORT_EBPF` documentation:
  <https://man7.org/linux/man-pages/man7/socket.7.html>
- aya program type info enum (no `SkReuseport` helper yet):
  <https://github.com/aya-rs/aya/blob/main/aya/src/programs/info.rs>

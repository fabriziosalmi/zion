# ADR-0009: IoUringStream — io_uring read/write data path (issue #51)

- **Status**: accepted
- **Date**: 2026-06-15
- **Tags**: io_uring, performance, async, unsafe, linux, v0.2

## Context

`src/uring.rs` uses io_uring today only for **multishot accept**; the
read/write half of every accepted connection still flows through tokio's
epoll-based `AsyncRead`/`AsyncWrite`. Issue #51 asks to move the rw path to
io_uring (vectored, behind the existing `io-uring-rw` feature) to cut
syscalls on large transfers. The rw data path was *deliberately deferred*
(`uring.rs:211` — "careful tokio-reactor integration, don't ship
half-baked"). This ADR is that careful design, produced before any unsafe
code and hardened by an adversarial review.

The connection stack is fixed by the existing code: an accepted socket →
`rustls` `TlsStream` → `hyper_util` `TokioIo` → `serve_connection_with_upgrades`
(`src/main.rs:1652-1730`). So the new stream must implement tokio
`AsyncRead + AsyncWrite + Unpin + Send + 'static` and slot **under** rustls
in place of the raw `TcpStream`.

**The core impedance mismatch.** io_uring is *completion-based*: the kernel
owns a buffer from SQE-submit until the CQE arrives. tokio's traits are
*poll-based* with a **borrowed** `ReadBuf`/`&[u8]` that hyper may drop or
reuse the instant `poll_read` returns `Pending`. You cannot hand a borrowed
buffer to the kernel: if the connection future is dropped while a `Recv` SQE
is in flight, the kernel writes into freed memory (use-after-free). The
buffer must be owned by something that outlives the SQE.

**tokio-uring is ruled out** (two independent fatal blockers, verified):
1. *Runtime incompatibility* — tokio-uring 0.5 is a `!Send`/`!Sync`
   thread-per-core current-thread runtime; zion runs one shared
   `multi_thread` runtime (`main.rs:721`) and moves each connection into a
   `Send`-bounded `tokio::spawn` (`main.rs:1635`). Its `start()`/`block_on`
   builds a nested current-thread runtime → panics "Cannot start a runtime
   from within a runtime" on a worker.
2. *No async traits* — the shipped `tokio_uring::net::TcpStream` implements
   only `AsRawFd`/`FromRawFd`, **not** `AsyncRead`/`AsyncWrite`
   (tokio-uring#188, open since 2022). Its owned-buffer `BufResult` API is
   borrow-incompatible by design.

So the only path that fits zion's stack is a hand-rolled stream over the
low-level `io-uring` crate (already a dep, 0.7.12) with a custom driver.

## Decision

Implement **Candidate A: a single shared io_uring driver thread + an
owned-buffer slab**, behind `io-uring-rw`, with a concrete-enum runtime
fallback. New module `src/uring_rw.rs`, gated
`cfg(all(target_os = "linux", feature = "io-uring-rw"))`.

### Shape

- **One dedicated driver thread** owns ONE `io_uring` (separate from the
  accept ring) and a `Slab<ConnState>` keyed by a `u32` slot. It is the
  *sole owner* of all ring state and all per-connection buffers. It parks in
  `submit_and_wait(1)` and, on each wake, drains the **entire** completion
  queue and the **entire** command channel before re-parking.
- **`IoUringStream`** (the `Send + Unpin + 'static` handle) holds only an
  `Arc<Shared>` + its slot id + a generation tag. All `!Send` ring state
  stays on the driver thread, so the handle slots cleanly under rustls and
  into `tokio::spawn`.
- **`ConnState`** (driver-owned): `read_buf`/`write_buf` (`Box<[u8]>`, 16 KiB
  default, tunable), read/write state enums, a `futures::task::AtomicWaker`
  per direction, fd, in-flight-op count, generation.

### Buffer ownership (the safety core)

The kernel **never** sees a caller-borrowed buffer.
- `poll_read`: driver submits `Recv` into the driver-owned `read_buf`; on
  completion the worker `memcpy`s the filled bytes into hyper's borrowed
  `ReadBuf` **after** the CQE is reaped, then re-arms `Recv`.
- `poll_write` / `poll_write_vectored`: gather the caller's slice(s) into the
  driver-owned `write_buf` (one `memcpy`), submit one `Send`.

This is the only `AsyncRead`/`AsyncWrite`-compatible shape over a completion
engine and satisfies the `io-uring` `push()` contract (params valid until the
matching CQE).

### Cancellation / Drop (non-blocking, UAF-proof by construction)

`IoUringStream::drop` sends `DriverCmd::Orphan(slot)` and returns immediately
— **never blocks** (blocking a worker is unsound; futures can be leaked). The
driver marks the slot `Orphaned`, best-effort `AsyncCancel`s in-flight ops,
and reclaims the slab entry **only when the slot's in-flight-op count hits 0**
(every CQE reaped). The slab keep-alive — not the cancel — is the safety net,
so UAF is impossible whether or not `AsyncCancel` lands. The fd is closed by
the driver after the final CQE.

### Waker integration

- **Completion → task:** each slot holds a `futures::task::AtomicWaker`;
  `poll_*` register-then-recheck before returning `Pending`; the driver
  writes the result with `Release` and calls `wake()`.
- **New-command → driver:** a permanently-armed `PollAdd(self_eventfd, POLLIN)`
  SQE; `cmd_tx.send()` is followed by an 8-byte `write(eventfd)` whose CQE
  breaks `submit_and_wait`. Drain-everything-each-wake + AtomicWaker's
  recheck close the lost-wakeup window.

### Fallback (two layers, both already scaffolded)

- *Compile-time:* all new code gated on `io-uring-rw`; on macOS / feature-off
  the binding at `main.rs:1652-1654` stays the plain `TcpStream`/`CorkStream`.
- *Runtime:* `enum RwStream { Uring(IoUringStream), Tcp(TcpStream) }`
  implementing `AsyncRead+AsyncWrite+Unpin+Send` by delegation (NOT
  `Box<dyn>` — the kTLS arms at `main.rs:1713-1725` are the template). Bind
  `Uring` only when `Platform.has_io_uring_rw_kernel` (`bootstrap.rs`,
  kernel ≥ 5.19); else `Tcp`.

### Resolutions baked in from the adversarial stress pass (must-haves, v1)

1. **`futures::task::AtomicWaker`**, not `tokio_util::sync::AtomicWaker`
   (the latter does not exist; tokio's is `pub(crate)`). Add `futures-util`
   as a direct dep gated under `io-uring-rw`. Pin with a signature test.
2. **`poll_write_vectored` is a first-class override** — rustls drives the
   inner IO vectored (tokio-rustls `write_vectored`, up to 64 `IoSlice`s);
   the default would write only the first slice and serialize every TLS
   flush, failing the <1% small-payload gate. Gather all slices into one
   `write_buf` + one `Send`; use a bounded write_buf high-water for
   backpressure, **not** strict per-`Send` serialization.
3. **Single-writer ownership protocol**, not a blanket `unsafe impl Send`
   over shared `ConnState`: the driver is the sole owner of buffers + state
   enum; the worker touches only the `AtomicWaker` and atomic state/result
   words (`Acquire` after the driver's `Release`), and reads `read_buf`
   **only** after the Recv CQE is reaped. Loom-test the state-transition
   ordering (increment 2 gate).
4. **Mandatory per-slot generation counter** in `user_data` from increment 1
   (`user_data = (slot:u32)<<32 | (gen:u16)<<16 | op_kind`). Stale CQE
   (gen mismatch) → decrement in-flight count to allow free, then discard.
   Prevents slot-reuse aliasing.
5. **Driver-thread death = `abort()` the process** (loud). Unlike the accept
   thread (which only loses accepts), a dead rw-driver while SQEs reference
   slab buffers is a memory-safety hazard, not a degraded-service one.
6. **No epoll+uring double-registration:** the accept path's
   `TcpStream::from_std` (`uring.rs:152`) registers the fd with tokio's
   epoll. The rw path must lift the raw fd (a from_std-free accept variant,
   or `into_std()` after `tune_accepted`) before handing it to the driver.
7. **Full-duplex is a first-class test:** HTTP/2 reads and writes are
   concurrent on one connection; a `Recv` re-arm must never be gated on a
   pending `Send`. Add a concurrent up+down stress test + a WebSocket echo.
8. **Bounded memory:** `active_conns × ~32 KiB` (16 KiB read + write).
   Reconcile with `conn_limit` / per-IP caps before flipping the seam on;
   expose held-buffer count on `/metrics` (the parked-Recv-on-Drop case can
   pin a buffer for the connection lifetime).

### Increments (ordered, each independently testable on the Linux box)

1. **Skeleton driver + echo** (no rustls/hyper): driver thread + slab +
   self-eventfd + cmd channel; `poll_read`/`poll_write`/`Drop` with the
   owned-buffer + AtomicWaker + Orphan model (`Recv`/`Send` only). Test:
   `socketpair` echo 1 MiB both ways via `tokio::io::copy`, byte-exact.
   Compiles cfg-stripped on macOS; `cargo test` green.
2. **EOF / error / reset / drop-with-inflight correctness** + Loom test of
   the state-transition ordering; ASan/Valgrind run on the box for the
   drop-with-inflight-Recv case (no UAF/double-free).
3. **`RwStream` enum + runtime gating** off `has_io_uring_rw_kernel`.
4. **Slot under rustls** (no hyper): real `tokio_rustls` accept over
   `RwStream::Uring` on loopback; handshake + plaintext round-trip.
5. **Wire the seam** at `main.rs:1652-1654` (fd lifted without
   double-registration); end-to-end HTTPS over io_uring rw (curl + small
   wrk). Full-duplex H2 + WebSocket stress.
6. **Write backpressure + re-arm tuning** (bounded high-water; slow-consumer
   test — no deadlock, bounded memory).
7. *(deferred, post-bench)* Fixed/registered buffers if the copy is the
   bottleneck.
8. *(deferred)* Sharding (candidate C) only if the single ring caps
   throughput on the e2e rig.

### Verification gate

Bench on the e2e rig (bare metal, not the nested-virt dev box): baseline
(no feature) vs candidate. **Pass = (a) measurable io_uring/read/write
syscall-count drop on 1 MiB & 10 MiB transfers, AND (b) <1% regression on
1 KiB req/s & p99.** If small-payload regresses >1% or no syscall drop
materializes, **do not wire the seam on by default** — keep it opt-in and
pursue increment 7 / candidate C first. The mandatory double `memcpy`
(kernel↔slab↔caller) on top of rustls's own copies is the central
unvalidated hypothesis of #51; the gate decides.

## Consequences

- **Pro:** a `Send+Unpin+'static` stream that fits zion's existing
  multi-thread + rustls + hyper stack untouched; reuses the proven
  dedicated-driver-thread pattern; correctness (UAF-proof buffers,
  lost-wakeup-proof wakeups) established by design + Loom/ASan before ship.
- **Con / risk:** real unsafe surface; the single driver ring is a potential
  throughput chokepoint (mitigation = deferred sharding); the extra copy may
  not pay off at rustls's small-record granularity — hence the hard bench
  gate before default-on.
- **kTLS (#52) composition:** `ktls` depends on `io-uring-rw` per Cargo.toml,
  but v1 keeps them **mutually exclusive per connection** (ktls takes the
  connection, io_uring rw is not used). Documented so the dependency edge
  isn't read as "they work together on one connection" yet.

## Alternatives considered

- **tokio-uring** — rejected (runtime `!Send` + nested-runtime panic; no
  `AsyncRead`/`AsyncWrite`, tokio-uring#188). See Context.
- **Sharded multi-ring (candidate C)** — the right end-state for scale, but a
  scale-out of A; deferred until the single-ring path is proven correct *and*
  beneficial on the rig (must not precede the perf validation that is the
  entire point of #51).

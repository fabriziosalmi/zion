# Profile-Guided Optimization (PGO) builds

Tracking issue: [#55](https://github.com/fabriziosalmi/zion/issues/55).
Scripts: [`scripts/pgo-build.sh`](../../scripts/pgo-build.sh) (the pipeline) and
[`scripts/pgo-train.sh`](../../scripts/pgo-train.sh) (the training workload).
Workflows: [`release.yml`](../../.github/workflows/release.yml) builds the artefact,
[`pgo.yml`](../../.github/workflows/pgo.yml) runs the same pipeline on pull requests that touch it.

## What ships

For every release tag the Linux x86_64 glibc target is built twice:

* `zion-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`: the plain build, the default download.
* `zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.tar.gz`: the same source, toolchain and
  flags, compiled with a profile of zion serving traffic.
* `zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.profdata`: that profile, so the PGO
  binary can be built again (see [Rebuilding](#rebuilding-the-pgo-binary-of-a-release)).

Each has its line in `SHA256SUMS` and its own SLSA build provenance. The profile is the
only difference between the two binaries: both are linked by cargo-zigbuild against the
same glibc floor (2.28) and both are compiled for baseline x86-64
([which processors a build runs on](/deploy/#which-processors-a-build-runs-on)), and the
release runs both under an emulated baseline processor before it signs them. The other
targets (musl, aarch64, macOS, Windows) and the container image have no PGO build.

Up to v0.12.0 the `-pgo` artefact differed from the plain one in two more ways, neither
intended. It was compiled for baseline x86-64 while the plain one was `x86-64-v3`,
because the profile flags were passed in `RUSTFLAGS` and Cargo drops the rustflags of
`.cargo/config.toml` when that variable is set. (The plain build has since dropped that
flag too, for its own reasons.) And it was linked natively on the build runner, so it
needed glibc 2.38 and did not start on Debian 12, Ubuntu 22.04 or RHEL 9, where the
plain artefact does.

## What it is worth

Measured on the v0.12.0 tree, one server core, CPU time per request (the server's
user + system time divided by the requests it answered), five trials of 8 s per
scenario, the builds interleaved trial by trial, twice (2026-10-09). Difference from the
plain build of that tree, which was compiled for `x86-64-v3`. What ships from this
release on is the second column for the PGO binary and the third for the plain one:

| scenario | profile | profile, without `x86-64-v3` | `x86-64-v3` removed, no profile |
|---|---|---|---|
| cached 5 KB document, HTTP/1.1 | −33.0 % / −32.8 % | −31.6 % / −29.4 % | −1.3 % / +3.6 % |
| the same, access log on | −27.1 % / −27.7 % | −28.5 % / −27.8 % | +1.7 % / +3.3 % |
| the same over HTTP/2 | −17.0 % / −17.2 % | −16.6 % / −16.7 % | +1.1 % / +0.7 % |
| the same at 1024 connections | −21.2 % / −22.0 % | −19.5 % / −21.2 % | 0.0 % / −1.3 % |
| the same at a fixed 15k req/s | −19.4 % / −21.0 % | −18.6 % / −20.6 % | +1.1 % / −0.8 % |
| proxied, no cache | −24.4 % / −22.7 % | −23.5 % / −21.9 % | −0.3 % / +1.8 % |
| the example site, mixed paths | −11.6 % / −12.4 % | −11.3 % / −11.1 % | +0.3 % / +0.7 % |
| the same, access log on | −13.5 % / −12.0 % | −12.8 % / −12.4 % | −0.4 % / +0.6 % |
| files from disk (`static` mode) | −8.8 % / −9.2 % | −9.2 % / −9.4 % | −1.0 % / −0.8 % |
| full TLS handshake per request | −4.4 % / −4.5 % | −4.2 % / −4.5 % | +0.2 % / +0.2 % |
| cached 200 KB image | −4.5 % / −4.4 % | −3.0 % / −4.1 % | +0.5 % / −0.6 % |
| 10 MiB download | −1.4 % / −1.2 % | −1.5 % / −0.8 % | −0.6 % / −0.4 % |

Two numbers per cell: the two runs. With the profile every trial of every scenario was
on the same side of zero, and no scenario got worse. The gain is largest where the
request is all zion's own code (a cache hit) and smallest where the time is in the
kernel or in the TLS library's hand-written assembly (a handshake, a large body), which
no profile of the Rust code reaches.

The second and third columns are there because the two effects were mixed up until
v0.12.0: the `target-cpu` alone moves these workloads by a point or two at most, in
either direction, which is one reason it is no longer set.

Those are native builds. The two binaries built the way the release then built them
(cargo-zigbuild, the 2.28 glibc floor, both `x86-64-v3`) compare the same, in two more
runs: −34 % and
−33 % on the cached document, −18 % and −18 % over HTTP/2, −24 % and −25 % proxied,
−13 % and −13 % on the site mix, −8.5 % and −9.1 % for files from disk, −4.0 % and
−3.9 % for a full handshake.

The host was a shared one and the harness's canary (a fixed SHA-256 loop on the server's
core) drifted by 9.4 % and 3.6 % over the two runs of the table, and by 5 % and 24 % over
the two of the release-style builds: all above its 3 % tolerance. Interleaving the builds
puts that drift on all of them alike, and the five runs of that day agree within two
points; still, read the table as "about a third on a cache hit, about a tenth on a real
mix", not to the decimal.

## How the build works

`scripts/pgo-build.sh` does all of it:

1. **Instrumented build.** `-Cprofile-generate`, in its own target directory, with the
   same build command as the optimised build. Only its link goes to the system linker
   (`PGO_GENERATE_LINKER=cc`): the binary runs only on the build machine, and zig's
   linker driver does not take the `-u __llvm_profile_runtime` that rustc passes for an
   instrumented link.
2. **Training.** `scripts/pgo-train.sh` drives the instrumented binary; each zion
   instance writes a `.profraw` as it exits.
3. **Merge.** rustc's own `llvm-profdata` (the `llvm-tools` component), whose raw
   format is the one this rustc writes.
4. **Optimised build.** `-Cprofile-use`, with the command and the target of the plain
   artefact (`cargo zigbuild --target x86_64-unknown-linux-gnu` in the release).

The profile flags go in `CARGO_TARGET_<TRIPLE>_RUSTFLAGS`, never in `RUSTFLAGS`. Cargo
joins the per-target variable with the rustflags of `.cargo/config.toml` and replaces
them when `RUSTFLAGS` is set; the script refuses to run with `RUSTFLAGS` set.

The optimised build reads the profile from
`/tmp/zion-pgo/<sha256 of the profile>.profdata` (`PGO_PROFILE_STORE` names another
directory), not from the work directory. The path is on every rustc command line, Cargo
hashes the command line into the file names of what it builds, and the order of code in
the binary follows those names: one profile read from two paths gave two binaries of
the same size that differ in 7,015 bytes, read from one path two identical ones. Cargo
also does not look inside the file, so a new profile at an old path would leave every
dependency "fresh", compiled with the old one. A path made of the profile's hash is the
same wherever that profile is used and another one for another profile. Tried: two work
directories gave the same binary; another profile on the same target directory
recompiled every crate of the target; the first profile again reused them and gave the
first binary.

Both builds must be made by the same cargo command. A profile names functions by their
mangled names, which contain a hash of the crate's identity, and that identity depends
on cargo's configuration: `cargo zigbuild` runs cargo with `target-applies-to-host =
false`, and an instrumented binary built with plain `cargo build` then names its
functions differently. The optimised build still succeeds, with most of the profile
matching nothing (5,024 functions without profile data instead of 814 when this was
tried); the script compares the two identities and stops.

### The training

Request counts, not durations, so a slow runner trains the same profile as a fast one.
Two zion instances: the access log on with an ECDSA certificate, then off with an RSA
one. Between them: cache hits and proxied requests over HTTP/1.1 and HTTP/2, files from
disk (whole, `304`, `Range`), full TLS handshakes, POST bodies through the WAF and past
it, requests the WAF refuses, large bodies, upstream errors and a dead upstream, health
and metrics. About 1.2 million requests, a minute and a half on four cores.

It executes about 2,590 of the roughly 19,900 Rust functions in the binary; the
three-endpoint workload it replaced executed 2,312 (none of the HTTP/2 stack, among
others), and its profile gave −3 % on the HTTP/2 scenario where this one gives −17 %.
Two trainings ten hours apart produced profiles whose edge counts overlap by 98.6 %
(`llvm-profdata overlap`).

The profile optimises the Rust code only. In the release's instrumented build the `cc`
crate passes the profile flag on to zig's C compiler, so the allocator and the TLS
library's C code are instrumented as well and the profile lists some 650 more functions
(3,242 executed in all); but that compiler is an older LLVM than rustc's and cannot read
the merged profile, the `cc` crate then leaves the flag out, and the C code of the PGO
binary is compiled exactly as in the plain one.

The workflows run it with the loopback interface at a network's MTU (1500 instead of
65536). On GitHub's runners a connection that receives megabytes a second over the 64 KB
loopback now and then crawls for minutes: the receiving socket's buffer ends up smaller
than one segment, the segments are dropped and the sender retransmits on its timer. It
happened in 10 runs of 58 of the "files over HTTP/2" phase, in 19 of 166 with nginx
serving the same files, and in none of 250 with the loopback at 1500; on another
machine with the same kernel series it did not happen in 188. The profile does not
depend on it (the same functions executed, 99.8 % of the edge counts in common). The
script gives each phase five minutes and, when one runs out, prints both ends' sockets
before failing, so this is recognisable if it happens to you.

### What makes it fail

A PGO binary that is silently not what it claims is worse than none, so the build stops
when:

* a training phase does not complete its requests, or gets errors where it expects
  none;
* the training executed fewer functions than `PGO_MIN_FUNCTIONS`;
* the optimised build reports a stale profile (a hash mismatch: the profile is of
  another source or compiler), or more functions without profile data than
  `PGO_MAX_MISSING`;
* the instrumented and the optimised build disagree on the zion crate's identity;
* the zion crate was not compiled with the profile;
* the binary needs a newer glibc than the plain artefact (`PGO_MAX_GLIBC`);
* the file the compiler reads is not the profile its name says, before or after the
  build;
* the optimised binary does not get through the training workload itself (the same
  1.2 million requests, each phase checked);
* with `PGO_TEST=1`, the test suite compiled with the same profile does not pass.

The release sets all of them but the last. `pgo.yml` sets all of them, on every pull
request that touches the scripts, the workflows, the training backend,
`.cargo/config.toml` or the toolchain pin, then builds a second time from the profile
alone and compares the binaries. Both workflows then run
`scripts/cpu-baseline-smoke.sh` on the binary, as the release does on every binary: it
must declare the compiler's defaults for its target and serve under an emulated
processor that has SSE2 and nothing later.

## Rebuilding the PGO binary of a release

The training is not bit-for-bit repeatable (the counts depend on timing), so the PGO
binary cannot be rebuilt from the source alone: the profile is an input, and it is
published for that. With the release's commit, toolchain (`release.yml` pins Rust, zig
and cargo-zigbuild) and commit time:

```bash
git checkout vX.Y.Z
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
export ZION_GIT_SHA=$(git rev-parse --short=12 HEAD)
export ZION_COMMIT_DATE=$(git show -s --format=%cd --date=format:%Y-%m-%d HEAD)
PGO_PROFDATA=zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.profdata \
PGO_TARGET=x86_64-unknown-linux-gnu PGO_CARGO="cargo zigbuild" \
  bash scripts/pgo-build.sh
strip target/x86_64-unknown-linux-gnu/release/zion
sha256sum target/x86_64-unknown-linux-gnu/release/zion
```

`SOURCE_DATE_EPOCH` matters here as it does for the plain build: the allocator's C code
embeds its compile time, and without it two builds differ in those bytes. The script
puts the profile where the release's build read it (the path depends on the profile's
content only), so nothing has to be said about that.

## Building one yourself

```bash
rustup component add llvm-tools
bash scripts/pgo-build.sh        # needs h2load (nghttp2-client), curl, openssl, python3, go
```

The binary is `target/<host triple>/release/zion`, the profile `target/pgo/zion.profdata`.
`benchmarks/bench-pgo.sh` is the same command.

## Verification

```bash
gh attestation verify zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.tar.gz --owner fabriziosalmi
gh attestation verify zion-vX.Y.Z-x86_64-unknown-linux-gnu-pgo.profdata --owner fabriziosalmi
```

## Not done

* **PGO as the default download, and in the image.** The image is built from source
  inside the Dockerfile, so it would need the profile handed to that build; and a
  profile made on x86_64 does not apply to arm64.
* **musl, aarch64.** musl can run its instrumented binary on the runner; aarch64 needs
  an arm64 runner for the training.
* **BOLT** (post-link optimisation), downstream of PGO.

## References

* Rust PGO guide: <https://doc.rust-lang.org/rustc/profile-guided-optimization.html>
* `llvm-profdata`: <https://llvm.org/docs/CommandGuide/llvm-profdata.html>
* Cargo, the sources of rustflags: <https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags>

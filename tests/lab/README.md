# CVE lab (#699)

Real stacks behind a real zion, one request-shape probe per CVE. Not a mock, not an exploit
framework: each probe sends the *shape* of a public vector (the header, cookie, path or body
that the advisory describes), never a weaponized payload, and compares four real observations.

## Run it

```
cargo build --release --bin zion
python3 tests/lab/run.py nextjs --zion-bin target/release/zion
```

Needs Docker and Docker Compose (`--no-compose` skips them when the stack's variants are
already running on the ports named in its `stack.toml`, e.g. for iterating on probes without
rebuilding images). Results land in `tests/lab/results/<stack>.json` (gitignored: they are a
dated, per-machine measurement, not something to commit).

Python 3.11+ (stdlib only, `tomllib`). `tests/lab/test_run.py --zion-bin ...` tests the runner
itself against a bare synthetic stack (`tests/lab/fake_upstream.py`, `stacks/synthetic/`) — no
Docker, no real CVE, just a controllable fixture to prove `judge()` and `run_stack()` report
`covered`, `inconclusive` and `bypass` correctly.

## What a probe proves

For each `[[probe]]` in `stacks/<name>/probes.toml`, four observations:

| observation | request | target | the oracle must say |
|---|---|---|---|
| `baseline` | the probe's `request`, with its vector fields overridden by `[probe.baseline]` | the vulnerable variant | not vulnerable |
| `vulnerable` | the probe's `request`, unchanged | the vulnerable variant | vulnerable |
| `fixed` | the probe's `request`, unchanged | the patched variant | not vulnerable |
| `zion` | the probe's `request`, unchanged | zion in front of the vulnerable variant | not vulnerable |

- **`covered`**: all four came out as expected. The vector works on the vulnerable version,
  not on the patched one, and zion neutralizes it.
- **`bypass`**: the vector works *through zion*. This is the one that fails the run.
- **`inconclusive`**: something about the first three observations doesn't support the claim
  (the baseline already looks vulnerable, the vector doesn't work on the vulnerable variant,
  or it also works on the patched one). Such a probe proves nothing either way and is not
  counted as coverage — it does not fail the run by default (`--strict` makes it do so).
- **`error`**: a connection to one of the four targets failed outright.

`[probe.baseline]` is **mandatory**. There is no generic way for the runner to know which part
of a request *is* the vector (a header, a cookie, a path segment, a body field) — only the
probe's author does. An early version of this runner silently fell back to "baseline = the
unchanged request" when none was given, which can turn a real bypass into a false
`inconclusive` (the bypass's own probe here caught this, by exercising a config where the
defense is genuinely absent and asserting `bypass`, not something softer).

`mechanism_verified = true` on a probe is a claim a human made after a break-test (temporarily
remove the specific defense named in `mechanism` and watch the probe flip from `covered` to
`bypass`), not something this runner can infer — `covered` only says *something* in the path
stopped the vector, not that it was the named mechanism. Leave it `false` (the default) until
you've done that.

## `[[benign]]`: the false-positive check

A normal step of using the stack (log in, read a protected page, post a form), run both
straight to the stack and through zion. `ok` only if both match `[benign.expect]`.
`false_positive` (direct worked, zion didn't) and `broken_step` (direct itself didn't match,
so the fixture or the expectation is wrong) both fail the run; so does `error` (a connection
failed outright — a mislabeled `false_positive` or `broken_step` would be dishonest).

## Adding a stack

```
stacks/<name>/
  stack.toml   # variants (vulnerable/fixed), each an "http://host:port" upstream
  probes.toml  # [[probe]] (the CVE) and [[benign]] (the false-positive session)
  compose.yml  # real containers for the variants (omit if using --no-compose only)
```

`stack.toml`'s `[[variant]]` can carry `service` (its compose service name, to read the image
digest and run `version_cmd` inside it) — informational, written into the result JSON, never
assumed from a Dockerfile `ARG`.

`stack.toml`'s optional `[zion] server_extra` is spliced into the `[server]` table of the zion
this runner stands up (e.g. to turn on `strip_headers`, or a whole new top-level table like
`[virtual_patch]`, since TOML table headers start a new table wherever they appear in the file).
`{stack_dir}` inside it expands to the stack's own absolute directory, so a rule referenced from
there (a virtual-patch `rules_file`, #698) can live right beside `stack.toml` without a
checkout-specific absolute path baked into the committed file — zion itself resolves a *relative*
`rules_file` against `zion.toml`'s own directory, a throwaway tmpdir this runner invents per run,
not the stack's.

Read the advisory before writing a probe. [GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
(the `nextjs` stack's CVE-2025-29927) is a case in point: the first version of that probe used
`X-Middleware-Subrequest: middleware` and came back `inconclusive` — the real vector repeats
the middleware's path segment up to `MAX_RECURSION_DEPTH` (5) times, colon-separated, confirmed
against a cited write-up before the probe was corrected. An `inconclusive` result from this
runner is doing its job when that happens; it is not something to silence by loosening the
oracle.

## Where this runs

Not on pull requests. Several stacks built and running at once, even one at a time, do not fit
a small CI runner's memory; `ci-zion` (the registered test host) is sized for the regular CI
matrix, not for this. Intended to run manually or from a nightly cron on that host, with
results reviewed (and, if useful, committed) through a PR — not pushed automatically. Setting
up that cron is a separate decision.

Part of the *Real-stack CVE hardening* milestone, together with #700 (a generated coverage
matrix and config presets, built from these JSON results).

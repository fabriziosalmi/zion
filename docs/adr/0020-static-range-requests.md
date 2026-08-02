# ADR-0020: Static file range requests (206 Partial Content)

- **Status**: accepted
- **Date**: 2026-08-02
- **Deciders**: fabriziosalmi
- **Tags**: static, http, rfc-9110, standards

## Context

The second of the ADR-0015 runtime follow-ups (after ADR-0019 conditional GET).
`mode = "static"` served every request whole, with no `Accept-Ranges` — so a
video seek, an audio scrub, or a resumed download re-fetched the entire file.
Range support is table stakes for the media/download assets these routes serve,
and it reuses the request-header plumbing ADR-0019 added.

## Decision

### One range, byte units, `Accept-Ranges: bytes` advertised

Every full 200 (and HEAD) now carries `Accept-Ranges: bytes`. A `Range: bytes=…`
is parsed into three outcomes:

- **satisfiable** single range → `206 Partial Content` with
  `Content-Range: bytes start-end/total` and the sliced body;
- **unsatisfiable** (start past EOF, reversed after clamping, `-0`) →
  `416 Range Not Satisfiable` with the authoritative `Content-Range: bytes */total`;
- **anything else** — no `Range`, an unknown unit, a **multi-range** set, or a
  malformed spec — is ignored and served as the full 200 (RFC 9110 §14.2 permits
  ignoring a Range). Open-ended (`N-`) and suffix (`-N`) forms are supported;
  multipart/byteranges is a deliberate follow-up, not a silent gap.

### The slice is read with seek + bounded buffer, under the same memory cap

A ranged GET opens the file, `seek`s to `start`, and reads exactly `end-start+1`
bytes — it does **not** read the whole file. This is both correct and a real win:
a large file that a full 200 refuses (>64 MiB, the ADR-0015 cap) can now be read
in bounded chunks via ranges. The **same** `MAX_FILE_BYTES` guard applies to the
*slice*: a single range larger than the cap is refused with 413 until streaming
(the next follow-up) lands, so the memory-amplification guarantee is unchanged.

### `If-Range` never honors our weak ETag

`If-Range` gates a resumed transfer: serve a 206 only if the representation is
unchanged, else the full 200. RFC 9110 §13.1.5 requires a **strong** comparison
for an entity-tag, and our validator is a *weak* ETag (ADR-0019) — so an
`If-Range` carrying any entity-tag always declines to a full 200 (never a 206
stitched onto a client's stale prefix). An `If-Range` carrying an HTTP-date
honors the range only on an exact `Last-Modified` match. This is the conservative,
correct default; a strong content-hash ETag (which *could* satisfy `If-Range`) is
out of scope.

### Precedence

Conditional evaluation runs first (RFC 9110 §13.2.1): a matching `If-None-Match` /
`If-Modified-Since` returns 304 and the `Range` is ignored. Only a would-be-200 is
subject to Range.

## Consequences

- **Positive**: media seeking, resumable downloads, and chunked large-file reads
  work; asset parity with nginx/Caddy improves. Ranged reads of files above the
  64 MiB whole-file cap now succeed in bounded slices.
- **Neutral / risks**: a single range above the cap still 413s (lifted by
  streaming). Multi-range (`multipart/byteranges`) is unsupported and degrades to
  a full 200 rather than erroring — safe, but not the minimal transfer a
  multi-range-aware client asked for.

## Alternatives considered

- **Multipart/byteranges now** — rejected for this PR: the `multipart/byteranges`
  boundary encoding is real surface for a rare client pattern; single-range covers
  the media/download cases. Degrading multi-range to a full 200 is spec-legal.
- **Stream the slice instead of buffering** — that *is* the next follow-up
  (streaming); doing it here would merge two changes. Bounded-buffer under the
  existing cap keeps this PR one idea.
- **Honor `If-Range` against the weak ETag** — rejected: it violates the strong
  comparison RFC 9110 §13.1.5 mandates and risks stitching mismatched bytes.

## References

- ADR-0015 (`mode = "static"`), ADR-0019 (conditional GET + the weak ETag this
  builds on)
- RFC 9110 §14 (Range requests), §14.4 (416), §13.1.5 (If-Range), §13.2.1
  (precedence)
- `src/static_files.rs` (`parse_range`, `if_range_allows`, `read_range`,
  `partial_response`, `range_not_satisfiable`)

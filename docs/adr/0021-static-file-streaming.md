# ADR-0021: Streaming large static files (lift the 64 MiB read cap)

- **Status**: accepted
- **Date**: 2026-08-02
- **Deciders**: fabriziosalmi
- **Tags**: static, streaming, memory, performance

## Context

The third and last of the ADR-0015 runtime follow-ups (after ADR-0019
conditional GET and ADR-0020 range requests). `mode = "static"` read the whole
representation — a full file, or a range slice — into one `Bytes` before
responding, guarded by a hard `MAX_FILE_BYTES = 64 MiB` cap: past it the server
returned `413 Payload Too Large`. So a legitimate large asset (a video, an
install image, a dataset) was simply un-servable, and a 60 MiB file still sat in
memory whole under every concurrent request.

## Decision

### Buffer below the threshold, stream above it

The 64 MiB constant is repurposed from a *hard limit* into a *buffer-vs-stream
threshold*. At or below it, the body is read into one `Bytes` and served as a
`Full` body — the low-latency common case (CSS, JS, images), byte-for-byte the
prior behavior. Above it, the body is **streamed** frame-by-frame, so an
arbitrarily large file is served with bounded memory instead of a 413. This
keeps the small-file fast path untouched while the change is confined to what was
previously the error path.

### The stream is a read task feeding a bounded channel

`stream_file(file, limit)` spawns a task that reads the file in `STREAM_CHUNK`
(64 KiB) reads and sends each as a `Frame` over an mpsc channel of depth
`STREAM_CHANNEL_CAP` (8); the response body drains the channel. In-flight memory
is therefore bounded to ≈ `64 KiB × 9 ≈ 576 KiB` per request regardless of file
size, and channel backpressure keeps the reader only slightly ahead of the
socket. This reuses the exact `StreamBody` + `ReceiverStream` idiom already in
the HTTP/3 bridge — no new dependency (`tokio-stream` is already direct).

The same helper serves ranged reads: after `seek(start)` the range path streams
`Some(len)` bytes, so a single range **larger** than the cap now streams too
(the range PR ADR-0020 previously 413'd it).

### `Content-Length` is preserved; a read fault truncates

The size is known from `stat`, so streamed responses still send an exact
`Content-Length` (not chunked-unknown) and emit precisely that many bytes. A
mid-stream read error drops the channel sender, ending the body early — the same
**truncate-on-error** contract the proxy path already has. The file was just
`stat`ed and opened, so a fault here is a rare disk error rather than a routine
branch; the client observes a short read (its own `Content-Length` check catches
it), not a hang.

## Consequences

- **Positive**: large static assets are servable; memory per request is bounded
  and constant instead of O(file size); the 413 wall is gone for full *and*
  ranged reads. Small files keep the one-shot low-latency path.
- **Neutral / risks**: streaming spawns a task + channel per large response —
  negligible next to the I/O, and only on the large-file path. Truncate-on-error
  means a disk fault yields a short 200/206 rather than an error status (the body
  is already committed by the time bytes flow); this matches the proxy and is
  caught by the client's `Content-Length`. A same-size-preserving mid-flight
  overwrite could interleave old/new bytes (a pre-existing static-serving TOCTOU,
  not introduced here).

## Alternatives considered

- **Always stream** — rejected: a task + channel on every tiny CSS/JS response is
  needless overhead where a one-shot read wins on latency. The threshold gives
  each regime its best path.
- **`tokio_util::io::ReaderStream`** — rejected: `tokio-util` is not a direct
  dependency, while `tokio-stream` (used by the H3 bridge) is. The channel form
  reuses an idiom already in the tree and keeps the dependency set flat.
- **Raise the cap instead of streaming** — rejected: it just moves the wall and
  makes the per-request memory blow-up larger, the opposite of the goal.

## References

- ADR-0015 (`mode = "static"` and its 64 MiB cap), ADR-0020 (range reads that
  now stream above the cap too)
- `src/static_files.rs` (`stream_file`, `full_body`, `read_file`, `read_range`),
  `src/quic.rs` (the `StreamBody` + `ReceiverStream` idiom reused)

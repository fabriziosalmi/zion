# HTTP/2 control frames, measured on real clients

`[server] h2_control_frames_per_sec` (#475) closes a connection that sends more control
frames in a second than a real client does. Whether it can be **on by default** (#561) depends
on what real clients send, so this rig measures it: it runs a backend (a web page of 120 small
resources, a 300 MiB download, and a gRPC service, all over TLS and HTTP/2), starts a **fresh**
zion per scenario (`zion_h2_control_frames_peak` is the most since start), and prints the peak.

```bash
ZION=target/release/zion benchmarks/h2-control/rig.sh grpc      # grpc-go, four shapes
ZION=target/release/zion benchmarks/h2-control/rig.sh browser   # you drive a browser, it reads the peak
```

Needs `go` (1.25 or the toolchain it downloads), `openssl`, `curl`. What counts as a control
frame is in [Hardening](../../docs/security/hardening.md#http-2-control-frame-floods): `PING`,
`SETTINGS`, `PRIORITY`, `GOAWAY`, unknown types, an empty `DATA` that does not end its stream;
`WINDOW_UPDATE` and `RST_STREAM` are bounded separately.

## Results

zion 0.9.15 (Linux: with the #618 fix; macOS: master), one connection, peak control frames in one second.

**grpc-go 1.84** (a `PING` per received batch of data, for bandwidth estimation, so the rate
follows the round-trip time). Linux, `ci-zion` (4 cores), RTT added on the loopback with
`tc qdisc add dev lo root netem delay <D>` (the client-to-zion round trip is 2 x D):

| Client-to-zion RTT | 500 MiB download (one stream) | 100 MiB in 16 KiB messages | 20,000 unary calls, 8 callers | 5,000 round trips on one bidirectional stream |
|---|---|---|---|---|
| none (loopback) | 726 | 301 | 2,019 | 5,003 |
| 0.2 ms | 712 | 236 | 1,411 | 1,700 |
| 1 ms | 412 | 151 | 616 | 380 |
| 5 ms | 169 | 92 | 166 | 90 |

On macOS loopback, 1 GiB in one stream peaked at 2,800 to 3,200, unary calls at 7,200 to 7,900,
and the bidirectional stream at 17,200 (20,000 round trips). The peak is the `PING`s: in the unary
run, about 7,500 `PING` and as many acks in the second, and `WINDOW_UPDATE`s in the same number
(not counted). Measured with a temporary per-type counter in `h2_guard.rs`; it is not kept.

**grpc-core** (Python `grpcio` 1.80, the engine behind the Python, Ruby, C#, PHP clients), macOS
loopback: 1 GiB download **13**, 20,000 unary calls **6**, 20,000 round trips on a stream **6**.

Browsers and tools, from the earlier measurements in the hardening guide: curl, nghttp, h2load and
Chrome send 2 to 3. **Firefox and Safari: not measured yet.** Run `rig.sh browser` in each.

## What it says

- A default of `1000` would close busy **grpc-go** connections inside a data centre (RTT of a
  fraction of a millisecond). Other gRPC stacks and every browser measured so far stay far below it.
- For gRPC through zion, a limit has to be well above `20000` to leave grpc-go alone on a very
  fast link, or left at `0`.

## Found on the way

Unary gRPC calls through zion on Linux made 190 calls a second against 14,000 direct: the pooled
upstream sockets had no `TCP_NODELAY` (#618). The rig now measures the fixed binary; the table above
was taken with the fix.

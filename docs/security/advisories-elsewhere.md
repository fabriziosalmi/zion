# Advisories in other proxies

When a serious vulnerability is published for another reverse proxy, the first question is whether
zion shares it. This page answers that for each one, with what was checked and how, so the answer
can be verified rather than taken on trust. A "not affected" here is about zion's own code and
dependencies at the commit named; it is not a claim that zion is free of bugs.

## nginx2root (CVE-2026-123007 and four more), November 2026

On 18 November 2026 F5 disclosed five memory-safety flaws in nginx, fixed in nginx 1.30.7 (stable)
and 1.31.9 (mainline). The lead one, CVE-2026-123007, is an integer underflow in HTTP/2 flow
control that lets an unauthenticated client run code as an nginx worker; public proof-of-concept
code exists.

**zion is not affected.** zion contains no nginx code. Checked on master at `8bd0982`:

| CVE | Where in nginx | What would have to exist in zion | In zion |
|---|---|---|---|
| CVE-2026-123007 | HTTP/2 flow control, integer underflow | nginx's HTTP/2 implementation | HTTP/2 is `hyper` 1.12 with `h2` 0.4.16, in Rust. No RustSec advisory against either (`cargo audit`, database of 19 November 2026). zion's own HTTP/2 frame guard (`h2_guard`) is safe Rust. |
| CVE-2026-123633 | HTTP/2, use-after-free | nginx's HTTP/2 implementation | As above. zion parses requests in safe Rust; its few `unsafe` blocks are socket options and platform system calls, none of which reads request data. |
| CVE-2026-121810 | HTTP/3 to an upstream, use-after-free | nginx's QUIC implementation | HTTP/3 (`--features http3`) is `h3` 0.0.8 with `quinn` 0.11, in Rust; request header sections are bounded at 16 KiB. |
| CVE-2026-123634 | DNS resolver, use-after-free | a `proxy_pass` target taken from the request, with `mirror` | The upstream host always comes from the configuration, never from the request, and zion has no request mirroring. |
| CVE-2026-113425 | mail proxy with `auth_http` | a mail proxy | zion has none. |

The container image (`distroless/cc-debian12`) and the Helm chart contain no nginx.

### If you run nginx

Upgrade to nginx 1.30.7 or 1.31.9; the [nginx security advisories](https://nginx.org/en/security_advisories.html)
list every affected version. Turning HTTP/2 off is a stopgap for the two HTTP/2 flaws only.

If zion sits in front of nginx, it terminates the client's HTTP/2 and opens its own connections to
the upstream, so the frames nginx receives come from zion's HTTP client, not from the attacker.
To a `http://` upstream, or to any upstream with `preserve_host`, zion speaks HTTP/1.1; to a
`https://` upstream it may negotiate HTTP/2. This narrows what an attacker can send to nginx; it
does not replace upgrading it.

If you are considering moving the proxy itself, [`zion import nginx`](/guide/migrate) converts an
nginx configuration and reports what has no equivalent.

### What the zion repository changed

The tests, the lab and the benchmarks run nginx to compare against. Those images moved to
`nginx:1.30.7-alpine`, pinned by digest, and the benchmark ports now listen on loopback only
([#801](https://github.com/fabriziosalmi/zion/pull/801)).

// Examples include `#[path = "../src/*.rs"]` modules whose surface
// is bigger than the example actually uses. Allow dead_code here so
// CI clippy with `-D warnings` doesn't flag every unread item.
#![allow(dead_code)]

//! AIMP gossip mesh stress driver.
//!
//! Standalone binary, runs as PID 1 in a microVM (or as a regular
//! process for local testing). Each instance bootstraps an aimp_cp,
//! optionally publishes a block at a given delay, and prints its
//! reputation-map size every second so an external observer can
//! measure convergence latency across an N-node mesh.
//!
//! Usage:
//!
//! ```sh
//! aimp_mesh \
//!     --listen 0.0.0.0:9443 \
//!     --peer 169.254.10.3:9443 --peer 169.254.10.4:9443 \
//!     [--block-after-secs 3 --block-target 198.51.100.42] \
//!     [--lifetime-secs 30] [--print-every-ms 500]
//! ```
//!
//! The binary is invoked from each microVM's init script. The host
//! orchestrator collects per-node stdout via the firecracker serial
//! console and computes:
//!
//!   * t_first_seen[node]: time at which `map_size` first crosses 0
//!   * convergence_p99 = max(t_first_seen) - t_publish

#[cfg(not(feature = "sovereign-aimp"))]
fn main() {
    eprintln!("This binary requires `--features sovereign-aimp`.");
    std::process::exit(2);
}

#[cfg(feature = "sovereign-aimp")]
fn main() {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    let args = parse_args();
    eprintln!("[aimp_mesh] args = {args:?}");

    let runtime = tokio::runtime::Runtime::new().expect("tokio");
    runtime.block_on(async move {
        let cfg = aimp_cp::AimpControlPlaneConfig {
            enabled: true,
            listen: args.listen,
            peers: args.peers.clone(),
            identity_path: PathBuf::from(format!("/tmp/aimp-{}.bin", args.listen.port())),
        };
        let cp = aimp_cp::bootstrap(cfg).await.expect("bootstrap");
        let started = Instant::now();
        eprintln!(
            "[aimp_mesh] booted, node_id[0..4]={:02x?} listen={} peers={}",
            &cp.node_id()[..4],
            args.listen,
            args.peers.len()
        );

        // Publish task — only if --block-target was given.
        if let (Some(target), Some(after_s)) = (args.block_target, args.block_after_secs) {
            let cp_pub = cp.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(after_s)).await;
                eprintln!(
                    "[aimp_mesh] t={:.3}s PUBLISH block ip={target}",
                    started.elapsed().as_secs_f64()
                );
                if let Err(e) = cp_pub.publish_block(target, 0.95, 1) {
                    eprintln!("[aimp_mesh] publish failed: {e}");
                }
            });
        }

        // Observer: print map size + entries every print_every.
        let deadline = started + Duration::from_secs(args.lifetime_secs);
        let mut tick = tokio::time::interval(Duration::from_millis(args.print_every_ms));
        loop {
            tick.tick().await;
            if Instant::now() >= deadline {
                break;
            }
            let map = cp.reputation();
            let n = map.len();
            let elapsed = started.elapsed().as_secs_f64();
            // Compact one-line emission: t=X.XXs n=K entries=[ip:score:src,…]
            let mut ents = Vec::with_capacity(n);
            for e in map.iter().take(8) {
                let (ip, rep) = e.pair();
                ents.push(format!(
                    "{}:{:.2}:{:02x}{:02x}",
                    ip, rep.score, rep.source_node[0], rep.source_node[1]
                ));
            }
            println!("MESH t={:.3}s n={} entries={}", elapsed, n, ents.join(","));
        }
        eprintln!("[aimp_mesh] lifetime reached, exiting");
    });
}

#[cfg(feature = "sovereign-aimp")]
#[path = "../src/aimp_cp.rs"]
mod aimp_cp;

#[cfg(feature = "sovereign-aimp")]
#[derive(Debug)]
struct Args {
    listen: std::net::SocketAddr,
    peers: Vec<std::net::SocketAddr>,
    block_target: Option<std::net::IpAddr>,
    block_after_secs: Option<u64>,
    lifetime_secs: u64,
    print_every_ms: u64,
}

#[cfg(feature = "sovereign-aimp")]
fn parse_args() -> Args {
    use std::net::SocketAddr;
    let mut listen: Option<SocketAddr> = None;
    let mut peers: Vec<SocketAddr> = vec![];
    let mut block_target: Option<std::net::IpAddr> = None;
    let mut block_after_secs: Option<u64> = None;
    let mut lifetime_secs: u64 = 30;
    let mut print_every_ms: u64 = 500;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => {
                listen = Some(
                    it.next()
                        .expect("--listen value")
                        .parse()
                        .expect("--listen addr"),
                )
            }
            "--peer" => peers.push(
                it.next()
                    .expect("--peer value")
                    .parse()
                    .expect("--peer addr"),
            ),
            "--block-target" => {
                block_target = Some(
                    it.next()
                        .expect("--block-target value")
                        .parse()
                        .expect("--block-target ip"),
                )
            }
            "--block-after-secs" => {
                block_after_secs = Some(
                    it.next()
                        .expect("--block-after-secs value")
                        .parse()
                        .expect("u64"),
                )
            }
            "--lifetime-secs" => {
                lifetime_secs = it
                    .next()
                    .expect("--lifetime-secs value")
                    .parse()
                    .expect("u64")
            }
            "--print-every-ms" => {
                print_every_ms = it
                    .next()
                    .expect("--print-every-ms value")
                    .parse()
                    .expect("u64")
            }
            other => {
                eprintln!("unknown flag: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        listen: listen.unwrap_or_else(|| "0.0.0.0:9443".parse().unwrap()),
        peers,
        block_target,
        block_after_secs,
        lifetime_secs,
        print_every_ms,
    }
}

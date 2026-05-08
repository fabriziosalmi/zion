// Examples include `#[path = "../src/*.rs"]` modules whose surface
// is bigger than the example actually uses. Allow dead_code here so
// CI clippy with `-D warnings` doesn't flag every unread item.
#![allow(dead_code)]

//! AIMP control-plane two-node gossip smoke test.
//!
//! Spawns two `aimp_cp` instances within one process on different
//! UDP ports, has node A publish a block, and asserts that node B's
//! reputation map sees it within a 2-second window.
//!
//! Runs on any OS (no CAP_NET_ADMIN required):
//!
//! ```sh
//! cargo run --release --features sovereign-aimp --example aimp_smoke
//! ```

#[cfg(not(feature = "sovereign-aimp"))]
fn main() {
    eprintln!("This example requires `--features sovereign-aimp`.");
    std::process::exit(2);
}

#[cfg(feature = "sovereign-aimp")]
fn main() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async move {
        // Bind two ephemeral ports on loopback.
        let port_a = bind_ephemeral().await;
        let port_b = bind_ephemeral().await;

        let cfg_a = aimp_cp::AimpControlPlaneConfig {
            enabled: true,
            listen: format!("127.0.0.1:{port_a}").parse().unwrap(),
            peers: vec![format!("127.0.0.1:{port_b}").parse::<SocketAddr>().unwrap()],
            identity_path: "/tmp/zion-aimp-a.bin".into(),
        };
        let cfg_b = aimp_cp::AimpControlPlaneConfig {
            enabled: true,
            listen: format!("127.0.0.1:{port_b}").parse().unwrap(),
            peers: vec![format!("127.0.0.1:{port_a}").parse::<SocketAddr>().unwrap()],
            identity_path: "/tmp/zion-aimp-b.bin".into(),
        };

        eprintln!("→ booting node A on :{port_a} (peer={port_b})");
        let a = aimp_cp::bootstrap(cfg_a).await.expect("boot a");
        eprintln!("→ booting node B on :{port_b} (peer={port_a})");
        let b = aimp_cp::bootstrap(cfg_b).await.expect("boot b");

        // Give the listeners a moment to enter their recv loops.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let target = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
        eprintln!("→ A publishes block on {target}");
        a.publish_block(target, 0.97, 1).expect("publish");

        // Wait up to 2s for B to see the entry.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut saw = false;
        while Instant::now() < deadline {
            if b.lookup(&target).is_some() {
                saw = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if saw {
            let rep = b.lookup(&target).unwrap();
            println!(
                "✓ B saw entry: score={:.3} reason={} source_node[0..4]={:02x?}",
                rep.score,
                rep.reason,
                &rep.source_node[..4]
            );
            assert_eq!(
                rep.source_node,
                a.node_id(),
                "B's entry should be signed by A"
            );
            std::process::exit(0);
        } else {
            eprintln!("✗ B did not see the entry within 2s");
            std::process::exit(1);
        }
    });

    async fn bind_ephemeral() -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    }
}

#[cfg(feature = "sovereign-aimp")]
#[path = "../src/aimp_cp.rs"]
mod aimp_cp;

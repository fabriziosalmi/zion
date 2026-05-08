// Examples include `#[path = "../src/*.rs"]` modules whose surface
// is bigger than the example actually uses. Allow dead_code here so
// CI clippy with `-D warnings` doesn't flag every unread item.
#![allow(dead_code)]

//! Minimal XDP attach smoke test.
//!
//! Run on Linux as root (or with `CAP_NET_ADMIN` + `CAP_BPF`):
//!
//! ```sh
//! cargo run --release --features xdp --example xdp_smoke
//! ```
//!
//! Reads:
//!   * `ZION_XDP_OBJECT`  — path to the compiled eBPF ELF object.
//!     Default: `xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog`.
//!   * `ZION_XDP_IFACE`   — interface to attach to. Default: `lo`.
//!
//! What it does:
//!   1. Loads the eBPF object and attaches `zion_xdp` to the interface.
//!   2. Inserts `127.0.0.42/32` into `BLOCKED_V4`.
//!   3. Polls the `STATS` map five times, one second apart, printing
//!      drops and passes.
//!   4. Detaches on Drop and exits.
//!
//! While the program is running, traffic from `127.0.0.42` to the
//! interface is dropped at the NIC layer. Try in another shell:
//!
//! ```sh
//! sudo ip addr add 127.0.0.42/8 dev lo  # add an alias so we can source-spoof
//! curl --interface 127.0.0.42 http://127.0.0.1/   # should hang/fail
//! ```

#[cfg(not(all(target_os = "linux", feature = "xdp")))]
fn main() {
    eprintln!("This example requires Linux + `--features xdp`.");
    std::process::exit(2);
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
fn main() {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::time::Duration;

    let obj_path: PathBuf = std::env::var("ZION_XDP_OBJECT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from("xdp/zion-xdp-prog/target/bpfel-unknown-none/release/zion-xdp-prog")
        });
    let iface = std::env::var("ZION_XDP_IFACE").unwrap_or_else(|_| "lo".to_string());

    if !obj_path.exists() {
        eprintln!("✗ eBPF object not found at: {}", obj_path.display());
        eprintln!("  Build it first with: ./xdp/build.sh");
        std::process::exit(2);
    }

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async move {
        eprintln!("→ attaching XDP to {iface} from {}…", obj_path.display());
        let handle = match zion_xdp::XdpHandle::attach(&iface, &obj_path) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("✗ attach failed: {e}");
                std::process::exit(1);
            }
        };
        eprintln!(
            "✓ attached: iface={} mode={:?}",
            handle.iface(),
            handle.mode()
        );

        let target = zion_xdp::Cidr4::host(Ipv4Addr::new(127, 0, 0, 42));
        if let Err(e) = handle.add_blocked(target).await {
            eprintln!("✗ add_blocked failed: {e}");
            std::process::exit(1);
        }
        eprintln!("✓ inserted 127.0.0.42/32 into BLOCKED_V4");

        for i in 1..=5 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            match handle.stats().await {
                Ok(s) => println!("  [{i}/5] drops={} passes={}", s.drops, s.passes),
                Err(e) => eprintln!("  [{i}/5] stats err: {e}"),
            }
        }
        // Drop = detach.
        drop(handle);
        eprintln!("✓ detached, exiting");
    });
}

// The example links against the binary's `xdp` module via the `zion`
// crate's lib boundary — but that module is bin-private. To keep the
// surface small, we re-declare a thin shim here that mirrors the public
// API. When zion graduates `xdp` into `lib.rs`, delete this and use it
// directly.
#[cfg(all(target_os = "linux", feature = "xdp"))]
#[path = "../src/xdp.rs"]
mod zion_xdp;

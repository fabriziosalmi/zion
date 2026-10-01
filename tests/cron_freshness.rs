//! The cron watchdog's decision logic (`scripts/check-cron-freshness.sh`) must tell a workflow
//! that is merely NEW (its first scheduled run is still due) from one that is STALE, and must
//! parse GitHub's two timestamp shapes. The script carries its own `--selftest`; this runs it
//! under `cargo test` so a regression fails the normal gate, not only the next daily watchdog.
#![cfg(unix)]

use std::process::Command;

#[test]
fn the_cron_watchdog_selftest_passes() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/scripts/check-cron-freshness.sh"
    );
    let out = Command::new("bash")
        .arg(script)
        .arg("--selftest")
        .output()
        .expect("bash is needed to run the script");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("selftest ok"), "{text}");
}

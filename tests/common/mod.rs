//! Helpers shared by the integration tests that boot the real binary.

use std::collections::HashSet;
use std::net::TcpListener;
use std::sync::{LazyLock, Mutex};

static HANDED_OUT: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(Mutex::default);

/// A TCP port that was free a moment ago and that this process has not handed out before.
///
/// Binding port 0 and dropping the listener hands the port back to the kernel, which is free to
/// give the very same one to the next caller. Tests run on parallel threads, so two of them would
/// then configure two daemons with one port: the second daemon fails to bind (the admin API is
/// "disabled", a listener is "unavailable") and the test talks to the OTHER test's daemon. Never
/// returning a port twice in a process closes that gap; a collision with some other process is
/// still possible, which is why the daemon-booting helpers also check the daemon's log.
pub fn free_port() -> u16 {
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if HANDED_OUT.lock().unwrap().insert(port) {
            return port;
        }
    }
}

/// The memory a process holds, in MiB, counting what the system has compressed or swapped
/// out. The resident size alone will not do: macOS compresses memory that sits idle within
/// a second, and 3.2 GiB held for a client that does not read showed as 26 MiB resident.
#[allow(dead_code)] // not every test binary measures memory
pub fn process_memory_mib(pid: u32) -> u64 {
    use std::process::Command;
    let pid = pid.to_string();
    if cfg!(target_os = "linux") {
        // VmRSS + VmSwap, both "<n> kB".
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("status");
        let kib = |field: &str| -> u64 {
            status
                .lines()
                .find_map(|l| l.strip_prefix(field))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        return (kib("VmRSS:") + kib("VmSwap:")) / 1024;
    }
    if cfg!(target_os = "macos") {
        // The "physical footprint", as `top` prints it: "3224M", "105M+", "980K".
        let out = Command::new("top")
            .args(["-l", "1", "-pid", &pid, "-stats", "mem"])
            .output()
            .expect("top");
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().last().unwrap_or_default().trim();
        let value = last.trim_end_matches(['+', '-']);
        let (digits, unit) = value.split_at(value.len().saturating_sub(1));
        let n: u64 = digits
            .parse()
            .unwrap_or_else(|_| panic!("top printed {last:?}"));
        return match unit {
            "K" => n / 1024,
            "M" => n,
            "G" => n * 1024,
            _ => panic!("top printed {last:?}"),
        };
    }
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .expect("ps");
    let kib: u64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("ps prints the resident size in KiB");
    kib / 1024
}

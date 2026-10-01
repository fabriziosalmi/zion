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

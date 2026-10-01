// SPDX-License-Identifier: Apache-2.0
//! Non-blocking log output.
//!
//! The `tracing` fmt layer writes each event to stderr from the thread that logged it. When
//! stderr is a pipe nobody is draining fast enough (a stalled journald, a full container log
//! driver, a `| tee` on a slow disk) that `write` blocks, and with it the request worker that
//! logged: a logging problem becomes a latency, then an availability problem.
//!
//! [`LogQueue`](crate::logq::LogQueue) puts a bounded queue between the two. Producers `try_send` a whole formatted
//! line and never wait; one dedicated thread owns the sink and writes lines in order. When the
//! queue is full the *new* line is dropped and counted ([`DROPPED`](crate::logq::DROPPED), `zion_log_lines_dropped_total`),
//! and the writer thread says so on the sink the next time it can write, so loss is never silent.
//! [`flush`](crate::logq::flush) waits (bounded) for the queue to drain, for shutdown and for the panic hook.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Lines dropped because the queue was full (or the writer thread had died).
pub static DROPPED: AtomicU64 = AtomicU64::new(0);

/// True when the process logs JSON: the drop notice then has to be a JSON object too, or it
/// would poison a JSON log pipeline at the moment it matters most.
static JSON: AtomicBool = AtomicBool::new(false);

/// The line announcing `n` lost lines, in the process's log format.
fn drop_notice(json: bool, ts: &str, n: u64) -> String {
    let msg = format!("{n} log line(s) dropped: the log sink is slower than the log rate");
    if json {
        format!(r#"{{"ts":"{ts}","level":"warn","event":"log_dropped","msg":"{msg}"}}"#) + "\n"
    } else {
        format!("zion: {msg}\n")
    }
}

/// A bounded, lossy, order-preserving line queue in front of a sink.
pub struct LogQueue {
    tx: SyncSender<Vec<u8>>,
    pending: std::sync::Arc<AtomicUsize>,
    dropped: std::sync::Arc<AtomicU64>,
}

impl LogQueue {
    /// Start the writer thread over `sink`. `capacity` is the number of lines that can wait.
    pub fn spawn(capacity: usize, mut sink: Box<dyn Write + Send>) -> Self {
        let (tx, rx) = sync_channel::<Vec<u8>>(capacity.max(1));
        let pending = std::sync::Arc::new(AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(AtomicU64::new(0));
        let (p, d) = (pending.clone(), dropped.clone());
        let spawned = std::thread::Builder::new()
            .name("zion-log".into())
            .spawn(move || {
                let mut reported = 0u64;
                for line in rx {
                    let lost = d.load(Relaxed);
                    if lost > reported {
                        let note = drop_notice(
                            JSON.load(Relaxed),
                            &crate::logging::now(),
                            lost - reported,
                        );
                        // announced only once it was actually written
                        if sink.write_all(note.as_bytes()).is_ok() {
                            reported = lost;
                        }
                    }
                    // A record the sink refuses (its reader went away) is a lost line like
                    // any other: counted, so the metric never under-reports.
                    if sink.write_all(&line).and_then(|()| sink.flush()).is_err() {
                        d.fetch_add(1, Relaxed);
                        DROPPED.fetch_add(1, Relaxed);
                    }
                    p.fetch_sub(1, Relaxed);
                }
            });
        if spawned.is_err() {
            // No thread, no queue: every line counts as dropped rather than blocking.
            dropped.fetch_add(1, Relaxed);
        }
        Self {
            tx,
            pending,
            dropped,
        }
    }

    /// Queue one line; never blocks. Returns false when it was dropped.
    pub fn push(&self, line: &[u8]) -> bool {
        self.pending.fetch_add(1, Relaxed);
        match self.tx.try_send(line.to_vec()) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.pending.fetch_sub(1, Relaxed);
                self.dropped.fetch_add(1, Relaxed);
                DROPPED.fetch_add(1, Relaxed);
                false
            }
        }
    }

    #[cfg(test)]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Relaxed)
    }

    /// Wait until everything queued so far has been written, or `timeout` has passed.
    /// Returns true when the queue drained.
    pub fn flush(&self, timeout: Duration) -> bool {
        let end = Instant::now() + timeout;
        while self.pending.load(Relaxed) > 0 {
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }
}

static GLOBAL: OnceLock<LogQueue> = OnceLock::new();

/// Install the process-wide queue over stderr. Idempotent; `capacity == 0` leaves output
/// synchronous (the previous behaviour).
pub fn install(capacity: usize, json: bool) {
    JSON.store(json, Relaxed);
    if capacity > 0 {
        GLOBAL.get_or_init(|| LogQueue::spawn(capacity, Box::new(std::io::stderr())));
    }
}

/// Wait for queued log lines to reach stderr (shutdown, panic). No-op when synchronous.
pub fn flush(timeout: Duration) {
    if let Some(q) = GLOBAL.get() {
        q.flush(timeout);
    }
}

/// Write `line` plus a newline: queued if the global queue is installed, else `eprintln!`.
pub fn line(line: &str) {
    match GLOBAL.get() {
        Some(q) => {
            let mut buf = Vec::with_capacity(line.len() + 1);
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
            q.push(&buf);
        }
        None => eprintln!("{line}"),
    }
}

/// `MakeWriter` for the fmt layer: the global queue if installed, else plain stderr.
#[derive(Clone, Copy)]
pub struct MakeLogWriter;

/// One event's writer. The fmt layer may emit an event in several `write` calls, so the queue
/// variant gathers them and enqueues the finished event once, when the writer is dropped: events
/// never interleave, a drop loses a whole event, and the queue counts events, not fragments.
pub enum LogWriter {
    Queue(&'static LogQueue, Vec<u8>),
    Stderr(std::io::Stderr),
}

impl Drop for LogWriter {
    fn drop(&mut self) {
        if let Self::Queue(q, buf) = self {
            if !buf.is_empty() {
                q.push(buf);
            }
        }
    }
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Queue(_, event) => {
                event.extend_from_slice(buf);
                Ok(buf.len())
            }
            Self::Stderr(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Queue(..) => Ok(()),
            Self::Stderr(s) => s.flush(),
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeLogWriter {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> LogWriter {
        match GLOBAL.get() {
            Some(q) => LogWriter::Queue(q, Vec::with_capacity(256)),
            None => LogWriter::Stderr(std::io::stderr()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Collect(Arc<Mutex<Vec<u8>>>);
    impl Write for Collect {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A sink that does not return until released: a stalled pipe.
    struct Stalled {
        gate: Arc<(Mutex<bool>, std::sync::Condvar)>,
        out: Collect,
    }
    impl Write for Stalled {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let (m, cv) = &*self.gate;
            let mut open = m.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            self.out.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lines_arrive_whole_and_in_order() {
        let out = Collect::default();
        let q = LogQueue::spawn(64, Box::new(out.clone()));
        for i in 0..50 {
            assert!(q.push(format!("line {i}\n").as_bytes()));
        }
        assert!(q.flush(Duration::from_secs(5)));
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let want: String = (0..50).map(|i| format!("line {i}\n")).collect();
        assert_eq!(text, want);
        assert_eq!(q.dropped(), 0);
    }

    #[test]
    fn a_stalled_sink_never_blocks_the_producer_and_drops_are_counted_and_reported() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let out = Collect::default();
        let q = LogQueue::spawn(
            8,
            Box::new(Stalled {
                gate: gate.clone(),
                out: out.clone(),
            }),
        );
        let t = Instant::now();
        let accepted = (0..1_000).filter(|_| q.push(b"x\n")).count();
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "producers must not wait on a stalled sink"
        );
        // 8 queued + the one the writer thread already holds
        assert!((8..=9).contains(&accepted), "accepted {accepted}");
        assert_eq!(q.dropped() as usize, 1_000 - accepted);
        // the sink recovers: queued lines are written, and the loss is announced
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(q.flush(Duration::from_secs(5)));
        q.push(b"after\n");
        assert!(q.flush(Duration::from_secs(5)));
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        // every lost line is announced exactly once: the notes add up to the drop count
        // (how many notes there are depends on when the writer thread first wakes)
        let announced: u64 = text
            .lines()
            .filter(|l| l.contains("log line(s) dropped"))
            .map(|l| l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap())
            .sum();
        assert_eq!(announced, q.dropped(), "{text}");
        assert!(text.ends_with("after\n"));
    }

    #[test]
    fn flush_times_out_instead_of_hanging_on_a_stalled_sink() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let q = LogQueue::spawn(
            4,
            Box::new(Stalled {
                gate: gate.clone(),
                out: Collect::default(),
            }),
        );
        q.push(b"a\n");
        let t = Instant::now();
        assert!(!q.flush(Duration::from_millis(100)));
        assert!(t.elapsed() < Duration::from_secs(2));
        *gate.0.lock().unwrap() = true; // release the writer thread
        gate.1.notify_all();
    }

    #[test]
    fn many_producers_lose_nothing_while_the_queue_has_room() {
        let out = Collect::default();
        let q = LogQueue::spawn(100_000, Box::new(out.clone()));
        std::thread::scope(|s| {
            for t in 0..8 {
                let q = &q;
                s.spawn(move || {
                    for i in 0..500 {
                        q.push(format!("{t}:{i}\n").as_bytes());
                    }
                });
            }
        });
        assert!(q.flush(Duration::from_secs(10)));
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 4_000);
        // per-producer order is preserved
        for t in 0..8 {
            let mine: Vec<u32> = text
                .lines()
                .filter_map(|l| l.strip_prefix(&format!("{t}:")))
                .map(|n| n.parse().unwrap())
                .collect();
            assert!(
                mine.windows(2).all(|w| w[0] < w[1]),
                "producer {t} reordered"
            );
        }
    }

    #[test]
    fn an_event_written_in_pieces_is_one_queued_line() {
        // A stalled sink keeps the queue from draining, so the count is deterministic: three
        // events written in three pieces each must take three slots, not nine.
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let out = Collect::default();
        let q: &'static LogQueue = Box::leak(Box::new(LogQueue::spawn(
            4,
            Box::new(Stalled {
                gate: gate.clone(),
                out: out.clone(),
            }),
        )));
        for n in 0..3 {
            let mut w = LogWriter::Queue(q, Vec::new());
            w.write_all(b"{\"a\":").unwrap();
            w.write_all(format!("{n}").as_bytes()).unwrap();
            w.write_all(b"}\n").unwrap();
        } // dropped here: the event is complete
        assert_eq!(
            q.dropped(),
            0,
            "three events, not nine fragments, against a capacity of 4"
        );
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(q.flush(Duration::from_secs(5)));
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            text, "{\"a\":0}\n{\"a\":1}\n{\"a\":2}\n",
            "whole events, in order"
        );
    }

    #[test]
    fn the_drop_notice_follows_the_log_format() {
        let text = drop_notice(false, "T", 3);
        assert_eq!(
            text,
            "zion: 3 log line(s) dropped: the log sink is slower than the log rate\n"
        );
        let json = drop_notice(true, "2026-10-01T00:00:00Z", 3);
        let v: serde_json::Value = serde_json::from_str(json.trim_end()).expect("valid JSON");
        assert_eq!(v["level"], "warn");
        assert_eq!(v["event"], "log_dropped");
        assert!(v["msg"]
            .as_str()
            .unwrap()
            .starts_with("3 log line(s) dropped"));
        assert!(json.ends_with('\n') && json.matches('\n').count() == 1);
    }

    /// A sink whose reader has gone away.
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lines_a_broken_sink_refuses_are_counted_as_lost() {
        let q = LogQueue::spawn(16, Box::new(Broken));
        for _ in 0..5 {
            q.push(b"x\n");
        }
        assert!(q.flush(Duration::from_secs(5)));
        assert_eq!(q.dropped(), 5, "every refused line is a counted loss");
    }

    /// Refuses the first drop notice it is given, then behaves.
    struct FailFirstNote {
        failed: bool,
        inner: Stalled,
    }
    impl Write for FailFirstNote {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if !self.failed && String::from_utf8_lossy(b).contains("log line(s) dropped") {
                self.failed = true;
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            self.inner.write(b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_notice_the_sink_refused_is_announced_again_not_forgotten() {
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let out = Collect::default();
        let q = LogQueue::spawn(
            4,
            Box::new(FailFirstNote {
                failed: false,
                inner: Stalled {
                    gate: gate.clone(),
                    out: out.clone(),
                },
            }),
        );
        for _ in 0..100 {
            q.push(b"x\n");
        }
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(q.flush(Duration::from_secs(5)));
        q.push(b"after\n");
        assert!(q.flush(Duration::from_secs(5)));
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let announced: u64 = text
            .lines()
            .filter(|l| l.contains("log line(s) dropped"))
            .map(|l| l.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap())
            .sum();
        assert_eq!(announced, q.dropped(), "the lost notice is retried: {text}");
    }
}

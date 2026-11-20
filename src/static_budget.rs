// SPDX-License-Identifier: Apache-2.0
//! What static responses may hold at once: per connection, per client address and in all.
//!
//! A static `GET` holds, while it is sent, either its open file and the read-ahead of a streamed
//! body (up to [`STREAMED_HOLD`], `static_files::stream_file`) or the bytes of a file read whole
//! (576 KiB or less). A client that does not read keeps them for as long as it keeps the
//! connection. One HTTP/2 or HTTP/3 connection is bounded by its own slots (`h2_stream::Conn`:
//! eight streamed files, 4.5 MiB read whole), but one address may open many connections (an
//! eighth of the connection ceiling over TCP, no cap at all over QUIC), and on a 16 GiB host
//! 2048 connections times about 10.5 MiB is more memory than the host has.
//!
//! So every static `GET`, on HTTP/1, HTTP/2 and HTTP/3 alike, also takes its bytes from a budget
//! for the whole process, and from the share of it its client's address may hold:
//!
//! - The budget is derived from the host, as the connection ceiling is: 128 KiB for each
//!   connection of the ceiling, at most an eighth of the memory the process may use (the
//!   response cache's default share), at least eight streamed responses ([`derived_bytes`]).
//!   16384 connections on a 16 GiB host give 2 GiB.
//! - One address may hold an eighth of it ([`SHARES`]), as one address may hold an eighth of the
//!   connection ceiling: 256 MiB on that host. The address is the one `connlimit` counts, or,
//!   on a connection from a `trusted_proxies` peer, the client that request resolves to (the
//!   address `X-Real-IP` carries), whose connection the proxy shares with other clients. Such a
//!   connection has no per-connection slots either: they would make unrelated clients wait for
//!   each other.
//! - A streamed response is counted as [`STREAMED_HOLD`] whatever it reads ahead, so the budget
//!   also bounds the files held open: 2730 on that host, a sixth of the connection ceiling,
//!   where the descriptor budget gives each connection two (`bootstrap::fd_conn_budget`).
//!
//! A request that finds its connection's slots taken waits for one, as before: what it waits
//! for is its own client's. One that finds its address's share or the budget spent waits at
//! most [`BUDGET_WAIT`], holding no file and no buffer, and is then answered `503`: what it
//! waits for may be another client's, and a client that does not read keeps what it holds
//! until `send_stall_secs` resets its stream or, on HTTP/1.1, closes its connection (five
//! minutes by default).
//!
//! There is no separate count of open files: a streamed response is charged what it may hold in
//! memory, so the byte budget is reached at a sixth of the connection ceiling's worth of open
//! files, far below the descriptors the ceiling plans for, and a file counter sized from the
//! descriptors could never be the bound that applies.

use std::net::IpAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::h2_stream;

/// What a streamed static response may hold in memory while its client does not read. The file
/// is read in 128 KiB blocks cut into 64 KiB frames, and a block lives while either of its
/// frames does: five blocks (640 KiB) when the window was never opened (the frame hyper waits
/// with, the seven queued behind it, the block being read), six (768 KiB) when it opened part of
/// the way and the library holds the rest of a frame whose block-mate hyper now waits with
/// (`static_files::STREAM_IN_FLIGHT_FRAMES`). It is what such a response takes from the budget,
/// whatever it reads ahead.
pub(crate) const STREAMED_HOLD: u64 = 768 * 1024;

/// What each connection of the ceiling adds to the budget.
const BYTES_PER_CONNECTION: u64 = 128 * 1024;

/// One address may hold `1 / SHARES` of the budget.
pub(crate) const SHARES: u64 = 8;

/// The longest a request waits for its address's share or for the budget before it is answered
/// `503`. Long enough for slots held by clients that read to come free (64 requests for a 2 MiB
/// file from one address, three times its share in the tests, were all served in 0.64 s), far
/// shorter than the `send_stall_secs` that frees one a client does not read (300 s by default):
/// without the bound, a request behind such clients waited for that.
pub(crate) const BUDGET_WAIT: Duration = Duration::from_secs(10);

/// The unit the budget is counted in.
const UNIT: u64 = 1024;

/// The static-response budget of a process whose connection ceiling is `ceiling` and which may
/// use `ram_mb` MiB of memory, in bytes (see the module documentation).
pub(crate) fn derived_bytes(ceiling: usize, ram_mb: u64) -> u64 {
    let from_ceiling = u64::try_from(ceiling)
        .unwrap_or(u64::MAX)
        .saturating_mul(BYTES_PER_CONNECTION);
    let from_memory = ram_mb.saturating_mul(1024 * 1024) / 8;
    from_ceiling.min(from_memory).max(SHARES * STREAMED_HOLD)
}

/// The budget, and the share of it each address holds.
pub(crate) struct Budget {
    all: Arc<Semaphore>,
    /// The budget, in [`UNIT`]s.
    all_units: u32,
    /// The share of one address, in [`UNIT`]s.
    share_units: u32,
    /// The shares in use: an address is here while it holds or waits for part of its share.
    shares: DashMap<IpAddr, Arc<Semaphore>>,
}

impl Budget {
    pub(crate) fn new(bytes: u64) -> Arc<Budget> {
        let all_units = u32::try_from(bytes.div_ceil(UNIT).max(1)).unwrap_or(u32::MAX);
        let share_units = (all_units / SHARES as u32).max(1);
        Arc::new(Budget {
            all: Arc::new(Semaphore::new(all_units as usize)),
            all_units,
            share_units,
            shares: DashMap::new(),
        })
    }

    /// The budget in bytes, and one address's share of it.
    pub(crate) fn sizes(&self) -> (u64, u64) {
        (
            u64::from(self.all_units) * UNIT,
            u64::from(self.share_units) * UNIT,
        )
    }

    /// The share of `ip`, made when the address holds none yet. Cloned under the map's lock,
    /// so a release that finds it unused cannot remove it in between ([`Held`]).
    fn share(&self, ip: IpAddr) -> Arc<Semaphore> {
        self.shares
            .entry(ip)
            .or_insert_with(|| Arc::new(Semaphore::new(self.share_units as usize)))
            .clone()
    }

    /// Forget the share of `ip` if no request holds or waits for any of it.
    fn release(&self, ip: IpAddr) {
        self.shares.remove_if(&ip, |_, s| Arc::strong_count(s) == 1);
    }

    /// The addresses that hold or wait for part of their share (for the tests).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.shares.len()
    }
}

/// The process's budget, sized from the connection ceiling in force when the first static
/// request asks for it (the ceiling is fixed at boot, before any listener).
fn budget() -> &'static Arc<Budget> {
    static BUDGET: OnceLock<Arc<Budget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        Budget::new(derived_bytes(
            crate::bootstrap::conn_ceiling(),
            crate::bootstrap::detect().ram_mb,
        ))
    })
}

/// The budget and the share of one address, in bytes, as the boot log reports them.
pub(crate) fn sizes() -> (u64, u64) {
    budget().sizes()
}

/// What a static response holds while it is sent, and so what it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// A body streamed from its open file: one of the connection's eight streamed-file slots,
    /// and [`STREAMED_HOLD`] of the budget.
    File,
    /// A body of this many bytes, read whole: that much of the connection's whole-read budget
    /// and of the budget.
    Whole(u64),
}

impl Need {
    fn bytes(self) -> u64 {
        match self {
            Need::File => STREAMED_HOLD,
            Need::Whole(len) => len,
        }
    }

    /// Whether a slot taken for `self` covers a response that turns out to need `other` (the
    /// file was replaced between the look at its path and its opening).
    pub(crate) fn covers(self, other: Need) -> bool {
        match (self, other) {
            (Need::File, _) => true,
            (Need::Whole(had), Need::Whole(wants)) => {
                wants.div_ceil(UNIT) <= had.div_ceil(UNIT)
                    && h2_stream::whole_units(wants) <= h2_stream::whole_units(had)
            }
            (Need::Whole(_), Need::File) => false,
        }
    }
}

/// `bytes` in [`UNIT`]s, rounded up, and never more than `cap` (a request for more than a
/// semaphore holds would wait forever).
fn units(bytes: u64, cap: u32) -> u32 {
    u32::try_from(bytes.div_ceil(UNIT))
        .unwrap_or(u32::MAX)
        .min(cap)
}

/// What a static response took: from its connection (none behind a trusted proxy and off
/// HTTP/2 and HTTP/3), from its address's share and from the budget. Every holder keeps a clone
/// (the file's reader, the response's body and each chunk of it), and it is all given back when
/// the last one goes.
pub(crate) type StaticSlot = Arc<Held>;

pub(crate) struct Held {
    _conn: Option<OwnedSemaphorePermit>,
    _all: OwnedSemaphorePermit,
    share: Option<OwnedSemaphorePermit>,
    ip: IpAddr,
    budget: Arc<Budget>,
}

impl Drop for Held {
    fn drop(&mut self) {
        // The share's permit first: it holds the share, which is forgotten once nothing does.
        drop(self.share.take());
        self.budget.release(self.ip);
    }
}

/// The client a static response is held for, as [`admission`] counts it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Client {
    /// The client's address: the peer's, or behind a trusted proxy the one the request
    /// resolves to.
    pub(crate) ip: IpAddr,
    /// The connection is from a `trusted_proxies` peer, which carries other clients' requests.
    pub(crate) via_trusted_proxy: bool,
}

/// Why a static response was refused a slot.
#[derive(Debug)]
pub(crate) struct Refused;

/// What a static `GET` from `client` takes its slot from.
#[derive(Clone)]
pub(crate) struct Admission {
    conn: Option<Arc<h2_stream::Conn>>,
    ip: IpAddr,
    budget: Arc<Budget>,
}

/// The [`Admission`] of the current request from `client`: its HTTP/2 or HTTP/3 connection's
/// slots unless that is a trusted proxy's, its address's share, and the budget.
pub(crate) fn admission(client: Client) -> Admission {
    Admission {
        conn: if client.via_trusted_proxy {
            None
        } else {
            h2_stream::current_conn()
        },
        ip: client.ip,
        budget: budget().clone(),
    }
}

impl Admission {
    /// The connection's pool for `need` and how much of it to take; `None` without slots.
    fn conn_pool(&self, need: Need) -> Option<(Arc<Semaphore>, u32)> {
        self.conn.as_ref().map(|c| c.pool(need))
    }

    fn held(
        &self,
        conn: Option<OwnedSemaphorePermit>,
        share: OwnedSemaphorePermit,
        all: OwnedSemaphorePermit,
    ) -> StaticSlot {
        Arc::new(Held {
            _conn: conn,
            _all: all,
            share: Some(share),
            ip: self.ip,
            budget: self.budget.clone(),
        })
    }

    /// A slot for `need` if one is free now, in all three. Never waits, so it may run on the
    /// blocking pool, where the file is looked at and opened.
    pub(crate) fn try_take(&self, need: Need) -> Option<StaticSlot> {
        let conn = match self.conn_pool(need) {
            Some((pool, n)) => Some(pool.try_acquire_many_owned(n).ok()?),
            None => None,
        };
        let bytes = need.bytes();
        let share = self.budget.share(self.ip);
        let got = share
            .try_acquire_many_owned(units(bytes, self.budget.share_units))
            .ok()
            .and_then(|share| {
                let all = self
                    .budget
                    .all
                    .clone()
                    .try_acquire_many_owned(units(bytes, self.budget.all_units))
                    .ok()?;
                Some((share, all))
            });
        match got {
            Some((share, all)) => Some(self.held(conn, share, all)),
            None => {
                self.budget.release(self.ip);
                None
            }
        }
    }

    /// A slot for `need`: waiting while the connection's are taken, then at most
    /// [`BUDGET_WAIT`] for the address's share and the budget. Call it holding no file and no
    /// bytes of one. [`Refused`] when the wait ran out.
    pub(crate) async fn take(&self, need: Need) -> Result<StaticSlot, Refused> {
        let conn = match self.conn_pool(need) {
            Some((pool, n)) => Some(pool.acquire_many_owned(n).await.map_err(|_| Refused)?),
            None => None,
        };
        let bytes = need.bytes();
        let (share_n, all_n) = (
            units(bytes, self.budget.share_units),
            units(bytes, self.budget.all_units),
        );
        let share = self.budget.share(self.ip);
        let all = self.budget.all.clone();
        let fast = share
            .clone()
            .try_acquire_many_owned(share_n)
            .ok()
            .and_then(|s| Some((s, all.clone().try_acquire_many_owned(all_n).ok()?)));
        let got = match fast {
            Some(got) => Some(got),
            None => {
                crate::metrics::METRICS
                    .static_budget_waited
                    .fetch_add(1, Relaxed);
                tokio::time::timeout(BUDGET_WAIT, async move {
                    let s = share.acquire_many_owned(share_n).await.ok()?;
                    Some((s, all.acquire_many_owned(all_n).await.ok()?))
                })
                .await
                .ok()
                .flatten()
            }
        };
        match got {
            Some((share, all)) => Ok(self.held(conn, share, all)),
            None => {
                self.budget.release(self.ip);
                crate::metrics::METRICS
                    .static_budget_refused
                    .fetch_add(1, Relaxed);
                Err(Refused)
            }
        }
    }
}

/// An [`Admission`] of `conn` (`None`: no connection slots) from a budget of `bytes` of its
/// own, for the tests of the modules that hold slots.
#[cfg(test)]
pub(crate) fn test_admission(conn: Option<Arc<h2_stream::Conn>>, bytes: u64) -> Admission {
    Admission {
        conn,
        ip: IpAddr::from([192, 0, 2, 1]),
        budget: Budget::new(bytes),
    }
}

#[cfg(test)]
impl Admission {
    /// The bytes of the budget free now.
    pub(crate) fn free_bytes(&self) -> u64 {
        self.budget.all.available_permits() as u64 * UNIT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h2_stream::{whole_units, STATIC_FILES_PER_CONN, STATIC_WHOLE_BYTES_PER_CONN};

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn adm(budget: &Arc<Budget>, addr: &str) -> Admission {
        Admission {
            conn: None,
            ip: ip(addr),
            budget: budget.clone(),
        }
    }

    #[test]
    fn the_budget_is_derived_from_the_connection_ceiling_and_memory() {
        // 16 GiB, 16384 connections (memory-bound ceiling, LimitNOFILE 65535): 2 GiB.
        assert_eq!(derived_bytes(16_384, 16_384), 2048 * MIB);
        // macOS with 10240 descriptors: a ceiling of 4608.
        assert_eq!(derived_bytes(4_608, 16_384), 576 * MIB);
        // A 512 MiB container (ceiling floor 1000): an eighth of its memory.
        assert_eq!(derived_bytes(1_000, 512), 64 * MIB);
        // Never less than eight streamed responses, one for each share.
        assert_eq!(derived_bytes(1, 16_384), SHARES * STREAMED_HOLD);
        let b = Budget::new(derived_bytes(16_384, 16_384));
        assert_eq!(b.sizes(), (2048 * MIB, 256 * MIB));
    }

    #[test]
    fn one_address_holds_at_most_its_share() {
        let b = Budget::new(64 * STREAMED_HOLD); // a share of eight streamed responses
        let a = adm(&b, "198.51.100.7");
        let held: Vec<_> = (0..8)
            .map(|_| a.try_take(Need::File).expect("within the share"))
            .collect();
        assert!(
            a.try_take(Need::File).is_none(),
            "a ninth is over the share"
        );
        assert!(
            a.try_take(Need::Whole(KIB)).is_none(),
            "so is one more KiB read whole"
        );
        // Another address has its own share.
        assert!(adm(&b, "198.51.100.8").try_take(Need::File).is_some());
        drop(held);
        assert!(a.try_take(Need::File).is_some(), "released");
    }

    #[test]
    fn eight_addresses_spend_the_whole_budget() {
        let b = Budget::new(16 * STREAMED_HOLD); // shares of two
        let mut held = Vec::new();
        for i in 0..8 {
            let a = adm(&b, &format!("203.0.113.{i}"));
            held.push(a.try_take(Need::File).unwrap());
            held.push(a.try_take(Need::File).unwrap());
        }
        assert!(
            adm(&b, "203.0.113.99").try_take(Need::Whole(1)).is_none(),
            "a ninth address finds the budget spent"
        );
        drop(held);
        assert_eq!(b.all.available_permits(), b.all_units as usize);
    }

    #[test]
    fn a_share_is_forgotten_once_nothing_holds_it() {
        let b = Budget::new(64 * MIB);
        let a = adm(&b, "2001:db8::1");
        let s1 = a.try_take(Need::File).unwrap();
        let s2 = s1.clone();
        assert_eq!(b.tracked(), 1);
        drop(s1);
        assert_eq!(b.tracked(), 1, "a clone still holds it");
        drop(s2);
        assert_eq!(b.tracked(), 0);
        // A refusal leaves nothing behind either.
        let tiny = Budget::new(1);
        let t = adm(&tiny, "2001:db8::2");
        let _hold = t.try_take(Need::Whole(tiny.sizes().1)).unwrap();
        assert!(t.try_take(Need::Whole(1)).is_none());
        drop(_hold);
        assert_eq!(tiny.tracked(), 0);
    }

    #[test]
    fn a_need_over_the_share_takes_the_whole_share_and_is_served() {
        let b = Budget::new(SHARES * 100 * KIB); // a share of 100 KiB
        let a = adm(&b, "192.0.2.1");
        let s = a.try_take(Need::File).expect("clamped to the share");
        assert!(a.try_take(Need::Whole(1)).is_none());
        drop(s);
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_finds_the_share_spent_waits_then_is_refused() {
        let b = Budget::new(SHARES * STREAMED_HOLD); // a share of one
        let a = adm(&b, "192.0.2.9");
        let held = a.take(Need::File).await.unwrap();
        // Freed while it waits: served.
        let waiter = {
            let a = a.clone();
            tokio::spawn(async move { a.take(Need::File).await.is_ok() })
        };
        tokio::time::sleep(BUDGET_WAIT / 2).await;
        drop(held);
        assert!(waiter.await.unwrap(), "served once the slot came free");
        // Never freed: refused after BUDGET_WAIT, not before.
        let _held = a.take(Need::File).await.unwrap();
        let t0 = tokio::time::Instant::now();
        assert!(a.take(Need::File).await.is_err());
        assert_eq!(t0.elapsed(), BUDGET_WAIT);
    }

    #[test]
    fn a_slot_covers_what_it_was_taken_for_and_less() {
        let kib = |n: u64| Need::Whole(n * KIB);
        assert!(Need::File.covers(Need::File));
        assert!(Need::File.covers(kib(576)));
        assert!(kib(10).covers(kib(10)));
        assert!(kib(10).covers(Need::Whole(10 * KIB - 1)));
        assert!(!kib(10).covers(kib(11)));
        assert!(!kib(576).covers(Need::File));
    }

    #[tokio::test]
    async fn a_connection_streams_at_most_eight_files_and_a_freed_slot_is_reused() {
        let conn = h2_stream::Conn::new(10);
        let a = test_admission(Some(conn.clone()), 1 << 30);
        let mut held: Vec<_> = (0..STATIC_FILES_PER_CONN)
            .map(|_| a.try_take(Need::File).expect("one of the eight"))
            .collect();
        assert_eq!(conn.free().0, 0);
        assert!(
            a.try_take(Need::File).is_none(),
            "a ninth streamed response"
        );
        // A small file is not kept waiting by them: it takes from the other budget.
        assert!(
            a.try_take(Need::Whole(20 * KIB)).is_some(),
            "a small file waited behind eight large ones"
        );
        // A ninth waits for a slot, and gets the one freed.
        let ninth = {
            let a = a.clone();
            tokio::spawn(async move { a.take(Need::File).await.is_ok() })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!ninth.is_finished(), "a ninth streamed response began");
        held.pop();
        assert!(ninth.await.unwrap(), "the ninth got the freed slot");
        drop(held);
        assert_eq!(
            conn.free(),
            (
                STATIC_FILES_PER_CONN,
                whole_units(STATIC_WHOLE_BYTES_PER_CONN)
            ),
            "every slot came back"
        );
    }

    #[test]
    fn bodies_read_whole_share_a_byte_budget_per_connection() {
        let conn = h2_stream::Conn::new(10);
        let a = test_admission(Some(conn.clone()), 1 << 30);
        let largest = Need::Whole(576 * KIB);
        let mut held: Vec<_> = (0..8)
            .map(|_| a.try_take(largest).expect("eight of the largest fit"))
            .collect();
        assert!(a.try_take(largest).is_none(), "a ninth does not");
        assert!(a.try_take(Need::Whole(1)).is_none(), "nor one byte more");
        assert!(
            a.try_take(Need::Whole(0)).is_some(),
            "an empty file holds nothing"
        );
        held.pop();
        let small: Vec<_> = (0..57)
            .map(|_| {
                a.try_take(Need::Whole(10 * KIB))
                    .expect("small files share it")
            })
            .collect();
        assert!(a.try_take(Need::Whole(10 * KIB)).is_none());
        drop((held, small));
        assert_eq!(conn.free().1, whole_units(STATIC_WHOLE_BYTES_PER_CONN));
    }

    #[test]
    fn a_trusted_proxys_connection_has_no_connection_slots() {
        // `admission` leaves the connection out for such a peer; the share still applies.
        let a = test_admission(None, 64 * STREAMED_HOLD);
        let held: Vec<_> = (0..8)
            .map(|_| a.try_take(Need::File).expect("no eight-file cap"))
            .collect();
        assert!(
            a.try_take(Need::File).is_none(),
            "the share still bounds it"
        );
        drop(held);
    }
}

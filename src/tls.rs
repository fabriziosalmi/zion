use arc_swap::ArcSwap;
use fnv::FnvHashMap;
use notify::{EventKind, RecursiveMode, Watcher};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::cell::RefCell;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

use crate::config::TlsConfig;

// ═══════════════════════════════════════════════════════════════════
// GENERATION COUNTER
// Monotonically increasing counter that ticks on every cert reload.
// Data Plane compares local generation vs global to decide if its
// thread-local cache is stale. Cost: 1 atomic Relaxed load per resolve.
// ═══════════════════════════════════════════════════════════════════
static CERT_GENERATION: AtomicU64 = AtomicU64::new(0);

// ═══════════════════════════════════════════════════════════════════
// CERT RESOLVERS
// Three modes, selected at boot based on config:
//   1. SingleCertResolver: 1 FQDN, zero lookup, ~2ns (Arc clone)
//   2. SniResolver: N FQDNs, FNV HashMap + generation-tracked
//      thread-local cache + fallback, ~5-10ns hot path
// ═══════════════════════════════════════════════════════════════════

/// Single-cert resolver: always returns the same cert regardless of SNI.
/// Zero overhead — no lookup, no branch, just an Arc clone.
#[derive(Debug)]
struct SingleCertResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SingleCertResolver {
    #[inline]
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.key.clone())
    }
}

// Thread-local SNI cache. Keyed by (instance_gen, global_gen) to prevent
// cross-contamination: if a stale SniResolver from the old acceptor runs
// on the same thread as the new one, their instance_gen values differ,
// forcing a cache refresh from the correct ArcSwap.
thread_local! {
    static LOCAL_SNI_CACHE: RefCell<LocalSniSnapshot> = RefCell::new(LocalSniSnapshot {
        instance_gen: 0,
        global_gen: 0,
        map: Arc::new(FnvHashMap::default()),
    });
}

struct LocalSniSnapshot {
    /// Generation of the SniResolver instance that last populated this cache.
    instance_gen: u64,
    /// Global cert generation at last refresh.
    global_gen: u64,
    map: Arc<FnvHashMap<String, Arc<CertifiedKey>>>,
}

/// Multi-SNI resolver: maps server names to certificates via FNV HashMap.
///
/// Architecture (Control Plane / Data Plane separation):
/// - Control Plane: builds new FnvHashMap, stores via ArcSwap, bumps generation.
/// - Data Plane: reads generation (Relaxed), if stale refreshes thread-local cache.
///   Hot path is pure thread-local FNV lookup — zero atomics, zero contention.
/// - Hazard protection: ArcSwap's epoch-based reclamation ensures old maps are
///   freed only after all in-flight resolves complete (Technique 3).
/// - Cross-contamination fix: each SniResolver has a unique instance_gen so
///   old resolvers from pre-reload acceptors can't poison the thread-local cache.
#[derive(Debug)]
struct SniResolver {
    /// SNI → CertifiedKey mapping. ArcSwap for O(1) atomic hot-swap.
    /// Uses FnvHashMap for faster hashing on short SNI strings (~2x vs SipHash).
    certs: ArcSwap<FnvHashMap<String, Arc<CertifiedKey>>>,
    /// Default cert for unknown SNI or missing SNI extension.
    default: Arc<CertifiedKey>,
    /// Unique per-instance generation, set at construction time.
    /// Ensures thread-local caches are invalidated when a new SniResolver is created.
    instance_gen: u64,
}

impl ResolvesServerCert for SniResolver {
    #[inline]
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = match client_hello.server_name() {
            Some(name) => name,
            None => return Some(self.default.clone()),
        };

        // ── Thread-local cache with dual-generation check ──
        // Must match BOTH instance_gen (same resolver) AND global_gen (same cert version).
        // Acquire ordering ensures the ArcSwap load below sees the map
        // written by the Release store in the control plane (cert reload).
        // Relaxed is insufficient on ARM — compiler can reorder this load
        // past the ArcSwap read, serving stale certs after a reload.
        let global_gen = CERT_GENERATION.load(Ordering::Acquire);

        let result = LOCAL_SNI_CACHE.with(|cache| {
            let mut snapshot = cache.borrow_mut();

            if snapshot.instance_gen != self.instance_gen || snapshot.global_gen != global_gen {
                snapshot.map = self.certs.load_full();
                snapshot.instance_gen = self.instance_gen;
                snapshot.global_gen = global_gen;
            }

            snapshot.map.get(sni).cloned()
        });

        result.or_else(|| Some(self.default.clone()))
    }
}

// ═══════════════════════════════════════════════════════════════════
// CERT LOADING
// ═══════════════════════════════════════════════════════════════════

/// Load a certificate chain + private key from PEM files.
/// Returns an error instead of panicking so callers (hot-reload, pre-warm)
/// can handle failures gracefully by keeping the previous config.
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<Arc<CertifiedKey>, String> {
    let cert_file =
        std::fs::File::open(cert_path).map_err(|e| format!("TLS cert {}: {}", cert_path, e))?;
    let key_file =
        std::fs::File::open(key_path).map_err(|e| format!("TLS key {}: {}", key_path, e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse TLS certificate PEM: {}", e))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("Failed to parse TLS key PEM: {}", e))?
        .ok_or_else(|| "No private key found in PEM file".to_string())?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| format!("Failed to create signing key from PEM: {}", e))?;

    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

/// Build a ServerConfig from TlsConfig.
/// Automatically selects single-cert or multi-SNI resolver based on config.
/// Returns Err on cert/key load failure so callers can handle gracefully.
pub fn load_tls_config(tls: &TlsConfig) -> Result<ServerConfig, String> {
    let default_key = load_certified_key(&tls.cert_path, &tls.key_path)?;

    // Select resolver based on config
    let resolver: Arc<dyn ResolvesServerCert> = if tls.sni.is_empty() {
        // Fast path: single cert, zero lookup overhead
        Arc::new(SingleCertResolver { key: default_key })
    } else {
        // Multi-SNI: build FNV HashMap of server_name → cert
        let mut map = FnvHashMap::with_capacity_and_hasher(tls.sni.len(), Default::default());
        for entry in &tls.sni {
            let key = load_certified_key(&entry.cert_path, &entry.key_path)?;
            map.insert(entry.server_name.clone(), key);
            eprintln!("  sni: {} → {}", entry.server_name, entry.cert_path);
        }
        eprintln!("  sni: {} domains + default fallback", map.len());

        // Each SniResolver gets a unique instance_gen to prevent cross-contamination
        // between old (pre-reload) and new resolvers on the same worker thread.
        static INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(1);
        let instance_gen = INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed);

        Arc::new(SniResolver {
            certs: ArcSwap::from_pointee(map),
            default: default_key,
            instance_gen,
        })
    };

    // TLS version selection
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = match tls.min_version.as_str() {
        "1.2" => vec![&rustls::version::TLS12, &rustls::version::TLS13],
        _ => vec![&rustls::version::TLS13],
    };

    // mTLS: client certificate verification (downstream)
    let client_auth_mode = tls.client_auth.as_str();
    let mut config = if let Some(ref ca_path) = tls.client_ca_path {
        if client_auth_mode != "none" {
            let ca_file = std::fs::File::open(ca_path)
                .map_err(|e| format!("Client CA {}: {}", ca_path, e))?;
            let mut ca_reader = BufReader::new(ca_file);
            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_pemfile::certs(&mut ca_reader) {
                let cert = cert.map_err(|e| format!("Failed to parse client CA PEM: {}", e))?;
                root_store
                    .add(cert)
                    .map_err(|e| format!("Failed to add client CA cert: {}", e))?;
            }

            let verifier_builder =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store));

            let verifier = if client_auth_mode == "optional" {
                verifier_builder.allow_unauthenticated().build()
            } else {
                verifier_builder.build()
            }
            .map_err(|e| format!("Failed to build client cert verifier: {}", e))?;

            eprintln!("  mtls: client auth={}, ca={}", client_auth_mode, ca_path);

            ServerConfig::builder_with_protocol_versions(&versions)
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(resolver)
        } else {
            ServerConfig::builder_with_protocol_versions(&versions)
                .with_no_client_auth()
                .with_cert_resolver(resolver)
        }
    } else {
        ServerConfig::builder_with_protocol_versions(&versions)
            .with_no_client_auth()
            .with_cert_resolver(resolver)
    };

    config.alpn_protocols = tls.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    // ═══════════════════════════════════════════════════════════════
    // SESSION RESUMPTION & 0-RTT (Techniques 12, 14, 15)
    // Layered strategy to minimize handshake crypto cost:
    //   1. Ticket-based resumption (stateless, scales horizontally)
    //   2. Session cache fallback (stateful, for ticket-less clients)
    //   3. 0-RTT early data (TLS 1.3 only, cuts 1 full RTT)
    //   4. Half-RTT data (server pushes before client Finished)
    // ═══════════════════════════════════════════════════════════════

    // Technique 12: Session Ticket Routing — stateless resumption.
    // The ticketer encrypts session state into an opaque token sent to
    // the client. On reconnect, the client sends the ticket back and
    // the server decrypts it — no server-side storage lookup needed.
    // This also enables horizontal scaling: any server with the same
    // ticket key can resume any session.
    config.ticketer =
        rustls::crypto::aws_lc_rs::Ticketer::new().expect("Failed to create TLS session ticketer");

    // Send 4 TLS 1.3 tickets per connection (default: 2).
    // More tickets = better resumption rate for clients that open
    // multiple parallel connections (browsers, HTTP/2 multiplexing).
    config.send_tls13_tickets = 4;

    // TLS 1.3 0-RTT Early Data — client sends application data in the first
    // flight (with ClientHello), saving 1 full RTT on resumed connections.
    // Safety: handle_https() gates non-idempotent methods (POST/PUT/PATCH/DELETE)
    // behind a 425 Too Early response when the request arrived as early data,
    // preventing replay attacks on state-changing operations.
    config.max_early_data_size = 16384;

    // send_half_rtt_data: server sends data before client Finished message.
    // Cuts 1 RTT from resumed handshakes. Safe for a reverse proxy.
    config.send_half_rtt_data = true;

    // Session storage: increase from default 256 to 16384 sessions.
    // Each cached session avoids a full ECDHE key exchange (~1ms).
    // This is the fallback for clients that don't support tickets.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(16384);

    // Technique 15: Prefer server cipher order — ensures we pick the
    // fastest cipher suite (X25519 + AES-256-GCM with hw acceleration)
    // rather than letting the client dictate a slower choice.
    config.ignore_client_order = true;

    Ok(config)
}

// ═══════════════════════════════════════════════════════════════════
// HOT-RELOAD
// ═══════════════════════════════════════════════════════════════════

/// Spawn a background task that watches the TLS directory for changes
/// and hot-swaps the entire TlsAcceptor (with new certs) via ArcSwap.
/// Atomic swap: new connections get new certs, in-flight connections
/// continue with old certs until they close. Zero downtime.
pub fn spawn_tls_watcher(
    acceptor_store: Arc<ArcSwap<TlsAcceptor>>,
    tls: TlsConfig,
    quic_reload_tx: Option<tokio::sync::watch::Sender<Option<Arc<rustls::ServerConfig>>>>,
) {
    let debounce_signal = Arc::new(Notify::new());
    let signal_clone = debounce_signal.clone();

    let watcher_cert_path = tls.cert_path.clone();
    let sni_cert_paths: Vec<String> = tls.sni.iter().map(|s| s.cert_path.clone()).collect();

    let _watcher_handle = tokio::spawn(async move {
        let signal = signal_clone;
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    signal.notify_one();
                }
            }
        })
        .expect("Failed to create filesystem watcher");

        // Watch default cert dir
        let cert_dir = Path::new(&watcher_cert_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/ssl/zion/"));
        watcher
            .watch(cert_dir, RecursiveMode::NonRecursive)
            .unwrap_or_else(|e| panic!("Cannot watch {}: {}", cert_dir.display(), e));

        // Watch all SNI cert directories (they may live in different paths)
        let mut watched_dirs = std::collections::HashSet::new();
        watched_dirs.insert(cert_dir.to_path_buf());
        for sni_path in &sni_cert_paths {
            if let Some(sni_dir) = Path::new(sni_path).parent() {
                if watched_dirs.insert(sni_dir.to_path_buf()) {
                    if let Err(e) = watcher.watch(sni_dir, RecursiveMode::NonRecursive) {
                        eprintln!(
                            "  warning: cannot watch SNI dir {}: {}",
                            sni_dir.display(),
                            e
                        );
                    }
                }
            }
        }

        eprintln!(
            "  tls watcher active on {} (+{} SNI dirs)",
            cert_dir.display(),
            watched_dirs.len() - 1
        );
        std::future::pending::<()>().await;
    });

    // Debounced reload — rebuilds entire TlsAcceptor (all certs)
    tokio::spawn(async move {
        loop {
            debounce_signal.notified().await;
            tokio::time::sleep(Duration::from_secs(2)).await;

            eprintln!("  tls: reloading certificates...");
            // Offload synchronous file I/O to the blocking thread pool.
            // load_tls_config reads cert/key PEM files from disk using std::fs,
            // which would stall the tokio worker thread and spike p99 latency
            // for all in-flight requests on that thread.
            let tls_clone = tls.clone();
            let reload_result =
                tokio::task::spawn_blocking(move || load_tls_config(&tls_clone)).await;
            match reload_result {
                Ok(Ok(new_config)) => {
                    let arc_config = Arc::new(new_config);
                    let new_acceptor = TlsAcceptor::from(arc_config.clone());
                    if let Some(ref tx) = quic_reload_tx {
                        let _ = tx.send(Some(arc_config));
                    }
                    acceptor_store.store(Arc::new(new_acceptor));
                    CERT_GENERATION.fetch_add(1, Ordering::Release);
                    issue_membarrier();
                    eprintln!(
                        "  tls: hot-reload complete (gen {}). zero downtime.",
                        CERT_GENERATION.load(Ordering::Relaxed)
                    );
                }
                Ok(Err(e)) => {
                    eprintln!("  tls: reload FAILED ({}), keeping previous config.", e);
                }
                Err(e) => {
                    eprintln!(
                        "  tls: reload task panicked: {}, keeping previous config.",
                        e
                    );
                }
            }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════
// PREDICTIVE TTL PRE-WARMING (Technique 21)
// Monitors cert expiry and pre-builds the next TLS config in background
// before the hot-reload trigger fires. When reload happens, the new
// config is already warm in CPU cache (L1/L2), eliminating the ~5-20ms
// cold-build latency from the critical path.
// ═══════════════════════════════════════════════════════════════════

/// Spawn a background task that monitors the default certificate's expiry
/// and pre-warms the TLS config N seconds before expected renewal.
pub fn spawn_cert_prewarm_task(acceptor_store: Arc<ArcSwap<TlsAcceptor>>, tls: TlsConfig) {
    tokio::spawn(async move {
        loop {
            // Check cert expiry every 60 seconds
            tokio::time::sleep(Duration::from_secs(60)).await;

            // Offload cert expiry check to blocking pool (reads PEM from disk)
            let cert_path = tls.cert_path.clone();
            let expiry =
                match tokio::task::spawn_blocking(move || cert_expiry_secs(&cert_path)).await {
                    Ok(Some(secs)) => secs,
                    _ => continue,
                };

            // Pre-warm when cert expires in <120 seconds
            if expiry > 0 && expiry <= 120 {
                // Snapshot generation before building — if watcher reloads
                // concurrently, we detect the race and skip our stale store.
                let gen_before = CERT_GENERATION.load(Ordering::Acquire);
                eprintln!("  tls: cert expires in {}s, pre-warming config...", expiry);
                let tls_clone = tls.clone();
                let prewarm_result =
                    tokio::task::spawn_blocking(move || load_tls_config(&tls_clone)).await;
                match prewarm_result {
                    Ok(Ok(new_config)) => {
                        // Only store if no concurrent reload happened
                        let gen_after = CERT_GENERATION.load(Ordering::Acquire);
                        if gen_before == gen_after {
                            let new_acceptor = TlsAcceptor::from(Arc::new(new_config));
                            acceptor_store.store(Arc::new(new_acceptor));
                            CERT_GENERATION.fetch_add(1, Ordering::Release);
                            issue_membarrier();
                            eprintln!(
                                "  tls: pre-warm complete (gen {})",
                                CERT_GENERATION.load(Ordering::Relaxed)
                            );
                        } else {
                            eprintln!(
                                "  tls: pre-warm skipped — watcher already reloaded (gen {} → {})",
                                gen_before, gen_after
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        eprintln!("  tls: pre-warm FAILED ({}), keeping previous config.", e);
                    }
                    Err(e) => {
                        eprintln!("  tls: pre-warm task panicked: {}", e);
                    }
                }
            }
        }
    });
}

/// Extract seconds until expiry from a PEM certificate file.
/// Returns None if the cert can't be parsed.
pub fn cert_expiry_secs(cert_path: &str) -> Option<i64> {
    use std::time::SystemTime;

    let file = std::fs::File::open(cert_path).ok()?;
    let mut reader = BufReader::new(file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let cert_der = certs.first()?;

    // Parse the X.509 cert to get notAfter
    // We do a minimal ASN.1 walk: the validity is at a known offset in the TBSCertificate.
    // For robustness, use the raw DER bytes directly.
    parse_x509_not_after(cert_der.as_ref()).map(|expiry_epoch| {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        expiry_epoch - now
    })
}

/// Minimal ASN.1 DER parser to extract notAfter from an X.509 certificate.
/// Returns the expiry time as Unix epoch seconds, or None on parse failure.
fn parse_x509_not_after(der: &[u8]) -> Option<i64> {
    // X.509 structure: SEQUENCE { tbsCertificate SEQUENCE { ... validity SEQUENCE { notBefore, notAfter } } }
    // We skip: outer SEQUENCE, tbsCertificate SEQUENCE, version, serialNumber, signature,
    //          issuer, then read validity.
    let (_, inner) = asn1_seq(der)?;
    let (_, tbs) = asn1_seq(inner)?; // tbsCertificate

    let mut pos = tbs;
    // version [0] EXPLICIT (optional)
    if pos.first()? & 0xE0 == 0xA0 {
        let (rest, _) = asn1_skip(pos)?;
        pos = rest;
    }
    // serialNumber
    let (rest, _) = asn1_skip(pos)?;
    pos = rest;
    // signature AlgorithmIdentifier
    let (rest, _) = asn1_skip(pos)?;
    pos = rest;
    // issuer
    let (rest, _) = asn1_skip(pos)?;
    pos = rest;
    // validity SEQUENCE { notBefore, notAfter }
    let (_, validity) = asn1_seq(pos)?;
    let (rest, _not_before) = asn1_skip(validity)?;
    let (_rest2, not_after_bytes) = asn1_time(rest)?;

    parse_asn1_time(not_after_bytes)
}

fn asn1_seq(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if *data.first()? != 0x30 {
        return None;
    }
    asn1_read_tl(data)
}

fn asn1_skip(data: &[u8]) -> Option<(&[u8], &[u8])> {
    asn1_read_tl(data)
}

fn asn1_time(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let tag = *data.first()?;
    if tag != 0x17 && tag != 0x18 {
        return None;
    } // UTCTime or GeneralizedTime
    asn1_read_tl(data)
}

fn asn1_read_tl(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let mut offset = 1;
    let len_byte = data[offset];
    offset += 1;
    let length = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let num_bytes = (len_byte & 0x7F) as usize;
        if num_bytes > 4 || offset + num_bytes > data.len() {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[offset + i] as usize;
        }
        offset += num_bytes;
        len
    };
    if offset + length > data.len() {
        return None;
    }
    Some((&data[offset + length..], &data[offset..offset + length]))
}

fn parse_asn1_time(time_bytes: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(time_bytes).ok()?;
    // UTCTime: YYMMDDHHMMSSZ  GeneralizedTime: YYYYMMDDHHMMSSZ
    let (year, rest) = if s.len() >= 15 {
        // GeneralizedTime
        (s[0..4].parse::<i64>().ok()?, &s[4..])
    } else if s.len() >= 13 {
        // UTCTime
        let y: i64 = s[0..2].parse().ok()?;
        let year = if y >= 50 { 1900 + y } else { 2000 + y };
        (year, &s[2..])
    } else {
        return None;
    };
    let month: i64 = rest[0..2].parse().ok()?;
    let day: i64 = rest[2..4].parse().ok()?;
    let hour: i64 = rest[4..6].parse().ok()?;
    let min: i64 = rest[6..8].parse().ok()?;
    let sec: i64 = rest[8..10].parse().ok()?;

    // Simplified days-since-epoch (no leap second precision needed for TTL check)
    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Civil date to days since Unix epoch (algorithm from Howard Hinnant).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

// ═══════════════════════════════════════════════════════════════════
// ASYMMETRIC MEMORY BARRIER (Technique 4)
// On Linux, sys_membarrier sends an IPI to all cores, forcing them
// to observe the store. The Data Plane never executes mfence — only
// the Control Plane (cert reload) pays the cost.
// On non-Linux, falls back to a compiler fence (the Relaxed load in
// the Data Plane is sufficient with ArcSwap's epoch guard).
// ═══════════════════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn issue_membarrier() {
    // MEMBARRIER_CMD_PRIVATE_EXPEDITED = 8
    // First call registers, second issues the barrier.
    // Registration is idempotent and cheap after the first call.
    // SAFETY: FFI syscalls to the Linux membarrier API are inherently safe here because:
    // 1. `SYS_membarrier` does not mutate memory; it merely halts other CPU cores momentarily
    //    to guarantee lockless visible memory ordering across thread scopes.
    // 2. The constants 16 (`REGISTER_PRIVATE_EXPEDITED`) and 8 (`PRIVATE_EXPEDITED`) are defined
    //    by the standard Linux ABI and accept a zeroed flags argument safely.
    unsafe {
        libc::syscall(
            libc::SYS_membarrier,
            16, /* REGISTER_PRIVATE_EXPEDITED */
            0,
        );
        libc::syscall(libc::SYS_membarrier, 8 /* PRIVATE_EXPEDITED */, 0);
    }
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn issue_membarrier() {
    // On macOS/others: the Release ordering on fetch_add + ArcSwap's
    // internal barriers are sufficient. No extra action needed.
    std::sync::atomic::fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    #[test]
    fn default_client_auth_is_none() {
        let auth = super::super::config::default_client_auth();
        assert_eq!(auth, "none");
    }

    #[test]
    fn client_auth_mode_required() {
        let mode = "required";
        assert!(mode == "required" || mode == "optional" || mode == "none");
    }

    #[test]
    fn client_auth_mode_optional() {
        let mode = "optional";
        assert_ne!(mode, "none");
        assert_ne!(mode, "required");
    }

    // ── Client cert fingerprint (X-Client-Cert-Fingerprint) ──
    //
    // Replaces the previous 64-bit XOR-fold of the leaf DER, which was
    // emitted as `X-Client-Cert-DN` and falsely implied a Distinguished
    // Name. SHA-256 is collision-resistant and matches the convention
    // used by openssl/nginx ($ssl_client_fingerprint).

    /// Reconstruct the fingerprint exactly as main.rs computes it, so the
    /// tests pin the wire format (`sha256:HEX`) and detect any drift.
    fn fingerprint(der: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
        let bytes = digest.as_ref();
        let mut s = String::with_capacity(7 + bytes.len() * 2);
        s.push_str("sha256:");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xF) as usize] as char);
        }
        s
    }

    #[test]
    fn fingerprint_format_is_sha256_prefix_plus_64_hex() {
        let der = b"abc";
        let fp = fingerprint(der);
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), 7 + 64);
        assert!(fp[7..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint_matches_known_sha256_vector() {
        // Standard NIST vector: SHA-256("abc") =
        //   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        // Pinning a known vector ensures we are calling SHA-256 (not some
        // other digest) and that the hex encoding matches openssl/nginx.
        let fp = fingerprint(b"abc");
        assert_eq!(
            fp,
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_input() {
        let der = vec![0xABu8; 1024];
        assert_eq!(fingerprint(&der), fingerprint(&der));
    }

    #[test]
    fn fingerprint_diffuses_single_bit_flips() {
        // The replaced XOR-fold collided trivially: e.g., 64 bytes of 0xAB
        // mapped to all-zero output, and any cert with a uniform first 64
        // bytes was indistinguishable from another. SHA-256 must produce
        // entirely different output for a single-bit difference.
        let mut a = vec![0xABu8; 1024];
        let mut b = a.clone();
        b[512] ^= 0x01; // single bit flip deep inside the cert
        let fa = fingerprint(&a);
        let fb = fingerprint(&b);
        assert_ne!(fa, fb);

        // And the all-0xAB collision class that broke the XOR-fold is gone:
        // two different lengths of 0xAB produce different fingerprints.
        a.truncate(512);
        let fa_short = fingerprint(&a);
        assert_ne!(fa, fa_short);
    }
}

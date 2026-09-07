//! Atomic, owner-only file writes.
//!
//! Two properties every secret/state file on disk needs, and that a bare
//! `std::fs::write` gives neither of:
//!
//!   * **Atomicity.** A crash (kill -9, ENOSPC, panic, power loss) mid-write must
//!     never leave a truncated or half-updated file where a consumer expects a
//!     complete one. We write to a sibling temp file, `fsync` it, then
//!     atomically `rename` it into place and `fsync` the directory so the rename
//!     itself survives power loss.
//!   * **Owner-only permissions from birth.** A private key must never be
//!     world-readable, not even for the instant between `create` and a later
//!     `chmod`. The temp file is created `0o600` up front via `OpenOptionsExt`.
//!
//! Used for the ACME account key, the renewed TLS cert/key pair, and the mesh
//! identity seed — every file whose corruption or exposure is a real incident.

// The consumers (`acme`, `sovereign-aimp`) are feature-gated, so a
// default-features build compiles the helpers but reaches none of them; the
// tests below always exercise them. Keep the allow until an always-on caller
// exists.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};

fn tmp_sibling(path: &Path, tag: &str) -> PathBuf {
    // A per-process, per-tag sibling so two concurrent writers (or the two legs
    // of a cert/key pair) never collide on the same temp path.
    let name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    let mut fname = name;
    fname.push(format!(".{}.{tag}.tmp", std::process::id()));
    path.with_file_name(fname)
}

fn dir_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Write `bytes` to a fresh `0o600` temp sibling of `dest`, `fsync` it, and
/// return the temp path — staged but NOT yet visible at `dest`. Call
/// [`commit`] to atomically move it into place, or drop it to abandon.
fn stage(dest: &Path, bytes: &[u8], tag: &str) -> Result<PathBuf, String> {
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = tmp_sibling(dest, tag);

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // created 0o600 — never wider, even in transit
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("cannot create temp file '{}': {e}", tmp.display()))?;

    let write = (|| -> std::io::Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?; // fsync the data before it can be renamed over a live file
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write '{}': {e}", tmp.display()));
    }
    Ok(tmp)
}

/// Atomically move a staged temp file onto `dest`.
fn commit(tmp: &Path, dest: &Path) -> Result<(), String> {
    std::fs::rename(tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(tmp);
        format!(
            "cannot rename '{}' -> '{}': {e}",
            tmp.display(),
            dest.display()
        )
    })
}

/// Best-effort `fsync` of a directory so a rename into it is durable across
/// power loss (not merely a process crash). A filesystem that refuses to fsync a
/// read-only dir handle must not fail an otherwise-successful write.
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    if let Ok(f) = std::fs::File::open(dir) {
        let _ = f.sync_all();
    }
}
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

/// Atomically write `bytes` to `path`, owner-only (`0o600`). All-or-nothing: on
/// any error `path` is left untouched.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = stage(path, bytes, "s")?;
    commit(&tmp, path)?;
    fsync_dir(dir_of(path));
    Ok(())
}

/// Atomically write a certificate and its private key as one logical unit.
///
/// Both temp files are staged and `fsync`ed FIRST, then renamed into place — key
/// before cert, so a crash never presents a new certificate without the private
/// key that matches it. The only residual window is the sub-microsecond gap
/// between the two `rename` syscalls; the TLS loader additionally verifies
/// cert/key correspondence and keeps the last-good pair on mismatch, so even
/// that window degrades to "keep serving the old cert", never a hard outage.
pub fn write_cert_key_atomic(
    key_path: &Path,
    key_bytes: &[u8],
    cert_path: &Path,
    cert_bytes: &[u8],
) -> Result<(), String> {
    let key_tmp = stage(key_path, key_bytes, "key")?;
    let cert_tmp = match stage(cert_path, cert_bytes, "cert") {
        Ok(t) => t,
        Err(e) => {
            let _ = std::fs::remove_file(&key_tmp);
            return Err(e);
        }
    };
    // Both staged + fsynced. Commit key first, then cert.
    commit(&key_tmp, key_path)?;
    commit(&cert_tmp, cert_path)?;
    fsync_dir(dir_of(key_path));
    if dir_of(cert_path) != dir_of(key_path) {
        fsync_dir(dir_of(cert_path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_content_and_replaces_existing() {
        let dir = std::env::temp_dir().join(format!("zion-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f");
        write_atomic_0600(&p, b"one").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        write_atomic_0600(&p, b"two-longer").unwrap(); // replace, no truncation artifact
        assert_eq!(std::fs::read(&p).unwrap(), b"two-longer");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn created_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("zion-atomic-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("key");
        write_atomic_0600(&p, b"secret").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be created owner-only");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_temp_files_left_behind() {
        let dir = std::env::temp_dir().join(format!("zion-atomic-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.pem");
        let cert = dir.join("c.pem");
        write_cert_key_atomic(&key, b"KEY", &cert, b"CERT").unwrap();
        assert_eq!(std::fs::read(&key).unwrap(), b"KEY");
        assert_eq!(std::fs::read(&cert).unwrap(), b"CERT");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "no .tmp files should remain: {leftovers:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

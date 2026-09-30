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
fn stage(dest: &Path, bytes: &[u8], tag: &str, mode: u32) -> Result<PathBuf, String> {
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = tmp_sibling(dest, tag);

    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode); // secrets pass 0o600 — never wider, even in transit
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts
        .open(&tmp)
        .map_err(|e| format!("cannot create temp file '{}': {e}", tmp.display()))?;

    let write = (|| -> std::io::Result<()> {
        f.write_all(bytes)?;
        // `mode` above is masked by the umask at creation; set it explicitly so
        // a config file keeps exactly the mode we were asked for.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
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

/// Hard-link the file currently at `path` (if any) to a sibling backup name.
fn backup_link(path: &Path) -> Option<std::path::PathBuf> {
    if !path.exists() {
        return None;
    }
    let mut name = path.file_name()?.to_os_string();
    name.push(format!(".zion-bak-{}", std::process::id()));
    let bak = path.with_file_name(name);
    let _ = std::fs::remove_file(&bak);
    std::fs::hard_link(path, &bak).ok().map(|()| bak)
}

fn discard(bak: Option<&Path>) {
    if let Some(b) = bak {
        let _ = std::fs::remove_file(b);
    }
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
    let tmp = stage(path, bytes, "s", 0o600)?;
    commit(&tmp, path)?;
    fsync_dir(dir_of(path));
    Ok(())
}

/// Atomically replace a non-secret config file (`zion.toml`): temp sibling,
/// `fsync`, `rename`, directory `fsync`. All-or-nothing — a kill or `ENOSPC`
/// mid-write leaves the previous file intact instead of a truncated one that the
/// hot-reload watcher (or the next boot) would read.
///
/// Unlike [`write_atomic_0600`] this is for files that are meant to be readable:
///   * an existing destination keeps its permission bits (a `0640` config stays
///     `0640`); a new file is `0644`;
///   * a symlinked destination is written *through* (the link survives, its
///     target is replaced) rather than being swapped for a regular file.
pub fn write_atomic_config(path: &Path, bytes: &[u8]) -> Result<(), String> {
    // Write through a symlink to the real file; a missing path is used as-is.
    let dest = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&dest)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o644)
    };
    #[cfg(not(unix))]
    let mode = 0o644;
    let tmp = stage(&dest, bytes, "c", mode)?;
    commit(&tmp, &dest)?;
    fsync_dir(dir_of(&dest));
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
    let key_tmp = stage(key_path, key_bytes, "key", 0o600)?;
    let cert_tmp = match stage(cert_path, cert_bytes, "cert", 0o600) {
        Ok(t) => t,
        Err(e) => {
            let _ = std::fs::remove_file(&key_tmp);
            return Err(e);
        }
    };
    // Both staged + fsynced. Keep a link to the current key so a failed cert commit
    // can put it back: without it the disk would hold the NEW key beside the OLD
    // cert, and a fresh boot could not load that pair.
    let key_bak = backup_link(key_path);
    if let Err(e) = commit(&key_tmp, key_path) {
        let _ = std::fs::remove_file(&cert_tmp);
        discard(key_bak.as_deref());
        return Err(e);
    }
    if let Err(e) = commit(&cert_tmp, cert_path) {
        return Err(match key_bak {
            Some(bak) => match std::fs::rename(&bak, key_path) {
                Ok(()) => format!("{e} (previous key restored)"),
                Err(re) => format!(
                    "{e}; ALSO could not restore the previous key from '{}': {re}",
                    bak.display()
                ),
            },
            None => e,
        });
    }
    discard(key_bak.as_deref());
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
    fn failed_cert_commit_restores_the_previous_key() {
        let dir = std::env::temp_dir().join(format!("zion-atomic-rb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (key, cert) = (dir.join("k.pem"), dir.join("c.pem"));
        write_cert_key_atomic(&key, b"KEY-1", &cert, b"CERT-1").unwrap();
        // A non-empty directory where the cert must land makes its rename fail.
        std::fs::remove_file(&cert).unwrap();
        std::fs::create_dir_all(cert.join("blocker")).unwrap();
        let e = write_cert_key_atomic(&key, b"KEY-2", &cert, b"CERT-2").unwrap_err();
        assert!(e.contains("previous key restored"), "{e}");
        assert_eq!(std::fs::read(&key).unwrap(), b"KEY-1", "old key must be back");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("zion-bak") || n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "stray files: {leftovers:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_write_replaces_atomically_and_defaults_to_0644() {
        let dir = std::env::temp_dir().join(format!("zion-atomic-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("zion.toml");
        write_atomic_config(&p, b"old = 1\n").unwrap();
        write_atomic_config(&p, b"new = 2\n").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"new = 2\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "a new config is world-readable, not 0600");
        }
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temp file may remain");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn config_write_preserves_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("zion-atomic-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("zion.toml");
        std::fs::write(&p, b"a").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic_config(&p, b"b").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "an existing config keeps its permissions");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn config_write_goes_through_a_symlink() {
        let dir = std::env::temp_dir().join(format!("zion-atomic-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.toml");
        let link = dir.join("zion.toml");
        std::fs::write(&real, b"a").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_atomic_config(&link, b"b").unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink must survive"
        );
        assert_eq!(
            std::fs::read(&real).unwrap(),
            b"b",
            "the target is replaced"
        );
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

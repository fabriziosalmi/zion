// SPDX-License-Identifier: Apache-2.0
//! Build script: stamp the git revision into the binary so a loose artifact can
//! be tied back to the exact commit it was built from (a SLSA/attestation gap
//! when only CARGO_PKG_VERSION is embedded).
//!
//! Dependency-free — it shells out to `git`. When `.git` is absent (a source
//! tarball, a vendored build), every value degrades to "unknown" and the build
//! still succeeds. The commit DATE (not wall-clock build time) is used so the
//! stamp stays reproducible across rebuilds of the same commit.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    // Re-run when HEAD moves or the index changes, so the stamp stays current.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let mut sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // Mark a build made from a dirty working tree — it does not correspond to
    // any published commit.
    if git(&["status", "--porcelain"]).is_some_and(|s| !s.is_empty()) {
        sha.push_str("-dirty");
    }
    let date = git(&[
        "show",
        "-s",
        "--format=%cd",
        "--date=format:%Y-%m-%d",
        "HEAD",
    ])
    .unwrap_or_else(|| "unknown".into());

    println!("cargo:rustc-env=ZION_GIT_SHA={sha}");
    println!("cargo:rustc-env=ZION_COMMIT_DATE={date}");
}

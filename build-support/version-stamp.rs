// Shared build-script body, include!()d by nfs-klldap-ui/build.rs and
// nfs-klldap-config/build.rs so every binary carries the same stamp in
// NFS_KLLDAP_BUILD_VERSION. Plain `//` comments only: this file is pasted
// into each build script, so `//!` inner docs would not parse there.
//
// Precedence: an explicit NFS_KLLDAP_BUILD_VERSION env override (escape hatch
// for builds without a repo), else git — the branch IS the version when it
// looks like one (leading digit, this repo's branch-as-version convention),
// the package version otherwise, with the short commit hash appended — else
// CARGO_PKG_VERSION alone (tarball builds).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

fn git_version() -> Option<String> {
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])?;
    let hash = git(&["rev-parse", "--short", "HEAD"])?;
    // Detached HEAD reads "HEAD" and integration branches read "main" — both
    // fall back to the package version as the name; the hash still pins code.
    let name = if branch.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        branch
    } else {
        env!("CARGO_PKG_VERSION").to_string()
    };
    Some(format!("{name} ({hash})"))
}

fn emit_version_stamp() {
    println!("cargo:rerun-if-env-changed=NFS_KLLDAP_BUILD_VERSION");
    // Re-stamp when the checkout moves: HEAD flips on branch switch, the ref
    // file / packed-refs move on commit. Only existing paths are watched — a
    // missing watch path would force a build-script rerun on every build.
    if let Some(dir) = git(&["rev-parse", "--absolute-git-dir"]) {
        let dir = std::path::PathBuf::from(dir);
        let mut watch = vec![dir.join("HEAD"), dir.join("packed-refs")];
        if let Some(r) = git(&["symbolic-ref", "-q", "HEAD"]) {
            watch.push(dir.join(r));
        }
        for p in watch {
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }
    let version = std::env::var("NFS_KLLDAP_BUILD_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(git_version)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=NFS_KLLDAP_BUILD_VERSION={version}");
}

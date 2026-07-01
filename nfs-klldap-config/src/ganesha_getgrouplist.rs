//! Ganesha 9.6 getgrouplist compatibility: Linux positive-return semantics + idhelper socket backstop.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use nfs_klldap_identity::{machine_short_name, principal_local_part};

/// Ganesha 9.6 `my_getgrouplist_alloc` treats success as `ret == 0`; Linux glibc returns positive ngroups.
pub fn normalize_linux_getgrouplist_ret(ret: i32) -> i32 {
    if ret > 0 {
        0
    } else if ret < 0 {
        -1
    } else {
        0
    }
}

/// Query idhelper `GROUPLIST` / `GRPS` socket for authoritative gid list.
pub fn query_idhelper_socket_gids(socket_path: &str, cmd: &str, query: &str) -> Option<Vec<u32>> {
    if !Path::new(socket_path).exists() {
        return None;
    }
    let mut stream = UnixStream::connect(socket_path).ok()?;
    let req = format!("{cmd} {query}\n");
    stream.write_all(req.as_bytes()).ok()?;
    stream.flush().ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let resp = line.trim();
    let rest = resp.strip_prefix("OK ")?;
    let gids: Vec<u32> = rest
        .split('|')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    if gids.is_empty() {
        None
    } else {
        Some(gids)
    }
}

/// Login aliases Ganesha may pass to getgrouplist for a configured principal.
fn shortnames_from_principal(principal: &str) -> Vec<String> {
    let mut out = Vec::new();
    for candidate in [machine_short_name(principal), principal_local_part(principal)] {
        if candidate.is_empty() {
            continue;
        }
        let s = candidate.to_string();
        if !out.iter().any(|x| x == &s) {
            out.push(s);
        }
    }
    out
}

/// Short passwd logins the shim intercepts (root + configured principals' local parts).
pub fn getgrouplist_intercept_shortnames() -> Vec<String> {
    let mut names = vec!["root".to_string()];
    if let Ok(extra) = std::env::var("NFS_KLLDAP_GETGROUPLIST_ALLOWLIST") {
        for part in extra.split(',') {
            let t = part.trim();
            if !t.is_empty() && !names.iter().any(|n| n == t) {
                names.push(t.to_string());
            }
        }
    }
    if let Ok(pre) = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE") {
        for part in pre.split(',') {
            let t = part.trim();
            if t.is_empty() {
                continue;
            }
            for s in shortnames_from_principal(t) {
                if !names.iter().any(|n| n == &s) {
                    names.push(s);
                }
            }
        }
    }
    if let Ok(user) = std::env::var("TEST_IDHELPER_CHECK_USER_PRINCIPAL") {
        let t = user.trim();
        if !t.is_empty() {
            for s in shortnames_from_principal(t) {
                if !names.iter().any(|n| n == &s) {
                    names.push(s);
                }
            }
        }
    }
    names
}

/// Map a short login to a principal query for the idhelper socket (best-effort).
pub fn principal_query_for_shortname(short: &str) -> String {
    if short.eq_ignore_ascii_case("root") {
        return "root".to_string();
    }
    if let Ok(pre) = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE") {
        for part in pre.split(',') {
            let t = part.trim();
            if shortnames_from_principal(t).iter().any(|s| s == short) {
                return t.to_string();
            }
        }
    }
    if let Ok(user) = std::env::var("TEST_IDHELPER_CHECK_USER_PRINCIPAL") {
        let t = user.trim();
        if shortnames_from_principal(t).iter().any(|s| s == short) {
            return t.to_string();
        }
    }
    short.to_string()
}

pub fn should_intercept_getgrouplist(user: &str) -> bool {
    getgrouplist_intercept_shortnames()
        .iter()
        .any(|n| n == user)
}

/// Resolve path to the Rust getgrouplist shim cdylib.
pub fn resolve_getgrouplist_shim_so() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("NFS_KLLDAP_GETGROUPLIST_SHIM_SO") {
        let pb = std::path::PathBuf::from(&p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let arch = std::env::consts::ARCH;
    for cand in [
        format!("/usr/lib/{arch}-linux-gnu/libnfs_klldap_getgrouplist_shim.so"),
        format!("/usr/lib/{arch}/libnfs_klldap_getgrouplist_shim.so"),
        "/usr/lib64/libnfs_klldap_getgrouplist_shim.so".into(),
        "/usr/lib/x86_64-linux-gnu/libnfs_klldap_getgrouplist_shim.so".into(),
        "/usr/lib/aarch64-linux-gnu/libnfs_klldap_getgrouplist_shim.so".into(),
        "/usr/local/lib/libnfs_klldap_getgrouplist_shim.so".into(),
    ] {
        let pb = std::path::PathBuf::from(cand);
        if pb.is_file() {
            return Some(pb);
        }
    }
    None
}

/// Build LD_PRELOAD chain: shim first, then nss_wrapper, then any existing entries.
pub fn ld_preload_chain_for_ganesha(nss_wrapper_so: &Path) -> std::path::PathBuf {
    let mut parts = Vec::new();
    if let Some(shim) = resolve_getgrouplist_shim_so() {
        parts.push(shim.display().to_string());
    }
    if nss_wrapper_so.is_file() {
        parts.push(nss_wrapper_so.display().to_string());
    }
    if let Ok(cur) = std::env::var("LD_PRELOAD") {
        for p in cur.split(':') {
            let p = p.trim();
            if !p.is_empty() && !parts.iter().any(|x| x == p) && Path::new(p).exists() {
                parts.push(p.to_string());
            }
        }
    }
    std::path::PathBuf::from(parts.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_linux_getgrouplist_ret_maps_positive_to_zero() {
        assert_eq!(normalize_linux_getgrouplist_ret(1), 0);
        assert_eq!(normalize_linux_getgrouplist_ret(3), 0);
        assert_eq!(normalize_linux_getgrouplist_ret(0), 0);
        assert_eq!(normalize_linux_getgrouplist_ret(-1), -1);
    }

    #[test]
    fn should_intercept_root_machine_short_and_user_shortnames() {
        let old = std::env::var("NFS_KLLDAP_IDHELPER_PRERESOLVE").ok();
        std::env::set_var(
            "NFS_KLLDAP_IDHELPER_PRERESOLVE",
            "host/zima-nas@REALM,testuser1@REALM",
        );
        assert!(should_intercept_getgrouplist("root"));
        assert!(should_intercept_getgrouplist("testuser1"));
        assert!(should_intercept_getgrouplist("zima-nas"), "machine_short_name must intercept");
        assert!(!should_intercept_getgrouplist("nobody"));
        assert_eq!(
            principal_query_for_shortname("zima-nas"),
            "host/zima-nas@REALM"
        );
        if let Some(v) = old {
            std::env::set_var("NFS_KLLDAP_IDHELPER_PRERESOLVE", v);
        } else {
            std::env::remove_var("NFS_KLLDAP_IDHELPER_PRERESOLVE");
        }
    }
}
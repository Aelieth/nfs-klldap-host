//! Principal resolution: NSS getent, structured LDAP, and cache.

use crate::dlog;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use nfs_klldap_config::{
    classify_principal, from_sssd_section, parse_getent_passwd, IdLdapResolver, IdMapSnapshot,
    NfsKlldapConfig, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
};

use crate::common::{
    debug_enabled, machine_short_name, normalize_principal, principal_local_part, IdCache,
    PrincipalKind, Resolved, CACHE_PATH,
};
use crate::materialize::{materialize_nss_wrappers_at, NssMaterializePaths};

/// getent (NSS) path for "same lookup a client would see". Falls back to resolver snapshot.
fn resolve_via_nss(name_or_principal: &str) -> Option<(u32, u32, String)> {
    let trimmed = name_or_principal.trim();
    let short = principal_local_part(trimmed);
    if let Some(res) = resolve_getent(trimmed) {
        return Some(res);
    }
    if short != trimmed {
        if let Some(res) = resolve_getent(short) {
            return Some(res);
        }
    }

    // LDAP fallback tries full principal and short posix name inside resolver.
    if let Some((uid, gid)) = resolve_via_structured_ldap(trimmed) {
        dlog!("ldap fallback principal=\"{}\" uid={} gid={}", trimmed, uid, gid);
        return Some((uid, gid, "ldap".to_string()));
    }
    None
}

fn uid_gid_from_user_resolve(
    resolver: &IdLdapResolver,
    name: &str,
    bind_dn: &str,
    bind_pw: &str,
) -> Option<(u32, u32)> {
    let (uid_i, gid_opt, _disp) = resolver.resolve_user(name, bind_dn, bind_pw)?;
    let uid = uid_i as u32;
    let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
    Some((uid, gid))
}

fn uid_gid_from_snapshot(snap: &IdMapSnapshot, full: &str, short: &str) -> Option<(u32, u32)> {
    if let Some(u) = snap.users.get(full) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some(u) = snap.users.get(short) {
        return Some((u.uid as u32, u.gid as u32));
    }
    None
}

/// LDAP snapshot first, then resolve_user; on miss reload full directory and retry.
fn resolve_via_structured_ldap(name_or_principal: &str) -> Option<(u32, u32)> {
    let (resolver, bind_dn, bind_pw) = get_or_init_resolver()?;
    let short = principal_local_part(name_or_principal);
    let try_resolve = |snap: &IdMapSnapshot| {
        uid_gid_from_snapshot(snap, name_or_principal, short)
            .or_else(|| uid_gid_from_user_resolve(resolver, name_or_principal, bind_dn, bind_pw))
            .or_else(|| uid_gid_from_user_resolve(resolver, short, bind_dn, bind_pw))
    };
    if let Some(ids) = try_resolve(&resolver.snapshot()) {
        return Some(ids);
    }
    let _ = resolver.load_full_identities(bind_dn, bind_pw);
    try_resolve(&resolver.snapshot())
}

/// Load resolver + bind creds from NfsKlldapConfig (NFS_CONFIG).
fn load_resolver_from_config() -> Option<(IdLdapResolver, String, String)> {
    let path = std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    let cfg = NfsKlldapConfig::load(std::path::Path::new(&path)).ok()?;
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty() || cfg.sssd.ldap_default_authtok.trim().is_empty() {
        return None;
    }
    let resolver = from_sssd_section(&cfg.ldap_uri, &cfg.sssd, &cfg.effective_realm());
    Some((resolver, cfg.sssd.ldap_default_bind_dn.clone(), cfg.sssd.ldap_default_authtok.clone()))
}

/// Lazy resolver init so 10m IdLdapResolver caches persist across resolve/getent/observer calls.
pub(crate) static ID_RESOLVER: OnceLock<Option<(IdLdapResolver, String, String)>> =
    OnceLock::new();

pub(crate) fn get_or_init_resolver() -> Option<(&'static IdLdapResolver, &'static str, &'static str)> {
    if ID_RESOLVER.get().and_then(|o| o.as_ref()).is_none() {
        let _ = ID_RESOLVER.set(Some(load_resolver_from_config()?));
    }
    let c = ID_RESOLVER.get().and_then(|o| o.as_ref())?;
    Some((&c.0, &c.1, &c.2))
}

fn resolve_getent(name: &str) -> Option<(u32, u32, String)> {
    // Primary lookup is short posix name; callers also try full principal forms.
    dlog!("getent passwd \"{}\" called", name);
    let out = Command::new("getent")
        .args(["passwd", name])
        .output()
        .ok()?;
    if !out.status.success() {
        dlog!("getent passwd \"{}\" -> failed (status={:?})", name, out.status.code());
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next().unwrap_or("");
    if let Some((uid, gid)) = parse_getent_passwd(line) {
        dlog!("getent passwd \"{}\" -> success uid={} gid={}", name, uid, gid);
        return Some((uid, gid, "sss".to_string()));
    }
    dlog!("getent passwd \"{}\" -> malformed output", name);
    None
}

/// Classify machine→uid 0 or resolve user via NSS/LDAP; materialize into nss_wrapper on change.
pub(crate) fn resolve_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
    cache: &mut IdCache,
) -> Resolved {
    let principal = principal.trim();
    let start = Instant::now();
    let norm = normalize_principal(principal);

    dlog!("RESOLVE principal=\"{}\"", principal);
    dlog!("  normalized=\"{}\"", norm);

    if principal.contains('@') {
        dlog!("  kerberos form: getent/LDAP try full principal then short name");
    }

    if let Some(existing) = cache.get(&norm).cloned() {
        let mut e = existing;
        e.source = "cache".to_string();
        if debug_enabled() {
            eprintln!("[idhelper] cache=HIT key=\"{}\"", norm);
            eprintln!(
                "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (cache hit)",
                e.principal, e.name, e.uid, e.gid, e.kind.as_str(), e.source
            );
        }
        let elapsed = start.elapsed();
        dlog!(
            "  result uid={} gid={} kind={} source={} elapsed={:?}",
            e.uid, e.gid, e.kind.as_str(), e.source, elapsed
        );
        return e;
    }
    if debug_enabled() {
        eprintln!("[idhelper] cache=MISS key=\"{}\"", norm);
    }

    let (is_machine, reason) = classify_principal(principal, realm, server_variants);
    dlog!("  classify is_machine={} reason=\"{}\"", is_machine, reason);
    if debug_enabled() {
        eprintln!(
            "[idhelper] CLASSIFY principal=\"{}\" -> {} (reason=\"{}\")",
            principal,
            if is_machine { "machine" } else { "user" },
            reason
        );
    }

    let kind = if is_machine {
        PrincipalKind::Machine
    } else {
        PrincipalKind::User
    };

    // Attempt resolution
    let resolved = if is_machine {
        // Machine principals (host/, nfs/, root/, server variants): map 0:0 without getent/LDAP.
        let short = machine_short_name(principal);
        if debug_enabled() {
            eprintln!(
                "[idhelper] short_name_extracted=\"{}\" (machine path, principal=\"{}\")",
                short, principal
            );
        }

        // No resolve_via_nss / getent calls for machines.
        Resolved {
            principal: principal.to_string(),
            name: short.to_string(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".to_string(),
        }
    } else {
        dlog!("  user_path principal=\"{}\"", principal);
        let looked = resolve_via_nss(principal);
        dlog!("  nss_getent final_got={:?}", looked.as_ref().map(|(u, g, s)| (*u, *g, s.as_str())));

        if let Some((uid, gid, src)) = looked {
            let name = principal_local_part(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid,
                gid,
                kind,
                source: src,
            }
        } else {
            // Nobody fallback: materialize so getpwnam under nss_wrapper can resolve it.
            eprintln!(
                "[idhelper] FALLBACK {} for principal=\"{}\" (no uid/gid from getent or structured resolver)",
                FALLBACK_NOBODY_UID, principal
            );
            let name = principal_local_part(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid: FALLBACK_NOBODY_UID,
                gid: FALLBACK_NOBODY_GID,
                kind: PrincipalKind::Unknown,
                source: "direct".to_string(),
            }
        }
    };

    dlog!(
        "  resolved principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={}",
        resolved.principal, resolved.name, resolved.uid, resolved.gid, resolved.kind.as_str(), resolved.source
    );

    if debug_enabled() {
        eprintln!(
            "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (sent to ganesha)",
            resolved.principal,
            resolved.name,
            resolved.uid,
            resolved.gid,
            resolved.kind.as_str(),
            resolved.source
        );
    }

    let fp_before = cache.content_fingerprint();
    cache.insert(resolved.clone());
    if fp_before != cache.content_fingerprint() {
        let write_res = cache.write_to_file(Path::new(CACHE_PATH));
        dlog!(
            "  cache_write result={}",
            if write_res.is_ok() { "ok" } else { "err" }
        );
        let snap_groups = get_or_init_resolver().map(|(r, _, _)| r.snapshot().groups);
        if let Err(e) = materialize_nss_wrappers_at(
            cache,
            &NssMaterializePaths::production(),
            snap_groups.as_ref(),
        ) {
            dlog!("  nss_wrapper_write err={}", e);
        }
    }

    // Warm SSSD/getent after a successful user resolve (non-blocking).
    if resolved.uid != 0 && resolved.uid != FALLBACK_NOBODY_UID {
        let _ = Command::new("sss_cache")
            .args(["-u", &resolved.name])
            .output();
        let _ = Command::new("getent")
            .args(["passwd", &resolved.name])
            .output();
    }

    eprintln!(
        "[idhelper] MAPPED FOR GANESHA principal=\"{}\" uid={} gid={} source={}",
        resolved.principal, resolved.uid, resolved.gid, resolved.source
    );

    let elapsed = start.elapsed();
    dlog!("  elapsed={:?}", elapsed);

    resolved
}

#[cfg(test)]
mod tests {
    use super::*;
    use nfs_klldap_config::PosixUserEntry;

    #[test]
    fn snapshot_lookup_needs_full_principal_key() {
        let mut snap = IdMapSnapshot::default();
        snap.users.insert(
            "alice@REALM".into(),
            PosixUserEntry {
                uid: 1001,
                gid: 1001,
                display: "alice".into(),
            },
        );
        assert_eq!(uid_gid_from_snapshot(&snap, "alice@REALM", "alice"), Some((1001, 1001)));
        assert_eq!(uid_gid_from_snapshot(&snap, "alice", "alice"), None);
    }
}

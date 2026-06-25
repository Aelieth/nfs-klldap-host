//! Principal resolution: NSS getent, structured LDAP, and cache.

use crate::dlog;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use nfs_klldap_config::{
    from_sssd_section, parse_getent_passwd, IdLdapResolver, IdMapSnapshot, NfsKlldapConfig,
    FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
};

use crate::common::{
    debug_enabled, is_machine_principal, normalize_principal, IdCache, PrincipalKind, Resolved,
    CACHE_PATH,
};
use crate::materialize::{materialize_nss_wrappers_at, NssMaterializePaths};

/// getent (NSS) path for "same lookup a client would see". Falls back to resolver snapshot.
fn resolve_via_nss(name_or_principal: &str) -> Option<(u32, u32, String)> {
    // Try as-is first (handles user@REALM in some setups)
    if let Some(res) = resolve_getent(name_or_principal) {
        return Some(res);
    }
    // Try without realm
    if let Some(at) = name_or_principal.rfind('@') {
        let short = &name_or_principal[..at];
        if let Some(res) = resolve_getent(short) {
            return Some(res);
        }
    }
    // Try common variants
    let short = name_or_principal.split('@').next().unwrap_or(name_or_principal);
    if let Some(res) = resolve_getent(short) {
        return Some(res);
    }

    // Fallback to structured LDAP resolution via IdLdapResolver.
    // Uses the same PosixAttributeMapping, filters, and caching logic as
    // nfs-klldap-ui/src/ldap.rs so behavior + cache effectiveness are identical
    // and we do not hit the server on every miss.
    if let Some((uid, gid)) = resolve_via_structured_ldap(short) {
        dlog!(
            "getent passwd \"{}\" -> ldap fallback uid={} gid={}",
            short,
            uid,
            gid
        );
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
    let short = name_or_principal.split('@').next().unwrap_or(name_or_principal);

    if let Some(ids) = uid_gid_from_snapshot(&resolver.snapshot(), name_or_principal, short) {
        return Some(ids);
    }
    if let Some(ids) = uid_gid_from_user_resolve(resolver, name_or_principal, &bind_dn, &bind_pw) {
        return Some(ids);
    }
    if let Some(ids) = uid_gid_from_user_resolve(resolver, short, &bind_dn, &bind_pw) {
        return Some(ids);
    }

    let _ = resolver.load_full_identities(&bind_dn, &bind_pw);
    let snap2 = resolver.snapshot();
    uid_gid_from_snapshot(&snap2, name_or_principal, short)
        .or_else(|| uid_gid_from_user_resolve(resolver, name_or_principal, &bind_dn, &bind_pw))
        .or_else(|| uid_gid_from_user_resolve(resolver, short, &bind_dn, &bind_pw))
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

pub(crate) fn get_or_init_resolver() -> Option<(&'static IdLdapResolver, String, String)> {
    if let Some(cached) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        return Some((&cached.0, cached.1.clone(), cached.2.clone()));
    }
    let (resolver, bind_dn, bind_pw) = load_resolver_from_config()?;
    let _ = ID_RESOLVER.set(Some((resolver, bind_dn.clone(), bind_pw.clone())));
    if let Some(cached) = ID_RESOLVER.get().and_then(|o| o.as_ref()) {
        return Some((&cached.0, cached.1.clone(), cached.2.clone()));
    }
    None
}

fn resolve_getent(name: &str) -> Option<(u32, u32, String)> {
    // getent passwd <name> -> name:pass:uid:gid:...
    // The short name path (testuser1) is the primary for "same lookup as client".
    // Full principal is also attempted (by callers) for principal mapping.
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
    let start = Instant::now();
    let norm = normalize_principal(principal);

    dlog!("RESOLVE principal=\"{}\"", principal);
    dlog!("  normalized=\"{}\"", norm);

    if principal.contains('@') {
        dlog!("  (kerberos principal form - will attempt full + short + principal attr paths)");
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

    let (is_machine, reason) = is_machine_principal(principal, realm, server_variants);
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
        let short = principal
            .split('@')
            .next()
            .unwrap_or(principal)
            .split('/')
            .next_back()
            .unwrap_or(principal);
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
        // Regular user
        let first_try = principal;
        let second_try = principal.split('@').next().unwrap_or(principal);
        dlog!("  user_path first_try=\"{}\" second_try=\"{}\"", first_try, second_try);

        // getent then LDAP (resolve_via_nss already chains structured LDAP on miss).
        let looked = resolve_via_nss(first_try).or_else(|| resolve_via_nss(second_try));
        dlog!("  nss_getent final_got={:?}", looked.as_ref().map(|(u, g, s)| (*u, *g, s.as_str())));

        if let Some((uid, gid, src)) = looked {
            let name = principal.split('@').next().unwrap_or(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid,
                gid,
                kind,
                source: src,
            }
        } else {
            // Nobody fallback: materialize into nss_passwd so Ganesha getpwnam under nss_wrapper can resolve it.
            eprintln!(
                "[idhelper] FALLBACK {} for principal=\"{}\" (no uid/gid from getent or structured resolver)",
                FALLBACK_NOBODY_UID, principal
            );
            let name = principal.split('@').next().unwrap_or(principal).to_string();
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

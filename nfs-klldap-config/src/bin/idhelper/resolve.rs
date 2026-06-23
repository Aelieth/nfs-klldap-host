//! Principal resolution: NSS getent, structured LDAP, and cache.

use crate::dlog;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

use nfs_klldap_config::{
    from_sssd_section, parse_getent_passwd, IdLdapResolver, IdMapSnapshot, NfsKlldapConfig,
};

use crate::common::{
    is_machine_principal, normalize_principal, IdCache, PrincipalKind, Resolved, CACHE_PATH,
};
use crate::materialize::materialize_nss_wrappers;

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
        eprintln!("[idhelper] getent passwd \"{}\" -> ldap fallback success uid={} gid={}", short, uid, gid);
        return Some((uid, gid, "ldap".to_string()));
    }
    None
}

/// Structured LDAP resolution using IdLdapResolver + full in-memory snapshot (preferred hot path).
/// The bulk 10m load (called at daemon start) ensures we have all users+groups with aligned gids.
/// On miss we force a fresh full load (covers users added after start or in nested OUs that a
/// previous narrow base might have missed) then retry.
/// Accepts full principal (for krbPrincipalName lookup) or short name.
fn resolve_via_structured_ldap(name_or_principal: &str) -> Option<(u32, u32)> {
    let (resolver, bind_dn, bind_pw) = get_or_init_resolver()?;

    let short = name_or_principal.split('@').next().unwrap_or(name_or_principal);

    // Prefer in-memory snapshot (try full principal key then short)
    let snap: IdMapSnapshot = resolver.snapshot();
    if let Some(u) = snap.users.get(name_or_principal) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some(u) = snap.users.get(short) {
        return Some((u.uid as u32, u.gid as u32));
    }

    // Single resolve with full first (enables dual principal attr logic), then short
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(name_or_principal, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(short, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }

    // Miss - force a fresh full load then retry
    let _ = resolver.load_full_identities(&bind_dn, &bind_pw);
    let snap2: IdMapSnapshot = resolver.snapshot();
    if let Some(u) = snap2.users.get(name_or_principal) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some(u) = snap2.users.get(short) {
        return Some((u.uid as u32, u.gid as u32));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(name_or_principal, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    if let Some((uid_i, gid_opt, _disp)) = resolver.resolve_user(short, &bind_dn, &bind_pw) {
        let uid = uid_i as u32;
        let gid = gid_opt.map(|g| g as u32).unwrap_or(uid);
        return Some((uid, gid));
    }
    None
}

/// Load resolver + bind creds from NfsKlldapConfig (NFS_CONFIG).
fn load_resolver_from_config() -> Option<(IdLdapResolver, String, String)> {
    let path = std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    let cfg = NfsKlldapConfig::load(std::path::Path::new(&path)).ok()?;
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty() || cfg.sssd.ldap_default_authtok.trim().is_empty() {
        return None;
    }
    let resolver = from_sssd_section(&cfg.ldap_uri, &cfg.sssd);
    Some((resolver, cfg.sssd.ldap_default_bind_dn.clone(), cfg.sssd.ldap_default_authtok.clone()))
}

/// Lazily initialized resolver (with creds) so that the 10m identity + reverse caches
/// inside IdLdapResolver are effective across RESOLVE/getent/observer calls
/// (addresses previous per-call fresh instance problem).
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
    eprintln!("[idhelper] getent passwd \"{}\" called", name);
    let out = Command::new("getent")
        .args(["passwd", name])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!("[idhelper] getent passwd \"{}\" -> failed (status={:?})", name, out.status.code());
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let line = s.lines().next().unwrap_or("");
    if let Some((uid, gid)) = parse_getent_passwd(line) {
        eprintln!("[idhelper] getent passwd \"{}\" -> success uid={} gid={}", name, uid, gid);
        return Some((uid, gid, "sss".to_string()));
    }
    eprintln!("[idhelper] getent passwd \"{}\" -> malformed output", name);
    None
}

/// Perform full classification + resolution.
/// This is the heart of the helper.
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
        eprintln!("[idhelper] cache=HIT key=\"{}\"", norm);
        eprintln!(
            "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (cache hit)",
            e.principal, e.name, e.uid, e.gid, e.kind.as_str(), e.source
        );
        let elapsed = start.elapsed();
        dlog!(
            "  result uid={} gid={} kind={} source={} elapsed={:?}",
            e.uid, e.gid, e.kind.as_str(), e.source, elapsed
        );
        return e;
    }
    eprintln!("[idhelper] cache=MISS key=\"{}\"", norm);

    let (is_machine, reason) = is_machine_principal(principal, realm, server_variants);
    dlog!("  classify is_machine={} reason=\"{}\"", is_machine, reason);
    eprintln!("[idhelper] CLASSIFY principal=\"{}\" -> {} (reason=\"{}\")", principal, if is_machine { "machine" } else { "user" }, reason);

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
        eprintln!("[idhelper] short_name_extracted=\"{}\" (machine path, principal=\"{}\")", short, principal);

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

        // Try NSS/getent first; on miss fall back to structured LDAP (covers cold SSSD cache).
        let nss_looked = resolve_via_nss(first_try).or_else(|| resolve_via_nss(second_try));
        let ldap_looked = resolve_via_structured_ldap(first_try)
            .or_else(|| resolve_via_structured_ldap(second_try))
            .map(|(u, g)| (u, g, "ldap".to_string()));
        let looked = nss_looked.or(ldap_looked);
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
            // Unknown / unmapped -> nobody-ish but keep the info.
            // This is the path that produces the "Could not map principal" in ganesha.
            // The bases used by the resolver (and thus bulk/single searches) determine
            // whether nested OUs under ou=users (or ou=people) are visible.
            eprintln!(
                "[idhelper] FALLBACK 65534 for principal=\"{}\" (no uid/gid from getent or structured resolver) - principal2uid path for kerberos",
                principal
            );
            let name = principal.split('@').next().unwrap_or(principal).to_string();
            Resolved {
                principal: principal.to_string(),
                name,
                uid: 65534,
                gid: 65534,
                kind: PrincipalKind::Unknown,
                source: "direct".to_string(),
            }
        }
    };

    dlog!(
        "  resolved principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={}",
        resolved.principal, resolved.name, resolved.uid, resolved.gid, resolved.kind.as_str(), resolved.source
    );

    eprintln!(
        "[idhelper] FINAL principal=\"{}\" name=\"{}\" uid={} gid={} kind={} source={} (sent to ganesha)",
        resolved.principal, resolved.name, resolved.uid, resolved.gid, resolved.kind.as_str(), resolved.source
    );

    // Store
    cache.insert(resolved.clone());

    // Persist to the cache file (best effort, non-fatal)
    let write_res = cache.write_to_file(Path::new(CACHE_PATH));
    dlog!(
        "  cache_write result={}",
        if write_res.is_ok() { "ok" } else { "err" }
    );

    // Materialize nss_wrapper files so Ganesha (under LD_PRELOAD) sees our classification.
    // This is the key "conjunction" point: idhelper decisions become visible to Ganesha's
    // getpwnam calls for Kerberos principals (machine -> 0, users -> real ids from SSSD).
    // Best effort, non-fatal.
    if let Err(e) = materialize_nss_wrappers(cache) {
        dlog!("  nss_wrapper_write err={}", e);
    }

    // Optional: try to warm SSSD cache for the resolved name (non-blocking).
    // This helps both direct getent passwd testuser1 (short) and the full
    // principal path (via shim + idhelper) see fresh data from LLDAP/SSSD.
    // Must not change behavior for ganesha 9.6/trixie.
    if resolved.uid != 0 && resolved.uid != 65534 {
        let _ = Command::new("sss_cache")
            .args(["-u", &resolved.name])
            .output();
        // Also do a best-effort getent (via the shell helper) to encourage sss
        // to cache the short name for the preload/extrausers path Ganesha may use.
        let _ = Command::new("getent")
            .args(["passwd", &resolved.name])
            .output();
    }

    // Distinct log line for correlation with Ganesha "Could not map" / nfs_req_creds failures.
    // Helps operators see that our side of the mapping just became available for
    // the next compound or retry.
    eprintln!(
        "[idhelper] MAPPED FOR GANESHA principal=\"{}\" uid={} gid={} source={}",
        resolved.principal, resolved.uid, resolved.gid, resolved.source
    );

    let elapsed = start.elapsed();
    dlog!("  elapsed={:?}", elapsed);

    resolved
}

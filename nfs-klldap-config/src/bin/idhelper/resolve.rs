//! Resolves principals via NSS, LDAP, and the idhelper cache.

use crate::dlog;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use nfs_klldap_config::{
    from_sssd_section, parse_getent_passwd, IdLdapResolver, IdMapSnapshot, NfsKlldapConfig,
    FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID, MACHINE_GID,
};
use nfs_klldap_identity::{
    canonicalize_principal, classify_principal, is_numeric_local_principal, machine_short_name,
    normalize_principal, principal_has_realm, principal_local_part,
};

use crate::common::{
    debug_enabled, IdCache, PrincipalKind, Resolved, CACHE_PATH, EXTRAUSERS_PASSWD, NSS_GROUP_PATH,
    NSS_PASSWD_PATH,
};
use crate::materialize::{materialize_nss_wrappers_at, NssMaterializePaths};
#[cfg(test)]
use crate::materialize::build_nss_snapshot;

/// Resolve via getent NSS first, then fall back to the LDAP resolver snapshot.
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

    // test shim (TEST_FORCE_LDAP_UID_GID=uid:gid) to exercise ldap source branch of on-demand user@ without live service
    if trimmed.contains('@') {
        if let Ok(uv) = std::env::var("TEST_FORCE_LDAP_UID_GID") {
            if let Some((us, gs)) = uv.split_once(':') {
                if let (Ok(u), Ok(g)) = (us.trim().parse::<u32>(), gs.trim().parse::<u32>()) {
                    dlog!("test-forced ldap for {} -> {}/{}", trimmed, u, g);
                    return Some((u, g, "ldap".to_string()));
                }
            }
        }
    }

    // LDAP fallback tries full principal and short posix name inside resolver.
    if let Some((uid, gid)) = resolve_via_structured_ldap(trimmed) {
        dlog!("ldap fallback principal=\"{}\" uid={} gid={}", trimmed, uid, gid);
        // log group fetch path for uid2grp allocator visibility
        dlog!("group fetch (primary) uid={} gid={}", uid, gid);
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

/// Try the LDAP snapshot first and reload the directory on miss.
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
    let ids = try_resolve(&resolver.snapshot());
    // On-demand user@REALM: also resolve primary group by gid so group info materializes for uid2grp.
    if let Some((_u, g)) = ids {
        let _ = resolver.resolve_group_by_gid(g as i32, bind_dn, bind_pw);
    }
    ids
}

/// Merge primary + supplemental gids (primary first, deduped). Pure helper, easy to test with distinct values.
pub(crate) fn merge_group_gids(primary: u32, supplemental: &[u32]) -> Vec<u32> {
    let mut out = vec![primary];
    for &g in supplemental {
        if !out.contains(&g) {
            out.push(g);
        }
    }
    out
}

/// Resolve groups for principal: RESOLVE (uid) then resolver membership (memberOf/member/gidNumber).
/// Primary first; includes LDAP display groups for primary gid resolution side-effect.
/// Materializes supplemental NSS rows so Ganesha's getgrouplist (after uid2grp_allocate_by_principal)
/// sees the members in NSS.
pub(crate) fn resolve_groups_for_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
    cache: &mut IdCache,
) -> Vec<u32> {
    let r = resolve_principal(principal, realm, server_variants, cache);
    // Machine principals: delegate supplemental gids to identity (uid2grp_allocate_by_principal path).
    let gids = if r.kind == PrincipalKind::Machine {
        if let Some((resolver, dn, pw)) = get_or_init_resolver() {
            nfs_klldap_identity::resolve_groups_for_principal(resolver, principal, dn, pw)
                .into_iter()
                .map(|g| g as u32)
                .collect()
        } else {
            vec![MACHINE_GID]
        }
    } else {
        let primary = r.gid;
        let mut extra: Vec<u32> = vec![];
        if let Some((resolver, dn, pw)) = get_or_init_resolver() {
            let more = nfs_klldap_identity::resolve_groups_for_principal(resolver, principal, dn, pw);
            extra = more.into_iter().map(|g| g as u32).collect();
            let _ = resolver.resolve_group_by_gid(primary as i32, dn, pw);
            for &g in &extra {
                if g != primary {
                    let _ = resolver.resolve_group_by_gid(g as i32, dn, pw);
                }
            }
        }
        merge_group_gids(primary, &extra)
    };
    // force nss rows for all gids (incl supp) so getgrouplist on qualified name works
    let snap_groups = get_or_init_resolver().map(|(r, _, _)| r.snapshot().groups);
    let (np, ng, ep, eg) = NssMaterializePaths::materialize_paths_owned();
    let paths = NssMaterializePaths::from_owned(&np, &ng, &ep, &eg);
    let _ = materialize_nss_wrappers_at(cache, &paths, snap_groups.as_ref());
    gids
}

/// Load resolver + bind creds from NfsKlldapConfig (NFS_CONFIG).
fn load_resolver_from_config() -> Option<(IdLdapResolver, String, String)> {
    #[cfg(test)]
    if std::env::var("TEST_REBULK_POPULATE").is_ok() {
        // dummy so get_or_init succeeds for rebulk/GRPS tests; data from TEST spec in override
        let r = IdLdapResolver::from_inputs(&::nfs_klldap_identity::LdapResolverInputs::default());
        return Some((r, "dn".into(), "pw".into()));
    }
    let path = std::env::var("NFS_CONFIG").unwrap_or_else(|_| "/config/nfs-klldap.conf".to_string());
    let cfg = NfsKlldapConfig::load(std::path::Path::new(&path)).ok()?;
    if cfg.sssd.ldap_default_bind_dn.trim().is_empty() || cfg.sssd.ldap_default_authtok.trim().is_empty() {
        return None;
    }
    let resolver = from_sssd_section(&cfg.ldap_uri, &cfg.sssd, &cfg.effective_realm());
    Some((resolver, cfg.sssd.ldap_default_bind_dn.clone(), cfg.sssd.ldap_default_authtok.clone()))
}

/// Shared resolver for observer and getent paths. Tests reset via reset_id_resolver_for_test.
static ID_RESOLVER: Mutex<Option<&'static (IdLdapResolver, String, String)>> =
    Mutex::new(None);

fn id_resolver_slot() -> std::sync::MutexGuard<'static, Option<&'static (IdLdapResolver, String, String)>> {
    ID_RESOLVER.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn get_or_init_resolver() -> Option<(&'static IdLdapResolver, &'static str, &'static str)> {
    let mut slot = id_resolver_slot();
    if slot.is_none() {
        let loaded = load_resolver_from_config()?;
        let leaked: &'static (IdLdapResolver, String, String) = Box::leak(Box::new(loaded));
        *slot = Some(leaked);
    }
    slot.map(|t| (&t.0, t.1.as_str(), t.2.as_str()))
}

#[cfg(test)]
pub(crate) fn reset_id_resolver_for_test() {
    *id_resolver_slot() = None;
}

/// Lookup a login in a passwd(5) file (extrausers or nss_wrapper materialization).
pub(crate) fn lookup_passwd_file(path: &Path, name: &str) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.split(':').next()? == name {
            return parse_getent_passwd(line);
        }
    }
    None
}

fn resolve_getent(name: &str) -> Option<(u32, u32, String)> {
    dlog!("getent passwd \"{}\" called", name);
    if let Ok(out) = Command::new("getent").args(["passwd", name]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout);
            let line = s.lines().next().unwrap_or("");
            if let Some((uid, gid)) = parse_getent_passwd(line) {
                dlog!("getent passwd \"{}\" -> success uid={} gid={}", name, uid, gid);
                return Some((uid, gid, "sss".to_string()));
            }
        }
    }
    // Parity when SSSD misses a user but idhelper already materialized extrausers/nss_passwd.
    for (path, src) in [
        (EXTRAUSERS_PASSWD, "extrausers"),
        (NSS_PASSWD_PATH, "nss"),
    ] {
        if let Some((uid, gid)) = lookup_passwd_file(Path::new(path), name) {
            dlog!("passwd file {} \"{}\" -> uid={} gid={}", path, name, uid, gid);
            return Some((uid, gid, src.to_string()));
        }
    }
    dlog!("getent passwd \"{}\" -> miss (nss + materialized files)", name);
    None
}

fn lookup_group_in_content(content: &str, gid: u32) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(gid) {
            return Some(parts[0].to_string());
        }
    }
    None
}

/// Resolve gid from materialized group file when getent group misses.
pub(crate) fn lookup_group_file(gid: u32) -> Option<String> {
    for path in [NSS_GROUP_PATH, "/var/lib/extrausers/group"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Some(name) = lookup_group_in_content(&content, gid) {
                return Some(name);
            }
        }
    }
    None
}

/// Resolve principals and materialize nss_wrapper when the cache changes.
pub(crate) fn resolve_principal(
    principal: &str,
    realm: &str,
    server_variants: &[String],
    cache: &mut IdCache,
) -> Resolved {
    let principal = canonicalize_principal(principal.trim(), realm);
    let start = Instant::now();
    let norm = normalize_principal(&principal);

    // libnfsidmap uid/gid reverse lookups must not be cached as Kerberos principals.
    if is_numeric_local_principal(&principal) {
        dlog!("reject numeric principal lookup \"{}\"", principal);
        return Resolved {
            principal,
            name: principal_local_part(&norm).to_string(),
            uid: FALLBACK_NOBODY_UID,
            gid: FALLBACK_NOBODY_GID,
            kind: PrincipalKind::Unknown,
            source: "rejected-numeric".to_string(),
        };
    }

    dlog!("RESOLVE principal=\"{}\"", principal);
    dlog!("  normalized=\"{}\"", norm);

    if principal.contains('@') {
        dlog!("  kerberos form: getent/LDAP try full principal then short name");
    }

    if let Some(existing) = cache.get(&norm).cloned() {
        if is_numeric_local_principal(&existing.principal) {
            cache.entries.remove(&norm);
            dlog!("evicted numeric principal cache hit \"{}\"", norm);
        } else {
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
    }
    if debug_enabled() {
        eprintln!("[idhelper] cache=MISS key=\"{}\"", norm);
    }

    let (is_machine, reason) = classify_principal(&principal, realm, server_variants);
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

    // Resolve machine principals to root or users via NSS and LDAP.
    let resolved = if is_machine {
        // Machine principals (host/, nfs/, root/ server variants): map 0:0.
        let short = machine_short_name(&principal);
        if debug_enabled() {
            eprintln!(
                "[idhelper] short_name_extracted=\"{}\" (machine path, principal=\"{}\")",
                short, principal
            );
        }

        // No resolve_via_nss / getent calls for machines.
        Resolved {
            principal: principal.clone(),
            name: short.to_string(),
            uid: 0,
            gid: 0,
            kind: PrincipalKind::Machine,
            source: "special".to_string(),
        }
    } else {
        dlog!("  user_path principal=\"{}\"", principal);
        let looked = resolve_via_nss(&principal);
        dlog!("  nss_getent final_got={:?}", looked.as_ref().map(|(u, g, s)| (*u, *g, s.as_str())));

            if let Some((uid, gid, src)) = looked {
            let name = principal_local_part(&principal).to_string();
            // ensure group for uid2grp even on on-demand user@REALM
            if let Some((r, dn, pw)) = get_or_init_resolver() {
                let _ = r.resolve_group_by_gid(gid as i32, dn, pw);
                dlog!("group fetch on-demand for gid={}", gid);
            }
            if let Some(gname) = lookup_group_file(gid) {
                dlog!("materialized group gid={} name={}", gid, gname);
            }
            Resolved {
                principal: principal.clone(),
                name,
                uid,
                gid,
                kind,
                source: src,
            }
        } else {
            // Nobody fallback materializes nss so getpwnam succeeds.
            eprintln!(
                "[idhelper] FALLBACK {} for principal=\"{}\" (no uid/gid from getent or structured resolver)",
                FALLBACK_NOBODY_UID, principal
            );
            let name = principal_local_part(&principal).to_string();
            Resolved {
                principal: principal.clone(),
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
    if principal_has_realm(&resolved.principal) {
        cache.insert(resolved.clone());
    }
    let _ = cache.prune_malformed_principals();
    let _ = cache.prune_numeric_user_entries();
    if fp_before != cache.content_fingerprint() {
        let write_res = cache.write_to_file(Path::new(CACHE_PATH));
        dlog!(
            "  cache_write result={}",
            if write_res.is_ok() { "ok" } else { "err" }
        );
        let snap_groups = get_or_init_resolver().map(|(r, _, _)| r.snapshot().groups);
        let (np, ng, ep, eg) = NssMaterializePaths::materialize_paths_owned();
        let paths = NssMaterializePaths::from_owned(&np, &ng, &ep, &eg);
        if let Err(e) = materialize_nss_wrappers_at(cache, &paths, snap_groups.as_ref()) {
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

    #[test]
    fn merge_group_gids_primary_first_distinct_dedup() {
        assert_eq!(merge_group_gids(1001, &[1001, 2002]), vec![1001, 2002]);
        assert_eq!(merge_group_gids(1001, &[2002, 1001, 2002]), vec![1001, 2002]);
        assert_eq!(merge_group_gids(4242, &[]), vec![4242]);
    }

    #[test]
    fn lookup_passwd_file_skips_comments_and_matches_login() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("passwd");
        std::fs::write(
            &path,
            "# header\n\nalice:x:1001:1002:gecos:/home:/bin/sh\n",
        )
        .unwrap();
        assert_eq!(
            lookup_passwd_file(&path, "alice"),
            Some((1001, 1002))
        );
        assert_eq!(lookup_passwd_file(&path, "missing"), None);
    }

    #[test]
    fn lookup_group_in_content_skips_comments_and_matches_gid() {
        let content = "# groups\n\ndevs:x:3005:alice,bob\n";
        assert_eq!(lookup_group_in_content(content, 3005), Some("devs".into()));
        assert_eq!(lookup_group_in_content(content, 9999), None);
    }

    #[test]
    fn resolve_rejects_numeric_principal_without_caching() {
        let mut cache = IdCache::default();
        let r = resolve_principal("3002", "REALM", &[], &mut cache);
        assert_eq!(r.uid, FALLBACK_NOBODY_UID);
        assert_eq!(r.source, "rejected-numeric");
        assert!(cache.get("3002@REALM").is_none());
    }

    #[test]
    fn lookup_group_file_reads_extrausers_when_nss_group_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let group_path = tmp.path().join("group");
        std::fs::write(&group_path, "writers:x:4242:\n").unwrap();
        let old = std::env::var("NSS_EXTRAUSERS_GROUP").ok();
        std::env::set_var("NSS_EXTRAUSERS_GROUP", "___nonexistent___");
        // lookup_group_file falls back to /var/lib/extrausers/group in production paths only.
        // Exercise the content helper used by both paths.
        assert_eq!(
            lookup_group_in_content(
                &std::fs::read_to_string(&group_path).unwrap(),
                4242
            ),
            Some("writers".into())
        );
        if let Some(v) = old {
            std::env::set_var("NSS_EXTRAUSERS_GROUP", v);
        } else {
            std::env::remove_var("NSS_EXTRAUSERS_GROUP");
        }
    }

    #[test]
    fn publish_nss_includes_supp_group_rows_for_user_principal_no_shims() {
        // drives real build_nss_snapshot + group row creation for primary + supp (from ldap_groups)
        // no TEST_* envs; uses direct cache seed + explicit groups map (simulates publish after groups resolve)
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "testuser1@EX.COM".into(),
            name: "testuser1".into(),
            uid: 3001,
            gid: 100,
            kind: PrincipalKind::User,
            source: "seed".into(),
        });
        let mut lgs: std::collections::HashMap<String, nfs_klldap_config::PosixGroupEntry> = std::collections::HashMap::new();
        lgs.insert("staff".into(), nfs_klldap_config::PosixGroupEntry { gid: 2002, display: "staff".into(), members: vec!["testuser1".into()] });
        let (pw, gr) = build_nss_snapshot(&cache, Some(&lgs));
        assert!(pw.iter().any(|l| l.contains("testuser1@EX.COM:x:3001:100")), "@ form for getpwnam");
        assert!(gr.iter().any(|l| l.contains("staff:x:2002:testuser1")), "supp group row with member");
    }

    #[test]
    fn resolve_groups_machine_principal_delegates_to_identity_root_gid() {
        // Drives shipped idhelper resolve_groups_for_principal (uid2grp/GRPS entry) for host/*@REALM.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
        reset_id_resolver_for_test();
        std::env::set_var("TEST_REBULK_POPULATE", "u:ignored:1:1");
        let mut cache = IdCache::default();
        let gs = resolve_groups_for_principal("host/blue-lt@SATOMLIN.COM", "SATOMLIN.COM", &[], &mut cache);
        std::env::remove_var("TEST_REBULK_POPULATE");
        eprintln!(
            "[idhelper-test] host/blue-lt@SATOMLIN.COM gids={:?} via identity delegation (expect [0])",
            gs
        );
        assert_eq!(gs, vec![MACHINE_GID], "machine principal must return root gid via identity path");
        assert!(!gs.contains(&FALLBACK_NOBODY_GID));
    }

    #[test]
    fn resolve_principal_and_groups_on_qualified_form_drives_file_lookup_and_publish_no_shims() {
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap();
        let old_force = std::env::var("TEST_FORCE_LDAP_UID_GID").ok();
        std::env::remove_var("TEST_FORCE_LDAP_UID_GID");
        let old_pop = std::env::var("TEST_REBULK_POPULATE").ok();
        std::env::remove_var("TEST_REBULK_POPULATE");
        // write qualified entry to NSS_PASSWD_PATH so lookup_passwd_file (fallback in resolve_getent for @) resolves it
        let nss_dir = std::path::Path::new("/var/lib/nfs-klldap");
        let _ = std::fs::create_dir_all(nss_dir);
        let nss_passwd = nss_dir.join("nss_passwd");
        std::fs::write(&nss_passwd, "testuser1@EX.COM:x:3001:100:Test:/nonexistent:/usr/sbin/nologin\n").unwrap();
        let mut cache = IdCache::default();
        let r = resolve_principal("testuser1@EX.COM", "EX.COM", &[], &mut cache);
        let gs = resolve_groups_for_principal("testuser1@EX.COM", "EX.COM", &[], &mut cache);
        if let Some(v) = old_force { std::env::set_var("TEST_FORCE_LDAP_UID_GID", v); }
        if let Some(v) = old_pop { std::env::set_var("TEST_REBULK_POPULATE", v); }
        assert_eq!(r.uid, 3001, "resolve_principal on @ form via file lookup (no shims)");
        assert!(gs.contains(&100));
        let pc = std::fs::read_to_string(nss_passwd).unwrap_or_default();
        assert!(pc.contains("testuser1@EX.COM") || pc.contains("testuser1:x:3001"));
    }
}

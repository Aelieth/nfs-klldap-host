//! NSS wrapper + extrausers materialization from the idhelper cache.

use crate::dlog;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use std::collections::HashMap;

use nfs_klldap_config::{
    IdMapSnapshot, PosixGroupEntry, FALLBACK_NOBODY_GID, FALLBACK_NOBODY_UID,
    MACHINE_PRINCIPAL_PREFIXES,
};

use nfs_klldap_identity::{is_numeric_local_principal, principal_has_realm, principal_local_part};

use crate::common::{IdCache, PrincipalKind, Resolved};

/// Output paths for nss_wrapper and extrausers writes.
/// Production or test temp dirs.
#[derive(Clone, Copy)]
pub(crate) struct NssMaterializePaths<'a> {
    pub nss_passwd: &'a Path,
    pub nss_group: &'a Path,
    pub extrausers_passwd: &'a Path,
    pub extrausers_group: &'a Path,
}

impl NssMaterializePaths<'_> {
    /// Owned paths from NSS_PASSWD/NSS_GROUP env (pipeline tempdir or production defaults).
    pub(crate) fn materialize_paths_owned() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        use crate::common::{
            EXTRAUSERS_GROUP, EXTRAUSERS_PASSWD, NSS_GROUP_PATH, NSS_PASSWD_PATH,
        };
        let env_path = |key: &str, default: &str| -> std::path::PathBuf {
            std::env::var(key)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| std::path::PathBuf::from(default))
        };
        (
            env_path("NSS_PASSWD", NSS_PASSWD_PATH),
            env_path("NSS_GROUP", NSS_GROUP_PATH),
            env_path("NSS_EXTRAUSERS_PASSWD", EXTRAUSERS_PASSWD),
            env_path("NSS_EXTRAUSERS_GROUP", EXTRAUSERS_GROUP),
        )
    }

    pub(crate) fn from_owned<'a>(
        np: &'a std::path::Path,
        ng: &'a std::path::Path,
        ep: &'a std::path::Path,
        eg: &'a std::path::Path,
    ) -> NssMaterializePaths<'a> {
        NssMaterializePaths {
            nss_passwd: np,
            nss_group: ng,
            extrausers_passwd: ep,
            extrausers_group: eg,
        }
    }

    // production() always the real /var paths (shipped). Tests use under(base).
    pub(crate) fn production() -> NssMaterializePaths<'static> {
        use crate::common::{
            EXTRAUSERS_GROUP, EXTRAUSERS_PASSWD, NSS_GROUP_PATH, NSS_PASSWD_PATH,
        };
        NssMaterializePaths {
            nss_passwd: Path::new(NSS_PASSWD_PATH),
            nss_group: Path::new(NSS_GROUP_PATH),
            extrausers_passwd: Path::new(EXTRAUSERS_PASSWD),
            extrausers_group: Path::new(EXTRAUSERS_GROUP),
        }
    }

    #[cfg(test)]
    pub(crate) fn under(base: &Path) -> NssMaterializePaths<'static> {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        NssMaterializePaths {
            nss_passwd: Path::new(leak(format!("{}/nss_passwd", base.display()))),
            nss_group: Path::new(leak(format!("{}/nss_group", base.display()))),
            extrausers_passwd: Path::new(leak(format!("{}/extra_passwd", base.display()))),
            extrausers_group: Path::new(leak(format!("{}/extra_group", base.display()))),
        }
    }
}

/// Skip passwd logins that are only digits; they break getpwuid for real users.
fn is_numeric_login(login: &str) -> bool {
    !login.is_empty() && login.chars().all(|c| c.is_ascii_digit())
}

/// Passwd login for user@REALM (and host/NAME@REALM) principals.
/// Keeps '@' and '/' (so getpwnam("host/client-a@REALM") under UseGetpwnam=true
/// finds the literal principal name that Ganesha passes). Only replace truly
/// problematic chars for the nss_wrapper file format.
pub(crate) fn principal_realm_login_for_nss(principal: &str) -> String {
    let mut out = String::with_capacity(principal.len());
    for c in principal.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@' || c == '/' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// Canonical set of passwd login names to emit for a resolved principal.
/// Machine+realm: exactly the raw principal@ form (with / preserved).
/// User+realm: short sanitized name + the @ form (when they differ).
pub(crate) fn nss_passwd_logins_for(r: &Resolved) -> std::collections::BTreeSet<String> {
    let mut s = std::collections::BTreeSet::new();
    let short = sanitize_for_nss(&r.name);
    s.insert(short.clone());
    if r.kind == PrincipalKind::Machine && principal_has_realm(&r.principal) {
        // Canonical for machine+realm:
        // - the short sanitized name (for getpwnam on the host segment)
        // - the raw local "host/NAME" (with / preserved) for the local candidate
        // - the full principal@ form (with /) for the full principal candidate
        // Never emit any "host_NAME" (sanitized local) form.
        let local = principal_local_part(&r.principal);
        if local != short {
            s.insert(local.to_string()); // raw "host/client-a"
        }
        s.insert(principal_realm_login_for_nss(&r.principal)); // raw "host/client-a@REALM"
    } else if principal_has_realm(&r.principal) {
        let at = principal_realm_login_for_nss(&r.principal);
        if at != short {
            s.insert(at);
        }
    }
    s
}

/// Sanitize a string for use as a passwd login name (allow alnum + _ - .).
pub(crate) fn sanitize_for_nss(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("unknown");
    }
    out
}

/// LDAP group display name takes priority over user-name stub for gid groups.
/// Ties on gid resolve by lowest map key so repeated builds emit identical bytes
/// (the materialize content guard depends on build determinism).
fn gname_for_gid(gid: u32, ldap_groups: Option<&HashMap<String, PosixGroupEntry>>, fallback: &str) -> String {
    if gid == FALLBACK_NOBODY_GID {
        return "nobody".to_string();
    }
    if let Some(groups) = ldap_groups {
        if let Some((_, entry)) = groups
            .iter()
            .filter(|(_, g)| g.gid as u32 == gid)
            .min_by(|a, b| a.0.cmp(b.0))
        {
            return sanitize_for_nss(&entry.display);
        }
    }
    sanitize_for_nss(fallback)
}

/// Gecos: principal or name, colon-free for libnss-extrausers.
pub(crate) fn gecos_for(r: &Resolved) -> String {
    let tag = if principal_has_realm(&r.principal) { &r.principal } else { &r.name };
    tag.chars().filter(|&c| c != ':').collect()
}

/// Builds a passwd(5) line and assigns uid and gid zero to machines.
#[cfg(test)]
pub(crate) fn passwd_line_for(r: &Resolved) -> String {
    let login = sanitize_for_nss(&r.name);
    let gecos = gecos_for(r);
    // The /nonexistent + nologin is synthetic nss entries, not real local.
    format!(
        "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
        login, r.uid, r.gid, gecos
    )
}

/// Build a group(5) line for the primary gid of this resolved entry.
pub(crate) fn group_line_for(r: &Resolved) -> String {
    if r.gid == 0 {
        // non-empty base for root so getgrouplist(0) reliable (central base used here too).
        group_line_with_members(0, "root", &["root".to_string(), "daemon".to_string(), "bin".to_string()])
    } else if r.gid == FALLBACK_NOBODY_GID {
        group_line_with_members(FALLBACK_NOBODY_GID, "nobody", &[])
    } else {
        let gname = sanitize_for_nss(&r.name);
        group_line_with_members(r.gid, &gname, &[])
    }
}

/// Build a full group(5) line with optional member list.
/// Members are comma-separated logins.
pub(crate) fn group_line_with_members(gid: u32, gname: &str, members: &[String]) -> String {
    if members.is_empty() {
        format!("{}:x:{}:", gname, gid)
    } else {
        format!("{}:x:{}:{}", gname, gid, members.join(","))
    }
}

/// Ensure a login appears in the member field for a gid (getgrouplist scans members, not memberOf).
/// Creates a minimal group row (gN fallback) if the gid is absent so supplemental membership is always recorded in both stores.
pub(crate) fn ensure_nss_group_member_login(
    paths: &NssMaterializePaths<'_>,
    gid: u32,
    login: &str,
) -> io::Result<()> {
    let login = login.trim();
    if login.is_empty() {
        return Ok(());
    }
    // helper to find display name from either store for this gid
    let find_name = |p: &Path| -> Option<String> {
        if let Ok(c) = fs::read_to_string(p) {
            for line in c.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with('#') { continue; }
                let parts: Vec<&str> = t.splitn(4, ':').collect();
                if parts.len() >= 3 && parts[2].parse::<u32>().ok() == Some(gid) {
                    return Some(parts[0].to_string());
                }
            }
        }
        None
    };
    for path in [paths.nss_group, paths.extrausers_group] {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let mut changed = false;
        let mut out: Vec<String> = Vec::new();
        let mut saw = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                out.push(line.to_string());
                continue;
            }
            let mut parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(g) = parts[2].parse::<u32>() {
                    if g == gid {
                        saw = true;
                        let members = if parts.len() >= 4 { parts[3] } else { "" };
                        let already = members.split(',').any(|m| m == login);
                        if !already {
                            let new_members = if members.is_empty() {
                                login.to_string()
                            } else {
                                format!("{members},{login}")
                            };
                            parts.resize(4, "");
                            parts[3] = "";
                            let rebuilt = format!(
                                "{}:x:{}:{}",
                                parts[0], parts[2], new_members
                            );
                            out.push(rebuilt);
                            changed = true;
                            continue;
                        }
                    }
                }
            }
            out.push(line.to_string());
        }
        if !saw {
            // create stub so getgrouplist sees membership for this gid even if snap lacked the group row
            let mut gname = find_name(paths.nss_group).or_else(|| find_name(paths.extrausers_group))
                .unwrap_or_else(|| if gid == 0 { "root".to_string() } else { format!("g{}", gid) });
            if gid == FALLBACK_NOBODY_GID { gname = "nobody".to_string(); }
            out.push(format!("{}:x:{}:{}", gname, gid, login));
            changed = true;
        }
        if changed {
            // Same fsync + unchanged-skip discipline as the bulk writer: this
            // is the second writer to the nss stores, and a bare rename here
            // bumped mtime (nss_wrapper reload) even for no-op rewrites —
            // exactly the in-flight-getgrouplist race the atomic path guards.
            write_atomic_if_changed(path, &(out.join("\n") + "\n"))?;
        }
    }
    Ok(())
}

/// Returns true when cache content changed and nss files should be rewritten.
pub(crate) fn cache_changed_since(fp_before: u64, cache: &IdCache) -> bool {
    fp_before != cache.content_fingerprint()
}

/// Live per-user group edges from the rebulk warm pass (short name → gids).
/// Carries the memberOf-direction truth the bulk snap cannot see: LLDAP
/// memberOf-only groups (e.g. lldap_sudohost) report empty member lists in a
/// bulk group search, so their membership is only visible via a live
/// per-user resolve.
pub(crate) type LiveGroupEdges = std::collections::HashMap<String, Vec<u32>>;

/// Prunes stale LDAP users from cache but keeps machine principals.
pub(crate) fn sync_user_cache_from_snapshot(
    snap: &IdMapSnapshot,
    realm: &str,
    cache: &mut IdCache,
    live: &LiveGroupEdges,
) -> usize {
    let pruned = cache.prune_non_machine_users();
    if pruned > 0 {
        dlog!("sync_user_cache pruned {} stale non-machine entries", pruned);
    }
    let n = seed_cache_and_nss_from_snapshot(snap, realm, cache);
    // Fold in the warm pass's LIVE memberOf edges so memberOf-only groups
    // still seed. This REPLACES the old preserve-prior-supps union: a rebulk
    // seeds from the two fresh LDAP edge directions ONLY (bulk member lists +
    // live memberOf), so a revoked membership actually drops. The old union
    // re-applied every previously discovered supp across prune+reseed forever
    // — revocation was structurally impossible (2026-07-18 B7 gate finding).
    for e in cache.entries.values_mut() {
        if e.kind != PrincipalKind::User || !principal_has_realm(&e.principal) {
            continue;
        }
        if let Some(gids) = live.get(&e.name) {
            for &g in gids {
                if g != 0 && g != e.gid && !e.supplemental_gids.contains(&g) {
                    e.supplemental_gids.push(g);
                }
            }
            e.supplemental_gids.sort_unstable();
            e.supplemental_gids.dedup();
        }
    }
    let bad = cache.prune_malformed_principals();
    let numeric = cache.prune_numeric_user_entries();
    if bad > 0 || numeric > 0 {
        dlog!(
            "sync_user_cache pruned {} malformed + {} numeric principal keys",
            bad,
            numeric
        );
    }
    n
}

/// Insert LDAP users from snapshot into cache.
/// Caller may prune first via sync_*.
pub(crate) fn seed_cache_and_nss_from_snapshot(
    snap: &IdMapSnapshot,
    realm: &str,
    cache: &mut IdCache,
) -> usize {
    let mut seeded = 0usize;
    let mut best_per_uid: std::collections::HashMap<i32, (String, u32, u32)> =
        std::collections::HashMap::new();

    // Keep one entry per LDAP uid and prefer short posix names over UPN keys.
    for (key, entry) in &snap.users {
        let uid = entry.uid;
        if uid == 0 {
            continue;
        }
        if key.contains('/')
            && MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| key.starts_with(p))
        {
            continue;
        }
        let short = principal_local_part(key).to_string();
        let uid_u = uid as u32;
        let gid_u = entry.gid as u32;
        best_per_uid
            .entry(uid)
            .and_modify(|(name, _, _)| {
                if !key.contains('@') && name.contains('@') {
                    *name = short.clone();
                }
            })
            .or_insert((short, uid_u, gid_u));
    }

    for (short_name, uid, gid) in best_per_uid.into_values() {
        let principal = format!("{}@{}", short_name, realm);
        let supplemental_gids =
            supplemental_gids_from_snapshot(&short_name, &principal, gid, snap);
        cache.insert(Resolved {
            principal,
            name: short_name,
            uid,
            gid,
            kind: PrincipalKind::User,
            source: "bulk".to_string(),
            supplemental_gids,
        });
        seeded += 1;
    }

    seeded
}

/// Supplemental gids from LDAP snap group membership so bulk materialize emits short member rows before post-start resolve_groups.
fn supplemental_gids_from_snapshot(
    short: &str,
    principal: &str,
    primary_gid: u32,
    snap: &IdMapSnapshot,
) -> Vec<u32> {
    let mut supps = Vec::new();
    let at = principal_realm_login_for_nss(principal);
    for entry in snap.groups.values() {
        let g = entry.gid as u32;
        if g == 0 || g == primary_gid {
            continue;
        }
        let member_hit = entry.members.iter().any(|m| {
            let m = m.trim();
            m == short || m == principal || m == at
        });
        if member_hit {
            supps.push(g);
        }
    }
    supps.sort_unstable();
    supps.dedup();
    supps
}

/// Minimal gid-0 members for nss group(5). Machine logins belong on supplemental groups, not here.
pub(crate) fn minimal_root_group_members() -> Vec<String> {
    vec!["root".to_string(), "daemon".to_string(), "bin".to_string()]
}

/// Supplemental gids uid0/machine principals require (union across cache). Used for GROUPLIST root + nss member rows.
pub(crate) fn root_supplemental_gids_from_cache(cache: &IdCache) -> Vec<u32> {
    let mut supps = Vec::new();
    for r in cache.entries.values() {
        if (r.uid == 0 || r.gid == 0) && principal_has_realm(&r.principal) {
            for &g in &r.supplemental_gids {
                if g != 0 && !supps.contains(&g) {
                    supps.push(g);
                }
            }
        }
    }
    supps.sort_unstable();
    supps
}

/// Build passwd/group line vectors from cache + optional LDAP group snapshot.
pub(crate) fn build_nss_snapshot(
    cache: &IdCache,
    ldap_groups: Option<&HashMap<String, PosixGroupEntry>>,
) -> (Vec<String>, Vec<String>) {
    let mut items: Vec<_> = cache
        .entries
        .values()
        .filter(|r| principal_has_realm(&r.principal))
        .collect();
    items.sort_by(|a, b| a.principal.cmp(&b.principal));

    let mut seen_login: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut passwd_lines: Vec<String> = Vec::new();
    let mut group_lines: Vec<String> = Vec::new();
    let mut seen_gid: std::collections::HashSet<u32> = std::collections::HashSet::new();

    // Primary-gid members for getgrouplist when LDAP member lists empty.
    // Include both short and user@REALM forms (latter for uid2grp getgrouplist on krb5 user TGT logins).
    let mut users_by_gid: HashMap<u32, Vec<String>> = HashMap::new();
    for r in items.iter().copied() {
        if r.kind == PrincipalKind::User && r.gid != 0 && !is_numeric_local_principal(&r.principal) {
            let short = sanitize_for_nss(&r.name);
            users_by_gid.entry(r.gid).or_default().push(short.clone());
            if principal_has_realm(&r.principal) {
                let at = principal_realm_login_for_nss(&r.principal);
                if at != short {
                    users_by_gid.entry(r.gid).or_default().push(at);
                }
            }
        }
    }

    // Members for *all* gids claimed by cached entries (primary + supplemental_gids stored on Resolved).
    // This centralizes complete supplemental membership inside build_nss_snapshot so rebulk
    // rewrites cannot drop runtime supps added by on-demand resolve_groups.
    let mut members_by_gid: HashMap<u32, Vec<String>> = HashMap::new();
    for r in items.iter().copied() {
        let mut gs = vec![r.gid];
        gs.extend_from_slice(&r.supplemental_gids);
        for &g in &gs {
            if g == 0 {
                continue;
            }
            if r.kind == PrincipalKind::Machine {
                let v = members_by_gid.entry(g).or_default();
                if !v.iter().any(|m| m == "root") {
                    v.push("root".to_string());
                }
            } else {
                for login in nss_passwd_logins_for(r) {
                    if !is_numeric_login(&login) {
                        let v = members_by_gid.entry(g).or_default();
                        if !v.iter().any(|m| m == &login) {
                            v.push(login);
                        }
                    }
                }
            }
        }
    }

    // Minimal root members only; machine logins are added to supplemental group rows (see below).
    let root_group_members: Vec<String> = minimal_root_group_members();
    let root_supps = root_supplemental_gids_from_cache(cache);
    for &g in &root_supps {
        let v = members_by_gid.entry(g).or_default();
        if !v.iter().any(|m| m == "root") {
            v.push("root".to_string());
        }
    }

    if let Some(groups) = ldap_groups {
        // Deterministic emission (sorted keys → gid-sorted rows): repeated builds of
        // the same data must be byte-identical or the materialize guard never skips.
        let mut by_gid: std::collections::BTreeMap<i32, &PosixGroupEntry> = std::collections::BTreeMap::new();
        let mut keys: Vec<&String> = groups.keys().collect();
        keys.sort();
        for k in keys {
            let entry = &groups[k];
            by_gid.entry(entry.gid).or_insert(entry);
        }
        for entry in by_gid.values() {
            let gid = entry.gid as u32;
            if seen_gid.insert(gid) {
                let mut gname = sanitize_for_nss(&entry.display);
                if gid == FALLBACK_NOBODY_GID { gname = "nobody".to_string(); }
                let mut members: Vec<String> = entry
                    .members
                    .iter()
                    .map(|m| sanitize_for_nss(m))
                    .collect();
                if let Some(logins) = users_by_gid.get(&gid) {
                    for login in logins {
                        if !members.iter().any(|m| m == login) {
                            members.push(login.clone());
                        }
                    }
                }
                if let Some(logins) = members_by_gid.get(&gid) {
                    for login in logins {
                        if !members.iter().any(|m| m == login) {
                            members.push(login.clone());
                        }
                    }
                }
                group_lines.push(group_line_with_members(gid, &gname, &members));
            }
        }
    }

    for r in &items {
        if is_numeric_local_principal(&r.principal) {
            continue;
        }
        // Use the single canonical policy for which logins to emit.
        for login in nss_passwd_logins_for(r) {
            if !is_numeric_login(&login) && seen_login.insert(login.clone()) {
                let gecos = gecos_for(r);
                passwd_lines.push(format!(
                    "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
                    login, r.uid, r.gid, gecos
                ));
            }
        }

        // Emit group rows for every gid this entry claims (its primary + any supplemental_gids
        // persisted from resolve_groups). This ensures build_nss is the single writer; supps
        // survive rebulk.
        let claimed: Vec<u32> = std::iter::once(r.gid).chain(r.supplemental_gids.iter().copied()).collect();
        for g in claimed {
            if seen_gid.insert(g) {
                if g == 0 {
                    group_lines.push(group_line_with_members(0, "root", &root_group_members));
                } else if r.kind == PrincipalKind::Machine {
                    let gname = gname_for_gid(g, ldap_groups, &format!("g{}", g));
                    let mut mems: Vec<String> = members_by_gid.get(&g).cloned().unwrap_or_default();
                    if !mems.iter().any(|m| m == "root") {
                        mems.push("root".to_string());
                    }
                    group_lines.push(group_line_with_members(g, &gname, &mems));
                } else if g != 0 {
                    // Use group name from snap if present, else stable "g{gid}" fallback; never r.name (which would be user name for pure supp gids).
                    let mut gname = gname_for_gid(g, ldap_groups, &format!("g{}", g));
                    if g == FALLBACK_NOBODY_GID { gname = "nobody".to_string(); }
                    let short = sanitize_for_nss(&r.name);
                    let mut mems: Vec<String> = members_by_gid.get(&g).cloned().unwrap_or_default();
                    if !mems.iter().any(|m| m == &short) {
                        mems.push(short.clone());
                    }
                    if principal_has_realm(&r.principal) {
                        let at = principal_realm_login_for_nss(&r.principal);
                        if at != short && !mems.iter().any(|m| m == &at) {
                            mems.push(at);
                        }
                    }
                    group_lines.push(group_line_with_members(g, &gname, &mems));
                } else {
                    group_lines.push(group_line_for(r));
                }
            }
        }
        if r.uid != r.gid && seen_gid.insert(r.uid) {
            if r.uid == 0 {
                seen_gid.insert(0);
            } else {
                group_lines.push(format!("u{}:x:{}:", r.uid, r.uid));
            }
        }
    }

    for &g in &root_supps {
        if seen_gid.insert(g) {
            let gname = gname_for_gid(g, ldap_groups, &format!("g{}", g));
            let mut mems: Vec<String> = members_by_gid.get(&g).cloned().unwrap_or_default();
            if !mems.iter().any(|m| m == "root") {
                mems.push("root".to_string());
            }
            group_lines.push(group_line_with_members(g, &gname, &mems));
        }
    }

    if seen_gid.is_empty() || !seen_gid.contains(&0) {
        group_lines.push(group_line_with_members(0, "root", &root_group_members));
    }

    // Final guarantee: root group always exists with minimal base members; root passwd leads.
    // Supplemental membership for uid0 is via members_by_gid rows (root login on supp gids).
    group_lines.retain(|l| !l.starts_with("root:x:0:"));
    group_lines.insert(0, group_line_with_members(0, "root", &root_group_members));
    let exact_root_passwd = "root:x:0:0:root:/root:/bin/sh".to_string();
    if !passwd_lines.iter().any(|l| l.starts_with("root:")) {
        passwd_lines.insert(0, exact_root_passwd.clone());
    } else {
        // Force exact root line (replace any prior root entry) and ensure leading.
        if let Some(pos) = passwd_lines.iter().position(|l| l.starts_with("root:")) {
            passwd_lines.remove(pos);
        }
        passwd_lines.insert(0, exact_root_passwd);
    }
    if !passwd_lines.iter().any(|l| l.starts_with("nobody:")) {
        passwd_lines.push(format!(
            "nobody:x:{}:{}:nfs-klldap fallback:/nonexistent:/usr/sbin/nologin",
            FALLBACK_NOBODY_UID, FALLBACK_NOBODY_GID
        ));
    }

    (passwd_lines, group_lines)
}

/// Atomic temp+fsync+rename write, skipped when the file already holds exactly
/// `content`. The skip is load-bearing, not an optimization: ganesha reads these
/// files through nss_wrapper, which reloads on mtime change, and a rename racing
/// an in-flight getgrouplist can yield a partial group view that uid2grp then
/// caches for the whole validity window. Unchanged content must not bump mtime.
fn write_atomic_if_changed(path: &Path, content: &str) -> io::Result<bool> {
    if let Ok(current) = fs::read_to_string(path) {
        if current == content {
            return Ok(false);
        }
    }
    let tmp = path.with_extension("new");
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
    f.write_all(content.as_bytes())?;
    let _ = f.sync_all();
    fs::rename(tmp, path)?;
    Ok(true)
}

/// Atomically write nss_wrapper passwd/group for ganesha.nfsd LD_PRELOAD.
/// Also writes extrausers supplement.
pub(crate) fn materialize_nss_wrappers(cache: &IdCache) -> io::Result<bool> {
    materialize_nss_wrappers_at(cache, &NssMaterializePaths::production(), None)
}

/// Same as materialize_nss_wrappers but writes to caller-supplied paths.
/// Used in rebulk tests. Returns true when any of the four stores was rewritten
/// (content-identical stores are left untouched — see write_atomic_if_changed).
pub(crate) fn materialize_nss_wrappers_at(
    cache: &IdCache,
    paths: &NssMaterializePaths<'_>,
    ldap_groups: Option<&HashMap<String, PosixGroupEntry>>,
) -> io::Result<bool> {
    let start = Instant::now();
    let nss_p = paths.nss_passwd.display().to_string();
    dlog!("materialize start nss={} cache_entries={}", nss_p, cache.entries.len());

    // Explicit dir creation for both nss_wrapper and extrausers (strengthen visibility).
    for p in [paths.nss_passwd, paths.nss_group, paths.extrausers_passwd, paths.extrausers_group] {
        if let Some(parent) = p.parent() {
            let _ = fs::create_dir_all(parent);
        }
    }

    let (passwd_lines, group_lines) = build_nss_snapshot(cache, ldap_groups);
    // Nss_wrapper (Debian trixie) and libnss-extrausers reject '#' comment lines;
    // both stores get bare entries only.
    let passwd_content: String = passwd_lines.iter().map(|l| format!("{}\n", l)).collect();
    let group_content: String = group_lines.iter().map(|l| format!("{}\n", l)).collect();

    let mut wrote = false;
    for (path, content) in [
        (paths.nss_passwd, &passwd_content),
        (paths.nss_group, &group_content),
        (paths.extrausers_passwd, &passwd_content),
        (paths.extrausers_group, &group_content),
    ] {
        wrote |= write_atomic_if_changed(path, content)?;
    }

    if !wrote {
        dlog!("materialize unchanged (no rewrite) nss={}", nss_p);
        return Ok(false);
    }

    // Post-write read-back check for visibility to subsequent NSS lookups (getpwnam/getgrouplist).
    let _ = std::fs::read_to_string(paths.nss_passwd);
    let _ = std::fs::read_to_string(paths.nss_group);
    let _ = std::fs::read_to_string(paths.extrausers_passwd);
    let _ = std::fs::read_to_string(paths.extrausers_group);
    if let Ok(m) = std::fs::metadata(paths.nss_passwd) {
        dlog!("post-write visibility: nss_passwd size={} mtime ok", m.len());
    }

    let elapsed = start.elapsed();
    eprintln!(
        "[idhelper] materialize done: elapsed={:?} passwd_entries={} group_entries={} nss_path={} extrausers_path={} outcome=ok",
        elapsed, passwd_lines.len(), group_lines.len(), nss_p,
        paths.extrausers_passwd.display()
    );
    dlog!(
        "materialize outcome elapsed={:?} passwd={} group={} nss={} outcome=ok",
        elapsed, passwd_lines.len(), group_lines.len(), nss_p
    );

    Ok(true)
}

#[cfg(test)]
mod root_snapshot_tests {
    use super::*;
    use crate::common::{IdCache, PrincipalKind, Resolved};

    #[test]
    fn materialize_skips_rewrite_when_content_unchanged() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let mut cache = IdCache::default();
        cache.insert(Resolved {
            principal: "testuser1@TESTLAB.LOCAL".into(),
            name: "testuser1".into(),
            uid: 3788,
            gid: 3002,
            kind: PrincipalKind::User,
            source: "bulk".into(),
            supplemental_gids: vec![3005, 3007],
        });
        let store_inodes = |paths: &NssMaterializePaths<'_>| -> Vec<u64> {
            [paths.nss_passwd, paths.nss_group, paths.extrausers_passwd, paths.extrausers_group]
                .iter()
                .map(|p| fs::metadata(p).expect("store exists").ino())
                .collect()
        };
        let first = materialize_nss_wrappers_at(&cache, &paths, None).expect("first materialize");
        assert!(first, "fresh paths must report a write");
        let inodes_after_first = store_inodes(&paths);
        let second = materialize_nss_wrappers_at(&cache, &paths, None).expect("second materialize");
        assert!(!second, "identical content must not rewrite");
        assert_eq!(
            store_inodes(&paths),
            inodes_after_first,
            "unchanged pass must leave every store untouched (rename would bump mtime and force an nss_wrapper reload in ganesha)"
        );
    }

    #[test]
    fn supplemental_gids_from_snapshot_collects_member_of_groups() {
        let mut snap = IdMapSnapshot::default();
        snap.groups.insert(
            "writers".into(),
            PosixGroupEntry {
                gid: 3005,
                display: "writers".into(),
                members: vec!["testuser1".into()],
            },
        );
        snap.groups.insert(
            "aux".into(),
            PosixGroupEntry {
                gid: 3007,
                display: "aux".into(),
                members: vec!["testuser1@REALM".into()],
            },
        );
        let supps = supplemental_gids_from_snapshot("testuser1", "testuser1@REALM", 3002, &snap);
        assert_eq!(supps, vec![3005, 3007]);
    }

    #[test]
    fn build_nss_snapshot_root_group_has_minimal_members_not_machine_logins() {
        // Drive shipped resolve_gids_and_materialize (not manual cache insert) so supplemental_gids
        // are populated from LDAP snapshot membership for machines + GROUPLIST root backstop.
        let _lock = crate::common::ENV_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        crate::resolve::reset_id_resolver_for_test();
        let old_pop = std::env::var("TEST_REBULK_POPULATE").ok();
        std::env::set_var(
            "TEST_REBULK_POPULATE",
            "g:admins:3005:root;g:hosts:3007:client-a",
        );
        let tmp = tempfile::tempdir().unwrap();
        let paths = NssMaterializePaths::under(tmp.path());
        let mut cache = IdCache::default();
        let realm = "TESTLAB.LOCAL";
        let _ = crate::resolve::resolve_principal(
            "host/nas-1@TESTLAB.LOCAL",
            realm,
            &[],
            &mut cache,
            &paths,
        );
        let _ = crate::resolve::resolve_gids_and_materialize(
            "host/nas-1@TESTLAB.LOCAL",
            realm,
            &[],
            &mut cache,
            &paths,
            false,
        );
        let root_gs = crate::resolve::resolve_gids_and_materialize(
            "root",
            realm,
            &[],
            &mut cache,
            &paths,
            false,
        );
        if let Some(v) = old_pop {
            std::env::set_var("TEST_REBULK_POPULATE", v);
        } else {
            std::env::remove_var("TEST_REBULK_POPULATE");
        }
        assert!(root_gs.contains(&0));
        assert!(root_gs.contains(&3005), "GROUPLIST root must include root-member group: {root_gs:?}");
        let (_, gr) = build_nss_snapshot(&cache, None);
        let root_line = gr
            .iter()
            .find(|l| l.starts_with("root:x:0:"))
            .expect("root group row");
        assert_eq!(*root_line, "root:x:0:root,daemon,bin", "gid-0 must not list machine logins: {root_line}");
        assert!(
            gr.iter().any(|l| l.contains(":3005:") && l.contains("root")),
            "root login on supplemental gid 3005: {gr:?}"
        );
        for bad in ["host/", "nas-1@", "client-a@"] {
            assert!(
                !root_line.contains(bad),
                "machine login must not appear on gid 0: {root_line}"
            );
        }
    }

    #[test]
    fn build_nss_snapshot_always_emits_exact_minimal_root_for_getgrouplist() {
        // Drives real shipped build_nss_snapshot (UUT) with empty + populated cache; must emit exact root passwd+group so getgrouplist("root",0) succeeds (AC2).
        let empty: IdCache = IdCache::default();
        let (pw0, gr0) = build_nss_snapshot(&empty, None);
        assert!(pw0.first().is_some_and(|l| l == "root:x:0:0:root:/root:/bin/sh"), "exact root passwd must lead even empty: {pw0:?}");
        assert!(gr0.iter().any(|l| l.starts_with("root:x:0:") && l.contains("root")), "root group must be present for getgrouplist root");

        // With a dynamic user, still force exact root first + its group.
        let mut c = IdCache::default();
        c.insert(Resolved {
            principal: "testuser1@TESTLAB.LOCAL".into(),
            name: "testuser1".into(),
            uid: 3788,
            gid: 3002,
            kind: PrincipalKind::User,
            source: "kldap".into(),
            supplemental_gids: vec![3004, 3005],
        });
        let (pw, gr) = build_nss_snapshot(&c, None);
        assert!(pw.first() == Some(&"root:x:0:0:root:/root:/bin/sh".to_string()), "root must be forced first: {pw:?}");
        assert!(gr.iter().any(|l| l == "root:x:0:root,daemon,bin" || l.starts_with("root:x:0:")), "root group line with members");
        assert!(pw.iter().any(|l| l.contains("testuser1")), "user seeded");
    }
}

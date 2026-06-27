//! NSS wrapper + extrausers materialization from the idhelper cache.

use crate::dlog;
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

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
}

/// Skip passwd logins that are only digits; they break getpwuid for real users.
fn is_numeric_login(login: &str) -> bool {
    !login.is_empty() && login.chars().all(|c| c.is_ascii_digit())
}

/// Passwd login for user@REALM principals; keeps @ for getpwnam while stripping unsafe chars.
pub(crate) fn principal_realm_login_for_nss(principal: &str) -> String {
    let mut out = String::with_capacity(principal.len());
    for c in principal.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@' {
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

/// Prefer LDAP group display name for a gid when snapshot data is available.
fn gname_for_gid(gid: u32, ldap_groups: Option<&HashMap<String, PosixGroupEntry>>, fallback: &str) -> String {
    if let Some(groups) = ldap_groups {
        if let Some(entry) = groups.values().find(|g| g.gid as u32 == gid) {
            return sanitize_for_nss(&entry.display);
        }
    }
    sanitize_for_nss(fallback)
}

/// Gecos safe for passwd/extrausers: no ':' (libnss-extrausers splits on colons).
pub(crate) fn gecos_for(r: &Resolved) -> String {
    let tag = if principal_has_realm(&r.principal) {
        r.principal.as_str()
    } else {
        r.name.as_str()
    };
    let safe: String = tag.chars().filter(|&c| c != ':').collect();
    format!("kll {} {}", r.kind.as_str(), safe)
}

/// Builds a passwd(5) line and assigns uid and gid zero to machines.
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
        group_line_with_members(0, "root", &[])
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

/// Returns true when cache content changed and nss files should be rewritten.
pub(crate) fn cache_changed_since(fp_before: u64, cache: &IdCache) -> bool {
    fp_before != cache.content_fingerprint()
}

/// Prunes stale LDAP users from cache but keeps machine principals.
pub(crate) fn sync_user_cache_from_snapshot(
    snap: &IdMapSnapshot,
    realm: &str,
    cache: &mut IdCache,
) -> usize {
    let pruned = cache.prune_non_machine_users();
    if pruned > 0 {
        dlog!("sync_user_cache pruned {} stale non-machine entries", pruned);
    }
    let n = seed_cache_and_nss_from_snapshot(snap, realm, cache);
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
        cache.insert(Resolved {
            principal,
            name: short_name,
            uid,
            gid,
            kind: PrincipalKind::User,
            source: "bulk".to_string(),
        });
        seeded += 1;
    }

    seeded
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

    // Primary-gid members for getgrouplist when LDAP member lists are empty.
    let mut users_by_gid: HashMap<u32, Vec<String>> = HashMap::new();
    for r in items.iter().copied() {
        if r.kind == PrincipalKind::User && r.gid != 0 && !is_numeric_local_principal(&r.principal) {
            users_by_gid
                .entry(r.gid)
                .or_default()
                .push(sanitize_for_nss(&r.name));
        }
    }

    if let Some(groups) = ldap_groups {
        let mut by_gid: HashMap<i32, &PosixGroupEntry> = HashMap::new();
        for entry in groups.values() {
            by_gid.entry(entry.gid).or_insert(entry);
        }
        for entry in by_gid.values() {
            let gid = entry.gid as u32;
            if seen_gid.insert(gid) {
                let gname = sanitize_for_nss(&entry.display);
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
                group_lines.push(group_line_with_members(gid, &gname, &members));
            }
        }
    }

    for r in &items {
        if is_numeric_local_principal(&r.principal) {
            continue;
        }
        let line = passwd_line_for(r);
        if let Some(login) = line.split(':').next() {
            if !is_numeric_login(login) && seen_login.insert(login.to_string()) {
                passwd_lines.push(line);
            }
        }

        let local = principal_local_part(&r.principal);
        if local.contains('/') && MACHINE_PRINCIPAL_PREFIXES.iter().any(|p| local.starts_with(p)) {
            let alias = sanitize_for_nss(local);
            if !is_numeric_login(&alias) && seen_login.insert(alias.clone()) {
                let gecos = gecos_for(r);
                passwd_lines.push(format!(
                    "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
                    alias, r.uid, r.gid, gecos
                ));
            }
        }

        // User principal@REALM login is required for Ganesha getpwnam(user@REALM) on krb5 auth.
        if r.kind == PrincipalKind::User && principal_has_realm(&r.principal) {
            let login = principal_realm_login_for_nss(&r.principal);
            let gecos = gecos_for(r);
            if !is_numeric_login(&login) && seen_login.insert(login.clone()) {
                passwd_lines.push(format!(
                    "{}:x:{}:{}:{}:/nonexistent:/usr/sbin/nologin",
                    login, r.uid, r.gid, gecos
                ));
            }
        }

        if seen_gid.insert(r.gid) {
            if r.kind != PrincipalKind::Machine && r.gid != 0 {
                let gname = gname_for_gid(r.gid, ldap_groups, &r.name);
                let member = sanitize_for_nss(&r.name);
                group_lines.push(format!("{}:x:{}:{}", gname, r.gid, member));
            } else {
                group_lines.push(group_line_for(r));
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

    if seen_gid.is_empty() || !seen_gid.contains(&0) {
        group_lines.push("root:x:0:root,daemon,bin".to_string());
    }

    if !passwd_lines.iter().any(|l| l.starts_with("root:")) {
        passwd_lines.insert(0, "root:x:0:0:root:/nonexistent:/usr/sbin/nologin".to_string());
    }
    if !passwd_lines.iter().any(|l| l.starts_with("nobody:")) {
        passwd_lines.push(format!(
            "nobody:x:{}:{}:nfs-klldap fallback:/nonexistent:/usr/sbin/nologin",
            FALLBACK_NOBODY_UID, FALLBACK_NOBODY_GID
        ));
    }

    (passwd_lines, group_lines)
}

/// Atomically write nss_wrapper passwd/group for ganesha.nfsd LD_PRELOAD.
/// Also writes extrausers supplement.
pub(crate) fn materialize_nss_wrappers(cache: &IdCache) -> io::Result<()> {
    materialize_nss_wrappers_at(cache, &NssMaterializePaths::production(), None)
}

/// Same as materialize_nss_wrappers but writes to caller-supplied paths.
/// Used in rebulk tests.
pub(crate) fn materialize_nss_wrappers_at(
    cache: &IdCache,
    paths: &NssMaterializePaths<'_>,
    ldap_groups: Option<&HashMap<String, PosixGroupEntry>>,
) -> io::Result<()> {
    if let Some(parent) = paths.nss_passwd.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let (passwd_lines, group_lines) = build_nss_snapshot(cache, ldap_groups);

    {
        let tmp = paths.nss_passwd.with_extension("tmp");
        let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        let mut w = BufWriter::new(f);
        // Nss_wrapper (Debian trixie) rejects '#' comment lines Emit entries.
        for l in &passwd_lines {
            writeln!(w, "{}", l)?;
        }
        fs::rename(tmp, paths.nss_passwd)?;
    }

    {
        let tmp = paths.nss_group.with_extension("tmp");
        let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        let mut w = BufWriter::new(f);
        for l in &group_lines {
            writeln!(w, "{}", l)?;
        }
        fs::rename(tmp, paths.nss_group)?;
    }

    dlog!(
        "nss_wrapper materialized passwd={} entries group={} entries",
        passwd_lines.len(),
        group_lines.len()
    );

    // Write supplemental extrausers entries so machines map to 0 via nsswitch.
    {
        // Ensure dir exists (harmless for nss_wrapper paths under.
        if let Some(p) = paths.extrausers_passwd.parent() {
            let _ = fs::create_dir_all(p);
        }
        {
            let tmp = paths.extrausers_passwd.with_extension("tmp");
            let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(f);
            // libnss-extrausers rejects '#' lines; emit passwd entries only.
            for l in &passwd_lines {
                writeln!(w, "{}", l)?;
            }
            fs::rename(tmp, paths.extrausers_passwd)?;
        }
        {
            let tmp = paths.extrausers_group.with_extension("tmp");
            let f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            let mut w = BufWriter::new(f);
            for l in &group_lines {
                writeln!(w, "{}", l)?;
            }
            fs::rename(tmp, paths.extrausers_group)?;
        }
    }

    Ok(())
}

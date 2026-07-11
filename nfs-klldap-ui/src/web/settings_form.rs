//! Form row logic and parsers extracted from settings.rs for modularization.
//! Target file size <=800 LOC.

#[derive(Debug, Clone, Default)]
pub(crate) struct ShareFormRow {
    pub idx: usize,
    pub name: String,
    pub host: String,
    pub pseudo_path: Option<String>,
    pub security: Option<String>,
    pub rw: bool,
    pub root_squash: bool,
    pub cache_profile: Option<String>,
    pub pref_read: Option<String>,
    pub pref_write: Option<String>,
    pub enable_acl: Option<bool>,
    pub manage_gids: Option<bool>,
    pub read_access_policy: Option<String>,
    pub manage_gids_expiration: Option<u64>,
    pub container_path: String,
    pub source_path: Option<String>,
    pub umask: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ShareTemplateRow {
    pub idx: usize,
    pub name: String,
    pub host_path: String,
    pub pseudo_path: String,
    pub pseudo_editable: bool,
    pub effective_pseudo: String,
    pub container_path: String,
    pub security: String,
    pub rw: bool,
    pub root_squash: bool,
    pub cache_profile: String,
    /// Raw select value: "auto" | "true" | "false".
    pub enable_acl: String,
    /// True only when the export will actually serve ACLs (enable_acl opted-in AND
    /// serve-path FS is ACL-capable). Drives status-dot / legend alignment with Share Permissions.
    pub effective_acl_capable: bool,
    pub manage_gids: String,
    pub read_access_policy: String,
    pub manage_gids_expiration: Option<u64>,
    pub warning: Option<String>,
    pub fs_warning: Option<String>,
}

impl ShareTemplateRow {
    /// Blank row for the "+ Add share" card, matching the pre-server-render JS defaults
    /// (RW, root_squash ON by default, auto/NOACL selects, editable pseudo path).
    pub(crate) fn blank(idx: usize) -> Self {
        Self {
            idx,
            name: String::new(),
            host_path: String::new(),
            pseudo_path: String::new(),
            pseudo_editable: true,
            effective_pseudo: String::new(),
            container_path: String::new(),
            security: String::new(),
            rw: true,
            root_squash: true,
            cache_profile: "Default".to_string(),
            enable_acl: "auto".to_string(),
            effective_acl_capable: false,
            manage_gids: "auto".to_string(),
            read_access_policy: "auto".to_string(),
            manage_gids_expiration: None,
            warning: None,
            fs_warning: None,
        }
    }
}

pub(crate) fn has_explicit(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> bool {
    if section.is_empty() {
        doc.get(key).is_some()
    } else {
        doc.get(section).and_then(|i| i.as_table()).is_some_and(|t| t.get(key).is_some())
    }
}

pub(crate) fn get_explicit_str(doc: &toml_edit::DocumentMut, section: &str, key: &str) -> Option<String> {
    let val = if section.is_empty() { doc.get(key) } else {
        doc.get(section).and_then(|i| i.as_table()).and_then(|t| t.get(key))
    };
    val.and_then(|v| v.as_str()).map(|s| s.to_string())
}

pub(crate) fn share_pseudo_path_explicit_in_raw(doc: &toml_edit::DocumentMut, idx: usize) -> bool {
    doc.get("shares").and_then(|s| s.as_array_of_tables()).is_some_and(|a| a.get(idx).is_some_and(|t| t.get("pseudo_path").is_some() || t.get("export_path").is_some()))
}

pub(crate) fn share_pseudo_path_from_raw(doc: &toml_edit::DocumentMut, idx: usize) -> String {
    let arr = match doc.get("shares").and_then(|s| s.as_array_of_tables()) { Some(a) => a, None => return String::new() };
    let tbl = match arr.get(idx) { Some(t) => t, None => return String::new() };
    // Prefer current key, fall back to legacy export_path for old on-disk configs.
    let key = if tbl.get("pseudo_path").is_some() { "pseudo_path" } else { "export_path" };
    if tbl.get(key).is_none() { return String::new(); }
    let raw = tbl.get(key).and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if raw.is_empty() { String::new() } else if raw.starts_with('/') { raw } else { format!("/{}", raw) }
}

pub(crate) fn infer_profile_from_prefs(pr: Option<u64>, pw: Option<u64>) -> String {
    match (pr, pw) {
        (Some(1048576), Some(1048576)) => "Default".to_string(),
        (Some(4194304), Some(4194304)) => "Read - Basic".to_string(),
        (Some(16777216), Some(8388608)) => "Read - Heavy".to_string(),
        (Some(2097152), Some(16777216)) => "Write - Heavy".to_string(),
        _ => "Default".to_string(),
    }
}

pub(crate) fn parse_tri_bool(v: &str) -> Option<bool> {
    match v.trim() {
        "true" => Some(true),
        "false" => Some(false),
        "auto" | "" => None,
        _ => None,
    }
}

pub(crate) fn collect_shares_from_structured_form(
    extra: &std::collections::HashMap<String, String>,
) -> Vec<nfs_klldap_config::Share> {
    let mut rows: Vec<ShareFormRow> = vec![];
    for (k, v) in extra {
        if let Some(suf) = k.strip_prefix("share_name_") {
            if let Ok(idx) = suf.parse::<usize>() {
                let nm = v.trim().to_string();
                let ht = extra.get(&format!("share_host_{}", idx)).cloned().unwrap_or_default().trim().to_string();
                let cp = extra
                    .get(&format!("share_container_path_{}", idx))
                    .cloned()
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                if nm.is_empty() || ht.is_empty() || cp.is_empty() { continue; }
                rows.push(ShareFormRow {
                    idx,
                    name: nm,
                    host: ht,
                    pseudo_path: extra.get(&format!("share_pseudo_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    security: extra.get(&format!("share_security_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    rw: extra.get(&format!("share_rw_{}", idx)).map(|vv| vv.trim() == "true").unwrap_or(true),
                    root_squash: extra.contains_key(&format!("share_root_squash_{}", idx)),
                    cache_profile: extra.get(&format!("share_cache_profile_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    pref_read: extra.get(&format!("share_pref_read_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    pref_write: extra.get(&format!("share_pref_write_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    enable_acl: extra.get(&format!("share_enable_acl_{}", idx)).and_then(|v| parse_tri_bool(v)),
                    manage_gids: extra.get(&format!("share_manage_gids_{}", idx)).and_then(|v| parse_tri_bool(v)),
                    read_access_policy: extra.get(&format!("share_read_access_policy_{}", idx)).and_then(|vv| if vv.trim() == "pre" { Some("pre".into()) } else if vv.trim() == "post" { Some("post".into()) } else { None }),
                    manage_gids_expiration: extra.get(&format!("share_manage_gids_expiration_{}", idx)).and_then(|vv| vv.trim().parse().ok()),
                    container_path: cp,
                    source_path: extra.get(&format!("share_source_path_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                    umask: extra.get(&format!("share_umask_{}", idx)).cloned().filter(|s| !s.trim().is_empty()),
                });
            }
        }
    }
    rows.sort_by_key(|r| r.idx);
    rows.into_iter().map(|r| nfs_klldap_config::Share {
        name: r.name,
        host_path: std::path::PathBuf::from(r.host),
        pseudo_path: r.pseudo_path,
        security: Some(r.security.unwrap_or_else(|| "krb5p".to_string())),
        rw: Some(r.rw),
        cache_profile: Some(r.cache_profile.unwrap_or_else(|| "Default".to_string())),
        pref_read: r.pref_read.and_then(|s| s.parse().ok()),
        pref_write: r.pref_write.and_then(|s| s.parse().ok()),
        enable_acl: r.enable_acl,
        manage_gids: r.manage_gids,
        read_access_policy: r.read_access_policy,
        manage_gids_expiration: r.manage_gids_expiration,
        container_path: r.container_path,
        source_path: r.source_path,
        umask: r.umask,
        // Explicit both ways: the default is root_squash, so an unchecked box
        // must emit no_root_squash to actually turn squashing off (None would
        // fall through to the safe default and the checkbox would be inert).
        squash: if r.root_squash { Some("root_squash".to_string()) } else { Some("no_root_squash".to_string()) },
    }).collect()
}
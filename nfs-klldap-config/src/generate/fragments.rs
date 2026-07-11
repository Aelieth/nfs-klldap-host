//! Fragment writing is split for modularization.

use std::fs;
use std::path::Path;

use crate::constants;
use crate::{ConfigError, FsCapabilities, NfsKlldapConfig};

use super::directives::{derive_export_id, export_fs_directives, export_read_access_line, export_pseudo_line, fragment_basename};

pub fn write_export_fragments(cfg: &NfsKlldapConfig, exports_dir: &Path) -> Result<(), ConfigError> {
    if exports_dir.exists() {
        for entry in fs::read_dir(exports_dir)? {
            let p = entry?.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".conf") && name.len() >= 7 {
                    let b = name.as_bytes();
                    if b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b'-' {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
    }
    fs::create_dir_all(exports_dir)?;
    let mountinfo_once: Option<String> = std::env::var("NFS_KLLDAP_MOUNTINFO_PATH").ok().and_then(|p| std::fs::read_to_string(p).ok()).or_else(|| std::fs::read_to_string("/proc/self/mountinfo").ok());

    for (i, share) in cfg.shares.iter().enumerate() {
        let export_id = derive_export_id(&share.name, 1000 + (i as u16 * 10));
        let path = cfg.serve_path_for(share);
        let pseudo = crate::derive_share_pseudo(share);
        let default_sec = &cfg.ganesha.default_security;
        let sec = share.security.as_deref().unwrap_or(default_sec);
        let access = if share.rw.unwrap_or(true) { "RW" } else { "RO" };
        let squash = share.squash.as_deref().unwrap_or(constants::GANESHA_DEFAULT_SQUASH);

        let (pref_r, pref_w) = if let Some(cp) = &share.cache_profile {
            if let Some((r, w)) = crate::resolve_cache_profile(cp) { (Some(r), Some(w)) } else { (share.pref_read, share.pref_write) }
        } else { (share.pref_read, share.pref_write) };

        let pref_read_line = pref_r.map(|v| format!("    PrefRead = {};\n", v)).unwrap_or_default();
        let pref_write_line = pref_w.map(|v| format!("    PrefWrite = {};\n", v)).unwrap_or_default();

        let caps = if let Some(ref c) = mountinfo_once { crate::probe_from_mountinfo(c, Path::new(&path)) } else { crate::probe_fs_capabilities(Path::new(&path)).unwrap_or_else(|_| FsCapabilities{fstype:"unknown".into(),mount_options:vec![],acl_capable:false}) };
        let (disable_acl_line, manage_gids_line, umask_line, auto_comment) = export_fs_directives(share, &caps);
        let read_access_line = export_read_access_line(share, &caps);
        let eff = crate::compute_effective_flags(share, &caps);
        if eff.enable_acl {
            // Warn loudly when opted-in ACL hits a non-capable serve path.
            let posix_acl = crate::serve_path_posix_acl_supported(Path::new(&path));
            if !caps.acl_capable || posix_acl == Some(false) {
                eprintln!(
                    "WARN [nfs-klldap-config] share '{}': enable_acl = true but serve path '{}' \
                     (fstype={}{}) does not look ACL-capable — the Ganesha VFS POSIX-ACL \
                     backend will return NFS4ERR_NOTSUPP for NFSv4 ACL ops there. Stage onto \
                     an ACL-capable tree via source_path. Verify with verify-ganesha.sh \
                     (docs/ganesha-architecture.md).",
                    share.name,
                    path,
                    caps.fstype,
                    if posix_acl == Some(false) { ", no POSIX ACL" } else { "" }
                );
            }
        }
        if share.umask.is_some() {
            eprintln!(
                "WARN [nfs-klldap-config] share '{}': umask is not emitted — Ganesha 9.13 \
                 dropped per-export FSAL Umask (module-global only). The key is inert until \
                 the ACL track (plan 2.4 POSIX gate) replaces it.",
                share.name
            );
        }
        // Deprecated share manage_gids_expiration seeds main-conf Idmapped_*.
        let pseudo_line = export_pseudo_line(&pseudo);
        let client_block = format!(r#"
    CLIENT {{
        Clients = *;
        Access_Type = {access};
        Protocols = {proto};
    }}

"#, access = access, proto = constants::GANESHA_PROTOCOLS);

        let block = format!(r#"# Generated from nfs-klldap.conf share "{}"
{auto_comment}EXPORT {{
    Export_Id = {};
    Path = {};
{pseudo_line}{disable_acl_line}    SecType = {};
    Squash = {};
{manage_gids_line}{read_access_line}{pref_read_line}{pref_write_line}{client_block}    FSAL {{
        Name = VFS;
{umask_line}    }}
}}
"#, share.name, export_id, path, sec, squash, auto_comment=auto_comment, pseudo_line=pseudo_line, disable_acl_line=disable_acl_line, manage_gids_line=manage_gids_line, read_access_line=read_access_line, pref_read_line=pref_read_line, pref_write_line=pref_write_line, client_block=client_block, umask_line=umask_line);

        let filename = fragment_basename(i, &share.name);
        fs::write(exports_dir.join(filename), block.as_bytes())?;
    }
    Ok(())
}

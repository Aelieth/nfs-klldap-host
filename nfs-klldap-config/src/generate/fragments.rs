//! Fragment writing is split for modularization.

use std::fs;
use std::path::Path;

use crate::constants;
use crate::{ConfigError, FsCapabilities, NfsKlldapConfig};

use super::directives::{derive_export_id, export_fs_directives, export_read_access_line, export_pseudo_line, fragment_basename};

pub fn write_export_fragments(cfg: &NfsKlldapConfig, exports_dir: &Path) -> Result<(), ConfigError> {
    // Validate all shares before any write; an abort mid-loop split the dir.
    let mut staged: Vec<(String, String)> = Vec::new();
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
            if let Some((r, w)) = crate::config::resolve_cache_profile(cp) { (Some(r), Some(w)) } else { (share.pref_read, share.pref_write) }
        } else { (share.pref_read, share.pref_write) };

        let pref_read_line = pref_r.map(|v| format!("    PrefRead = {};\n", v)).unwrap_or_default();
        let pref_write_line = pref_w.map(|v| format!("    PrefWrite = {};\n", v)).unwrap_or_default();
        // Per-share attribute-cache override; 0 = always fresh on this export.
        let attr_expiry_line = share
            .attr_expiration_secs
            .map(|v| format!("    Attr_Expiration_Time = {};\n", v))
            .unwrap_or_default();

        let caps = if let Some(ref c) = mountinfo_once { crate::probe_from_mountinfo(c, Path::new(&path)) } else { crate::probe_fs_capabilities(Path::new(&path)).unwrap_or_else(|_| FsCapabilities{fstype:"unknown".into(),mount_options:vec![],acl_capable:false}) };
        // Explicit-off shares skip the write probe (nothing to prove).
        let verdict = if share.enable_acl == Some(false) {
            crate::verdict_from_caps(&caps)
        } else {
            crate::acl_probe_verdict(&caps, Path::new(&path))
        };
        let eff = crate::compute_effective_flags_probed(share, &caps, verdict);
        let (disable_acl_line, manage_gids_line, umask_line, auto_comment) = export_fs_directives(share, &caps, &eff);
        let read_access_line = export_read_access_line(share, &eff);
        if share.enable_acl == Some(true) {
            // Negative probe refuses; inconclusive warns; auto skips this.
            match verdict {
                crate::AclProbeVerdict::Capable => {}
                crate::AclProbeVerdict::Incapable => {
                    return Err(crate::ConfigError::Generation(format!(
                        "share '{}': enable_acl = true but serve path '{}' (fstype={}) \
                         cannot store POSIX ACLs. Refusing to emit a broken ACL export. \
                         Escape: use the staging pattern — set source_path to the data \
                         tree and container_path to an ACL-capable serve tree, with the \
                         post-generate sync hook (examples/post-generate-staging-sync.sh, \
                         docs/ganesha-architecture.md#acl-and-filesystem-compatibility) — \
                         or set enable_acl = false.",
                        share.name, path, caps.fstype
                    )));
                }
                crate::AclProbeVerdict::Inconclusive => {
                    eprintln!(
                        "WARN [nfs-klldap-config] share '{}': enable_acl = true but the \
                         ACL write probe on serve path '{}' (fstype={}) was inconclusive — \
                         if the filesystem cannot store POSIX ACLs, client attribute \
                         fetches will fail there. Verify with verify-ganesha.sh \
                         (docs/ganesha-architecture.md).",
                        share.name, path, caps.fstype
                    );
                }
            }
        }
        if share.umask.is_some() {
            return Err(crate::ConfigError::Generation(format!(
                "share '{}': the umask key is retired — Ganesha 9.13 dropped per-export \
                 FSAL Umask, and creation-mode enveloping now lives in default (inheritance) \
                 ACL entries plus setgid (the permission panel's Inherit tab; \
                 docs/ganesha-architecture.md#nfs-create-inheritance-umask-and-acl-default-entries). \
                 Remove `umask` from this share to generate.",
                share.name
            )));
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
{manage_gids_line}{read_access_line}{pref_read_line}{pref_write_line}{attr_expiry_line}{client_block}    FSAL {{
        Name = VFS;
{umask_line}    }}
}}
"#, share.name, export_id, path, sec, squash, auto_comment=auto_comment, pseudo_line=pseudo_line, disable_acl_line=disable_acl_line, manage_gids_line=manage_gids_line, read_access_line=read_access_line, pref_read_line=pref_read_line, pref_write_line=pref_write_line, attr_expiry_line=attr_expiry_line, client_block=client_block, umask_line=umask_line);

        staged.push((fragment_basename(i, &share.name), block));
    }

    // Write the validated set; prune after writing so a crash keeps fragments.
    fs::create_dir_all(exports_dir)?;
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (filename, block) in staged {
        crate::atomic_write(&exports_dir.join(&filename), block.as_bytes())?;
        written.insert(filename);
    }
    // Prune fragments for shares that no longer exist (same NN- naming rule).
    for entry in fs::read_dir(exports_dir)? {
        let p = entry?.path();
        if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
            if written.contains(name) {
                continue;
            }
            if name.ends_with(".conf") && name.len() >= 7 {
                let b = name.as_bytes();
                if b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b'-' {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }
    Ok(())
}

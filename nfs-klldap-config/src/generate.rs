//! Generation of sssd.conf, krb5.conf, and Ganesha EXPORT fragments.
//!
//! This module owns the "produce derived configs from NfsKlldapConfig" logic.
//! Extracted during Phase 5 of the modularization.

use std::fs;
use std::path::Path;

use crate::{ConfigError, GenerationPaths, NfsKlldapConfig};

// The two small pure helpers (moved in micro-step 1)
pub(crate) fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

pub(crate) fn derive_export_id(name: &str, base: u16) -> u16 {
    let mut h: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        h = h.wrapping_mul(16777619) ^ (*b as u32);
    }
    base + (h % 55000) as u16
}

/// Full generation driver. Call this from entrypoint / watcher / UI save hooks.
pub fn generate_all(cfg: &NfsKlldapConfig, paths: &GenerationPaths) -> Result<(), ConfigError> {
    fs::create_dir_all(&paths.exports_dir)?;

    write_sssd_conf(cfg, &paths.sssd_conf)?;
    write_krb5_conf(cfg, &paths.krb5_conf)?;
    write_ganesha_main(cfg, &paths.ganesha_conf, &paths.exports_dir)?;
    write_export_fragments(cfg, &paths.exports_dir)?;

    Ok(())
}

fn write_sssd_conf(cfg: &NfsKlldapConfig, out: &Path) -> Result<(), ConfigError> {
    let realm = cfg.effective_realm();
    let search_base = cfg
        .sssd
        .ldap_search_base
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));

    let default_user_base = format!("ou=people,{}", search_base);
    let default_group_base = format!("ou=groups,{}", search_base);

    let user_base = cfg
        .sssd
        .ldap_user_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_user_base);
    let group_base = cfg
        .sssd
        .ldap_group_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_group_base);

    let domain_name = cfg
        .sssd
        .domain
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "default".to_string());

    let is_plain_ldap = cfg.ldap_uri.starts_with("ldap://");

    // Determine auth provider (default "ldap", but "krb5" is very common in Kerberized NFS setups)
    let auth_provider = cfg
        .sssd
        .auth_provider
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "ldap".to_string());

    let mut content = format!(
        r#"[sssd]
config_file_version = 2
services = nss, pam
domains = {domain_name}

[nss]
filter_users = root
filter_groups = root

[domain/{domain_name}]
id_provider = ldap
auth_provider = {auth_provider}
ldap_uri = {ldap_uri}
ldap_search_base = {search_base}
ldap_default_bind_dn = {bind_dn}
ldap_default_authtok = {bind_pw}
cache_credentials = true
"#,
        domain_name = domain_name,
        auth_provider = auth_provider,
        ldap_uri = cfg.ldap_uri,
        search_base = search_base,
        bind_dn = cfg.sssd.ldap_default_bind_dn,
        bind_pw = cfg.sssd.ldap_default_authtok,
    );

    // Rich LLDAP + POSIX attribute mappings + production safety flags.
    // The helper now also handles hybrid Kerberos authentication when requested.
    content.push_str(&build_ldap_domain_options(
        cfg,
        user_base,
        group_base,
        is_plain_ldap,
    ));

    fs::write(out, content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Builds the rich body of the [domain/xxx] section.
///
/// This is the main "broad spectrum" helper. It aims to generate something
/// very close to real-world proven LLDAP + Kerberos + Ganesha configurations
/// (both plain ldap:// and ldaps:// variants).
fn build_ldap_domain_options(
    cfg: &NfsKlldapConfig,
    user_base: &str,
    group_base: &str,
    is_plain_ldap: bool,
) -> String {
    let s = &cfg.sssd;

    // --- POSIX attribute mappings (user overrides always win) ---
    let user_obj = s
        .ldap_user_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixAccount".to_string());
    let group_obj = s
        .ldap_group_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixGroup".to_string());

    let u_name = s
        .ldap_user_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uid".to_string());
    let u_uid = s
        .ldap_user_uid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uidNumber".to_string());
    let u_gid = s
        .ldap_user_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());
    let u_home = s
        .ldap_user_home_directory
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "homeDirectory".to_string());
    let u_shell = s
        .ldap_user_shell
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "loginShell".to_string());

    let g_name = s
        .ldap_group_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "cn".to_string());
    let g_gid = s
        .ldap_group_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    // enumerate default = true because this project benefits from a warm cache
    let enumerate = if s.enumerate.unwrap_or(true) {
        "true"
    } else {
        "false"
    };

    let mut out = format!(
        r#"ldap_user_search_base = {user_base}
ldap_user_object_class = {user_obj}
ldap_user_name = {u_name}
ldap_user_uid_number = {u_uid}
ldap_user_gid_number = {u_gid}
ldap_user_home_directory = {u_home}
ldap_user_shell = {u_shell}

ldap_group_search_base = {group_base}
ldap_group_object_class = {group_obj}
ldap_group_name = {g_name}
ldap_group_gid_number = {g_gid}

enumerate = {enumerate}
access_provider = {access}"#,
        user_base = user_base,
        user_obj = user_obj,
        u_name = u_name,
        u_uid = u_uid,
        u_gid = u_gid,
        u_home = u_home,
        u_shell = u_shell,
        group_base = group_base,
        group_obj = group_obj,
        g_name = g_name,
        g_gid = g_gid,
        enumerate = enumerate,
        access = s
            .access_provider
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or("permit"),
    );

    // Optional fields — only emit when explicitly set
    if let Some(v) = &s.ldap_tls_reqcert {
        if !v.trim().is_empty() {
            out.push_str(&format!("\nldap_tls_reqcert = {}", v.trim()));
        }
    }
    if let Some(v) = &s.ldap_tls_cacert {
        if !v.trim().is_empty() {
            out.push_str(&format!("\nldap_tls_cacert = {}", v.trim()));
        }
    }
    if let Some(v) = s.ldap_id_use_start_tls {
        out.push_str(&format!(
            "\nldap_id_use_start_tls = {}",
            if v { "true" } else { "false" }
        ));
    }
    if let Some(v) = s
        .ldap_user_fullname
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        out.push_str(&format!("\nldap_user_fullname = {}", v.trim()));
    }
    if let Some(v) = s
        .ldap_group_member
        .as_ref()
        .filter(|v| !v.trim().is_empty())
    {
        out.push_str(&format!("\nldap_group_member = {}", v.trim()));
    }

    // Advanced krb5 knobs
    if let Some(v) = s.krb5_server.as_ref().filter(|v| !v.trim().is_empty()) {
        out.push_str(&format!("\nkrb5_server = {}", v.trim()));
    }
    if let Some(v) = s.krb5_kpasswd.as_ref().filter(|v| !v.trim().is_empty()) {
        out.push_str(&format!("\nkrb5_kpasswd = {}", v.trim()));
    }
    if let Some(v) = s.krb5_validate {
        out.push_str(&format!(
            "\nkrb5_validate = {}",
            if v { "true" } else { "false" }
        ));
    }
    if let Some(v) = s.krb5_store_password_if_offline {
        out.push_str(&format!(
            "\nkrb5_store_password_if_offline = {}",
            if v { "true" } else { "false" }
        ));
    }

    // Plain ldap:// safety flag
    if is_plain_ldap
        && s.ldap_auth_disable_tls_never_use_in_production
            .unwrap_or(true)
    {
        out.push_str("\nldap_auth_disable_tls_never_use_in_production = true");
    }

    out
}

fn write_krb5_conf(cfg: &NfsKlldapConfig, out: &Path) -> Result<(), ConfigError> {
    let realm = cfg.effective_realm();
    let kdc_host = crate::extract_host_from_uri(&cfg.ldap_uri);

    let content = format!(
        r#"[libdefaults]
    default_realm = {realm}
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    {realm} = {{
        kdc = {kdc_host}
        admin_server = {kdc_host}
    }}

[domain_realm]
    .{realm_lower} = {realm}
    {realm_lower} = {realm}
"#,
        realm = realm,
        realm_lower = realm.to_lowercase(),
        kdc_host = kdc_host,
    );

    fs::write(out, content.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(out, fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

fn write_ganesha_main(
    cfg: &NfsKlldapConfig,
    out: &Path,
    exports_dir: &Path,
) -> Result<(), ConfigError> {
    let sec = &cfg.ganesha.default_security;

    let content = format!(
        r#"NFS_CORE_PARAM {{
    Protocols = 4;
}}

NFSV4 {{
    Lease_Lifetime = 60;
}}

EXPORT_DEFAULTS {{
    SecType = {sec};
}}

%include "{exports}/*.conf"
"#,
        sec = sec,
        exports = exports_dir.display(),
    );

    fs::write(out, content.as_bytes())?;
    Ok(())
}

fn write_export_fragments(cfg: &NfsKlldapConfig, exports_dir: &Path) -> Result<(), ConfigError> {
    // Clean old managed fragments (we own them)
    if exports_dir.exists() {
        for entry in fs::read_dir(exports_dir)? {
            let p = entry?.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                if name.ends_with(".conf") {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    for (i, share) in cfg.shares.iter().enumerate() {
        let export_id = derive_export_id(&share.name, 1000 + (i as u16 * 10));
        let path = cfg.container_path_for(share);
        let default_pseudo = format!("/{}", share.name);
        let pseudo = share.export_path.as_deref().unwrap_or(&default_pseudo);
        let default_sec = &cfg.ganesha.default_security;
        let sec = share.security.as_deref().unwrap_or(default_sec);
        let access = if share.rw.unwrap_or(true) { "RW" } else { "RO" };
        let squash = share.squash.as_deref().unwrap_or("no_root_squash");

        let block = format!(
            r#"# Generated from nfs-klldap.conf share "{}"
EXPORT {{
    Export_Id = {};
    Path = {};
    Pseudo = {};
    Access_Type = {};
    SecType = {};
    Protocols = 4;
    Transports = TCP;
    Squash = {};

    FSAL {{
        Name = VFS;
    }}
}}
"#,
            share.name, export_id, path, pseudo, access, sec, squash
        );

        let filename = format!("{:02}-{}.conf", i + 10, sanitize_name(&share.name));
        fs::write(exports_dir.join(filename), block.as_bytes())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_replaces_invalid_chars() {
        assert_eq!(sanitize_name("my share!"), "my-share-");
        assert_eq!(sanitize_name("data_01"), "data_01");
        assert_eq!(sanitize_name("foo@bar#baz"), "foo-bar-baz");
    }

    #[test]
    fn derive_export_id_is_deterministic() {
        let id1 = derive_export_id("movies", 1000);
        let id2 = derive_export_id("movies", 1000);
        assert_eq!(id1, id2);
        assert_ne!(
            derive_export_id("movies", 1000),
            derive_export_id("data", 1000)
        );
    }
}

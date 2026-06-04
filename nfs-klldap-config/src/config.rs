//! Data model for nfs-klldap.conf. Validation/derivation/generation in validate.rs + generate.rs.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level config (nfs-klldap.conf)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NfsKlldapConfig {
    pub ldap_uri: String,

    #[serde(default)]
    pub storage: StorageSection,

    #[serde(default)]
    pub server: ServerSection,

    #[serde(default)]
    pub sssd: SssdSection,

    #[serde(default)]
    pub kerberos: KerberosSection,

    #[serde(default)]
    pub ganesha: GaneshaSection,

    #[serde(default)]
    pub management: ManagementSection,

    #[serde(default)]
    pub shares: Vec<Share>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageSection {
    #[serde(default = "default_container_root")]
    pub container_root: String,
}

fn default_container_root() -> String {
    "/export".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerSection {
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SssdSection {
    pub ldap_default_bind_dn: String,
    pub ldap_default_authtok: String,
    /// Derived 636/389 for reference; SSSD uses ldap_uri (port must be in the URI).
    pub port: Option<u16>,
    pub ldap_user_search_base: Option<String>,
    pub ldap_group_search_base: Option<String>,

    /// Optional explicit override for the main ldap_search_base.
    /// When unset, it is derived from the Kerberos realm (recommended).
    pub ldap_search_base: Option<String>,

    /// TLS options emitted verbatim into generated sssd.conf.
    pub ldap_tls_reqcert: Option<String>,
    pub ldap_tls_cacert: Option<String>,
    pub ldap_id_use_start_tls: Option<bool>,

    // === Rich LLDAP + POSIX attribute mapping (broad spectrum support) ===
    // These have excellent defaults for typical LLDAP deployments with POSIX attributes.
    // Override only when your LLDAP schema differs.
    pub enumerate: Option<bool>,

    // Object classes (user often has inetOrgPerson + posixAccount auxiliary in LLDAP)
    pub ldap_user_object_class: Option<String>,
    pub ldap_group_object_class: Option<String>,

    // User attribute mappings (highly recommended for correct UID/GID + home/shell)
    pub ldap_user_name: Option<String>,
    pub ldap_user_uid_number: Option<String>,
    pub ldap_user_gid_number: Option<String>,
    pub ldap_user_home_directory: Option<String>,
    pub ldap_user_shell: Option<String>,
    pub ldap_user_fullname: Option<String>,

    // Group attribute mappings
    pub ldap_group_name: Option<String>,
    pub ldap_group_gid_number: Option<String>,
    pub ldap_group_member: Option<String>,

    pub domain: Option<String>,
    pub kllldap_ignored_attributes: Option<bool>,
    pub auth_provider: Option<String>,
    pub chpass_provider: Option<String>,
    pub ldap_schema: Option<String>,
    pub ldap_id_mapping: Option<bool>,
    pub ldap_auth_disable_tls_never_use_in_production: Option<bool>,
    pub access_provider: Option<String>,
    pub use_fully_qualified_names: Option<bool>,
    pub krb5_server: Option<String>,
    pub krb5_kpasswd: Option<String>,
    pub krb5_validate: Option<bool>,
    pub krb5_store_password_if_offline: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAttributeMapping {
    pub user_object_class: String,
    pub group_object_class: String,
    pub user_name: String,
    pub user_uid_number: String,
    pub user_gid_number: String,
    pub user_home_directory: String,
    pub user_shell: String,
    pub user_full_name: String,
    pub group_name: String,
    pub group_gid_number: String,
    pub group_member: String,
}

/// Resolves POSIX attribute names from [sssd] overrides (or built-in defaults).
pub fn resolve_posix_attribute_mapping(sssd: &SssdSection) -> PosixAttributeMapping {
    let user_obj = sssd
        .ldap_user_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixAccount".to_string());

    let group_obj = sssd
        .ldap_group_object_class
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "posixGroup".to_string());

    let u_name = sssd
        .ldap_user_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uid".to_string());

    let u_uid = sssd
        .ldap_user_uid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "uidNumber".to_string());

    let u_gid = sssd
        .ldap_user_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    let u_home = sssd
        .ldap_user_home_directory
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "homeDirectory".to_string());

    let u_shell = sssd
        .ldap_user_shell
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "loginShell".to_string());

    let u_full = sssd
        .ldap_user_fullname
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "displayName".to_string());

    let g_name = sssd
        .ldap_group_name
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "cn".to_string());

    let g_gid = sssd
        .ldap_group_gid_number
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "gidNumber".to_string());

    // For KLLDAP (when using the recommended ignored attributes feature, which
    // is active by default), we prefer the modern "member" attribute (DNs) over
    // the legacy "memberUid" (which KLLDAP does not synthesize by default).
    // This works excellently with ldap_schema = rfc2307bis.
    // Users can still force the old behavior by setting ldap_group_member explicitly
    // or by disabling kllldap_ignored_attributes.
    let kllldap_mode = sssd.kllldap_ignored_attributes.unwrap_or(true);

    let g_member = sssd
        .ldap_group_member
        .as_ref()
        .filter(|v| !v.trim().is_empty())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            if kllldap_mode {
                "member".to_string()
            } else {
                "memberUid".to_string()
            }
        });

    PosixAttributeMapping {
        user_object_class: user_obj,
        group_object_class: group_obj,
        user_name: u_name,
        user_uid_number: u_uid,
        user_gid_number: u_gid,
        user_home_directory: u_home,
        user_shell: u_shell,
        user_full_name: u_full,
        group_name: g_name,
        group_gid_number: g_gid,
        group_member: g_member,
    }
}

/// Effective user/group search bases (Subtree) from [sssd] overrides or realm-derived defaults.
pub fn effective_ldap_search_bases(sssd: &SssdSection, realm: &str) -> (String, String) {
    let search_base = sssd
        .ldap_search_base
        .clone()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));

    let default_user_base = format!("ou=people,{}", search_base);
    let default_group_base = format!("ou=groups,{}", search_base);

    let user_base = sssd
        .ldap_user_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_user_base)
        .to_string();

    let group_base = sssd
        .ldap_group_search_base
        .as_deref()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(&default_group_base)
        .to_string();

    (user_base, group_base)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KerberosSection {
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GaneshaSection {
    #[serde(default = "default_security")]
    pub default_security: String,
}

fn default_security() -> String {
    "krb5p".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagementSection {
    pub lldap_graphql_url: Option<String>,
    pub helper_path: Option<PathBuf>,
    pub use_sudo: Option<bool>,
    pub ganesha_container_name: Option<String>,
    pub webui_admin_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Absolute path on the Docker host (used for UI allow-list and direct chown/chmod).
    /// Container view is `storage.container_root` + name.
    pub host_path: PathBuf,
    /// Optional explicit NFS pseudo path. Defaults to "/" + name.
    pub export_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
    /// Whether to use synchronous writes for this share (default true for safety).
    /// If None or true, the key is typically omitted from nfs-klldap.conf (default behavior).
    pub sync: Option<bool>,
    /// Cache profile selector (preferred for UI-driven shares).
    /// Written as `cache_profile = "..."` inside [[shares]].
    /// When present and valid, the generator resolves it to Ganesha PrefRead/PrefWrite
    /// values for the share's EXPORT block.
    /// This is the mechanism for the "Cache Profile" dropdown in System Settings.
    ///
    /// Allowed values (exact): "Default", "Read - Basic", "Read - Heavy", "Mixed Use", "Write - Heavy".
    /// See README for the matrix and "Best For" descriptions. (Server read_ahead_kb is a
    /// host-only concern; see the short note in the README.)
    pub cache_profile: Option<String>,
    /// Optional PrefRead size in bytes (Ganesha EXPORT.PrefRead). Advanced/raw use.
    /// When a valid cache_profile is also present it takes precedence for generation.
    /// (Legacy numeric values in nfs-klldap.conf are still accepted and validated.)
    pub pref_read: Option<u64>,
    /// Optional PrefWrite size in bytes (Ganesha EXPORT.PrefWrite). Advanced/raw use.
    /// Symmetric to pref_read; usually resolved from cache_profile in normal operation.
    pub pref_write: Option<u64>,
}

impl Default for Share {
    fn default() -> Self {
        Self {
            name: String::new(),
            host_path: PathBuf::new(),
            export_path: None,
            security: None,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
            sync: Some(true),
            cache_profile: Some("Default".to_string()),
            pref_read: None,
            pref_write: None,
        }
    }
}

/// Output paths for generated configuration (container namespace).
#[derive(Debug, Clone)]
pub struct GenerationPaths {
    pub sssd_conf: PathBuf,
    pub krb5_conf: PathBuf,
    pub ganesha_conf: PathBuf,
    pub exports_dir: PathBuf,
}

impl Default for GenerationPaths {
    fn default() -> Self {
        Self {
            sssd_conf: PathBuf::from("/etc/sssd/sssd.conf"),
            krb5_conf: PathBuf::from("/etc/krb5.conf"),
            ganesha_conf: PathBuf::from("/etc/ganesha/ganesha.conf"),
            exports_dir: PathBuf::from("/etc/ganesha/exports.d"),
        }
    }
}

// =============================================================================
// Cache Profiles (for [[shares]] "Cache Profile" dropdown)
// The profile *name* is written into nfs-klldap.conf under [[shares]].
// The generator resolves it at emit time to Ganesha PrefRead/PrefWrite values
// for the corresponding EXPORT block.
// =============================================================================

/// The 5 supported values for share.cache_profile (order matches the WebUI dropdown).
pub const CACHE_PROFILES: &[&str] = &[
    "Default",
    "Read - Basic",
    "Read - Heavy",
    "Mixed Use",
    "Write - Heavy",
];

/// Resolve a cache profile name to the Ganesha tunables (PrefRead, PrefWrite in bytes).
pub fn resolve_cache_profile(profile: &str) -> Option<(u64, u64)> {
    match profile.trim() {
        "Default" => Some((1048576, 1048576)),
        "Read - Basic" => Some((4194304, 4194304)),
        "Read - Heavy" => Some((16777216, 8388608)),
        "Mixed Use" => Some((4194304, 4194304)),
        "Write - Heavy" => Some((2097152, 16777216)),
        _ => None,
    }
}










//! Data model for nfs-klldap.conf. Validation/derivation/generation in validate.rs + generate.rs.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level config (nfs-klldap.conf)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NfsKlldapConfig {
    #[serde(default)]
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
    pub webui: WebuiSection,

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
    #[serde(default)]
    pub ldap_default_bind_dn: String,
    #[serde(default)]
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

    // POSIX attribute mapping (excellent LLDAP defaults; override only on schema mismatch)
    pub enumerate: Option<bool>,

    // Object classes (LLDAP typical: inetOrgPerson + posixAccount aux)
    pub ldap_user_object_class: Option<String>,
    pub ldap_group_object_class: Option<String>,

    // User attr mappings (for UID/GID + home/shell)
    pub ldap_user_name: Option<String>,
    pub ldap_user_uid_number: Option<String>,
    pub ldap_user_gid_number: Option<String>,
    pub ldap_user_home_directory: Option<String>,
    pub ldap_user_shell: Option<String>,
    pub ldap_user_fullname: Option<String>,

    // Group attr mappings
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
    // Note: krb5_realm is always the effective realm (no separate override);
    // krb5_server + krb5_kpasswd are auto-derived from ldap_uri host in the generator
    // (with these fields as overrides). This provides the Kerberos equivalent of
    // the auto ldap_ configuration for co-located LDAP+KDC deployments.

    /// Optional attribute holding the Kerberos principal (e.g. krbPrincipalName or userPrincipalName).
    /// When set, the IdLdapResolver will use it for direct principal-form lookups in addition to name match.
    /// Default in resolver is "krbPrincipalName".
    pub ldap_user_principal_name: Option<String>,

    // Cache tuning for ample/quick UID/GID lookups (emitted to sssd.conf to minimize LDAP hits).
    // Defaults chosen for "ample" behavior in getent/sssd paths without constant LDAP.
    pub entry_cache_timeout: Option<u32>,
    pub entry_negative_timeout: Option<u32>,
}

pub use nfs_klldap_identity::PosixAttributeMapping;

/// Resolves POSIX attribute names from [sssd] overrides (or built-in defaults).
pub fn resolve_posix_attribute_mapping(sssd: &SssdSection) -> PosixAttributeMapping {
    nfs_klldap_identity::resolve_posix_attribute_mapping(&crate::idmap::posix_mapping_input_from_sssd(
        sssd,
    ))
}

/// Effective user/group search bases (Subtree) from [sssd] overrides or realm-derived defaults.
pub fn effective_ldap_search_bases(sssd: &SssdSection, realm: &str) -> (String, String) {
    nfs_klldap_identity::effective_ldap_search_bases(
        &crate::idmap::search_bases_input_from_sssd(sssd),
        realm,
    )
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
    pub webui_admin_group: Option<String>,
}

/// WebUI runtime options (single-source in nfs-klldap.conf under [webui]).
/// These align with NFS_KLLDAP_WEBUI_* env vars (env takes precedence at runtime; only prefixed forms supported).
/// tls=false (or NFS_KLLDAP_WEBUI_TLS=off/false) disables internal TLS for reverse-proxy setups.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebuiSection {
    /// If Some(false), equivalent to NFS_KLLDAP_WEBUI_TLS=off (reverse proxy mode; plain HTTP + X-Forwarded-Proto).
    pub tls: Option<bool>,
    /// Optional path to custom cert PEM (NFS_KLLDAP_WEBUI_TLS_CERT env wins).
    pub tls_cert: Option<String>,
    /// Optional path to custom key PEM (NFS_KLLDAP_WEBUI_TLS_KEY env wins).
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Absolute path on the Docker host (used for UI allow-list and direct chown/chmod).
    /// Independent of container bind layout. The WebUI privileged operations (fs.rs/privileged.rs)
    /// and allow-listing continue to key exclusively off host_path values.
    pub host_path: PathBuf,
    /// Optional explicit name/subtree used for the *client-visible* NFSv4 Pseudo path
    /// (what clients put after the server name in mount commands, e.g. server:/movies).
    ///
    /// Editable in System Settings → Shares as the "Export Path" field. This is the
    /// external / shortenable name. It no longer affects the real container location.
    ///
    /// The real internal container location (used for Ganesha EXPORT.Path and for the
    /// WebUI FsManager / permission tree translations) is always derived from the share's
    /// own host_path + container_root:
    ///
    ///   - Take the first directory component of host_path after the leading "/" as the
    ///     implicit per-share "bind root" (e.g. host_path="/media/NVME-RAID/nvme" → "/media").
    ///   - Strip that prefix; the remaining tail becomes the subpath under container_root.
    ///   - Example: host_path="/media/NVME-RAID/nvme" + container_root="/export" →
    ///     internal = "/export/NVME-RAID/nvme".
    ///
    /// This supports multiple different host bind roots naturally (no global host_root
    /// setting required) while letting export_path be used purely for nice client names.
    ///
    /// Defaults (via validation) to "/" + name when absent.
    pub export_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
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
    /// Standardized idmap configuration (Domain + Local-Realms + Method + GSS-Methods)
    /// derived from kerberos.realm + [sssd] policy. Written to the canonical Debian location
    /// so Ganesha 9.x (default IdmapConf=/etc/idmapd.conf), the nfsidmap shim, fallback
    /// libnfsidmap, and client rpc.idmapd see consistent NFSv4 domain + Kerberos realm
    /// handling matching DIRECTORY_SERVICES.DomainName.
    pub idmap_conf: PathBuf,
}

impl Default for GenerationPaths {
    fn default() -> Self {
        Self {
            sssd_conf: PathBuf::from("/etc/sssd/sssd.conf"),
            krb5_conf: PathBuf::from("/etc/krb5.conf"),
            ganesha_conf: PathBuf::from("/etc/ganesha/ganesha.conf"),
            exports_dir: PathBuf::from("/etc/ganesha/exports.d"),
            idmap_conf: PathBuf::from("/etc/idmapd.conf"),
        }
    }
}

// Cache Profiles (for [[shares]] dropdown; name stored in TOML, resolved to Pref* at generate)

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

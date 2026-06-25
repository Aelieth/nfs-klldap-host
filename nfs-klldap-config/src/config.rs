//! Data model for nfs-klldap.conf.
//! Validation/derivation/generation in validate.rs + generate.rs.

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
    pub host: HostSection,

    #[serde(default)]
    pub webui: WebuiSection,

    #[serde(default)]
    pub shares: Vec<Share>,

    /// Populated at load time from raw TOML (not serialized).
    #[serde(skip)]
    pub share_warnings: Vec<ShareFieldWarning>,
}

/// Recognized keys inside each `[[shares]]` table in nfs-klldap.conf.
pub const SHARE_KNOWN_KEYS: &[&str] = &[
    "name",
    "host_path",
    "export_path",
    "security",
    "rw",
    "squash",
    "cache_profile",
    "pref_read",
    "pref_write",
    "disable_acl",
    "manage_gids",
    "ganesha_path",
];

/// Warning for unrecognized keys in a `[[shares]]` table (config still loads).
#[derive(Debug, Clone)]
pub struct ShareFieldWarning {
    pub share_index: usize,
    pub share_name: Option<String>,
    pub unknown_keys: Vec<String>,
}

impl ShareFieldWarning {
    /// Find a warning for a loaded share (match by index, then by name).
    pub fn for_share<'a>(
        warnings: &'a [Self],
        share_index: usize,
        share_name: &str,
    ) -> Option<&'a Self> {
        warnings
            .iter()
            .find(|w| w.share_index == share_index || w.share_name.as_deref() == Some(share_name))
    }

    pub fn display_message(&self) -> String {
        let label = self
            .share_name
            .as_deref()
            .map(|n| format!("\"{}\"", n))
            .unwrap_or_else(|| format!("index {}", self.share_index));
        format!(
            "share {} (index {}): unrecognized [[shares]] key(s) {:?} — ignored by generator. \
             Remove from nfs-klldap.conf or delete this share and re-add via System Settings → Shares.",
            label, self.share_index, self.unknown_keys
        )
    }
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
    /// Derived 636/389 for reference
    /// SSSD uses ldap_uri (port must be in the URI).
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

    // POSIX attribute mapping (excellent LLDAP defaults
    // override only on schema mismatch)
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
    /// Kerberos principal LDAP attribute; default krbPrincipalName.
    pub ldap_user_principal_name: Option<String>,

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

/// Effective user/group search bases (Subtree).
/// From [sssd] overrides or realm-derived defaults.
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
    /// Optional executable invoked by the supervisor after each successful generate.
    /// Runs per share.
    pub post_generate_hook: Option<String>,
}

fn default_security() -> String {
    "krb5p".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagementSection {
    pub webui_admin_group: Option<String>,
}

/// Host deployment mode; host_nfs=true runs WebUI/SSSD only (host serves NFS).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostSection {
    /// Sidecar mode: host ganesha.nfsd reads bind-mounted /etc/ganesha fragments.
    pub host_nfs: Option<bool>,
}

/// WebUI runtime options from [webui]; NFS_KLLDAP_WEBUI_* env wins at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebuiSection {
    /// Some(false) disables TLS (reverse-proxy mode with X-Forwarded-Proto).
    pub tls: Option<bool>,
    /// Optional path to custom cert PEM (NFS_KLLDAP_WEBUI_TLS_CERT env wins).
    pub tls_cert: Option<String>,
    /// Optional path to custom key PEM (NFS_KLLDAP_WEBUI_TLS_KEY env wins).
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Host-visible path for allow-list and chown/chmod.
    /// See docs/ganesha-architecture.md.
    pub host_path: PathBuf,
    /// Client NFSv4 Pseudo path; FsManager uses host_path. Defaults to /<name>.
    pub export_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
    /// UI cache profile name → generator maps to Ganesha PrefRead/PrefWrite.
    /// See CACHE_PROFILES / README.
    pub cache_profile: Option<String>,
    /// Raw PrefRead bytes; cache_profile takes precedence when both are set.
    pub pref_read: Option<u64>,
    /// Raw PrefWrite bytes; usually resolved from cache_profile instead.
    pub pref_write: Option<u64>,
    /// When true, emit `Disable_ACL = true;` in the Ganesha EXPORT block.
    pub disable_acl: Option<bool>,
    /// When false, emit `Manage_Gids = false;` in the Ganesha EXPORT block.
    /// Auto-applied on limited FS.
    pub manage_gids: Option<bool>,
    /// When set, used verbatim as Ganesha EXPORT Path= and for fs probe.
    /// Staging tree path.
    pub ganesha_path: Option<String>,
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
            disable_acl: None,
            manage_gids: None,
            ganesha_path: None,
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
    /// idmapd.conf path; domain/realm aligned with Ganesha DIRECTORY_SERVICES.
    pub idmap_conf: PathBuf,
    /// nfs-utils client defaults (rpc.gssd use-machine-creds, pipefs path).
    pub nfs_conf: PathBuf,
}

impl Default for GenerationPaths {
    fn default() -> Self {
        Self::from_env()
    }
}

impl GenerationPaths {
    /// Resolve output paths from env (SSSD_CONF, GANESHA_CONF
    /// …) or container defaults.
    pub fn from_env() -> Self {
        let env_path = |key: &str, default: &str| -> PathBuf {
            std::env::var(key)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(default))
        };
        Self {
            sssd_conf: env_path("SSSD_CONF", "/etc/sssd/sssd.conf"),
            krb5_conf: env_path("KRB5_CONF", "/etc/krb5.conf"),
            ganesha_conf: env_path("GANESHA_CONF", "/etc/ganesha/ganesha.conf"),
            exports_dir: env_path("EXPORTS_DIR", "/etc/ganesha/exports.d"),
            idmap_conf: env_path("IDMAP_CONF", "/etc/idmapd.conf"),
            nfs_conf: env_path("NFS_CONF", "/etc/nfs.conf"),
        }
    }
}

// Cache Profiles (for [[shares]] dropdown
// name stored in TOML, resolved to Pref* at generate)

/// The 5 supported share.cache_profile values.
/// Order matches the WebUI dropdown.
pub const CACHE_PROFILES: &[&str] = &[
    "Default",
    "Read - Basic",
    "Read - Heavy",
    "Mixed Use",
    "Write - Heavy",
];

/// Resolve a cache profile name to the Ganesha tunables (PrefRead
/// PrefWrite in bytes).
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

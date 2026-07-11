//! Data model for nfs-klldap.conf.
//! Validation/derivation/generation in validate.rs + generate.rs.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level config (nfs-klldap.conf).
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
    "pseudo_path",
    "security",
    "rw",
    "squash",
    "cache_profile",
    "pref_read",
    "pref_write",
    "enable_acl",
    "manage_gids",
    "read_access_policy",
    "manage_gids_expiration",
    "container_path",
    "source_path",
    "umask",
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
        if self.unknown_keys.iter().any(|k| k == "ganesha_path") {
            return format!(
                "share {} (index {}): `ganesha_path` was renamed to required `container_path` — \
                 set `container_path` to the directory inside the container (maps to Ganesha Path=).",
                label, self.share_index
            );
        }
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
    /// Derived 636/389 port is reference only because SSSD uses ldap_uri.
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

    // POSIX attribute mapping uses LLDAP defaults unless overridden here.
    pub enumerate: Option<bool>,

    // Object classes (LLDAP typical is inetOrgPerson + posixAccount aux).
    pub ldap_user_object_class: Option<String>,
    pub ldap_group_object_class: Option<String>,

    // User attr mappings (for UID/GID + home/shell).
    pub ldap_user_name: Option<String>,
    pub ldap_user_uid_number: Option<String>,
    pub ldap_user_gid_number: Option<String>,
    pub ldap_user_home_directory: Option<String>,
    pub ldap_user_shell: Option<String>,
    pub ldap_user_fullname: Option<String>,

    // Group attribute mappings override LLDAP defaults when set.
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
    /// Names the krbPrincipalName LDAP attribute for Kerberos principals.
    pub ldap_user_principal_name: Option<String>,

    pub entry_cache_timeout: Option<u32>,
    pub entry_negative_timeout: Option<u32>,
}

pub use nfs_klldap_identity::PosixAttributeMapping;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KerberosSection {
    pub realm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GaneshaSection {
    #[serde(default = "default_security")]
    pub default_security: String,
    /// Runs an optional executable after each successful generate pass.
    pub post_generate_hook: Option<String>,
    /// Extra krb5 principals to materialize in nss_wrapper before Ganesha accepts clients.
    #[serde(default)]
    pub warm_principals: Vec<String>,
    /// When false, omit enable_rpc_cred_fallback in ganesha.conf (fail closed on uid2grp miss).
    pub enable_rpc_cred_fallback: Option<bool>,
    /// Override Idmapped_*_Time_Validity seconds (default 600). On 9.13 this
    /// is also the getgroups() trust window; wins over the manage-gids knobs.
    pub idmapped_validity_secs: Option<u32>,
    /// Kerberos principal service-name parts granted root privilege
    /// (DIRECTORY_SERVICES Root_Kerberos_Principal). Comma-separated tokens
    /// from none|nfs|root|host|all. Default "nfs, root" — `host` is excluded
    /// so enrolled client machine keytabs cannot act as root on exports.
    pub root_kerberos_principals: Option<String>,
    /// Seconds Ganesha trusts getgroups() results under Manage_Gids. 9.13
    /// dropped the core Manage_Gids_Expiration param for the DS
    /// Idmapped_*_Time_Validity, so this feeds that value now (unless
    /// idmapped_validity_secs is set). Default 600, max 604800.
    pub manage_gids_expiration_secs: Option<u64>,
    /// DIRECTORY_SERVICES Negative_Cache_Time_Validity seconds (default 60):
    /// how long a failed user/group lookup is remembered.
    pub negative_cache_validity_secs: Option<u32>,
    /// NFS_CORE_PARAM Max_Uid_To_Group_Reqs — concurrent uid→groups lookups
    /// allowed against SSSD/LDAP (default 64; 0 = unlimited).
    pub max_uid_to_group_reqs: Option<u32>,
    /// NFS_CORE_PARAM Readdir_Res_Size response bytes (default 32768).
    pub readdir_res_size: Option<u32>,
    /// NFS_CORE_PARAM Readdir_Max_Count entries (emitted only when set).
    pub readdir_max_count: Option<u32>,
    /// Extra getattr after each READ to revalidate EOF — only ESXi clients
    /// need it; default false (upstream default is true).
    pub getattrs_in_complete_read: Option<bool>,
    /// Enable_malloc_trim for flat long-running memory (default true).
    pub malloc_trim: Option<bool>,
    /// Malloc_trim_MinThreshold in MB (default 1024; upstream 15360 never
    /// fires under the 4 GB container memory limit).
    pub malloc_trim_min_threshold_mb: Option<u32>,
}

fn default_security() -> String {
    "krb5p".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagementSection {
    pub webui_admin_group: Option<String>,
}

/// Host deployment mode runs WebUI and SSSD only when host_nfs is true.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostSection {
    /// In sidecar mode the host nfsd reads bind-mounted export fragments.
    pub host_nfs: Option<bool>,
}

/// WebUI runtime options come from [webui] but NFS_KLLDAP_WEBUI_* env wins.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebuiSection {
    /// Setting tls to false disables TLS for reverse-proxy mode.
    pub tls: Option<bool>,
    /// Sets custom cert PEM unless NFS_KLLDAP_WEBUI_TLS_CERT wins.
    pub tls_cert: Option<String>,
    /// Sets custom key PEM unless NFS_KLLDAP_WEBUI_TLS_KEY wins.
    pub tls_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Host-visible path for allow-list and chown/chmod.
    /// See docs/ganesha-architecture.md.
    pub host_path: PathBuf,
    /// Sets the NFSv4 pseudo path (Ganesha `Pseudo = ...;`) and defaults to slash-name when omitted.
    /// Accepts `export_path` as alias for backward compatibility with older configs.
    #[serde(alias = "export_path")]
    pub pseudo_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
    /// UI cache profile name → generator maps to Ganesha PrefRead/PrefWrite.
    /// See CACHE_PROFILES / README.
    pub cache_profile: Option<String>,
    /// Sets raw PrefRead bytes but cache_profile wins when both are set.
    pub pref_read: Option<u64>,
    /// Sets raw PrefWrite bytes but cache_profile usually supplies the value.
    pub pref_write: Option<u64>,
    pub enable_acl: Option<bool>, // ACL primary vs NOACL
    pub manage_gids: Option<bool>,
    pub read_access_policy: Option<String>,
    /// DEPRECATED: Manage_Gids_Expiration is a global NFS_CORE_PARAM, not a
    /// per-export directive. Still accepted; the smallest share value seeds
    /// the global when [ganesha] manage_gids_expiration_secs is unset.
    pub manage_gids_expiration: Option<u64>,
    /// Absolute path inside the container where Ganesha serves this share (EXPORT Path=).
    pub container_path: String,
    /// Optional distinct data-source path inside the container for ACL staging.
    /// When set (and different from `container_path`), the post-generate hook syncs
    /// `source_path` → `container_path` so Ganesha can serve an ACL-capable copy while the
    /// real data lands elsewhere (see docs/ganesha-architecture.md staging pattern). Unset
    /// means source == serve (no staging).
    pub source_path: Option<String>,
    /// Umask (octal e.g. "0022"), accepted but currently inert: Ganesha 9.13
    /// dropped per-export FSAL Umask (module-global only), so generate warns
    /// and emits nothing. The 0.9.9x ACL track replaces it (plan 2.4 gate).
    pub umask: Option<String>,
}

/// Derive the Ganesha NFSv4 Pseudo path from `pseudo_path` or `/{name}` (0.9.40-style).
pub fn derive_share_pseudo(share: &Share) -> String {
    let default = format!("/{}", share.name);
    let raw = share.pseudo_path.as_deref().unwrap_or(&default);
    if raw.starts_with('/') {
        raw.to_string()
    } else {
        format!("/{}", raw)
    }
}

impl Default for Share {
    fn default() -> Self {
        Self {
            name: String::new(),
            host_path: PathBuf::new(),
            pseudo_path: None,
            security: None,
            rw: Some(true),
            squash: Some("no_root_squash".to_string()),
            cache_profile: Some("Default".to_string()),
            pref_read: None,
            pref_write: None,
            enable_acl: None,
            manage_gids: None,
            read_access_policy: None,
            manage_gids_expiration: None,
            container_path: String::new(),
            source_path: None,
            umask: None,
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
    /// Holds the output path for generated idmapd.conf.
    pub idmap_conf: PathBuf,
    /// Holds the output path for nfs-utils client defaults.
    pub nfs_conf: PathBuf,
}

impl Default for GenerationPaths {
    fn default() -> Self {
        Self::from_env()
    }
}

impl GenerationPaths {
    /// Resolves output paths from env vars or container defaults.
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

// Cache profile names in [[shares]] resolve to Ganesha PrefRead and PrefWrite.

pub const CACHE_PROFILES: &[&str] = &[
    "Default",
    "Read - Basic",
    "Read - Heavy",
    "Mixed Use",
    "Write - Heavy",
];

/// Resolves a cache profile to Ganesha PrefRead and PrefWrite byte counts.
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

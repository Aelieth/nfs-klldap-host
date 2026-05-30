//! Data model for nfs-klldap.conf and derived generation paths.
//!
//! This module contains only the pure data structures with their serde
//! and Default implementations. All behavior (validation, derivation,
//! generation) lives in other modules.

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
    pub port: Option<u16>,
    pub ldap_user_search_base: Option<String>,
    pub ldap_group_search_base: Option<String>,

    /// Optional explicit override for the main ldap_search_base.
    /// When unset, it is derived from the Kerberos realm (recommended).
    pub ldap_search_base: Option<String>,

    // TLS / connection security options (for both ldaps:// and plain ldap:// + STARTTLS).
    // These are emitted verbatim into the generated [domain/default] section.
    // Common values for self-signed LLDAP:
    //   ldap_tls_reqcert = "never"
    // For insecure ldap:// with opportunistic STARTTLS upgrade:
    //   ldap_id_use_start_tls = true
    //   ldap_tls_reqcert = "never"
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

    // === Advanced / production knobs from real deployments ===
    /// Name of the SSSD domain section. Defaults to "default".
    /// Setting this to "lldap" produces [domain/lldap] which some people prefer.
    pub domain: Option<String>,

    /// Authentication provider. Common values: "ldap" or "krb5".
    /// For Kerberized NFS environments, many people prefer auth_provider = krb5
    /// while still using LDAP for POSIX identity (uidNumber/gidNumber etc.).
    pub auth_provider: Option<String>,

    /// chpass_provider when using Kerberos auth (usually also "krb5").
    pub chpass_provider: Option<String>,

    /// LDAP schema. Common with modern LLDAP + POSIX: "rfc2307bis".
    pub ldap_schema: Option<String>,

    /// Explicitly disable ID mapping (recommended when LLDAP provides real uidNumber/gidNumber).
    pub ldap_id_mapping: Option<bool>,

    /// Very important safety flag when using plain ldap:// (non-TLS).
    /// The generator will automatically set this to true for ldap:// URIs unless overridden.
    pub ldap_auth_disable_tls_never_use_in_production: Option<bool>,

    /// Access control. "permit" is common and simple for trusted internal setups.
    pub access_provider: Option<String>,

    /// Whether to use fully qualified names (user@REALM). Usually false for homelab/small setups.
    pub use_fully_qualified_names: Option<bool>,

    /// Optional explicit Kerberos settings for the domain (when auth_provider = krb5).
    /// If not set, they are derived from ldap_uri host + the effective realm.
    pub krb5_server: Option<String>,
    pub krb5_kpasswd: Option<String>,

    // Additional Kerberos tuning seen in real ldaps production configs
    pub krb5_validate: Option<bool>,
    pub krb5_store_password_if_offline: Option<bool>,
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
    /// Group whose members (plus the special "localhost" simple-password user) are allowed
    /// to make changes via the WebUI. Defaults to "lldap_admin".
    pub webui_admin_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    /// Full absolute path on the *Docker host* (used by host UI; container performs chown/chmod on the bind mount)
    pub host_path: PathBuf,
    /// Optional explicit NFS pseudo path. Defaults to "/" + name (short + clean)
    pub export_path: Option<String>,
    pub security: Option<String>,
    pub rw: Option<bool>,
    pub squash: Option<String>,
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
        }
    }
}

/// Paths the generator will write to (container view)
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

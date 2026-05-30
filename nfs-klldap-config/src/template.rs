//! Default config template generation.
//!
//! Contains the large, heavily-commented first-run safe template string
//! plus the helper that writes it only if the file is missing.

use std::fs;
use std::path::Path;

use crate::ConfigError;

/// Generate the first-run safe, heavily commented template.
/// Never overwrites an existing file.
pub fn generate_default_template() -> String {
    r#"# =============================================================================
# nfs-klldap.conf — Single Source of Truth for nfs-klldap-host
# =============================================================================
# This file is the ONLY configuration users edit.
# The container (via bundled Rust generator) auto-derives sssd.conf,
# krb5.conf, and all Ganesha EXPORT fragments from it.
#
# REQUIRED: ldap_uri + [sssd] bind credentials.
# ldap_uri host MUST be a DNS name (A/AAAA + PTR recommended). IP addresses are
# rejected because forward/reverse DNS is required for the NFS service principal
# in the keytab and for Kerberos GSSAPI operation.
# Everything else has smart defaults.
#
# After first edit: the container NEVER overwrites this file.
# =============================================================================

ldap_uri = "ldaps://klldap.example.com:6360"

[storage]
# container_root is the base inside the container where your data appears.
# Match this to your docker -v ...:/export  (or change if you prefer another mount)
container_root = "/export"

[server]
# hostname = "yourhost-nfs"   # Optional override. The recommended way is to start
#                             # the container with --uts=host so it sees the real
#                             # host hostname. The TUI will tell you the exact
#                             # principal (with -nfs insertion) to use in the keytab.
#                             # Explicit --hostname takes precedence if set.

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"

# The generator now produces a much richer sssd.conf based on real-world
# LLDAP + Kerberos + Ganesha production setups (both your ldap:// and ldaps:// examples).
#
# It auto-switches based on the scheme in ldap_uri:
#   - ldap://   → emits the "I know this is insecure" safety flags
#   - ldaps://  → defaults to stricter tls_reqcert=demand
#
# It also supports the popular hybrid model (LDAP for identity + Kerberos for auth).
#
# Common overrides:
#   auth_provider = "krb5"
#   domain = "lldap"
#   ldap_schema = "rfc2307bis"
#   ldap_id_mapping = false
#   enumerate = false          # conservative setting used in some production ldaps configs
#   access_provider = "permit"

# [kerberos]
# realm = "KRB.EXAMPLE.COM"  # REQUIRED if auto-derivation from ldap_uri host domain fails
#                            # (or set NFS_REALM env var before starting the container).
#                            # Auto-derivation only works for real DNS hostnames in ldap_uri.

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# WebUI settings (in-container on port 9630)
# lldap_graphql_url = "https://kllap.example.com:6360/api/graphql"
# ganesha_container_name = "nfs-klldap"   # (legacy, no longer used — WebUI performs FS ops directly)
# webui_admin_group = "lldap_admin"       # LLDAP group whose members can modify shares/settings from any machine
#                                         # (plus the special immutable "localhost" user via simple sidecar password)

# =============================================================================
# Shares — add as many as you need. Names must be unique.
# =============================================================================
#
# IMPORTANT:
#   host_path  = The REAL absolute path on your Docker HOST machine.
#                This is used by the web UI and privileged helper for permissions
#                (chown/chmod). Ganesha does NOT use this value.
#
#   You MUST still provide a bind mount when starting the container so the data
#   becomes visible inside at the expected path (/export/{name} by default).
#
# Recommended patterns:
#
#   1. Mount parent directory (cleanest):
#      -v /home/user/nfs-data:/export
#
#      Then in config:
#      host_path = "/home/user/nfs-data/movies"
#
#   2. Mount specific directories:
#      -v /home/user/nfs-data/movies:/export/movies
#      host_path = "/home/user/nfs-data/movies"
#
# The NFS client will see short clean paths like /movies (not /export/movies).
# =============================================================================

# [[shares]]
# name = "movies"
# host_path = "/home/user/nfs-data/movies"   # REAL path on the HOST
#
# [[shares]]
# name = "backups"
# host_path = "/home/user/nfs-data/backups"
"#
    .to_string()
}

// Stable public orchestration entry point.
// (Will be re-exported from template.rs after Phase 5 extraction.)
/// Write the default template only if the file does not exist.
/// Returns true if a file was created.
pub fn write_default_config_if_missing(path: &Path) -> Result<bool, ConfigError> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmpl = generate_default_template();
    fs::write(path, tmpl.as_bytes())?;
    // Secure perms (contains secrets)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

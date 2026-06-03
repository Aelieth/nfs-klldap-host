//! Default first-run nfs-klldap.conf template.

use std::fs;
use std::path::Path;

use crate::ConfigError;

/// Generate the first-run safe, heavily commented template.
/// Never overwrites an existing file.
pub fn generate_default_template() -> String {
    r#"# =============================================================================
# nfs-klldap.conf — Single Source of Truth for nfs-klldap-host
# =============================================================================
# This file is the ONLY configuration file that needs editing.
# The container (via bundled Rust generator) auto-derives sssd.conf,
# krb5.conf, and all Ganesha EXPORT fragments from it.
#
# REQUIRED: ldap_uri + [sssd] bind credentials.
# ldap_uri host MUST be a DNS name (A/AAAA + PTR recommended). IP addresses are
# rejected because forward/reverse DNS is required for Kerberos NFS principals.
#
# Kerberos keytab (best practice with --uts=host):
#   Include nfs/<short-hostname>@REALM and nfs/<fqdn>@REALM when they differ.
#   The hostname is confirmed by `hostname` matching /proc/sys/kernel/hostname.
#
# After first edit: the container NEVER overwrites this file.
# =============================================================================

ldap_uri = "ldaps://klldap.example.com:6360"
# Port must appear in ldap_uri. [sssd] port is derived for display only (636/389).

[storage]
container_root = "/export"   # Match docker -v ...:/export

[server]
# hostname = "myhost.example.com"   # Optional override for keytab only.
# Recommended: docker run --uts=host (container sees the real host hostname).

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"
# ldap_user_search_base = "ou=people,dc=example,dc=com"
# ldap_group_search_base = "ou=groups,dc=example,dc=com"

# [kerberos]
# realm = "KRB.EXAMPLE.COM"   # Required if auto-derivation from ldap_uri fails

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# webui_admin_group = "lldap_admin"   # LLDAP group for WebUI admins (default)

# =============================================================================
# Shares — at least one [[shares]] required for startup.
#   host_path = absolute path on the Docker HOST (WebUI chown/chmod allow-list).
#   Bind-mount so data appears at container_root/name (default /export/<name>).
# =============================================================================

# [[shares]]
# name = "movies"
# host_path = "/home/user/nfs-data/movies"
"#
    .to_string()
}

/// Write the default template only if the file does not exist.
pub fn write_default_config_if_missing(path: &Path) -> Result<bool, ConfigError> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmpl = generate_default_template();
    fs::write(path, tmpl.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(true)
}

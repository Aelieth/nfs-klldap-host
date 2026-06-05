//! First-run default template (long header kept for new users; see generate_default_template).

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
# The container auto-derives sssd.conf, krb5.conf, and all Ganesha EXPORT fragments.
#
# REQUIRED: ldap_uri + [sssd] bind credentials.
# ldap_uri host MUST be a DNS name (A/AAAA + PTR recommended). IP addresses are
# rejected because forward/reverse DNS is required for Kerberos NFS principals.
#
# Kerberos keytab (best practice with --uts=host):
#   Include nfs/<short-hostname>@REALM and nfs/<fqdn>@REALM
#   The hostname is confirmed by `hostname` matching /proc/sys/kernel/hostname.
#
# After first edit: the container NEVER overwrites this file.
# Advanced users may insert 1:1 value overrides under respective section.
# =============================================================================

ldap_uri = "ldaps://kllap.example.com:6360"                     # LLDAP default secure port. 3890 for LLDAP unencrypted

[storage]
container_root = "/export"                                      # Where your Ganesha NFS shares mount at. Match docker -v ...:/export

[management]
# webui_admin_group = "lldap_admin"                             # Default - Edit to change group for WebUI admins

[server]
# hostname = "myhost.example.com"                               # Default - Optional override for keytab only. Recommended: docker run --uts=host

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "strong-secret"
# ldap_user_search_base = "ou=people,dc=example,dc=com"         # Default - Edit this if your base user OU differs
# ldap_group_search_base = "ou=groups,dc=example,dc=com"        # Default - Edit this if your base user OU differs
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default - auto-derived from ldap_uri host, edit to override

[ganesha]
default_security = "krb5p"                                      # securtiy, krb5p (default) | krb5i | krb5

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

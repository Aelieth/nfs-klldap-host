// ! First-run default template

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
# The container auto-derives sssd.conf
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

ldap_uri = "ldaps://kllap.example.com:6360"                     # Required - LLDAP default secure port. 3890 for LLDAP unencrypted (389, 636 for standard)

[storage]
container_root = "/export"                                      # Required - Ganesha Path base + UI translation root. Bind one or more host parent dirs to this target (e.g. /media/:/export and/or /mount/:/export). The first directory component of each share's host_path is treated as the implicit per-share bind root; the tail becomes the subpath under container_root. This lets export_path (below) be a short external name only.

[management]
# webui_admin_group = "lldap_admin"                             # Default

[server]
# hostname = "myhost.example.com"                               # Default

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"  # Required - LDAP bind DN
ldap_default_authtok = "strong-secret"                          # Required - LDAP bind password
# ldap_user_search_base = "ou=people,dc=example,dc=com"          # Opti...
# ldap_group_search_base = "ou=people,dc=example,dc=com"        # Optio...
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

# ldap_tls_reqcert = "never"                                    # auto-...
# ldap_tls_cacert = "/path/to/ca.pem"                           # when...
# ldap_id_use_start_tls = true                                  # only...

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default

[ganesha]
default_security = "krb5p"                                      # Security, krb5p (default) | krb5i | krb5

[webui]
# tls = false                                                   # comme...
# tls_cert = "/config/webui.crt"                                # optio...
# tls_key = "/config/webui.key"                                 # optio...

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

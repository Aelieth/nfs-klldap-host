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
# hostname = "myhost.example.com"   # Optional override for keytab reminders only.
# Recommended: docker run --uts=host (container sees the real host hostname).

# =============================================================================
# [sssd] — LDAP bind + options passed through to generated /etc/sssd/sssd.conf
# =============================================================================
# REQUIRED (startup blocks until set and bind succeeds):
#   ldap_default_bind_dn, ldap_default_authtok
#
# DEFAULTS when omitted (see also comments in generated sssd.conf):
#   kllldap_ignored_attributes = true   → emit KLLDAP ignore lists + use member
#   ldap_schema                  = rfc2307bis
#   ldap_id_mapping              = false (emitted)
#   enumerate                    = false  (do NOT set true on KLLDAP without reason)
#   auth_provider                = ldap    (use krb5 for Kerberos-auth hybrid)
#   access_provider              = permit
#   ldap_group_member            = member when kllldap_ignored_attributes=true,
#                                  else memberUid
#   POSIX attrs                  = uid, uidNumber, gidNumber, homeDirectory,
#                                  loginShell, cn, gidNumber (override per field below)
#   Search bases                 = ou=people,dc=<realm> / ou=groups,dc=<realm>
#
# TLS (ldap_uri scheme drives behavior):
#   ldaps://  — generator does NOT auto-set ldap_tls_reqcert. For self-signed
#               LLDAP/KLLDAP certificates add:
#                 ldap_tls_reqcert = "never"
#   ldap://   — emits ldap_auth_disable_tls_never_use_in_production = true (lab only)
#
# Common optional overrides:
#   ldap_tls_cacert = "/etc/pki/ca.crt"
#   ldap_id_use_start_tls = true          # plain ldap:// + STARTTLS
#   auth_provider = "krb5"
#   domain = "default"
#   ldap_user_search_base = "ou=people,dc=example,dc=com"
#   ldap_group_search_base = "ou=groups,dc=example,dc=com"
#
# Copy the ignored_* lines from generated sssd.conf into your KLLDAP server config
# to reduce attribute spam from SSSD. Setting enumerate=true with a dirsync-style
# bind account is a common cause of overload and TLS disconnects on KLLDAP.
# =============================================================================

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_THIS_TO_A_STRONG_SECRET"

# [kerberos]
# realm = "KRB.EXAMPLE.COM"   # Required if auto-derivation from ldap_uri fails
#                             # (or NFS_REALM env before container start).

[ganesha]
default_security = "krb5p"   # krb5p (recommended) | krb5i | krb5

[management]
# webui_admin_group = "lldap_admin"   # LLDAP group for WebUI admins (default)
# localhost user: sidecar webui-password next to this config file

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
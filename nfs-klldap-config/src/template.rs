//! First-run default template.

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
#   When the system hostname is short, the FQDN is {short}.{realm_lower}
#   (from Kerberos realm / ldap_uri). Confirmed by hostname + /proc agreement.
#
# After first edit: the container NEVER overwrites this file.
# Advanced users may insert 1:1 value overrides under respective section.
# =============================================================================

ldap_uri = ""                                                  # Required - e.g. ldaps://klldap.example.com:6360 (DNS name, not an IP; 6360 is the LLDAP default LDAPS port)
navahi_discovery = false                                        # Optional - Navahi Network Discovery: advertise flagged shares via mDNS/Avahi and enable their NFSv3/AUTH_SYS click-mount path; applies on "Restart & apply"

[storage]
container_root = "/export"                                      # Required - Ganesha Path each share requires container_path (inside container; maps to Ganesha EXPORT Path=)

[management]
# webui_admin_group = "lldap_admin"                             # Default - Edit to change group for WebUI admins

[server]
# hostname = "myhost.example.com"                               # Optional - override for keytab/Navahi/certs. Short UTS uses {short}.{realm}; set full FQDN here only if it differs.

[sssd]
ldap_default_bind_dn = ""                                       # Required - LDAP bind DN, e.g. uid=admin,ou=people,dc=example,dc=com
ldap_default_authtok = ""                                       # Required - LDAP bind password (your LLDAP admin secret)
# ldap_user_search_base = "ou=people,dc=example,dc=com"         # Optional - defaults to dc=<realm> (Subtree)
# ldap_group_search_base = "ou=people,dc=example,dc=com"        # Optional - defaults to dc=<realm> (Subtree)
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

# ldap_tls_reqcert = "never"                                    # auto-derived - typical for internal/self-signed
# ldap_tls_cacert = "/path/to/ca.pem"                           # when using custom CA instead of never
# ldap_id_use_start_tls = true                                  # only with ldap:// + STARTTLS (not ldaps://)

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default - auto-derived from ldap_uri host, edit to override

[ganesha]
default_security = "krb5p"                                      # Optional - krb5p (default) | krb5i | krb5 (per-share security key overrides)
# post_generate_hook = "/config/post-generate-staging-sync.sh"  # optional; runs after each generate (see examples/)

[webui]
# tls = false                                                   # commented off by default (tls on). Set via NFS_KLLDAP_WEBUI_TLS=off for reverse-proxy.
# tls_cert = "/config/webui.crt"                                # optional custom cert (NFS_KLLDAP_WEBUI_TLS_CERT env wins)
# tls_key = "/config/webui.key"                                 # optional custom key (NFS_KLLDAP_WEBUI_TLS_KEY env wins; 0600)
# session_timeout_minutes = 720                                 # WebUI auto-logout minutes (default 720 = 12h, min 5); new logins after "Restart & apply"

# ---------------------------------------------------------------------------
# Shares — one [[shares]] block per export, kept at the bottom of this file.
# The WebUI rewrites these blocks on every shares save. Uncomment and edit:
# ---------------------------------------------------------------------------
# [[shares]]
# name            = "users"                                      # Required - unique share name; default client mount path becomes /<name>
# host_path       = "/var/data/nvme-raid/users"                  # Required - host-side data path (WebUI ownership + allow-list checks)
# container_path  = "/export/nvme-raid/users"                    # Required - in-container serve path under [storage] container_root (Ganesha EXPORT Path)
# pseudo_path     = "/users"                                     # Optional - client-visible mount path; defaults to /<name>
# rw              = true                                         # Optional - default true; false exports read-only
# manage_gids     = true                                         # Optional - default true; resolves full LDAP group lists server-side
# enable_acl      = false                                        # Optional - omit = auto (the POSIX-ACL write probe decides); true hard-fails generate on a non-ACL filesystem; false forces NOACL
# source_path     = "/export/hdd-pool/users"                     # Optional - ACL staging source; post_generate_hook syncs it into the ACL-capable container_path
# navahi_insecure = false                                        # Optional - advertise via mDNS for NFSv3/AUTH_SYS click-mount; active only while navahi_discovery = true

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

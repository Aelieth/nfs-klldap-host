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
#   The hostname is confirmed by `hostname` matching /proc/sys/kernel/hostname.
#
# After first edit: the container NEVER overwrites this file.
# Advanced users may insert 1:1 value overrides under respective section.
# =============================================================================

ldap_uri = "ldaps:// Kllap.example.com:6360"                     # Required - LLDAP default secur.

[storage]
container_root = "/export"                                      # Required - Ganesha Path base. Each share also requires container_path (absolute path inside the container; maps to Ganesha EXPORT Path=). Example: bind /var/data:/export and host_path=/var/data/nvme-raid/users → container_path=/export/nvme-raid/users. pseudo_path (below) is only the client-visible NFSv4 Pseudo.

[management]
# webui_admin_group = "lldap_admin"                             # Default - Edit to change group for WebUI admins

[server]
# hostname = "myhost.example.com"                               # Default - Optional override for keytab only. Recommended: docker run --uts=host

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"  # Required - LDAP bind DN
ldap_default_authtok = "strong-secret"                          # Required - LDAP bind password
# ldap_user_search_base = "ou=people,dc=example,dc=com"          # Optional - defaults to dc=<realm> (Subtree)
# ldap_group_search_base = "ou=people,dc=example,dc=com"        # Optional - defaults to dc=<realm> (Subtree)
kllldap_ignored_attributes = true                               # KLLDAP specific - improves lookup time, prevents attribute spam

# ldap_tls_reqcert = "never"                                    # auto-derived - typical for internal/self-signed
# ldap_tls_cacert = "/path/to/ca.pem"                           # when using custom CA instead of never
# ldap_id_use_start_tls = true                                  # only with ldap:// + STARTTLS (not ldaps://)

[kerberos]
# realm = "EXAMPLE.COM"                                         # Default - auto-derived from ldap_uri host, edit to override

[ganesha]
default_security = "krb5p"                                      # Security, krb5p (default) | krb5i | krb5
# post_generate_hook = "/config/post-generate-staging-sync.sh"  # optional; runs after each generate (see examples/)

# ---------------------------------------------------------------------------
# Shares (repeat the [[shares]] block per export). Uncomment and edit:
# ---------------------------------------------------------------------------
# [[shares]]
# name          = "users"                                        # Required - unique; drives default Pseudo (/users)
# host_path     = "/var/data/nvme-raid/users"                    # Required - host path (WebUI chown/allow-list)
# container_path = "/export/nvme-raid/users"                     # Required - Ganesha EXPORT Path= (serve dir in container)
# pseudo_path   = "/users"                                       # Optional - client-visible NFSv4 Pseudo (defaults to /<name>)
# rw            = true                                           # Optional - default true
# manage_gids   = true                                           # Optional - default true
#
# ACL is opt-in. Omit enable_acl (or set false) for a reliable NOACL export that
# works over krb5p on any POSIX filesystem. Set enable_acl = true ONLY when the
# serve path can actually serve NFSv4 ACLs on this Ganesha 9.6 build — verify with
# scripts/verify-ganesha.sh, since the packaged VFS FSAL may return NFS4ERR_NOTSUPP.
# enable_acl    = true                                           # opt-in ACL path (FSAL Umask, no Disable_ACL)
# umask         = "0022"                                         # ACL path only (inside FSAL)
#
# ACL staging: when the real data lives on a filesystem the VFS can't serve ACLs
# from, set source_path to where it lands and container_path to an ACL-capable tree;
# the post_generate_hook syncs source_path -> container_path.
# source_path   = "/export/nvme-raid/users"                      # staging source (Ganesha serves container_path)

[webui]
# tls = false                                                   # commented off by default (tls on). Set via NFS_KLLDAP_WEBUI_TLS=off for reverse-proxy.
# tls_cert = "/config/webui.crt"                                # optional custom cert (NFS_KLLDAP_WEBUI_TLS_CERT env wins)
# tls_key = "/config/webui.key"                                 # optional custom key (NFS_KLLDAP_WEBUI_TLS_KEY env wins; 0600)

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

# LLDAP POSIX + SSSD for Ganesha NFSv4 ID Mapping

SSSD (LDAP provider) supplies `uidNumber`/`gidNumber` from LLDAP/KLLDAP to Ganesha. The WebUI applies chown/chmod on bind-mounted host paths inside the container.

## LLDAP Requirements

Users (`ou=people`): `posixAccount` + `uid`, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`.

Groups (`ou=groups`): `posixGroup` + `cn`, `gidNumber`.

Numeric IDs in LDAP must match ownership on host data directories.

## nfs-klldap.conf → generated sssd.conf

Edit [sssd] in `nfs-klldap.conf`. The generator writes `/etc/sssd/sssd.conf` with a comment header listing effective defaults.

| TOML field | Default when omitted | In generated sssd.conf |
|------------|----------------------|-------------------------|
| `ldap_default_bind_dn` / `authtok` | required | yes |
| `kllldap_ignored_attributes` | `true` | verbose ignore block + `ldap_group_member=member` |
| `ldap_schema` | `rfc2307bis` | yes |
| `ldap_id_mapping` | `false` | yes |
| `enumerate` | `false` | yes (avoid `true` on KLLDAP) |
| `auth_provider` | `ldap` | yes (`krb5` optional) |
| `access_provider` | `permit` | yes |
| POSIX attribute names | uid, uidNumber, gidNumber, … | yes (overridable per field) |
| Search bases | `ou=people,dc=<realm>` etc. | derived from realm |
| `ldap_tls_reqcert` | not set for ldaps | only if set in TOML |
| `ldap_auth_disable_tls_never_use_in_production` | `true` for `ldap://` only | conditional |

### TLS

- **`ldaps://` without `ldap_tls_reqcert`:** SSSD uses system/OpenLDAP TLS defaults (not auto-`never`). For self-signed LLDAP/KLLDAP add `ldap_tls_reqcert = "never"` in `[sssd]` (lab/internal only).
- **`ldap://`:** generator emits `ldap_auth_disable_tls_never_use_in_production = true` by default (insecure; lab only).
- **WebUI LDAP client:** uses `ldap_tls_policy()` — unset ldaps behaves permissively for probes unless you set `ldap_tls_reqcert`.

### Example `[sssd]` snippet

```toml
ldap_uri = "ldaps://kllap.example.com:6360"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "..."
ldap_tls_reqcert = "never"   # typical for self-signed LLDAP/KLLDAP
# kllldap_ignored_attributes = true   # default
# enumerate = false                     # default — do not enable casually
```

Copy `ignored_user_attributes` / `ignored_group_attributes` from the generated sssd.conf into your KLLDAP server configuration.

## Verification (inside container)

```bash
/container/healthcheck.sh
getent passwd alice && id alice
ganesha-ctl show-exports
klist -k /etc/krb5.keytab
```

## Common Issues

- `nobody` / 65534 → missing POSIX objectClasses/attributes in LDAP, or host FS UID mismatch.
- Permission denied with correct IDs → host ownership ≠ LDAP IDs, or SELinux on bind mounts.
- LDAP/TLS noise → enable KLLDAP ignores; avoid `enumerate=true` with dirsync-style binds.

Client `rpc.idmapd` (Method=sss) still helps pretty `ls` output on NFS clients.

See [README.md](../README.md) and [TESTING.md](../TESTING.md).
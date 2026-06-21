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

## Machine vs User Principals (Fedora Immutable + host keytabs)

When clients use Kerberos host keytabs (e.g. `/etc/krb5.keytab` on Fedora Immutable/Silverblue) plus user TGTs, Ganesha receives Kerberos-authenticated principals on NFSv4 compounds:
- Machine principals: `host/CLIENT@REALM`, `nfs/CLIENT@REALM`, `root/...` (from the client's host keytab).
- User principals: `alice@REALM` (from the user's TGT, resolved via SSSD + LLDAP POSIX attributes).

If Ganesha maps these inconsistently (or falls back to nobody/65534 for machine names), the client can see credential mixing that causes NFSv4 session teardown or permission failures.

`nfs-klldap-idhelper` (using structured LDAP resolution via shared IdLdapResolver for consistency with the UI LdapClient + its caches, plus getent for client parity) is the authoritative layer for this:

- It classifies principals (machine vs. user) using `is_machine_principal`.
- It resolves via NSS/SSSD (users) or forces uid/gid 0 (machines).
- On every resolution it materializes machine overrides (uid 0) into both the nss_wrapper files and `/var/lib/extrausers/{passwd,group}` (supplemental).
- Ganesha either runs under the (optional) wrapper preload or (preferred) benefits from extrausers in nsswitch after "files". This ensures machine principals (from client names or host/...) map to 0 while normal LDAP users resolve via sss without being hidden. The idhelper's classification is what prevents the mixed-credential session teardown on immutable clients.
- It also keeps its classic fast cache + unix socket (used by `ganesha-ctl id-resolve`, the log observer, and diagnostics).

Use from inside the container:
```
nfs-klldap-idhelper resolve 'host/myclient.example.com@MY.REALM'
ganesha-ctl id-resolve 'alice@MY.REALM'
ganesha-ctl id-map-test testuser1
cat /var/lib/nfs-klldap/nss_passwd   # what Ganesha sees for these names
getent passwd testuser1
```

The server must perform the same lookups clients do (`getent passwd testuser1` + principal forms). For ganesha 9.6 on Debian trixie, a small nfsidmap shim + explicit `Read_Access_Check_Policy = pre;` in CLIENT blocks (and EXPORT_DEFAULTS) address mapping failures. The observer now also reacts to Ganesha "Could not map principal X@REALM" lines so first-use user principals self-heal quickly for subsequent compounds/ACCESS. Machine principals map to 0; some group-fetch INFO for uid 0 and winbind noise are expected. The idhelper (IdLdapResolver + getent) is authoritative.

This is what actually makes the idhelper work "in conjunction" with Ganesha and SSSD. It does **not** inject untrusted data into `ganesha.conf` (Ganesha stays on a conservative static `Root_Kerberos_Principal = host, nfs;` list; the live translation lives in the nss_wrapper view controlled by the idhelper).

See the main README for more on the helper.

See [README.md](../README.md) and [TESTING.md](../TESTING.md).
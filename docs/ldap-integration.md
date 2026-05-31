# LLDAP POSIX + SSSD for Ganesha NFSv4 ID Mapping

SSSD (LDAP provider) supplies `uidNumber`/`gidNumber` from LLDAP to Ganesha. The WebUI keeps host filesystem ownership in sync via direct container-side chown/chmod.

## LLDAP Requirements

Users (`ou=people`): `posixAccount` + `uid`, `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`.

Groups (`ou=groups`): `posixGroup` + `cn`, `gidNumber`.

Numeric IDs assigned in LLDAP **must** match ownership on the host data directories.

## Container Side (nfs-klldap.conf)

```toml
ldap_uri = "ldaps://kllap.example.com:6360"

[sssd]
ldap_default_bind_dn = "..."
ldap_default_authtok = "..."
# ldap_tls_reqcert = "never"          # common for self-signed
# ldap_id_use_start_tls = true        # for plain ldap:// + STARTTLS

# kllldap_ignored_attributes = true   # default: emits recommended server-side ignore lists
# ldap_group_member = "member"        # recommended with rfc2307bis + KLLDAP (default when ignored_attributes=true)
```

The generator produces a working `sssd.conf` + the ignore block (when enabled). Copy the two `ignored_*_attributes` lines into your KLLDAP server config to stop spam from non-POSIX attributes requested by SSSD/dirsync clients.

## Verification (inside container)

```bash
/container/healthcheck.sh
getent passwd alice && id alice
ganesha-ctl show-exports
klist -k /etc/krb5.keytab
```

## Common Issues

- nobody/65534 → missing posix* objectClasses or attributes in LLDAP, or host ownership mismatch.
- Permission denied with correct IDs → host FS ownership != LLDAP IDs, or SELinux/AppArmor on bind mounts.
- No DBUS mount needed — everything is self-contained (inotify + supervisor restart).

Client `rpc.idmapd` (Domain + Method=sss) is still useful for pretty `ls` output on the client side.

See the main README architecture section and TESTING.md.

# LLDAP POSIX + SSSD for Ganesha NFSv4 ID Mapping

SSSD (LDAP provider) supplies `uidNumber`/`gidNumber` from LLDAP/KLLDAP to Ganesha. The WebUI applies chown/chmod on bind-mounted host paths inside the container.

Shared LDAP resolution (`IdLdapResolver`, POSIX attribute mapping, principal classification) lives in the **`nfs-klldap-identity`** crate (`nfs-klldap-identity/src/ldap/resolver.rs`). The config crate, idhelper, and WebUI `LdapClient` all use it for consistent behavior and caching.

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
| Search bases | `dc=<realm>` (realm-derived) + Subtree scope; explicit `ldap_user_search_base` etc. allowed (e.g. `ou=users,...`) | derived or explicit; always Subtree |
| Kerberos KDC (krb5_*) | Auto-derived from ldap_uri host + realm (co-located KDC case) | krb5_realm, krb5_server, krb5_kpasswd always emitted (explicit krb5_server/kpasswd override) |
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

Client `rpc.idmapd` (Method=nsswitch) still helps pretty `ls` output on NFS clients. The generator also writes `/etc/idmapd.conf` (Domain + Local-Realms from the Kerberos realm, Method + GSS-Methods = nsswitch) directly from the same nfs-klldap.conf + [sssd] info used for sssd.conf and ganesha DomainName. In sssd.conf it now auto-derives krb5_realm/krb5_server/krb5_kpasswd (same host as ldap_uri, same realm) — the "kerberos format" of the ldap auto values — for co-located KDC setups. Ganesha krb5* security (default krb5p) works with default auth_provider=ldap (sufficient); these settings make the domain Kerberos-aware for resolution. The authoritative live mapping + machine-vs-user classification for hybrid Kerberos principals remains the nfs-klldap-idhelper (IdLdapResolver + getent + nss_wrapper/extrausers materialization).

## Machine vs User Principals (Fedora Immutable + host keytabs)

When clients use Kerberos host keytabs (e.g. `/etc/krb5.keytab` on Fedora Immutable/Silverblue) plus user TGTs, Ganesha receives Kerberos-authenticated principals on NFSv4 compounds:
- Machine principals: `host/CLIENT@REALM`, `nfs/CLIENT@REALM`, `root/...` (from the client's host keytab).
- User principals: `alice@REALM` (from the user's TGT, resolved via SSSD + LLDAP POSIX attributes).

If Ganesha maps these inconsistently (or falls back to nobody/65534 for machine names), the client can see credential mixing that causes NFSv4 session teardown or permission failures.

`nfs-klldap-idhelper` (using structured LDAP resolution via shared IdLdapResolver for consistency with the UI LdapClient + its caches, plus getent for client parity) is the authoritative layer for this. At daemon start it eagerly inits the resolver (the "ldap cache") and pre-resolves server host principals + forces a root uid0 entry so nsswitch (sss + extrausers + wrapper for ganesha) has user/machine info *immediately* after startup, avoiding cold first-access races ("Could not map", getpwuid 0 fails for host/ principals).

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

The server must perform the same lookups clients do (`getent passwd testuser1` + principal forms). For ganesha 9.6 on Debian trixie, `principal2uid` calls in-process libnfsidmap (`nfs4_gss_princ_to_ids`), which does `getpwnam` inside ganesha.nfsd under nss_wrapper — so LDAP users must be present in `/var/lib/nfs-klldap/nss_passwd`. The idhelper syncs LDAP→nss_wrapper at startup and every 10 minutes by default (`NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS`, `0` disables). Each sync prunes non-machine cache entries then reloads from LDAP (adds, uid/gid changes, and deletions propagate). Manual refresh: `echo REBULK | nc -U /var/run/nfs-klldap/idhelper.sock` or config SIGHUP (restarts idhelper). The nfsidmap binary shim does not intercept the principal2uid path. Explicit `Read_Access_Check_Policy = pre;` inside CLIENT blocks addresses ACCESS timing for krb5 compounds. Machine principals map to 0; some group-fetch INFO for uid 0 and winbind noise are expected.

This is what actually makes the idhelper work "in conjunction" with Ganesha and SSSD. It does **not** inject untrusted data into `ganesha.conf` (Ganesha stays on a conservative static `Root_Kerberos_Principal = host, nfs;` list; the live translation lives in the nss_wrapper view controlled by the idhelper).

See [README.md](../README.md) (Identity & Kerberos section) and [TESTING.md](../TESTING.md).
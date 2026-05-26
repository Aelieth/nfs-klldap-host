# LLDAP POSIX Integration for NFSv4 ID Mapping

This is the most critical operational piece for reliable UID/GID mapping when using user-only Kerberos tickets.

The container uses SSSD (primary on AlmaLinux 10) + `rpc.idmapd` to translate Kerberos principals (`user@REALM`) into POSIX numeric IDs from LLDAP.

## 1. LLDAP Requirements

Your LLDAP instance must store POSIX attributes on users and groups.

### Recommended objectClasses + attributes

**Users** (under `ou=people`):
- `objectClass: inetOrgPerson`
- `objectClass: posixAccount`
- Required attributes:
  - `uid` (login name)
  - `uidNumber`
  - `gidNumber`
  - `homeDirectory`
  - `loginShell` (can be `/bin/bash` or `/bin/false`)

**Groups** (under `ou=groups`):
- `objectClass: posixGroup`
- Required attributes:
  - `cn`
  - `gidNumber`

### Creating POSIX users/groups in LLDAP

**Via web UI (easiest):**
1. Create the user normally.
2. Go to the user → "Attributes" tab.
3. Add the `posixAccount` auxiliary objectClass.
4. Fill in `uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`.
5. Do the same for the group (add `posixGroup` + `gidNumber`).

**Via GraphQL / scripts:**
See the LLDAP documentation for bulk creation. The attribute names above are the standard ones.

**Important:** The numeric `uidNumber`/`gidNumber` values you assign here **must** match the ownership on the host filesystem for the exported shares.

## 2. Container Configuration

The container already ships good default templates in `container/templates/`.

### Recommended approach

1. Bind-mount your templates directory:
   ```yaml
   - ./templates:/container/templates:ro
   ```

2. Copy the provided templates and customize:
   - `sssd.conf.template` — the most important file
   - `idmapd.conf.template` — usually fine with `Method = sss`
   - `krb5.conf.template`

### Key sssd.conf settings for LLDAP + NFS

See the current `container/templates/sssd.conf.template` for a working starting point.

Critical sections:

```ini
[domain/default]
id_provider = ldap
auth_provider = ldap
access_provider = permit

ldap_uri = ldaps://lldap.example.com:6360
ldap_search_base = dc=example,dc=com

ldap_user_search_base = ou=people,dc=example,dc=com
ldap_group_search_base = ou=groups,dc=example,dc=com

# POSIX mappings
ldap_user_object_class = inetOrgPerson
ldap_user_uid_number = uidNumber
ldap_user_gid_number = gidNumber
...
```

Enable enumeration (`enumerate = true`) during initial bring-up — it makes `getent` and idmapping more reliable for small environments.

## 3. Verification Commands (run inside the container)

After the container is running with your LLDAP and keytab:

```bash
# 1. Can SSSD see the user?
getent passwd alice
id alice

# 2. Can the NFS idmapper resolve the principal?
rpc.idmapd -f -vvv
# In another shell, try to access a share or run:
#   ls -n /export/some-share
# Watch the idmapd output

# 3. Check current exports
exportfs -s

# 4. Quick sanity check from a Kerberized client
kinit alice
mount -t nfs4 -o sec=krb5p server.example.com:/export/share1 /mnt/test
ls -l /mnt/test
```

## 4. Common Problems & Fixes

**Everything maps to nobody / 65534**
- `idmapd.conf` `Domain` does not match your Kerberos realm.
- `rpc.idmapd` started before SSSD was ready (the entrypoint should prevent this).
- LLDAP user is missing `posixAccount` or the `uidNumber` attribute.

**Permission denied even with correct numeric IDs**
- Host filesystem ownership does not match the `uidNumber`/`gidNumber` in LLDAP.
- SELinux or AppArmor on the host is interfering.

**SSSD cannot contact LLDAP**
- TLS/certificate issues (`ldap_tls_reqcert = demand` is strict).
- Bind credentials (if required) are wrong or missing.
- Firewall between container and LLDAP.

**Debugging tips**
- Run the container with `SSSD_DEBUG_LEVEL=7` (or higher).
- Inside the container: `sss_cache -E` then retry `getent`.
- Check container logs for SSSD and `rpc.idmapd`.

## 5. Client-side Considerations

Even though the server does authoritative mapping, clients benefit from running `rpc.idmapd` with a matching `Domain` in `/etc/idmapd.conf` and `Method = sss` (or `nsswitch`).

This gives nice `ls` output (names instead of numbers) and improves some application behavior.

## 6. Recommended Workflow

1. Create user + POSIX attributes in LLDAP.
2. `chown` the host directories to the same numeric IDs.
3. Add an `*.exports` file in your `exports.d/` directory.
4. Send `SIGHUP` to the container (or restart it).
5. Verify with the commands in section 3.

## References

- Current working templates: `container/templates/`
- Validation script: `scripts/verify-idmap.sh`
- LLDAP documentation on custom attributes and POSIX objectClasses

---

This document is intentionally practical. For deeper SSSD tuning, see `sssd.conf(5)` and the Red Hat SSSD + NFS integration guides.

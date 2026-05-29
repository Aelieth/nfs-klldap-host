# LLDAP POSIX Integration for NFSv4 ID Mapping (Ganesha)

This is the most critical operational piece for reliable UID/GID mapping when using user-only Kerberos tickets.

The container uses **SSSD** (talking to LLDAP) as the source of POSIX `uidNumber`/`gidNumber` values. NFS-Ganesha serves the files with those numeric IDs. The management tool on the host keeps directory ownership in sync with LLDAP.

The old kernel path (`rpc.idmapd`, `exportfs`, `rpc.gssd`, etc.) has been removed. All guidance below is for the current Ganesha + SSSD architecture.

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

The container uses a single `nfs-klldap.conf` (TOML) as the source of truth. The bundled Rust binary auto-derives `sssd.conf`, `krb5.conf`, and Ganesha exports. No template bind-mounts are needed.

### Recommended approach

Mount the central config (and your data + keytab). Edit `nfs-klldap.conf` via the host UI
or by hand; the container regenerates `sssd.conf` / `krb5.conf` / Ganesha exports automatically.

```yaml
volumes:
  - ./config:/config:rw
  - /media/SSD-01:/export:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

### Key settings (in nfs-klldap.conf) for LLDAP + NFS

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

## 3. Verification Commands (inside the running container)

```bash
# 1. Healthcheck (recommended first step)
 /container/healthcheck.sh

# 2. Can SSSD see LLDAP users and groups?
getent passwd alice
id alice
getent group some-ldap-group

# 3. What does Ganesha currently have loaded?
ganesha-ctl show-exports

# 4. Kerberos keytab and principal
klist -k /etc/krb5.keytab

# 5. Quick end-to-end test from a client with a user ticket
kinit alice
mount -t nfs4 -o sec=krb5p nfs-server-01.example.com:/project-alpha /mnt/test
# (data for /project-alpha lives on an attached drive such as /media/SSD-01/project-alpha on the server)
ls -l /mnt/test
```

## 4. Common Problems & Fixes

**Everything maps to nobody / 65534**
- LLDAP user/group is missing `posixAccount` / `posixGroup` or the `uidNumber`/`gidNumber` attributes.
- SSSD has not enumerated or the NSS pipe is not ready (the entrypoint waits for it).
- Mismatch between `Domain` / realm settings in `krb5.conf` and `ganesha.conf`.

**Permission denied even with correct numeric IDs on the wire**
- Host filesystem ownership does not match the `uidNumber`/`gidNumber` values in LLDAP.
- SELinux / AppArmor on the host is interfering with the bind mounts.

**SSSD cannot contact LLDAP**
- TLS/certificate problems (`ldap_tls_reqcert = demand`).
- Firewall, bind credentials, or wrong `ldap_uri`.
- Run the container with `SSSD_DEBUG_LEVEL=7` and look at the logs.

**Direct management (ganesha-ctl) not working**
- (Historical) The host DBUS socket is not mounted into the container. This is no longer required or used. The container is fully self-contained.

## 5. Client-side Considerations

Even though the server does authoritative mapping, clients benefit from running `rpc.idmapd` with a matching `Domain` in `/etc/idmapd.conf` and `Method = sss` (or `nsswitch`).

This gives nice `ls` output (names instead of numbers) and improves some application behavior.

## 6. Recommended Workflow

1. Create the user + POSIX attributes (`uidNumber`, `gidNumber`, etc.) in LLDAP.
2. Use the management web UI (it asks the container via `docker exec`) to `chown`/`chmod` the host directories so the numeric IDs match LLDAP.
3. Define shares in the central `nfs-klldap.conf` (the container and host UI both use it).
4. The tool writes a native Ganesha `EXPORT {}` fragment into the bind-mounted exports directory. The container supervisor detects the change (via inotify + pkill) and restarts Ganesha (no DBUS involved).
5. Verify with the commands in section 3 and from a Kerberized client.

## References

- Current templates: `container/templates/`
- `ganesha-ctl` (file-based reload helper): `container/scripts/`
- Management tool source: `management/`
- LLDAP documentation (POSIX attributes + GraphQL)

---

This document is intentionally practical. For deeper SSSD tuning see `sssd.conf(5)`. Ganesha export changes are now handled entirely inside the container via the inotify watcher + supervisor restart (no DBUS).

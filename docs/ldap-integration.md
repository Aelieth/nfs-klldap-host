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

**Via the KLLDAP management UI or scripts:**
See the KLLDAP/LLDAP documentation for bulk creation via the management interface or scripts. The attribute names above are the standard ones.

**Note:** The in-container WebUI permission editor and login no longer use GraphQL — they use standardized LDAP searches and binds against the same configuration as SSSD.

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

The container's Rust generator produces a minimal but functional `sssd.conf` from the single TOML.
Critical sections live under the top-level `ldap_uri` and `[sssd]`:

```toml
ldap_uri = "ldaps://lldap.example.com:6360"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "your-password"
ldap_user_search_base = "ou=people,dc=example,dc=com"
ldap_group_search_base = "ou=groups,dc=example,dc=com"

# TLS flexibility (new in current version)
# ldap_tls_reqcert = "never"          # accept self-signed LLDAP certs (common)
# ldap_id_use_start_tls = true        # only when using plain ldap:// + STARTTLS
```

The generator emits the standard ldap_* search bases + bind credentials. For advanced POSIX attribute mapping or custom objectClasses you can still drop a fully custom `/etc/sssd/sssd.conf` (advanced users only; the watcher will overwrite on next nfs-klldap.conf change unless you disable it).

The generator now defaults to `enumerate = false`. Enable enumeration by adding `enumerate = true` under `[domain/default]` (via a raw edit or the UI) if you want a warm cache for `getent` / `id` lookups. Be aware that with KLLDAP this can generate significant attribute request volume.

### Stopping KLLDAP "unrecognized attribute" warning spam (SSSD + sync tools)

SSSD (and especially AD-style directory sync tools) request a very large number of attributes (`userAccountControl`, `shadow*`, `krb*`, `nsAccountLock`, `gecos`, `authorizedService`, `login*`, `passkey`, etc.) that a minimal KLLDAP instance will never have. This produces a constant flood of:

```
WARN  Ignoring unrecognized user attribute: accountexpires. Add to "ignored_user_attributes".
WARN  Ignoring unrecognized group attribute: memberuid. Add to "ignored_group_attributes".
```

**KLLDAP has a built-in solution**: `ignored_user_attributes` and `ignored_group_attributes` in its own server configuration.

By default, `nfs-klldap-config` now emits a ready-to-copy block at the end of the generated `sssd.conf` (and the full recommended lists) when you run generation.

In your `nfs-klldap.conf`:

```toml
[sssd]
# ... your other settings ...

# Emit recommended ignored_*_attributes lists for your KLLDAP server
# (dramatically reduces warning spam from SSSD and dirsync-style tools).
# See below for how to apply the lists on the KLLDAP side.
kllldap_ignored_attributes = true   # default
```

To disable the emitted recommendations entirely (you manage the KLLDAP ignore lists yourself):

```toml
[sssd]
kllldap_ignored_attributes = false
```

The generator will then omit the block.

**Applying the lists on the KLLDAP side**

Copy the two lines from the generated `sssd.conf` (look for the big "KLLDAP SERVER-SIDE IGNORED ATTRIBUTES" comment block) into your KLLDAP server configuration file (usually `lldap.toml` or the equivalent in the kerberos fork, under the `[ldap]` or root section).

Example (from a real production run):

```toml
ignored_user_attributes = ["accountexpires", "authorizedservice", "gecos", "host", "krblastpwdchange", ...]
ignored_group_attributes = ["memberuid", "userpassword"]
```

Restart KLLDAP after changing its config. The spam should disappear almost completely while real POSIX attributes (`uidNumber`, `gidNumber`, `member`/`uniqueMember`, etc.) continue to work normally.

This feature was added specifically because the combination of SSSD + various sync clients against KLLDAP is extremely noisy by default.

### Group membership attribute recommendation for KLLDAP

When using KLLDAP with `ldap_schema = rfc2307bis` (the default emitted by the generator), the modern and cleanest approach is to use the `member` (or `uniqueMember`) attribute for group membership.

KLLDAP already populates these attributes with proper DNs for every group member. The legacy `memberUid` approach requires either custom attributes or extra work on the KLLDAP side and produces warnings.

**What the generator now does by default:**

- When `kllldap_ignored_attributes = true` (the default), `ldap_group_member` resolves to `"member"`.
- When you explicitly set `kllldap_ignored_attributes = false`, it falls back to the old `"memberUid"` default for compatibility with non-KLLDAP or legacy setups.

You can always override it explicitly:

```toml
[sssd]
ldap_group_member = "uniqueMember"   # or "member" or "memberUid"
```

This change, combined with the ignored attributes feature, eliminates the most common sources of "unrecognized group attribute" warnings (`memberuid` and `userpassword` on groups) when talking to KLLDAP.

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
- TLS/certificate problems (set `ldap_tls_reqcert = "never"` under [sssd] in nfs-klldap.conf for self-signed LLDAP certs).
- Firewall, bind credentials, or wrong `ldap_uri`.
- Run the container with `SSSD_DEBUG_LEVEL=7` and look at the logs.

**Direct management (ganesha-ctl) not working**
- (Historical) The host DBUS socket is not mounted into the container. This is no longer required or used. The container is fully self-contained.

**Massive "Ignoring unrecognized attribute" spam + TLS "peer closed without close_notify" + later searches with bare username as base DN (e.g. `dn: "dirsync"`)**

This exact symptom cluster almost always happens when:

- You use a dedicated service account (e.g. `uid=dirsync,ou=sync,...`) as `ldap_default_bind_dn` for SSSD.
- `enumerate = true` (explicitly enabled; the generator now defaults to `false`).
- The account lives in a custom OU outside `ou=people`/`ou=groups`.
- No server-side `ignored_*_attributes` are configured on KLLDAP.

SSSD (especially with enumeration) does very broad attribute requests. KLLDAP logs a warning for every unknown attribute on every result. The noise + volume causes the client to hard-close LDAPS connections without proper TLS shutdown. Later internal operations in SSSD can then send searches with just the short username as the `baseObject`, producing the `Invalid DN syntax ... dn: "dirsync"` errors.

**Fix (in order of impact):**

1. Rebuild the container with current code (the `kllldap_ignored_attributes` feature is now on by default).
2. Apply the recommended `ignored_user_attributes` / `ignored_group_attributes` block that now appears at the bottom of the generated `sssd.conf` into your KLLDAP server config.
3. The generator now also defaults `ldap_group_member = member` (instead of `memberUid`) when the above toggle is active.
4. Consider setting `enumerate = false` (or only enable it temporarily while warming caches) if the service account is doing heavy work.

After applying the ignores on the KLLDAP side, the spam disappears, connections stabilize, and the mangled-DN searches stop occurring. The generator now also emits a prominent diagnostic comment block in `sssd.conf` when it detects a bind DN outside the normal user tree.

## 5. Client-side Considerations

Even though the server does authoritative mapping, clients benefit from running `rpc.idmapd` with a matching `Domain` in `/etc/idmapd.conf` and `Method = sss` (or `nsswitch`).

This gives nice `ls` output (names instead of numbers) and improves some application behavior.

## 6. Recommended Workflow

1. Create the user + POSIX attributes (`uidNumber`, `gidNumber`, etc.) in LLDAP.
2. Use the in-container WebUI (on port 9630) to `chown`/`chmod` the directories so the numeric IDs match LLDAP. The WebUI's long-lived LLDAP client uses the same `sssd.ldap_default_bind_dn` + `authtok` (or `NFS_KLLDAP_LLDAP_*` env) as SSSD; use the "Reload NFS client" widget on `/settings` after changing them.
3. Define shares in the central `nfs-klldap.conf` (the container and host UI both use it).
4. The tool writes a native Ganesha `EXPORT {}` fragment into the bind-mounted exports directory. The container supervisor detects the change (via inotify + pkill) and restarts Ganesha (no DBUS involved).
5. Verify with the commands in section 3 and from a Kerberized client.

## References

- Current templates: `container/templates/`
- `ganesha-ctl` (file-based reload helper): `container/scripts/`
- WebUI source: `nfs-klldap-ui/`
- KLLDAP/LLDAP documentation (POSIX attributes + management UI for user creation)

---

This document is intentionally practical. For deeper SSSD tuning see `sssd.conf(5)`. Ganesha export changes are now handled entirely inside the container via the inotify watcher + supervisor restart (no DBUS).

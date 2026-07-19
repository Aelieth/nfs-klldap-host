# Running & Deployment

**Purpose:** compose/run flags, env vars, setup wizard, TLS/proxy, HOST_NFS, keytab, container ops.

All services run as **root in the container**. Recommended: `--uts=host`, matching NFS keytab principals, bind mounts for config + data. Quick start: root [README.md](../../README.md).

## docker-compose

See [examples/docker-compose.yml](../../examples/docker-compose.yml): `uts: host`, `network_mode: host`, volumes for data/config/keytab + `ganesha-recovery`, `cap_add: [SYS_ADMIN, DAC_READ_SEARCH]`.

## Realm & ldap_uri

- `kerberos.realm` required after first init (or `NFS_KLLDAP_KERBEROS_REALM`). No silent EXAMPLE.COM.
- `ldap_uri` host must be DNS (literal IPs rejected). Port belongs in the URI.
- Forward + reverse DNS required for Kerberos NFS.

## First-run setup (WebUI wizard)

Supervisor starts the WebUI immediately and polls until setup completes.

1. **https://\<host\>:9630/setup/1** — persistent `/config` bind mount  
2. **/setup/2** — `ldap_uri` (DNS); **Test Settings** → **Save and Continue**  
3. **/setup/3** — `[sssd]` bind DN/password; **Test Settings** → **Save and Continue**  
4. **Restarting** — SIGUSR1 full recycle (same as **Restart and apply**); polls `/restart-status` → **/login** for localhost admin password  

**Pre-configured:** mount valid `nfs-klldap.conf` + `/etc/krb5.keytab` → skip steps 1–3.

### Wizard troubleshooting

| Symptom | Check |
|---------|--------|
| DNS failure (step 2) | Host DNS; `getent hosts <host>`; `--network=host` / `--dns` |
| Port unreachable | Port in `ldap_uri`; firewall; `nc -zv <host> <port>` |
| Bind failed / 49 (step 3) | DN + password match LLDAP exactly |
| TLS errors (step 3) | Self-signed: `[sssd] ldap_tls_reqcert = "never"` |

## WebUI (9630)

HTTPS by default (self-signed or custom cert/key). Login: `localhost` (`webui-password`) or LLDAP `webui_admin_group` (default `lldap_admin`).

### TLS / reverse proxy

| Mode | Setting | Behavior |
|------|---------|----------|
| Default TLS | (on) | Internal rustls; `Secure` cookies |
| Reverse proxy | `NFS_KLLDAP_WEBUI_TLS=off` or `[webui] tls = false` | Plain HTTP; proxy must set `X-Forwarded-Proto: https` for Secure cookies |

`NFS_KLLDAP_WEBUI_BIND` (default `0.0.0.0:9630`) is runtime-only (not TOML-validated). `NFS_KLLDAP_WEBUI_COOKIE_SECURE=false` forces non-Secure cookies.

```nginx
# Nginx example
location / {
    proxy_pass http://127.0.0.1:9630;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
}
```

```toml
[webui]
tls = false
# session_timeout_minutes = 720   # default 12h, min 5; after Restart & apply
```

## Environment overrides

Env always wins over file. Core options:

| Variable | Default | Description |
|----------|---------|-------------|
| `NFS_CONFIG` | `/config/nfs-klldap.conf` | TOML path |
| `NFS_KLLDAP_LDAP_URI` | required | LDAP(S) URI (DNS + port) |
| `NFS_KLLDAP_SSSD_LDAP_DEFAULT_BIND_DN` | required | Bind DN |
| `NFS_KLLDAP_SSSD_LDAP_DEFAULT_AUTHTOK` | required | Bind password |
| `NFS_KLLDAP_LLDAP_USER` / `_PW` | — | Compat aliases for bind DN/password |
| `NFS_KLLDAP_KERBEROS_REALM` | from ldap_uri host | Realm override |
| `NFS_KLLDAP_SERVER_HOSTNAME` | container hostname | Keytab match; prefer `--uts=host` |
| `NFS_KLLDAP_STORAGE_CONTAINER_ROOT` | `/export` | Data mount inside container |
| `NFS_KLLDAP_GANESHA_DEFAULT_SECURITY` | `krb5p` | krb5p / krb5i / krb5 |
| `NFS_KLLDAP_MANAGEMENT_WEBUI_ADMIN_GROUP` | `lldap_admin` | WebUI admin group |
| `NFS_KLLDAP_SSSD_KLLLDAP_IGNORED_ATTRIBUTES` | `true` | Emit KLLDAP ignore blocks |
| `NFS_KLLDAP_SSSD_LDAP_TLS_REQCERT` | — | e.g. `never` |
| `NFS_KLLDAP_SSSD_LDAP_TLS_CACERT` | — | CA PEM path |
| `NFS_KLLDAP_SSSD_LDAP_ID_USE_START_TLS` | `false` | `ldap://` only |
| `NFS_KLLDAP_WEBUI_TLS` | on | `off` = plain HTTP for proxy |
| `NFS_KLLDAP_WEBUI_TLS_CERT` / `_KEY` | self-signed | Custom PEM paths |
| `NFS_KLLDAP_WEBUI_BIND` | `0.0.0.0:9630` | Listen address |

Operational:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_FORMAT` | `text` | `text` or `json` |
| `SSSD_DEBUG_LEVEL` | — | Passed as `-d` to sssd |
| `GANESHA_DEBUG` | — | Emit DEBUG LOG block (troubleshooting) |
| `WATCHER_DEBOUNCE_SECONDS` | `2` | Conf-watcher debounce before SIGHUP |
| `HOST_NFS` / `NFS_KLLDAP_HOST_NFS` | `false` | Management sidecar (no ganesha.nfsd) |
| `NFS_KLLDAP_IDHELPER_REBULK_INTERVAL_SECS` | `180` | `0` = off |
| `NFS_KLLDAP_WEBUI_COOKIE_SECURE` | derived | Force non-Secure cookies |

### HOST_NFS mode

Management sidecar: WebUI, SSSD, generate, permission trees — **not** container `ganesha.nfsd`.

```yaml
volumes:
  - /etc/ganesha:/etc/ganesha:rw   # host daemon reads fragments
  - /media/SSD-01:/export:rw
  - ./config:/config:rw
  - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
environment:
  - HOST_NFS=true
```

Or persistently: `[host] host_nfs = true` (env still wins). Healthcheck asserts SSSD + WebUI only (no 2049). Host Ganesha needs the same `nfs/` keytab principals.

## Keytab

Mount 0600 root-owned keytab at `/etc/krb5.keytab:ro` (`:Z` on SELinux). With `--uts=host`, create principals for short + FQDN when they differ:

```bash
addprinc -randkey nfs/aurora@EXAMPLE.COM
addprinc -randkey nfs/aurora.example.com@EXAMPLE.COM
ktadd -k /tmp/keytab nfs/aurora@EXAMPLE.COM nfs/aurora.example.com@EXAMPLE.COM
```

## Navahi network discovery

Optional, **off by default**. Core toggle `navahi_discovery` (Restart & apply) + per-share `navahi_insecure` advertises shares over mDNS for GNOME/KDE **NFSv3/AUTH_SYS** click-mount. Kerberized v4.2 path unchanged. Client story: [client-fedora-immutable.md](../client-fedora-immutable.md).

- Host network + firewall: mdns (5353/udp), 111, 20048/tcp (MOUNT), 2049/tcp.
- Global toggle is full-recycle gated; per-share flags apply on graceful shares save (export + advert XML).
- Adverts prefer qualified `[server] hostname` (not `.local`) when dotted.
- Healthcheck **WARN** only if toggle on but avahi/adverts missing.

## Troubleshooting at start

```bash
docker logs <name>
docker kill -s HUP <name>    # graceful apply (exports + WebUI reload; identity staged)
docker kill -s USR1 <name>   # full recycle (= Restart and apply)
```

Do not set compose `user:` — pid 1 must be root.

## Docker ops (caps, dbus, bind mounts)

| Flag | Why |
|------|-----|
| `network_mode: host` | Required for production NFS + Kerberos (bridge puts `172.17.x.x` in CLIENT records) |
| `uts: host` | Hostname matches keytab principals |
| `SYS_ADMIN` | Ganesha VFS on host binds |
| `DAC_READ_SEARCH` | Walk restrictive intermediate dirs (WebUI + Ganesha) |

`--privileged` works but is overkill. Numeric UID/GID must match host and container (no userns-remap).

Entrypoint starts `dbus-daemon` (Ganesha bus) and best-effort `rpcbind`. Management is fragments + signals to pid 1 — not D-Bus export RPCs.

Generator writes minimal `ganesha.conf` + `/etc/ganesha/exports.d/*`. Defaults: Protocols=4, DIRECTORY_SERVICES nsswitch, `Root_Kerberos_Principal = nfs, root`, Idmapped validity 180, Only/Allow_Numeric, UseGetpwnam. Hand-appended CLIENT blocks are lost on regenerate.

```bash
/container/healthcheck.sh
verify-ganesha.sh
ganesha-ctl show-fragments
ganesha-ctl id-resolve 'user@REALM' --grps
```

SELinux: `:Z` on binds. Deep identity: [ldap-integration.md](../ldap-integration.md).

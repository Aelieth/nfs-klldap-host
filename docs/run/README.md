# Running nfs-klldap-host (Practical Examples)

This document focuses on day-to-day container invocation after the v0.5 central TOML + in-container WebUI changes. The container runs all services (including the WebUI on port 9630) as root for simplicity and compatibility with Red Hat service expectations.

## Quick Start (docker run)

```bash
docker run -d \
  --name nfs-klldap \
  --uts=host \
  --cap-add CHOWN \
  --cap-add FOWNER \
  --cap-add DAC_OVERRIDE \
  --cap-add DAC_READ_SEARCH \   # helpful for Ganesha VFS
  --cap-add NET_BIND_SERVICE \  # for port 2049
  -p 2049:2049/tcp \
  -p 2049:2049/udp \
  -e NFS_CONFIG=/config/nfs-klldap.conf \
  -v /path/to/config:/config \
  -v /media/SSD-01:/export \
  -v /media/SSD-01/krb5/krb5.keytab:/etc/krb5.keytab:ro \
  ghcr.io/aelieth/nfs-klldap-host:latest
```

**First run** will create a default `nfs-klldap.conf` in your `-v ...:/config` volume. Edit it, then restart the container.

## Important: Realm Requirement (no more silent EXAMPLE.COM)

The container will **refuse to start** (after the initial `init` template write) if it cannot determine a real Kerberos realm.

You must either:

- Edit the generated config and set:
  ```toml
  [kerberos]
  realm = "KRB.YOURDOMAIN.COM"
  ```
- Or pass the env var on every start:
  ```bash
  -e NFS_REALM=KRB.YOURDOMAIN.COM
  ```

Auto-derivation only works when `ldap_uri` contains a usable DNS domain (e.g. `ldaps://kllap.example.com:6360` → `EXAMPLE.COM`). IP-based URIs or single-label names that produce `EXAMPLE.COM` will now cause a clear validation error on `generate`.

**New explicit check:** `ldap_uri` whose host portion is a literal IP address (IPv4 or IPv6) is rejected early with the message:

> LDAP IP addresses are not supported, DNS resolution is required for operation.

Forward + reverse DNS is mandatory for the NFS `nfs/<hostname>@REALM` service principal (keytab) and for reliable Kerberos/GSSAPI operation with NFS-Ganesha. The KDC host is derived from your `ldap_uri`.

This is intentional hardening so misconfigurations are loud.

## docker-compose Example (Recommended)

See the top-level [examples/docker-compose.yml](../examples/docker-compose.yml). Add the user and any extra env if needed:

```yaml
services:
  nfs-kerb:
    # ... build/image ...
    # Recommended standard: share the host UTS namespace so the container
    # sees the real hostname of the machine running Docker.
    uts: host

    # Do NOT set a non-root user here — the entrypoint and all services run as root
    # (standard model for Red Hat sssd/kerberos appliances).
    # cap_add, volumes, etc. as before

    # hostname: myhost-nfs   # Only set if you want the container to use a different name
```

**Hostname with `--uts=host` (current standard)**

The recommended way to run the container is with `--uts=host`:

```bash
docker run ... --uts=host ...
```

This makes the container share the Docker host's UTS namespace. As a result, commands like `hostname` and the value in `/proc/sys/kernel/hostname` inside the container will return the real hostname of the machine running Docker (for example `aurora.testdomain.com`).

The `nfs-klldap-startup` guided TUI will then automatically compute and display the recommended Kerberos service principal using the `-nfs` insertion pattern:

- Real host hostname seen: `aurora.testdomain.com`
- Recommended keytab principal: `nfs/aurora-nfs.testdomain.com@YOUR.REALM`

You do **not** need to pass `-e HOST_HOSTNAME`, mount `/etc/hostname`, or use any privileged discovery tricks. `--uts=host` gives the container the real name directly.

**Override with `--hostname`**

If you want the container to present a completely different hostname, simply pass `--hostname your-desired-name`. This is fully supported and takes precedence.

**Warning about combining `--uts=host` with `--hostname`**

Using both at the same time will attempt to change the hostname in the shared UTS namespace, which affects the Docker host itself. Only do this if you really intend to change the host's hostname. In normal use, prefer `--uts=host` by itself (no `--hostname` flag) and let the TUI tell you the correct principal to put in the keytab.

**Hostname two-tier confirmation (new reliability contract)**

The system now requires two independent sources inside the container to report the *exact same* hostname:

- Primary: the `hostname` command
- Secondary confirmation: `/proc/sys/kernel/hostname`

Both the guided startup TUI (`nfs-klldap-startup`) and the in-container WebUI (`nfs-klldap-ui`) call the same `get_consistent_hostname()` function. If the two sources disagree (the classic case is a random Docker container ID like `d81b4e782f65` when you forget `--uts=host`), you will see a large, unmistakable diagnostic block at startup that shows the exact value from each source and tells you the precise fix.

This guarantees that the name printed in every keytab reminder, on the Settings page, and in the alignment diagnostics is identical across the entire bring-up chain (entrypoint → config library → startup binary → WebUI).

## Execution Model (All Services as Root)

The container runs **all services as root** inside the container (SSSD, Ganesha, config watcher, and the WebUI on port 9630). This matches upstream Red Hat package expectations for sssd and Kerberos components and eliminates the fragile permission workarounds required by the previous non-root attempt.

- The entrypoint shell runs as **root** and stays as pid 1. This is required to:
  - Run the Rust generator (must produce `/etc/sssd/sssd.conf` as **root:root 0600** — SSSD's `access_check_file()` strictly enforces this).
  - Start **sssd** (and all other daemons) as root.
  - Handle SIGHUP for privileged regeneration and orchestrated restarts.

- No gosu, no dedicated `nfs` service user, and no post-start pipe permission hacks are needed (all services run as root).

You should **not** pass `--user` (or `user:` in compose) unless you have a very specific reason; doing so would prevent the root supervisor from performing required privileged steps.

### Recommended capabilities

The following capabilities remain useful at the `docker run` / compose level for VFS operations and the WebUI's direct `chown`/`chmod` on bind-mounted data:

```yaml
# docker-compose excerpt
services:
  nfs-kerb:
    cap_add:
      - CHOWN
      - FOWNER
      - DAC_OVERRIDE
      - DAC_READ_SEARCH     # often helpful for Ganesha VFS FSAL
      - NET_BIND_SERVICE    # for listening on privileged port 2049
    volumes:
      - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

### Keytab handling (now simple)

With all services running as root inside the container, a standard root-owned 0600 keytab mounted at `/etc/krb5.keytab:ro` (with `:Z` recommended on SELinux hosts) is directly usable by Ganesha. No special group membership, `chgrp`, or host-side permission scripts are required.

The legacy `./scripts/fix-keytab-perms.sh` is deprecated and no longer needed.

The entrypoint and `nfs-klldap-startup` diagnostics will print clear messages if the keytab or config directory permissions are insufficient at startup.

## Management WebUI (Port 9630)

The WebUI runs inside the container and starts automatically from `entrypoint.sh`.

- **Port**: 9630 (HTTPS)
- **How it starts**: `entrypoint.sh` runs the `webui-certs` helper early (for custom cert discovery), then launches `nfs-klldap-ui`.
- **TLS**:
  - A self-signed certificate is generated at container startup by default (handled inside the Rust binary using `rcgen`).
  - Provide your own by placing `webui.crt` + `webui.key` (or `tls.crt` + `tls.key`) in the same directory as `nfs-klldap.conf`. The helper script will make them available.
- **Access**:
  - From the Docker host: `https://localhost:9630`
  - From the network: `https://<host>:9630` (after publishing the port with `-p 9630:9630`)

See the root [README.md](../README.md) for the recommended access section.

## Volume Permissions (config + data)

Because the container runs as root, `/config` and runtime directories are straightforward to write to from inside. For exported data, the numeric `uidNumber`/`gidNumber` on the host must match LLDAP (independent of the container user). The in-container WebUI performs `chown`/`chmod` directly.

## Healthcheck and Watcher Behavior

Both continue to function normally (now under the root model).

## Troubleshooting Permission Issues at Startup

The Rust diagnostics (`nfs-klldap-startup`) and entrypoint print remediation early.

```bash
# Watch the startup logs — the diagnostics are emitted here before daemons start
docker logs -f <name>

# If you missed the messages, re-run the checks manually inside the container
docker exec -it <name> /bin/bash -c '
  id
  ls -l /etc/krb5.keytab || true
  touch /var/log/ganesha/.test 2>&1 && echo "writable" || echo "NOT writable"
'

# Force a config regeneration (from the host)
docker kill -s HUP <name>
```

If you need to run the entire container (including entrypoint) as root for debugging:

```bash
docker run ... --user root ...
# or in compose: user: "root"
```

This is the normal and recommended mode (no gosu drops are performed).

## Related Hardening Items (Already Applied)

- Realm is now strictly required (no silent `EXAMPLE.COM`).
- `ganesha.default_security` and per-share `security` are enum-validated (`krb5p` | `krb5i` | `krb5` only).
- Config watcher process is reaped on shutdown.

For the older template-based (pre v0.23) run instructions, see the git history or older tags.

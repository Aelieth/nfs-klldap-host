# Running nfs-klldap-host (Practical Examples)

This document focuses on day-to-day container invocation after the v0.3+ central TOML changes, including the non-root hardening (the `nfs` user).

## Quick Start (docker run)

```bash
docker run -d \
  --name nfs-klldap \
  --hostname "$(hostname)-nfs" \
  --user nfs \
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
    hostname: myhost-nfs     # Must match the NFS principal in your keytab: nfs/myhost-nfs@REALM
    # Do NOT set "user: nfs" here — the entrypoint needs root for setup and will
    # use gosu to drop to the unprivileged user for the actual daemons.
    environment:
      - NFS_REALM=KRB.EXAMPLE.COM   # only needed if your ldap_uri won't auto-derive cleanly
    # cap_add, volumes, etc. as before
```

**Note:** The container no longer attempts any automatic hostname adjustment. You are responsible for setting `--hostname` (or the compose `hostname:` field) to the exact value that exists in your keytab.

## Privilege Model (Root for Setup, Drop to nfs for Daemons)

The container image is designed so that:

- `entrypoint.sh` runs as **root** (this is the default). This allows it to:
  - Generate config files into `/etc/sssd`, `/etc/krb5.conf`, `/etc/ganesha/`, etc.
  - Perform early permission checks and directory setup.
  - Run any other bootstrap operations that require elevated privileges.

- Once setup is complete, the entrypoint uses `gosu nfs` to drop privileges before starting the long-running processes (`sssd`, `ganesha.nfsd`, and the config watcher). Most of the container's runtime is therefore as the unprivileged `nfs` user.

You should generally **not** pass `--user nfs` (or `user: "nfs"` in compose) — doing so would prevent the entrypoint from performing its required root-level setup steps and would lead to permission errors.

### Recommended capabilities

Even though the daemons run as the `nfs` user, the following capabilities are still very useful (and recommended) at the `docker run` / compose level:

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
    group_add:
      - "keytab"            # lets the nfs user read a group-readable keytab
    volumes:
      - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

On the host, make the keytab group-readable for the container's `keytab` group (the image creates this group and adds the `nfs` user to it):

```bash
# On the host — one-time (adjust path as needed)
sudo chgrp "$(docker run --rm --entrypoint getent ghcr.io/aelieth/nfs-klldap-host:latest keytab | cut -d: -f3)" /path/to/your/krb5.keytab
sudo chmod g+r /path/to/your/krb5.keytab
```

The entrypoint prints the exact remediation command when it detects permission problems.

### Alternative (largely superseded): Narrow sudoers inside the image

> **Note:** With the current design (entrypoint runs as root and uses `gosu` to drop to the `nfs` user for daemons), the need for an internal sudoers fragment is greatly reduced. The section below is kept for historical/compatibility reasons.

Some environments or older Ganesha VFS behavior work more reliably when the daemons themselves run with real uid 0. For these cases we provide a **very narrow, auditable sudoers fragment**:

- Location in the repo: `container/sudoers.d/nfs`
- It only allows the `nfs` user to:
  - Start `ganesha.nfsd` and `sssd` with the exact argument lists the entrypoint uses.
  - Send the precise `pkill -TERM/-HUP` signals the supervisor and watcher send.
  - Perform a one-time safe copy of the keytab into `/tmp` (so a root-only RO mount still works).

To use this mode:

1. In a derived Dockerfile or via a sidecar init container:
   ```dockerfile
   RUN dnf install -y sudo
   COPY container/sudoers.d/nfs /etc/sudoers.d/nfs
   RUN chmod 440 /etc/sudoers.d/nfs && chown root:root /etc/sudoers.d/nfs
   ```
2. Modify (or extend) the entrypoint to prefix daemon starts and the targeted pkills with `sudo -n --` when not already root.

This pattern is deliberately "one unprivileged supervisor + five extremely specific sudo rules."

### Keytab handling (the #1 non-root gotcha)

The image now:
- Creates a `keytab` system group and adds the `nfs` user to it.
- Runs an early `check_runtime_permissions()` that prints the exact host-side `chgrp` + `chmod` (or `group_add`) command if `/etc/krb5.keytab` is present but unreadable.

For even less friction, use the helper script:

```bash
./scripts/fix-keytab-perms.sh /path/on/host/to/krb5.keytab
```

It automatically detects the correct GID from the image and applies the right permissions on the host file.

You should almost never have to debug "Kerberos not working" blindly anymore.

### Running the entire container as root

You can still force the whole container (including entrypoint) to run as root with `--user root` (or `user: "root"` in compose). This is occasionally useful for debugging permission issues or in very restrictive environments where even the gosu drop causes problems. It is not the recommended default.

## Host-Side Volume Permissions (config + data)

The `nfs` user inside the container is a high system UID/GID created at image build time. For volumes the container must write to:

- The shared config dir (`/config`) must be writable by the container user (or a shared group).
- The data exports (`/export/*`) are a different concern: their numeric owners must match the `uidNumber`/`gidNumber` values stored in LLDAP for the users/groups that should own the files over NFS. This is independent of the container runtime user.

The new proactive permission checks in the entrypoint will loudly tell you (with exact commands) if a critical directory is not writable.

## Healthcheck and Watcher Behavior

The healthcheck (`/container/healthcheck.sh`) and the config watcher (`nfs-klldap-conf-watcher`) continue to function under the non-root user. The watcher PID is now correctly tracked for clean shutdown (see entrypoint.sh).

## Troubleshooting Permission Issues at Startup

The entrypoint (running as root) runs `check_runtime_permissions()` very early and prints prominent, copy-pasteable remediation for common problems (keytab readability and unwritable runtime directories). The actual daemons then run as the `nfs` user via `gosu`.

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

This disables the normal `gosu` privilege drop for the daemons.

## Related Hardening Items (Already Applied)

- Realm is now strictly required (no silent `EXAMPLE.COM`).
- `ganesha.default_security` and per-share `security` are enum-validated (`krb5p` | `krb5i` | `krb5` only).
- Config watcher process is reaped on shutdown.

For the older template-based (pre v0.23) run instructions, see the git history or older tags.

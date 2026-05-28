# Running nfs-klldap-host (Practical Examples)

This document focuses on day-to-day container invocation after the v0.3+ central TOML changes, including the non-root hardening (the `nfs` user).

## Quick Start (docker run)

```bash
docker run -d \
  --name nfs-klldap \
  --hostname "$(hostname)-nfs" \
  --user nfs \
  --cap-add SYS_ADMIN \
  --cap-add DAC_READ_SEARCH \
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

This is intentional hardening so misconfigurations are loud.

## docker-compose Example (Recommended)

See the top-level [examples/docker-compose.yml](../examples/docker-compose.yml). Add the user and any extra env if needed:

```yaml
services:
  nfs-kerb:
    # ... build/image ...
    user: "nfs"
    environment:
      - NFS_REALM=KRB.EXAMPLE.COM   # only needed if your ldap_uri won't auto-derive cleanly
    # cap_add, volumes, etc. as before
```

## Recommended Minimal-Privilege Patterns (Non-Root by Default)

The image now ships with proactive hardening so that the default experience with `--user nfs` (or no user override) requires as little admin intervention as possible.

### What the image does for you automatically

- Creates an unprivileged system user `nfs` (and a companion `keytab` group).
- Pre-creates and chowns all known runtime directories (`/var/log/ganesha`, `/var/lib/sss`, `/var/run/ganesha`, `/etc/ganesha*`, etc.).
- Runs `setcap cap_net_bind_service+ep` on the ganesha binary.
- Emits **clear, copy-pasteable remediation commands** at startup (in `entrypoint.sh`) the first time it detects a keytab permission problem or a missing write permission — before the daemons fail cryptically.
- Supports two supported operating modes (see below).

### Primary recommended mode: Capabilities + unprivileged user (no sudo inside image)

This is the default and preferred path. It keeps the attack surface smallest.

```yaml
# docker-compose excerpt
services:
  nfs-kerb:
    user: "nfs"                    # or omit; the image defaults to this
    cap_add:
      - SYS_ADMIN
      - DAC_READ_SEARCH
      - NET_BIND_SERVICE           # for 2049 without root
    group_add:
      - "keytab"                   # lets the nfs user read a group-readable keytab
    volumes:
      - ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

On the **host**, make your keytab group-readable by a GID that matches the container's `keytab` group (or use ACLs):

```bash
# On the host — one-time
sudo chgrp  (getent group keytab | cut -d: -f3)  /path/to/your/krb5.keytab
sudo chmod g+r /path/to/your/krb5.keytab
```

The entrypoint now prints the exact command you need if it detects the problem.

### Alternative mode: Narrow sudoers for daemon startup (maximum compatibility)

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

You should almost never have to debug "Kerberos not working" blindly anymore.

### When you might still choose `--user root`

Only as a temporary debugging step or in environments where even `SYS_ADMIN` + the narrow sudoers is blocked by the container runtime / security policy. The goal of the current work is to make this the *exception*, not the common case.

## Host-Side Volume Permissions (config + data)

The `nfs` user inside the container is a high system UID/GID created at image build time. For volumes the container must write to:

- The shared config dir (`/config`) must be writable by the container user (or a shared group).
- The data exports (`/export/*`) are a different concern: their numeric owners must match the `uidNumber`/`gidNumber` values stored in LLDAP for the users/groups that should own the files over NFS. This is independent of the container runtime user.

The new proactive permission checks in the entrypoint will loudly tell you (with exact commands) if a critical directory is not writable.

## Healthcheck and Watcher Behavior

The healthcheck (`/container/healthcheck.sh`) and the config watcher (`nfs-klldap-conf-watcher`) continue to function under the non-root user. The watcher PID is now correctly tracked for clean shutdown (see entrypoint.sh).

## Troubleshooting Non-Root Starts

The entrypoint now runs `check_runtime_permissions()` very early and prints prominent, copy-pasteable remediation for the two most common problems (keytab readability and unwritable runtime directories).

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

If you still need to fall back to root for a specific container (temporary debugging only):

```bash
docker run ... --user root ...
# or in compose: user: "root"
```

## Related Hardening Items (Already Applied)

- Realm is now strictly required (no silent `EXAMPLE.COM`).
- `ganesha.default_security` and per-share `security` are enum-validated (`krb5p` | `krb5i` | `krb5` only).
- Config watcher process is reaped on shutdown.

For the older template-based (pre v0.23) run instructions, see the git history or older tags.

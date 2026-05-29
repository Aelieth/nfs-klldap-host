# Running nfs-klldap-host (Practical Examples)

This document focuses on day-to-day container invocation after the v0.3+ central TOML changes, including the non-root hardening (the `nfs` user).

## Quick Start (docker run)

```bash
docker run -d \
  --name nfs-klldap \
  --uts=host \
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
    # Recommended standard: share the host UTS namespace so the container
    # sees the real hostname of the machine running Docker.
    uts: host

    # Do NOT set "user: nfs" here — the entrypoint needs root for setup and will
    # use gosu to drop to the unprivileged user for the actual daemons.
    # cap_add, volumes, etc. as before

    # hostname: myhost-nfs   # Only set if you want the container to use a different name
```

**Hostname with `--uts=host` (current standard)**

The recommended way to run the container is with `--uts=host`:

```bash
docker run ... --uts=host ...
```

This makes the container share the Docker host's UTS namespace. As a result, commands like `hostname` and the value in `/proc/sys/kernel/hostname` inside the container will return the real hostname of the machine running Docker (for example `aurora.satomlin.com`).

The `nfs-klldap-startup` guided TUI will then automatically compute and display the recommended Kerberos service principal using the `-nfs` insertion pattern:

- Real host hostname seen: `aurora.satomlin.com`
- Recommended keytab principal: `nfs/aurora-nfs.satomlin.com@YOUR.REALM`

You do **not** need to pass `-e HOST_HOSTNAME`, mount `/etc/hostname`, or use any privileged discovery tricks. `--uts=host` gives the container the real name directly.

**Override with `--hostname`**

If you want the container to present a completely different hostname, simply pass `--hostname your-desired-name`. This is fully supported and takes precedence.

**Warning about combining `--uts=host` with `--hostname`**

Using both at the same time will attempt to change the hostname in the shared UTS namespace, which affects the Docker host itself. Only do this if you really intend to change the host's hostname. In normal use, prefer `--uts=host` by itself (no `--hostname` flag) and let the TUI tell you the correct principal to put in the keytab.

## Privilege Model (Root for Setup + SSSD, Unprivileged for Ganesha + Watcher)

The container uses a carefully tuned split-privilege model:

- The entrypoint shell runs as **root** and stays as pid 1 for the life of the container. This is required so it can:
  - Run the Rust generator (which must produce `/etc/sssd/sssd.conf` as **root:root 0600** — SSSD's `access_check_file()` strictly enforces this and rejects any other owner, even 0600 files owned by another user).
  - Start **sssd** itself as root (standard for SSSD; it creates responder pipes/sockets with tight permissions).
  - Handle SIGHUP for privileged regeneration + daemon restarts.
  - Perform the post-start fixups that let the unprivileged user talk to SSSD's NSS responder.

- **ganesha.nfsd** and the **config watcher** run as the unprivileged `nfs` user (via `gosu`). This is the important security boundary for VFS access to user data and for the inotify watcher.

- After sssd starts we explicitly relax the permissions on its responder pipes (`/var/lib/sss/pipes`) so that `getent`/`id` and Ganesha (running as `nfs`) can still perform UID/GID mapping via the NSS module.

You should generally **not** pass `--user nfs` (or `user: "nfs"` in compose) — doing so would prevent the root supervisor from doing the required privileged steps (especially writing a root-owned sssd.conf).

If you need a fully unprivileged container for some other reason, the only viable path is to start the whole thing as root (`--user root`) and accept that sssd + generator run privileged (still the safest practical choice for this workload).

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

The entrypoint (and Rust diagnostics) print exact remediation commands. After the root-owned generate step the entrypoint now does an automatic `chown nfs:nfs + chmod 600` on `sssd.conf` (the main historical source of "Permission denied" at SSSD start when running daemons as the unprivileged user).

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

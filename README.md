# alma_nfs-kerb

AlmaLinux 10 container providing **Kerberized NFSv4** shares with LDAP-backed UID/GID mapping (via SSSD) and a future small Rust management UI.

**Current status:** PR 1 foundation — hardened container + correct daemon ordering + SSSD support.

## Goals

- Run real kernel `nfsd` (NFSv4 only) in a container on AlmaLinux 10.
- Support **user-only Kerberos tickets** (no machine keytabs or host principals required on NFS clients).
- Use LLDAP (or any POSIX-capable LDAP) for reliable `uidNumber`/`gidNumber` mapping via `rpc.idmapd` + SSSD.
- Make it easy to add new shares via simple host volume mounts (`/etc/exports.d/*.exports`).
- Provide a small, pleasant Rust-based visual management tool in later PRs (Axum + HTMX primary path).

## Architecture (PR 1)

```
Host
 ├── /srv/nfs/...               (your actual data)
 ├── /etc/exports.d/            (share definitions)
 ├── secrets/krb5.keytab        (nfs/hostname@REALM)
 └── config/
      ├── sssd.conf             (LLDAP connection + POSIX)
      ├── idmapd.conf
      └── krb5.conf

Container (privileged-ish, host net)
 ├── rpcbind
 ├── sssd (+ readiness wait)
 ├── rpc.idmapd
 ├── rpc.gssd
 ├── exportfs
 └── rpc.nfsd (NFSv4 only)
```

The container is **not** a full replacement for a proper NAS, but it is excellent for:
- Lab / homelab Kerberized shares
- Consistent UID/GID across many machines using the same LLDAP
- Easy addition of new exports without rebuilding images

## Host Prerequisites (Critical)

Before running the container you **must** do the following on the Docker host:

1. **Load kernel modules**
   ```bash
   modprobe nfs
   modprobe nfsd
   modprobe rpcsec_gss_krb5
   ```

2. **Time synchronization** — Kerberos is extremely sensitive to clock skew.
   ```bash
   chronyc tracking
   ```

3. **DNS / hostname** — The container hostname must exactly match the instance in your NFS principal (e.g. `nfs/nfs-server-01.example.com@EXAMPLE.COM`).

4. **Keytab** — Create the NFS service keytab (`nfs/<hostname>@REALM`) and bind-mount it at `/etc/krb5.keytab` (mode 600). See `examples/secrets/README.md`.

5. **Share directories** — Create them on the host and chown to the numeric UID/GID from LLDAP.
   ```bash
   mkdir -p /srv/nfs/share1
   chown 10000:10000 /srv/nfs/share1
   ```

## Keytab

The container requires a keytab containing only the NFS service principal for its hostname:

    nfs/nfs-server-01.example.com@EXAMPLE.COM

Mount it read-only with strict permissions:

```yaml
- ./secrets/krb5.keytab:/etc/krb5.keytab:ro
```

See `examples/secrets/README.md` for preparation steps.

## Configuration via Templates (Clear Separation)

The container looks for `*.template` files in a dedicated directory controlled by the `TEMPLATES_DIR` environment variable (default: `/container/templates`).

It renders them (via `envsubst`) to the official locations **unless** you also bind-mount final versions directly to `/etc/...`.

This keeps templates and final configs in separate directories when you export volumes from the host — no mixing of `foo.template` and `foo.conf` in the same place.

**How to customize:**

1. Bind-mount your templates directory (recommended):
   ```bash
   -v ./my-templates:/container/templates:ro
   # or point anywhere:
   -e TEMPLATES_DIR=/path/inside/container
   ```

2. Optionally bind-mount final configs directly (they win):
   ```bash
   -v ./final/sssd.conf:/etc/sssd/sssd.conf:ro
   ```

3. (Optional) You can still use environment variables inside templates if you want (`${MY_LDAP_HOST}` etc.). Most admins simply edit the values directly in the templates.

There are **no mandatory environment variables**. The system is driven by the templates you maintain.

## Quick Start (docker run)

```bash
docker run -d \
  --name alma-nfs-kerb \
  --net=host \
  --hostname nfs-server-01.example.com \
  --cap-add SYS_ADMIN \
  -v /proc/fs/nfsd:/proc/fs/nfsd:rw \
  -v /var/lib/nfs:/var/lib/nfs:rw \
  -v /srv/nfs:/export:rw \
  -v $(pwd)/exports.d:/etc/exports.d:ro \
  -v $(pwd)/secrets/krb5.keytab:/etc/krb5.keytab:ro \
  # Templates (separate volume/dir)
  -v $(pwd)/my-templates:/container/templates:ro \
  # Or override the templates directory:
  # -e TEMPLATES_DIR=/container/my-templates \
  alma-nfs-kerb:latest
```

See `examples/docker-compose.yml` for the recommended compose pattern.

**Dynamic re-exports (new in this iteration):**  
Send `SIGHUP` to the container (or `kill -HUP 1` inside it) to run `exportfs -ra` without restarting the NFS daemons. This is the mechanism the future management tool will use.

## Verification

Inside the container (or with `docker exec`):

```bash
# Check exports
exportfs -s

# Check that SSSD can see your POSIX users
getent passwd some-ldap-user
id some-ldap-user

# Debug idmapping in real time (very useful)
rpc.idmapd -f -vvv

# Check Kerberos keytab
klist -k /etc/krb5.keytab

# From a client with a user ticket
kinit alice
mount -t nfs4 -o sec=krb5p nfs-server-01.example.com:/export/share1 /mnt/test
```

From the client `ls -n /mnt/test` should show the numeric IDs that match LLDAP, and `ls` (without `-n`) should resolve names once client-side idmapping is also configured.

## Dynamic Shares

Add or remove shares by dropping `*.exports` files into a host directory bind-mounted to `/etc/exports.d/`.

Example (`exports.d/10-myshare.exports`):

```exports
/export/myshare   *(rw,sec=krb5p,no_root_squash,sync,hide)
```

Send `SIGHUP` to the container to re-export without restart:

```bash
docker kill -s HUP <container>
```

See `examples/exports.d/` and the SIGHUP note in `entrypoint.sh`.

## Important Warnings

- **Hostname / principal matching** is not optional.
- **Host filesystem ownership** must match the `uidNumber`/`gidNumber` values stored in LLDAP. The container cannot magically fix this.
- Running real `nfsd` inside Docker requires elevated privileges and host networking in almost all practical deployments.
- Client-side `rpc.idmapd` (with matching `Domain` and `Method = sss` or nsswitch) is still very useful for nice `ls` output and some applications, even though the server does the authoritative mapping.

## Configuration Templates

See `container/templates/` for the `.template` files. Bind-mount this directory (or set `TEMPLATES_DIR`) and edit them directly. The container renders them to the real locations on every start.

## Project Status & Roadmap

PR 1 (container foundation + SSSD + templates) is complete.

PR 2 (dynamic shares via `exports.d/` + proper keytab patterns) is complete.

Next: PR 3 — LLDAP POSIX integration guide + validation scripts (the most important operational piece).

See `docs/ldap-integration.md` and `scripts/verify-idmap.sh`.

## References

- Design document (full architecture, security model, PR plan): see the `design/` artifacts or the original design run output
- erichough/docker-nfs-server (excellent reference patterns for containerized kernel NFS)
- Red Hat / AlmaLinux SSSD + NFS integration guidance
- `idmapd.conf(5)`, `rpc.gssd(8)`, `rpc.idmapd(8)`, `sssd.conf(5)`

## Contributing

PRs are welcome once the foundational pieces (especially PR 3) are in place. Please read the design doc first so we stay aligned on the user-only Kerberos + LLDAP POSIX model and the "small management tool" philosophy.

---

**License:** TBD (likely MIT or similar once we have more code)

# Security Model

**Purpose:** WebUI mutation boundary and container deployment assumptions.

The WebUI runs as **root in the container** and mutates bind-mounted `host_path` trees via `privileged.rs` (std/nix APIs, no shell).

## Deployment assumptions

- **Host networking** (`network_mode: host`) so Ganesha CLIENT records use host-reachable addresses, not Docker bridge `172.17.x.x`.
- **`uts: host`** for Kerberos NFS principal hostname match.
- Caps `SYS_ADMIN` + `DAC_READ_SEARCH` (see `examples/docker-compose.yml`, [docs/run/README.md](../../docs/run/README.md)) — improve Ganesha VFS and WalkDir reliability on restrictive intermediate dirs; not required for root `chown`/`chmod` on a normal bind mount alone.
- Real root (0600 sssd.conf, port 2049, arbitrary numeric UIDs). Host-side binary run is unsupported. No userns-remap / rootless uid shift (on-disk owners must match LLDAP numbers on the host).

## Mutation gates

| Gate | Rule |
|------|------|
| Allow-list | Only paths under configured share roots (`FsManager`) |
| Symlinks | No WalkDir descent (`follow_links(false)`); symlink inodes skipped |
| setuid | Refused; setgid/sticky allowed on directories |
| uid/gid 0 | First-class owner (nobody/anonymous under root_squash) |
| Directory mode | Server fuses r→x per dir entry; client may submit x-less |
| File mode | Explicit triad only; special bits refused; never inherits directory mode |
| Scope | `ApplyScope` bounds recursive reach |
| ACL capability | `/acl-apply` AND `/apply` with a staged `acl_ops` batch re-probe the selected node's own mount (`acl_apply_gate`) — NOACL/incapable paths refuse ACL writes outright |
| ACL batch | Parsed, gated, and LDAP-resolved before any mutation; one bad op rejects the whole apply, chown/chmod included |

See `fs.rs` and `privileged.rs`.

# Security Model

**Purpose:** WebUI mutation boundary and container deployment assumptions.

The WebUI runs as **root in the container** and mutates bind-mounted `host_path` trees via `privileged.rs` (std/nix APIs, no shell).

## Deployment assumptions

- **Host networking** so Ganesha CLIENT records use host-reachable addresses (not Docker bridge).
- **`uts: host`** for Kerberos NFS principal hostname match.
- Caps `SYS_ADMIN` + `DAC_READ_SEARCH` (see `examples/docker-compose.yml`, [docs/run/README.md](../../docs/run/README.md)).
- Real root (0600 sssd.conf, port 2049, arbitrary numeric UIDs). No userns-remap / rootless uid shift — on-disk owners must match LLDAP numbers on the host.

## Mutation gates

| Gate | Rule |
|------|------|
| Allow-list | Only under configured share roots (`FsManager`) |
| Symlinks | No WalkDir descent (`follow_links(false)`); symlink inodes skipped |
| setuid | Refused; setgid/sticky allowed on directories |
| uid/gid 0 | First-class owner (nobody/anonymous under root_squash) |
| Directory mode | Server fuses r→x per dir entry; client may submit x-less |
| File mode | Explicit triad only; special bits refused |
| Scope | `ApplyScope` bounds recursive reach |
| ACL capability | `/acl-apply` and `/apply` with `acl_ops` re-probe the selected node's mount — NOACL/incapable refuse ACL writes |
| ACL batch | Parse + gate + LDAP-resolve before any mutation; one bad op rejects the whole apply |

See `fs.rs` and `privileged.rs`.

# Security Model for the Management Tool

The management tool has significant power: it can change ownership and permissions on host directories that are exported via NFS.

## Core Principle

**Never run the management tool as root.**

The tool validates requests and then asks the running NFS container (via `docker exec`) to perform the actual `chown`/`chmod` operations on the bind-mounted data. The container is the privileged actor.

## How Permission Changes Work

1. The unprivileged management UI (web or CLI) receives a user request (owner, group, mode, recursive).
2. It performs allow-list validation against the current `[[shares]]` `host_path` entries in `nfs-klldap.conf`.
3. It refuses uid/gid 0 and modes containing setuid/setgid/sticky bits.
4. It maps the host path to the equivalent path inside the container (using each share's `name` + `storage.container_root`).
5. It executes the change inside the container using `docker exec <name> chown ...` / `chmod ...`.

Because the container already runs with the capabilities required for Ganesha VFS and has the bind mounts, it can safely mutate ownership and permissions on the exported trees.

The host user running the management tool only needs permission to run `docker exec` against the specific container (typically by being in the `docker` group or an equivalent narrow policy).

## Optional: Narrow Host Sudoers (Alternative Path)

If you prefer not to give the management user docker exec rights, you can instead create narrow sudoers rules on the host that allow direct `chown`/`chmod` limited to the managed share paths (and combine with the container name for SIGHUP reloads if desired). This is a deployment choice — the primary supported model uses the container as the permission actor.

## Additional Hardening Recommendations

- Run the tool behind authentication (if web UI) or as a desktop app that requires the admin to be logged in.
- Log every permission change (who, what, old vs new ownership).
- Consider making the tool read-only by default and require an explicit "apply" step.
- Never allow the tool to manage paths outside explicitly configured roots.

This model keeps the host-side tool unprivileged while still allowing safe, auditable permission management on the exported data.

# Security Model for the Management Tool

The management tool has significant power: it can change ownership and permissions on host directories that are exported via NFS.

## Core Principle

The WebUI runs inside the container as root (the supported model) and performs `chown`/`chmod` directly on the bind-mounted data using the capabilities and mounts provided to the container.

Running the UI binary directly on the host as root is not recommended for normal operation.

## How Permission Changes Work

1. The unprivileged management UI (web or CLI) receives a user request (owner, group, mode, recursive).
2. It performs allow-list validation against the current `[[shares]]` `host_path` entries in `nfs-klldap.conf`.
3. It refuses uid/gid 0 and modes containing setuid/setgid/sticky bits.
4. It maps the host path to the equivalent path inside the container (using each share's `name` + `storage.container_root`).
   The same mapping is used when the live directory tree browser (`build_tree`) reads the filesystem so that browsing and permission editing see the same data.
5. It performs the change directly inside the container.

Because the container already runs with the capabilities required for Ganesha VFS and has the bind mounts, it can safely mutate ownership and permissions on the exported trees.

No special host permissions (beyond access to the container's volumes) are required for normal operation.

## Optional: Running the UI outside the container (Advanced / Legacy)

It is still technically possible to build and run `nfs-klldap-ui` as a separate host process. In that (unsupported) mode it would fall back to using `docker exec` for permission changes. The primary and recommended model is the in-container WebUI running as root.

## Additional Hardening Recommendations

- Run the tool behind authentication (if web UI) or as a desktop app that requires the admin to be logged in.
- Log every permission change (who, what, old vs new ownership).
- Consider making the tool read-only by default and require an explicit "apply" step.
- Never allow the tool to manage paths outside explicitly configured roots.

The WebUI runs inside the container and performs operations directly.

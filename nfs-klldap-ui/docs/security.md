# Security Model

The WebUI runs as root inside the container and performs chown/chmod directly on bind-mounted host_path trees via `src/privileged.rs` (safe std APIs, no extra capabilities required).

It validates requests against the `[[shares]]` host_path list in nfs-klldap.conf and refuses uid/gid 0 or set*id bits.

The in-container root model is the supported path. Running the binary on the host is not recommended.

# Container Internals

Thin shell (entrypoint, healthcheck, watcher, ganesha-ctl) + Rust binaries (nfs-klldap-config + nfs-klldap-startup + nfs-klldap-ui) run as root inside container. Privileged work (0600 derived files, direct chown/chmod on bind-mounted host_paths) happens here only. See entrypoint.sh and source for flow.
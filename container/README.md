# Container Internals

Thin shell (entrypoint, healthcheck, watcher, ganesha-ctl) + two Rust binaries (`nfs-klldap-config`, `nfs-klldap-startup`, `nfs-klldap-ui`) running as root. All privileged work (0600 files, direct chown on bind mounts) happens inside the container.
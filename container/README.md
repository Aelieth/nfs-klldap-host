# Container Internals

Thin shell (entrypoint, healthcheck, watcher, ganesha-ctl) + Rust binaries (nfs-klldap-config + nfs-klldap-startup + nfs-klldap-ui) run as root inside container. Privileged work (0600 derived files, direct chown/chmod on bind-mounted host_paths) happens here only. See entrypoint.sh and source for flow.

The container now includes dbus-daemon (launched by entrypoint before Ganesha) and rpcbind for Ganesha/runtime compatibility. Management of Ganesha (export fragments + reload) is still performed via the supervisor HUP path rather than DBUS RPCs to ganesha.
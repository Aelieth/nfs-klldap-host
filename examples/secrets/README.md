# Keytab

Mount at `/etc/krb5.keytab:ro` (0600, root:root on host).

Must contain `nfs/<container-hostname>@REALM` (exact match for the name the container sees via hostname or --hostname).

Recommended: `--uts=host` (or compose `uts: host`) → TUI shows the precise `nfs/<realhost>-nfs@REALM` you need.

See root README + docs/run/README.md for kadmin examples and uts:host behavior.

Never commit real keytabs.

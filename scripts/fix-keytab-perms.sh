#!/usr/bin/env bash
# DEPRECATED for the default root-in-container model.
#
# nfs-klldap-host runs Ganesha, SSSD, and the WebUI as root inside the container.
# Mount your keytab read-only with mode 0600 on the host:
#
#   chmod 600 /path/to/krb5.keytab
#   docker run ... -v /path/to/krb5.keytab:/etc/krb5.keytab:ro ...
#
# This script remains only for legacy experiments with non-root container UIDs.
set -euo pipefail

echo "fix-keytab-perms.sh is deprecated for the standard nfs-klldap-host deployment." >&2
echo "Use a 0600 root-owned keytab and -v ...:/etc/krb5.keytab:ro instead." >&2
exit 1
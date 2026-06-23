#!/bin/bash
# Shared advisory checks for healthcheck.sh and verify-ganesha.sh (source, do not execute).
# Bridge + idhelper + export-fragment warnings only; hard failures stay in healthcheck.

warn_bridge_network() {
    command -v ip >/dev/null 2>&1 || return 0
    local _BRIDGE_IP
    _BRIDGE_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '/inet / {split($4,a,"/"); print a[1]; exit}')
    if [ -n "${_BRIDGE_IP:-}" ] && [[ "$_BRIDGE_IP" == 172.17.* ]]; then
        echo "WARN: container primary IPv4 is $_BRIDGE_IP (Docker bridge 172.17.0.0/16)"
        echo "WARN: use --network=host (docker run) or network_mode: host (compose) for production NFS"
    fi
}

warn_idhelper_overrides() {
    if command -v /usr/local/bin/nfs-klldap-idhelper >/dev/null 2>&1; then
        echo "OK: nfs-klldap-idhelper present"
    else
        echo "WARN: nfs-klldap-idhelper missing — Kerberos ID translation may be degraded"
    fi
    if [ -f /var/lib/nfs-klldap/nss_passwd ] || [ -f /var/lib/extrausers/passwd ]; then
        echo "OK: idhelper override files present (nss_passwd or extrausers)"
    else
        echo "WARN: no idhelper override files yet (bulk-seed may still be running)"
    fi
}

warn_export_fragments() {
    local ctl="${1:-/usr/local/bin/ganesha-ctl}"
    command -v "$ctl" >/dev/null 2>&1 || return 0
    if ! "$ctl" show-fragments >/dev/null 2>&1; then
        echo "WARN: no export fragments listed yet (may be normal during startup)"
    fi
}
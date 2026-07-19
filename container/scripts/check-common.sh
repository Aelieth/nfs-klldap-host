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

warn_navahi_discovery() {
    local config="${NFS_CONFIG:-/config/nfs-klldap.conf}"
    local svc_dir="${AVAHI_SERVICES_DIR:-/etc/avahi/services}"
    [ -f "$config" ] || return 0
    grep -Eq '^[[:space:]]*navahi_discovery[[:space:]]*=[[:space:]]*true' "$config" || return 0
    if ! pgrep -x avahi-daemon >/dev/null 2>&1; then
        echo "WARN: navahi_discovery = true but avahi-daemon is not running (staged toggle? apply via 'Restart and apply')"
    fi
    if grep -Eq '^[[:space:]]*navahi_insecure[[:space:]]*=[[:space:]]*true' "$config"; then
        local n
        n=$(find "$svc_dir" -maxdepth 1 -name 'nfs-klldap-*.service' 2>/dev/null | wc -l)
        if [ "$n" -eq 0 ]; then
            echo "WARN: navahi shares flagged but no advert XMLs in $svc_dir (regenerate pending?)"
        fi
    fi
}

warn_fs_limited_shares() {
    local config="${NFS_CONFIG:-/config/nfs-klldap.conf}"
    local bin="${1:-}"
    if [ -z "$bin" ]; then
        if [ -n "${CONFIG_BIN:-}" ] && [ -x "$CONFIG_BIN" ]; then
            bin="$CONFIG_BIN"
        elif command -v nfs-klldap-config >/dev/null 2>&1; then
            bin="$(command -v nfs-klldap-config)"
        elif [ -x /usr/local/bin/nfs-klldap-config ]; then
            bin="/usr/local/bin/nfs-klldap-config"
        else
            return 0
        fi
    fi
    command -v "$bin" >/dev/null 2>&1 || [ -x "$bin" ] || return 0
    [ -f "$config" ] || return 0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        echo "WARN: fs: $line"
    done < <("$bin" fs-warnings --config "$config" 2>/dev/null || true)
}
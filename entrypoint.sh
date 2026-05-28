#!/bin/bash
#
# entrypoint.sh - Modern Ganesha + KLLDAP entrypoint (v0.23+)
#
# This container is a self-contained Kerberized NFSv4 server using NFS-Ganesha.
# It is designed for hosts that cannot or will not run the kernel NFS stack.
#
# New architecture:
#   - Single source of truth: nfs-klldap.conf (TOML)
#   - Auto-derives most values from ldap_uri
#   - Generates sssd.conf, krb5.conf, and Ganesha EXPORT fragments internally
#   - First-run safe template generation (never overwrites user config)
#   - Watches config file for changes and reloads automatically
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Paths & Defaults
# -----------------------------------------------------------------------------
NFS_CONFIG="${NFS_CONFIG:-/config/nfs-klldap.conf}"
CONFIG_DIR="$(dirname "$NFS_CONFIG")"
SSSD_CONF="/etc/sssd/sssd.conf"
KRB5_CONF="/etc/krb5.conf"
GANESHA_CONF="/etc/ganesha/ganesha.conf"
EXPORTS_DIR="/etc/ganesha/exports.d"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    log "FATAL: $*"
    exit 1
}

# -----------------------------------------------------------------------------
# Proactive diagnostics for non-root / hardened operation.
# These run before we start the daemons so the user gets actionable messages
# instead of opaque failures deep in ganesha or sssd logs.
# -----------------------------------------------------------------------------
check_runtime_permissions() {
    log "Checking runtime permissions for non-root operation..."

    # 1. Keytab readability (most common source of "it worked as root but not now")
    if [ -f /etc/krb5.keytab ]; then
        if [ -r /etc/krb5.keytab ]; then
            log "    Keytab /etc/krb5.keytab is readable by current user — good."
        else
            log "    WARNING: /etc/krb5.keytab exists but is not readable by $(id -un 2>/dev/null || echo 'current user')."
            log "    This is the #1 cause of Kerberos/GSS failures when running as non-root."
            log "    On the Docker *host*, run one of the following (pick the matching path):"
            log "      sudo chgrp keytab /path/on/host/to/krb5.keytab && sudo chmod g+r /path/on/host/to/krb5.keytab"
            log "      # or use a numeric GID that matches the 'keytab' group inside the container:"
            log "      # (find it with: docker exec <name> getent group keytab)"
            log "    You can also add the container to the host group with group_add in compose."
            # Do not die — some people use other auth methods or will fix it and SIGHUP.
        fi
    else
        log "    NOTE: No /etc/krb5.keytab found at container start (mount it read-only)."
    fi

    # 2. Critical writable locations (defensive — we chown these in the image)
    for d in /var/log/ganesha /var/lib/sss /etc/ganesha /etc/ganesha/exports.d /etc/sssd /var/run/ganesha /var/run/sssd; do
        if [ -d "$d" ]; then
            if ! touch "$d/.nfs-perms-check.$$" 2>/dev/null; then
                log "    WARNING: Cannot write to $d as current user. Daemon startup may fail."
                log "    This should not happen in the stock image. Check your volume mounts."
            else
                rm -f "$d/.nfs-perms-check.$$" 2>/dev/null || true
            fi
        fi
    done

    log "    Permission pre-flight checks complete."
}

# First-run template generation is now handled by: nfs-klldap-config init
# (kept the old function name only as a comment for git history; fully removed)

# -----------------------------------------------------------------------------
# Delegate ALL complex TOML logic to the bundled Rust binary (type-safe).
# The nfs-klldap-config binary lives at /usr/local/bin (built in Dockerfile).
# -----------------------------------------------------------------------------
CONFIG_BIN="/usr/local/bin/nfs-klldap-config"

ensure_config_binary() {
    if [ ! -x "$CONFIG_BIN" ]; then
        die "Missing $CONFIG_BIN — the container image was not built correctly (multi-stage step missing?)"
    fi
}

# -----------------------------------------------------------------------------
# All generation now happens inside the Rust binary (single source of truth).
# It writes sssd.conf, krb5.conf, ganesha.conf + per-share fragments.
# -----------------------------------------------------------------------------
generate_configs() {
    ensure_config_binary
    log "Invoking $CONFIG_BIN generate for $NFS_CONFIG ..."
    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || die "Rust config generator failed — check $NFS_CONFIG for syntax or required fields (ldap_uri + bind credentials)"
}

# -----------------------------------------------------------------------------
# Signal handling
# -----------------------------------------------------------------------------
WATCHER_PID=""

cleanup() {
    log "Shutting down services..."
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    pkill -TERM sssd 2>/dev/null || true
    if [ -n "$WATCHER_PID" ]; then
        kill -TERM "$WATCHER_PID" 2>/dev/null || true
    else
        pkill -TERM nfs-klldap-conf-watcher 2>/dev/null || true
    fi
    sleep 1
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT

handle_sighup() {
    log "SIGHUP received — reloading configuration via Rust generator..."
    generate_configs
    /usr/local/bin/ganesha-ctl reload 2>/dev/null || pkill -HUP ganesha.nfsd 2>/dev/null || true
}
trap 'handle_sighup' SIGHUP

# -----------------------------------------------------------------------------
# Main (now tiny — real work is in the Rust binary + ganesha/sssd)
# -----------------------------------------------------------------------------
main() {
    log "=== Starting nfs-klldap-host (v0.23+ central TOML) ==="
    ensure_config_binary

    if [ ! -f "$NFS_CONFIG" ]; then
        "$CONFIG_BIN" init --config "$NFS_CONFIG" || die "Failed to create default config"
        log "Default config written. Edit $NFS_CONFIG and restart the container."
        exit 0
    fi

    generate_configs

    # Proactive checks so non-root operation fails with clear guidance instead of later
    check_runtime_permissions

    # Start SSSD
    log "[1/3] Starting SSSD..."
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
    SSSD_PID=$!

    # Wait for NSS pipe
    log "    Waiting for SSSD NSS responder..."
    for i in {1..60}; do
        if [ -S /var/lib/sss/pipes/nss ]; then
            log "    SSSD ready."
            break
        fi
        sleep 0.3
    done

    if [ ! -S /var/lib/sss/pipes/nss ]; then
        die "SSSD NSS pipe did not appear. Check bind credentials and LLDAP connectivity."
    fi

    # Start config watcher for automatic reload when the host UI edits nfs-klldap.conf
    if [ -x /usr/local/bin/nfs-klldap-conf-watcher ]; then
        /usr/local/bin/nfs-klldap-conf-watcher "$NFS_CONFIG" &
        WATCHER_PID=$!
        log "    Config watcher started (auto-reload on nfs-klldap.conf changes)."
    fi

    # Start Ganesha (exec replaces the shell)
    log "[2/3] Starting NFS-Ganesha..."
    exec ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log
}

main

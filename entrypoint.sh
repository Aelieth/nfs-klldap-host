#!/bin/bash
#
# entrypoint.sh - Ganesha-only entrypoint for alma_nfs-kerb
#
# This container IS the complete Kerberized NFSv4 server using NFS-Ganesha
# (user-space). It is designed for hosts that cannot or will not run the
# kernel NFS stack (no nfs/nfsd/rpcsec_gss_krb5 modules required on the host).
#
# Responsibilities:
#   1. Render configuration templates (sssd, krb5, ganesha.conf) via envsubst
#   2. Start SSSD and wait for its NSS responder (critical for LLDAP POSIX IDs)
#   3. Ensure Ganesha export fragments directory exists
#   4. Start ganesha.nfsd (the actual NFSv4 + Kerberos server)
#   5. Handle signals (SIGHUP for simple reload path, SIGTERM for clean shutdown)
#
# Direct management (preferred):
#   The host-side management tool speaks directly to Ganesha via:
#     docker exec <container> ganesha-ctl add-export ...
#     docker exec <container> ganesha-ctl remove-export ...
#
#   The container's ganesha-export-watcher (inotify) detects changes to
#   the exports directory and triggers a restart of ganesha.nfsd. No DBUS.
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration via environment
# -----------------------------------------------------------------------------
GSSD_VERBOSITY="${GSSD_VERBOSITY:-0}"
SSSD_DEBUG_LEVEL="${SSSD_DEBUG_LEVEL:-0}"

# TEMPLATES_DIR: where the container looks for *.template files.
# Default: /container/templates
# Override with: -e TEMPLATES_DIR=/path/on/host/or/in/container
TEMPLATES_DIR="${TEMPLATES_DIR:-/container/templates}"

# Container name hint (used by management tool for docker exec)
# Not used inside the container itself.
CONTAINER_NAME="${CONTAINER_NAME:-alma-nfs-kerb}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    log "FATAL: $*"
    exit 1
}

# -----------------------------------------------------------------------------
# Template application (same clean philosophy as before)
#
# Looks for templates in $TEMPLATES_DIR.
# Renders them with envsubst to the official locations *unless* a final
# config has already been bind-mounted directly (e.g. /etc/ganesha/ganesha.conf).
#
# Bind-mount your templates directory from the host for easy customization:
#   -v $(pwd)/my-templates:/container/templates:ro
# -----------------------------------------------------------------------------
apply_config_templates() {
    log "Applying configuration templates from ${TEMPLATES_DIR} ..."

    # sssd.conf (required for LLDAP POSIX)
    local sssd_tmpl="${TEMPLATES_DIR}/sssd.conf.template"
    if [ -f "$sssd_tmpl" ]; then
        if [ -s /etc/sssd/sssd.conf ]; then
            log "  Using bind-mounted /etc/sssd/sssd.conf (skipping template)"
        else
            log "  Rendering sssd.conf.template → /etc/sssd/sssd.conf"
            mkdir -p /etc/sssd
            envsubst < "$sssd_tmpl" > /etc/sssd/sssd.conf
            chmod 600 /etc/sssd/sssd.conf
        fi
    fi

    # krb5.conf (required for Kerberos client + Ganesha NFS_KRB5)
    local krb5_tmpl="${TEMPLATES_DIR}/krb5.conf.template"
    if [ -f "$krb5_tmpl" ]; then
        if [ -s /etc/krb5.conf ]; then
            log "  Using bind-mounted /etc/krb5.conf (skipping template)"
        else
            log "  Rendering krb5.conf.template → /etc/krb5.conf"
            envsubst < "$krb5_tmpl" > /etc/krb5.conf
            chmod 644 /etc/krb5.conf
        fi
    fi

    # ganesha.conf (the heart of the server)
    local ganesha_tmpl="${TEMPLATES_DIR}/ganesha.conf.template"
    if [ -f "$ganesha_tmpl" ]; then
        if [ -s /etc/ganesha/ganesha.conf ]; then
            log "  Using bind-mounted /etc/ganesha/ganesha.conf (skipping template)"
        else
            log "  Rendering ganesha.conf.template → /etc/ganesha/ganesha.conf"
            mkdir -p /etc/ganesha
            envsubst < "$ganesha_tmpl" > /etc/ganesha/ganesha.conf
            chmod 644 /etc/ganesha/ganesha.conf
        fi
    fi

    chmod 700 /etc/sssd 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Signal handling
# -----------------------------------------------------------------------------
cleanup() {
    log "Shutting down services..."
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    pkill -TERM sssd         2>/dev/null || true
    sleep 1
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT

# Simple SIGHUP handler: ask Ganesha to reload (via our wrapper or direct signal)
handle_sighup() {
    log "Received SIGHUP — requesting Ganesha config/export reload..."
    /usr/local/bin/ganesha-ctl reload 2>/dev/null || true
    # Some Ganesha builds also react to SIGHUP directly for adding new exports
    pkill -HUP ganesha.nfsd 2>/dev/null || true
}
trap 'handle_sighup' SIGHUP

log "=== Starting NFS-Ganesha Kerberized NFSv4 Server (AlmaLinux 10 + LLDAP/SSSD) ==="

# -----------------------------------------------------------------------------
# Apply templates
# -----------------------------------------------------------------------------
apply_config_templates

# -----------------------------------------------------------------------------
# 1. Start SSSD (our bridge to LLDAP POSIX attributes)
# -----------------------------------------------------------------------------
log "[1/3] Starting SSSD (identity provider for LLDAP POSIX uids/gids)..."
sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
SSSD_PID=$!

# Wait for the NSS responder socket/pipe — this is critical.
# Ganesha (and any nss-using components) rely on this for uid/gid resolution.
log "    Waiting for SSSD NSS pipe (/var/lib/sss/pipes/nss)..."
for i in {1..60}; do
    if [ -S /var/lib/sss/pipes/nss ]; then
        log "    SSSD NSS responder ready."
        break
    fi
    sleep 0.3
    if [ $((i % 10)) -eq 0 ]; then
        log "    ... still waiting for SSSD (attempt $i/60)"
    fi
done

if [ ! -S /var/lib/sss/pipes/nss ]; then
    die "SSSD NSS pipe did not appear in time. Check sssd.conf and LLDAP connectivity."
fi

# Quick sanity check
if command -v getent >/dev/null 2>&1; then
    log "    getent passwd root (sanity) -> $(getent passwd root | cut -d: -f1,3 || echo 'failed')"
fi

# -----------------------------------------------------------------------------
# 2. Prepare Ganesha exports directory
# -----------------------------------------------------------------------------
log "[2/3] Preparing Ganesha exports directory..."
mkdir -p /etc/ganesha/exports.d
# The management tool (and/or admins) will drop *.conf fragments here.
# Each fragment should contain one or more EXPORT {} blocks.
# Example filename: 10-myshare.conf

# -----------------------------------------------------------------------------
# 3. Start NFS-Ganesha (the actual user-space NFSv4 + Kerberos server)
# -----------------------------------------------------------------------------
log "[3/3] Starting NFS-Ganesha..."

# The config file (rendered above) should contain:
#   - NFS_CORE_PARAM, NFSv4, NFS_KRB5 sections
#   - EXPORT_DEFAULTS with SecType = krb5p
#   - %include "/etc/ganesha/exports.d/*.conf" (or equivalent)
#
# Ganesha is started under a supervisor loop. The internal watcher restarts
# it when export fragments change. No DBUS is involved.

exec ganesha.nfsd -f /etc/ganesha/ganesha.conf -L /var/log/ganesha.log

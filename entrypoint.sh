#!/bin/bash
#
# entrypoint.sh - Hardened entrypoint for AlmaLinux 10 Kerberized NFSv4 + SSSD
#
# Correct daemon startup order is critical:
#   1. rpcbind
#   2. SSSD (nss responder) + wait for readiness socket
#   3. rpc.idmapd (uses SSSD or nsswitch for name<->id mapping)
#   4. rpc.gssd (Kerberos GSS context handling for NFS)
#   5. exportfs -ra
#   6. rpc.nfsd
#
# This ordering ensures that idmapping works for user@REALM principals
# before any NFS traffic or Kerberos ticket validation occurs.
#
set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration via environment
# -----------------------------------------------------------------------------
GSSD_VERBOSITY="${GSSD_VERBOSITY:-0}"
USE_LEGACY_NSLCD="${USE_LEGACY_NSLCD:-false}"
SSSD_DEBUG_LEVEL="${SSSD_DEBUG_LEVEL:-0}"

# TEMPLATES_DIR: where the container looks for *.template files.
# Default: /container/templates (cleanly separated from final configs).
# Override with: -e TEMPLATES_DIR=/path/on/host/or/in/container
TEMPLATES_DIR="${TEMPLATES_DIR:-/container/templates}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

die() {
    log "FATAL: $*"
    exit 1
}

# -----------------------------------------------------------------------------
# Template application (core of configuration flexibility)
#
# Looks for templates in $TEMPLATES_DIR (default /container/templates).
# Renders them with envsubst to the official locations *unless* a final
# config has already been bind-mounted directly (e.g. /etc/sssd/sssd.conf).
#
# This gives clear separation:
#   - Templates live in one directory (bind-mount your templates here)
#   - Final/override configs are either direct /etc/ mounts or in a separate dir
#
# Any environment variables you set on the container are available inside
# the templates (e.g. ${DOMAIN}, ${REALM}, ${LDAP_HOST}, etc.).
# -----------------------------------------------------------------------------
apply_config_templates() {
    log "Applying configuration templates from ${TEMPLATES_DIR} ..."

    # sssd
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

    # krb5.conf
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

    # idmapd.conf
    local idmap_tmpl="${TEMPLATES_DIR}/idmapd.conf.template"
    if [ -f "$idmap_tmpl" ]; then
        if [ -s /etc/idmapd.conf ]; then
            log "  Using bind-mounted /etc/idmapd.conf (skipping template)"
        else
            log "  Rendering idmapd.conf.template → /etc/idmapd.conf"
            envsubst < "$idmap_tmpl" > /etc/idmapd.conf
            chmod 644 /etc/idmapd.conf
        fi
    fi

    chmod 700 /etc/sssd 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Signal handling for graceful shutdown
# -----------------------------------------------------------------------------
cleanup() {
    log "Shutting down services..."
    pkill -TERM rpc.nfsd     2>/dev/null || true
    pkill -TERM rpc.gssd     2>/dev/null || true
    pkill -TERM rpc.idmapd   2>/dev/null || true
    pkill -TERM sssd         2>/dev/null || true
    sleep 1
    exportfs -ua 2>/dev/null || true
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT SIGHUP

# Special handler for SIGHUP: re-export without full restart (useful for management tool)
handle_sighup() {
    log "Received SIGHUP — re-exporting shares (exportfs -ra)..."
    exportfs -ra 2>&1 | while read -r line; do log "  exportfs: $line"; done
}
trap 'handle_sighup' SIGHUP

log "=== Starting Kerberized NFSv4 Server (AlmaLinux 10 + SSSD) ==="

# -----------------------------------------------------------------------------
# Apply templates (see apply_config_templates above for details)
# -----------------------------------------------------------------------------
apply_config_templates

# -----------------------------------------------------------------------------
# 1. rpcbind
# -----------------------------------------------------------------------------
log "[1/6] Starting rpcbind..."
rpcbind -w || die "Failed to start rpcbind"

# -----------------------------------------------------------------------------
# 2. Identity provider (SSSD primary, legacy nslcd supported with warning)
# -----------------------------------------------------------------------------
if [ "${USE_LEGACY_NSLCD}" = "true" ]; then
    log "WARNING: USE_LEGACY_NSLCD=true is set."
    log "         nss-pam-ldapd (nslcd) is NOT available in AlmaLinux 10 base repos."
    log "         This will almost certainly fail unless you built nslcd yourself."
    log "         The supported path is SSSD + sssd-nfs-idmap."
    log "[2/6] Starting legacy nslcd (not recommended on AL10)..."
    nslcd || die "Failed to start nslcd"
    # Wait for nslcd socket if it creates one (less standardized)
    for i in {1..30}; do
        if pgrep -x nslcd >/dev/null; then break; fi
        sleep 0.2
    done
else
    log "[2/6] Starting SSSD (primary identity provider)..."
    # sssd -i : run in foreground (we background it)
    # --logger=files : useful inside containers
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
    SSSD_PID=$!

    # Wait for the NSS responder socket/pipe to appear.
    # This is the critical readiness signal that rpc.idmapd relies on.
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
fi

# -----------------------------------------------------------------------------
# 3. rpc.idmapd (NFSv4 name-to-ID mapping)
#    Must start AFTER the identity provider (SSSD/nslcd) is ready.
# -----------------------------------------------------------------------------
log "[3/6] Starting rpc.idmapd..."
rpc.idmapd -f &
IDMAPD_PID=$!
sleep 0.5

# Optional: quick sanity check that idmapd can talk to the backend
if command -v getent >/dev/null 2>&1; then
    log "    getent passwd root (sanity check) -> $(getent passwd root | cut -d: -f1,3 || echo 'failed')"
fi

# -----------------------------------------------------------------------------
# 4. rpc.gssd (Kerberos ticket handling for NFS)
# -----------------------------------------------------------------------------
log "[4/6] Starting rpc.gssd (Kerberos)..."
if [ "$GSSD_VERBOSITY" -gt 0 ]; then
    # rpc.gssd verbosity is controlled via /etc/nfs.conf or command line in some versions
    rpc.gssd -f -v "$GSSD_VERBOSITY" &
else
    rpc.gssd -f &
fi
GSSD_PID=$!
sleep 0.5

# -----------------------------------------------------------------------------
# 5. Apply exports
# -----------------------------------------------------------------------------
log "[5/6] Applying NFS exports (exportfs -ra)..."
exportfs -ra || log "WARNING: exportfs -ra returned non-zero (check /etc/exports or /etc/exports.d/)"

log "    Current exports:"
exportfs -s || true

# -----------------------------------------------------------------------------
# 6. Start NFS server (NFSv4 only - no v2/v3 for security)
# -----------------------------------------------------------------------------
log "[6/6] Starting rpc.nfsd (NFSv4 only)..."
# -N 4 -V 4 : disable versions < 4, enable only v4
# You can tune threads with -t (default is usually fine)
rpc.nfsd -N 2 -N 3 -V 4 -t 8 || die "Failed to start rpc.nfsd"

log "=== NFS server is ready ==="
log "    Keytab:   /etc/krb5.keytab"
log "    Exports:  /etc/exports + /etc/exports.d/*.exports  (SIGHUP re-exports)"
log "    Identity: $([ "${USE_LEGACY_NSLCD}" = "true" ] && echo 'LEGACY nslcd (unsupported on AL10)' || echo 'SSSD (recommended)')"
log "    Hostname (must == NFS principal instance): $(hostname)"
log ""
log "    Re-export shares:   kill -HUP 1    (or docker kill -s HUP ...)"
log "    Debug idmapping:    rpc.idmapd -f -vvv"
log "    Check exports:      exportfs -s"
log "    Inspect keytab:     klist -k /etc/krb5.keytab"

# -----------------------------------------------------------------------------
# Keep the container alive and wait for signals
# -----------------------------------------------------------------------------
wait

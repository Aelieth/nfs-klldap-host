#!/bin/bash
#
# entrypoint.sh - Modern Ganesha + KLLDAP entrypoint (v0.5+)
#
# This container is a self-contained Kerberized NFSv4 server using NFS-Ganesha.
# It is designed for hosts that cannot or will not run the kernel NFS stack.
#
# v0.5 changes:
#   - Single source of truth: nfs-klldap.conf (TOML)
#   - First-run guided setup with smart waiting loop (no more "edit and restart" dance)
#   - Everything starts with ldap_uri (must be a DNS name — IP addresses rejected)
#   - Auto-tests LDAP connectivity, ping fallback, and DNS resolution
#   - Once config is valid → services start automatically

set -euo pipefail

# -----------------------------------------------------------------------------
# Paths & Defaults
# -----------------------------------------------------------------------------
NFS_CONFIG="${NFS_CONFIG:-/config/nfs-klldap.conf}"
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
# All guided setup (4-step TUI), reachability tests, persistent volume detection,
# realm derivation display, hostname suggestions, and permission/keytab diagnostics
# have been moved into the Rust binary `nfs-klldap-startup`.
#
# The shell is now a minimal launcher + daemon supervisor (all services run as root).
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# NOTE: The 4-step guided setup TUI, reachability tests, banner, waiting loop,
# and runtime diagnostics (including hostname/keytab guidance based on --uts=host)
# now live in the Rust binary `nfs-klldap-startup`.
#
# Only thin orchestration + daemon startup remains in this shell script.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Delegate ALL complex TOML logic to the bundled Rust binary
# -----------------------------------------------------------------------------
CONFIG_BIN="/usr/local/bin/nfs-klldap-config"

ensure_config_binary() {
    if [ ! -x "$CONFIG_BIN" ]; then
        die "Missing $CONFIG_BIN — the container image was not built correctly (multi-stage step missing?)"
    fi
}

generate_configs() {
    ensure_config_binary
    log "Invoking $CONFIG_BIN generate for $NFS_CONFIG ..."
    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || die "Rust config generator failed — check $NFS_CONFIG for syntax or required fields (ldap_uri + bind credentials)"
}

# -----------------------------------------------------------------------------
# Signal handling (unchanged)
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
    if [ -n "$WEBUI_PID" ]; then
        kill -TERM "$WEBUI_PID" 2>/dev/null || true
    fi
    sleep 1
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT

handle_sighup() {
    log "SIGHUP received — reloading configuration via Rust generator (as root)..."
    generate_configs

    # Fix perms again after regeneration (sssd.conf must stay root:root 0600).
    chown root:root /etc/sssd/sssd.conf 2>/dev/null || true
    chmod 600 /etc/sssd/sssd.conf 2>/dev/null || true
    chown root:root /etc/krb5.conf 2>/dev/null || true
    chmod 644 /etc/krb5.conf 2>/dev/null || true
    # Ganesha config and exports are owned by root (everything runs as root in v0.5+)
    chown -R root:root /etc/ganesha 2>/dev/null || true
    chmod -R a+rX /etc/ganesha 2>/dev/null || true

    # Ganesha can usually be reloaded via its own mechanism or a TERM that
    # the supervisor will turn into a restart.
    /usr/local/bin/ganesha-ctl reload 2>/dev/null || pkill -HUP ganesha.nfsd 2>/dev/null || true

    # SSSD config changes (bind DN, TLS settings, uri, etc.) generally require
    # a full restart of the daemon. We do a controlled stop + start here.
    # This is safe because we are still the root supervisor.
    pkill -TERM sssd 2>/dev/null || true
    sleep 1
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} 2>/dev/null &
    log "    SSSD restarted to pick up any config changes."
}
trap 'handle_sighup' SIGHUP

# -----------------------------------------------------------------------------
# Main — now with guided first-run experience
# -----------------------------------------------------------------------------
main() {
    log "=== Starting nfs-klldap-host (v0.5 guided setup) ==="

    # Hostname guidance is now based on --uts=host (the new standard).
    # With --uts=host the container sees the real host hostname; the Rust
    # `nfs-klldap-startup` TUI shows the recommended keytab principal.
    # entrypoint.sh remains a thin launcher.

    ensure_config_binary

    # ------------------------------------------------------------------
    # NEW: The heavy guided first-run TUI and reachability logic now lives
    # in the Rust binary `nfs-klldap-startup`. It runs as root (we are
    # still root here) and presents a clean 4-step status until everything
    # is ready.
    # ------------------------------------------------------------------
    if [ ! -f "$NFS_CONFIG" ]; then
        "$CONFIG_BIN" init --config "$NFS_CONFIG" || die "Failed to create default config"
    fi

    # This blocks (with nice TUI output) until the 4 steps are satisfied.
    /usr/local/bin/nfs-klldap-startup run || die "Startup checks failed"

    generate_configs

    # Note: Runtime permission/keytab/hostname diagnostics are now handled
    # inside the Rust startup binary (see `nfs-klldap-startup check` or the
    # end of the `run` guided flow). The old shell functions have been retired.

    # -----------------------------------------------------------------------------
    # Permission model (standard root for all services)
    # -----------------------------------------------------------------------------
    # - /etc/sssd/sssd.conf MUST be root:root 0600.
    # - All services (sssd, ganesha.nfsd, watcher, WebUI) run as root.
    # - The root entrypoint shell stays as pid 1 for SIGHUP handling + orchestration.
    # -----------------------------------------------------------------------------

    # Force correct ownership for the main SSSD config (non-negotiable).
    chown root:root /etc/sssd/sssd.conf 2>/dev/null || true
    chmod 600 /etc/sssd/sssd.conf 2>/dev/null || true

    # krb5.conf is public config; root-owned 0644 is fine and expected.
    chown root:root /etc/krb5.conf 2>/dev/null || true
    chmod 644 /etc/krb5.conf 2>/dev/null || true

    # Ganesha config/exports are generated world-readable.
    chmod -R a+rX /etc/ganesha 2>/dev/null || true

    # Start SSSD as root (standard for the service on Red Hat systems).
    log "[1/3] Starting SSSD..."
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
    SSSD_PID=$!

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

    # No pipe permission hacks needed — everything runs as root.

    # Start config watcher (as root). It signals pid 1 on changes.
    if [ -x /usr/local/bin/nfs-klldap-conf-watcher ]; then
        /usr/local/bin/nfs-klldap-conf-watcher "$NFS_CONFIG" &
        WATCHER_PID=$!
        log "    Config watcher started (auto-reload on changes)."
    fi

    # Start Ganesha as root.
    log "[2/3] Starting NFS-Ganesha..."
    ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log &
    GANESHA_PID=$!

    # -------------------------------------------------------------------------
    # In-container WebUI (always runs on port 9630) - started last because it
    # depends on SSSD (for LLDAP identity) and Ganesha being operational.
    # -------------------------------------------------------------------------
    log "Preparing WebUI TLS certificates..."
    # Run the cert helper. It prints diagnostic messages to stderr (which will appear in container logs)
    # and ONLY the two VAR=value lines to stdout on success.
    WEBUI_CERT_OUTPUT=$(/usr/local/bin/webui-certs) || true

    if [ -n "$WEBUI_CERT_OUTPUT" ]; then
        eval "$WEBUI_CERT_OUTPUT"
    fi

    if [[ -x /usr/local/bin/nfs-klldap-ui && -n "${WEBUI_TLS_CERT:-}" && -n "${WEBUI_TLS_KEY:-}" && -f "$WEBUI_TLS_CERT" && -f "$WEBUI_TLS_KEY" ]]; then
        log "[3/3] WebUI Starting on 0.0.0.0:9630 (HTTPS)..."
        NFS_KLLDAP_CONF="$NFS_CONFIG" \
        WEBUI_TLS_CERT="$WEBUI_TLS_CERT" \
        WEBUI_TLS_KEY="$WEBUI_TLS_KEY" \
        /usr/local/bin/nfs-klldap-ui --config "$NFS_CONFIG" \
            >/var/log/webui.log 2>&1 &
        WEBUI_PID=$!
        log "    WebUI started (logs: /var/log/webui.log)"
    else
        log "WARNING: Could not start WebUI (binary or valid certificates missing)"
        # Log the cert script output for debugging
        if [[ -n "$WEBUI_CERT_OUTPUT" ]]; then
            echo "$WEBUI_CERT_OUTPUT" | while read -r line; do log "    $line"; done
        fi
    fi

    log "All services launched (as root). Supervisor remains as root for signal handling."

    # Wait for children. If any die the script exits and the container will
    # be restarted by the policy (unless-stopped etc.).
    wait
}

main

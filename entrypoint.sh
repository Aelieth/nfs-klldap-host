#!/bin/bash
#
# entrypoint.sh - Modern Ganesha + KLLDAP entrypoint (v0.3+)
#
# This container is a self-contained Kerberized NFSv4 server using NFS-Ganesha.
# It is designed for hosts that cannot or will not run the kernel NFS stack.
#
# v0.3+ changes:
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

# Run a command as the unprivileged 'nfs' user (gosu is installed in the image).
# Used for long-running daemons after root-only setup is complete.
run_as_nfs() {
    gosu nfs "$@"
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
# The shell is now a minimal launcher + daemon supervisor using gosu.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# NOTE: The entire 4-step guided setup TUI, reachability tests, banner (with
# auto-derived realm), waiting loop, hostname suggestion logic, and runtime
# permission/keytab/hostname diagnostics now live in the Rust binary
# `nfs-klldap-startup` (built from nfs-klldap-config crate).
#
# The old shell implementations have been removed. Only thin orchestration
# + gosu daemon startup remains here.
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
# Main — now with guided first-run experience
# -----------------------------------------------------------------------------
main() {
    log "=== Starting nfs-klldap-host (v0.3+ guided setup) ==="

    # Hostname auto-normalization (HOST_HOSTNAME env → <short>-nfs.<rest> when Docker
    # gave us a default container ID) plus all guidance now lives in the Rust
    # `nfs-klldap-startup` binary. entrypoint.sh remains a thin launcher.

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

    # Start SSSD (as the unprivileged nfs user)
    log "[1/3] Starting SSSD..."
    run_as_nfs sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
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

    # Start config watcher (as the unprivileged nfs user)
    if [ -x /usr/local/bin/nfs-klldap-conf-watcher ]; then
        run_as_nfs /usr/local/bin/nfs-klldap-conf-watcher "$NFS_CONFIG" &
        WATCHER_PID=$!
        log "    Config watcher started (auto-reload on changes)."
    fi

    # Start Ganesha (drop to unprivileged nfs user; gosu + setcap on the binary
    # gives it the necessary privileges like NET_BIND_SERVICE)
    log "[2/3] Starting NFS-Ganesha..."
    exec gosu nfs ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log
}

main

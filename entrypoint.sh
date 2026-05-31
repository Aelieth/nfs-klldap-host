#!/bin/bash
# pid-1 supervisor. Heavy logic lives in the Rust binaries (nfs-klldap-startup + nfs-klldap-config).
set -euo pipefail

# Paths (override for CI/test)
NFS_CONFIG="${NFS_CONFIG:-/config/nfs-klldap.conf}"
SSSD_CONF="${SSSD_CONF:-/etc/sssd/sssd.conf}"
KRB5_CONF="${KRB5_CONF:-/etc/krb5.conf}"
GANESHA_CONF="${GANESHA_CONF:-/etc/ganesha/ganesha.conf}"
EXPORTS_DIR="${EXPORTS_DIR:-/etc/ganesha/exports.d}"

# Binaries (override only if you know what you are doing)
CONFIG_BIN="${CONFIG_BIN:-/usr/local/bin/nfs-klldap-config}"
STARTUP_BIN="${STARTUP_BIN:-/usr/local/bin/nfs-klldap-startup}"
UI_BIN="${UI_BIN:-/usr/local/bin/nfs-klldap-ui}"
WATCHER_BIN="${WATCHER_BIN:-/usr/local/bin/nfs-klldap-conf-watcher}"
GANESHA_CTL="${GANESHA_CTL:-/usr/local/bin/ganesha-ctl}"
# WebUI TLS certs are now handled internally by nfs-klldap-ui (rcgen self-signed
# or user-provided via WEBUI_TLS_*). The certs live under
# /var/lib/nfs-klldap/webui-certs inside the container.
HEALTHCHECK="${HEALTHCHECK:-/container/healthcheck.sh}"

# Logging
LOG_FORMAT="${LOG_FORMAT:-text}"   # text | json

# Logging (text or json)
_log_ts() {
    date -u '+%Y-%m-%dT%H:%M:%S.%3NZ'
}

log() {
    local level="${1:-INFO}"
    shift || true
    local msg="$*"

    if [[ "$LOG_FORMAT" == "json" ]]; then
        # Minimal JSON without external dependencies (jq may not be present)
        # We escape only the most common problematic characters.
        local escaped
        escaped=$(printf '%s' "$msg" | sed 's/\\/\\\\/g; s/"/\\"/g; s/$/\\n/g' | tr -d '\n')
        printf '{"ts":"%s","level":"%s","msg":"%s"}\n' \
            "$(_log_ts)" "$level" "$escaped"
    else
        printf '[%s] %-5s %s\n' "$(_log_ts)" "$level" "$msg"
    fi
}

info()  { log "INFO"  "$@"; }
warn()  { log "WARN"  "$@"; }
error() { log "ERROR" "$@"; }

die() {
    log "FATAL" "$*"
    exit 1
}

# Permission hygiene (root:root 0600 for sssd.conf is mandatory)
fix_derived_permissions() {
    # sssd.conf is extremely picky about ownership (root:root 0600).
    chown root:root "$SSSD_CONF" 2>/dev/null || true
    chmod 600 "$SSSD_CONF" 2>/dev/null || true

    # krb5.conf can be world-readable.
    chown root:root "$KRB5_CONF" 2>/dev/null || true
    chmod 644 "$KRB5_CONF" 2>/dev/null || true

    # Ganesha fragments must be readable by the daemon.
    chown -R root:root "$EXPORTS_DIR" 2>/dev/null || true
    chmod -R a+rX "$EXPORTS_DIR" 2>/dev/null || true

    # Also fix the main ganesha.conf if it exists.
    if [ -f "$GANESHA_CONF" ]; then
        chown root:root "$GANESHA_CONF" 2>/dev/null || true
        chmod 644 "$GANESHA_CONF" 2>/dev/null || true
    fi
}

# Preflight (fail fast)
preflight_checks() {
    local missing=0

    for bin in "$CONFIG_BIN" "$STARTUP_BIN" "$UI_BIN" "$WATCHER_BIN" "$GANESHA_CTL"; do
        if [ ! -x "$bin" ]; then
            error "Required binary missing or not executable: $bin"
            missing=1
        fi
    done

    if [ ! -x "$HEALTHCHECK" ]; then
        error "Healthcheck script missing or not executable: $HEALTHCHECK"
        missing=1
    fi

    # The watcher depends on inotifywait (provided by inotify-tools in the image)
    if ! command -v inotifywait >/dev/null 2>&1; then
        error "inotifywait not found in PATH (inotify-tools package required)"
        missing=1
    fi

    if [ "$missing" -ne 0 ]; then
        die "Preflight failed — container image is incomplete or corrupted"
    fi

    info "Preflight checks passed"
}

# Signal handling (pid 1)
WATCHER_PID=""
SSSD_PID=""
GANESHA_PID=""
WEBUI_PID=""

cleanup() {
    log "INFO" "Shutting down services (received termination signal)..."

    # Prefer killing tracked PIDs when we have them
    for pidvar in WEBUI_PID GANESHA_PID SSSD_PID WATCHER_PID; do
        local pid="${!pidvar:-}"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Broad fallback (important for restart races)
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    pkill -TERM sssd 2>/dev/null || true
    pkill -TERM nfs-klldap-conf-watcher 2>/dev/null || true

    # Give processes a moment to exit cleanly
    sleep 1

    log "INFO" "Shutdown complete."
    exit 0
}

trap cleanup SIGTERM SIGINT EXIT

handle_sighup() {
    info "SIGHUP received — reloading configuration via Rust generator..."

    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || {
        error "Rust config generator failed during SIGHUP reload"
        return 1
    }

    fix_derived_permissions

    # Ask Ganesha to pick up new exports (via our helper or direct signal)
    if [ -x "$GANESHA_CTL" ]; then
        "$GANESHA_CTL" reload 2>/dev/null || pkill -HUP ganesha.nfsd 2>/dev/null || true
    else
        pkill -HUP ganesha.nfsd 2>/dev/null || true
    fi

    # SSSD almost always needs a full restart when its config changes.
    pkill -TERM sssd 2>/dev/null || true
    sleep 1
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} 2>/dev/null &
    SSSD_PID=$!
    info "SSSD restarted after config change"
}

trap 'handle_sighup' SIGHUP

# Main supervisor loop
main() {
    info "=== Starting nfs-klldap-host (self-contained) ==="

    preflight_checks

    # Ensure we have a config file (the startup binary will guide the user if not)
    if [ ! -f "$NFS_CONFIG" ]; then
        info "No config file found at $NFS_CONFIG — running first-time initialization"
        "$CONFIG_BIN" init --config "$NFS_CONFIG" || die "Failed to initialize default config"
    fi

    # Run the guided first-run experience + reachability checks.
    # This blocks (with nice TUI) until the environment is ready.
    "$STARTUP_BIN" run || die "Startup checks failed"

    # Generate derived configs (sssd.conf, krb5.conf, ganesha exports)
    info "Generating derived configuration from $NFS_CONFIG"
    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || \
        die "Initial config generation failed — check $NFS_CONFIG"

    fix_derived_permissions

    # --- Start core services (order matters) ---

    # 1. SSSD (provides NSS for POSIX identity from LLDAP)
    info "Starting SSSD..."
    # Do not fully silence stderr here — early SSSD errors (config, permissions, etc.)
    # are valuable in the primary container logs for quick diagnosis.
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
    SSSD_PID=$!

    info "Waiting for SSSD NSS responder..."
    for _ in {1..60}; do
        if [ -S /var/lib/sss/pipes/nss ]; then
            info "SSSD ready"
            break
        fi
        sleep 0.3
    done

    if [ ! -S /var/lib/sss/pipes/nss ]; then
        die "SSSD NSS pipe did not appear. Check LLDAP connectivity and bind credentials."
    fi

    # 2. Config watcher (signals this pid 1 on changes) — critical for auto-reload
    info "Starting config watcher..."
    "$WATCHER_BIN" "$NFS_CONFIG" &
    WATCHER_PID=$!

    # 3. Ganesha (the actual NFS server)
    info "Starting NFS-Ganesha..."
    # Allow early Ganesha startup errors (bad config, missing exports dir, etc.)
    # to appear in the main container logs. The long-term log is still in /var/log/ganesha.log.
    ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log &
    GANESHA_PID=$!

    # 4. WebUI (started last — it needs SSSD + Ganesha operational for some features)
    #
    # Plain HTTP by design. Reverse proxy (Caddy, nginx, Traefik, etc.) in front
    # of the container if you need TLS at the network edge.
    info "Starting WebUI on 0.0.0.0:9630 (HTTPS via axum-server)..."
    NFS_KLLDAP_CONF="$NFS_CONFIG" \
    "$UI_BIN" --config "$NFS_CONFIG" \
        > >(tee -a /var/log/webui.log) 2>&1 &
    WEBUI_PID=$!

    sleep 1.5
    if ! kill -0 "$WEBUI_PID" 2>/dev/null; then
        warn "WebUI process exited quickly — last log lines:"
        tail -n 30 /var/log/webui.log 2>/dev/null || true
    fi


    info "All services launched. Supervisor (this process) remains as pid 1 for signal handling."
    info "Container is ready."

    # Wait for any child to exit. When one dies we exit, letting the container
    # runtime apply its restart policy. This is the desired behavior for
    # "unless-stopped", "on-failure", etc.
    wait
}

main "$@"
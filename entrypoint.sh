#!/bin/bash
# PID-1 supervisor: Rust tools generate config; this script starts services, handles signals, and reaps children.
set -euo pipefail

# Paths (override for CI/test)
NFS_CONFIG="${NFS_CONFIG:-/config/nfs-klldap.conf}"
SSSD_CONF="${SSSD_CONF:-/etc/sssd/sssd.conf}"
KRB5_CONF="${KRB5_CONF:-/etc/krb5.conf}"
GANESHA_CONF="${GANESHA_CONF:-/etc/ganesha/ganesha.conf}"
EXPORTS_DIR="${EXPORTS_DIR:-/etc/ganesha/exports.d}"
IDMAP_CONF="${IDMAP_CONF:-/etc/idmapd.conf}"

# Binaries (override only if you know what you are doing)
CONFIG_BIN="${CONFIG_BIN:-/usr/local/bin/nfs-klldap-config}"
STARTUP_BIN="${STARTUP_BIN:-/usr/local/bin/nfs-klldap-startup}"
UI_BIN="${UI_BIN:-/usr/local/bin/nfs-klldap-ui}"
WATCHER_BIN="${WATCHER_BIN:-/usr/local/bin/nfs-klldap-conf-watcher}"
GANESHA_CTL="${GANESHA_CTL:-/usr/local/bin/ganesha-ctl}"
IDHELPER_BIN="${IDHELPER_BIN:-/usr/local/bin/nfs-klldap-idhelper}"
# idhelper writes nss_passwd/group; only ganesha.nfsd runs with LD_PRELOAD=nss_wrapper for Kerberos owner mapping.
NSS_PASSWD="${NSS_PASSWD:-/var/lib/nfs-klldap/nss_passwd}"
NSS_GROUP="${NSS_GROUP:-/var/lib/nfs-klldap/nss_group}"

# Prepend GANESHA_PATH_PREFIX so fallback nfsidmap execs hit our shim (not in-process libnfsidmap path).
GANESHA_PATH_PREFIX="/usr/local/bin"
# Compute a best-effort path for libnss_wrapper.so on Debian multiarch.
NSS_WRAPPER_SO="${NSS_WRAPPER_SO:-}"
if [ -z "${NSS_WRAPPER_SO}" ]; then
    # Try dpkg-architecture first (most reliable on Debian)
    if command -v dpkg-architecture >/dev/null 2>&1; then
        arch=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)
        if [ -n "$arch" ] && [ -f "/usr/lib/$arch/libnss_wrapper.so" ]; then
            NSS_WRAPPER_SO="/usr/lib/$arch/libnss_wrapper.so"
        fi
    fi
fi
if [ -z "${NSS_WRAPPER_SO}" ]; then
    # Common fallbacks for x86_64 and aarch64
    for cand in \
        /usr/lib/x86_64-linux-gnu/libnss_wrapper.so \
        /usr/lib/aarch64-linux-gnu/libnss_wrapper.so \
        /usr/lib/libnss_wrapper.so
    do
        if [ -f "$cand" ]; then
            NSS_WRAPPER_SO="$cand"
            break
        fi
    done
fi
# WebUI TLS certs are now handled internally by nfs-klldap-ui (rcgen self-signed
# or user-provided via NFS_KLLDAP_WEBUI_TLS_*). The certs live under
# /var/lib/nfs-klldap/webui-certs inside the container.
HEALTHCHECK="${HEALTHCHECK:-/container/healthcheck.sh}"

LOG_FORMAT="${LOG_FORMAT:-text}"   # text | json

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

# Mask winbind helper — stack uses sss + idhelper, not winbind.
quiet_winbind() {
    if command -v wbinfo >/dev/null 2>&1; then
        ln -sf /bin/false /usr/bin/wbinfo 2>/dev/null || true
    fi
}

# Start ganesha.nfsd with nfsidmap shim PATH; LD_PRELOAD nss_wrapper unless USE_NSS_WRAPPER=0.
start_ganesha() {
    quiet_winbind
    if [ "${USE_NSS_WRAPPER:-1}" = "1" ] || [ "${USE_NSS_WRAPPER:-1}" = "true" ]; then
        PATH="${GANESHA_PATH_PREFIX}:$PATH" \
        NSS_WRAPPER_PASSWD="$NSS_PASSWD" \
        NSS_WRAPPER_GROUP="$NSS_GROUP" \
        LD_PRELOAD="${NSS_WRAPPER_SO}" \
            ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log &
    else
        PATH="${GANESHA_PATH_PREFIX}:$PATH" \
            ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log &
    fi
    GANESHA_PID=$!
}

# Fix ownership/modes on derived configs (sssd.conf must be root:root 0600).
fix_derived_permissions() {
    # sssd.conf is extremely picky about ownership (root:root 0600).
    chown root:root "$SSSD_CONF" 2>/dev/null || true
    chmod 600 "$SSSD_CONF" 2>/dev/null || true

    # krb5.conf can be world-readable.
    chown root:root "$KRB5_CONF" 2>/dev/null || true
    chmod 644 "$KRB5_CONF" 2>/dev/null || true

    # idmapd.conf (standardized Domain + Local-Realms + Method + GSS-Methods from
    # nfs-klldap.conf + sssd info) is consumed by nfsidmap/libnfsidmap (shim fallback),
    # Ganesha default IdmapConf, and client rpc.idmapd.
    chown root:root "$IDMAP_CONF" 2>/dev/null || true
    chmod 644 "$IDMAP_CONF" 2>/dev/null || true

    # Ganesha fragments must be readable by the daemon.
    chown -R root:root "$EXPORTS_DIR" 2>/dev/null || true
    chmod -R a+rX "$EXPORTS_DIR" 2>/dev/null || true

    # Also fix the main ganesha.conf if it exists.
    if [ -f "$GANESHA_CONF" ]; then
        chown root:root "$GANESHA_CONF" 2>/dev/null || true
        chmod 644 "$GANESHA_CONF" 2>/dev/null || true
    fi
}

# --- Preflight (fail fast) ---
preflight_checks() {
    local missing=0

    for bin in "$CONFIG_BIN" "$STARTUP_BIN" "$UI_BIN" "$WATCHER_BIN" "$GANESHA_CTL" "$IDHELPER_BIN"; do
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

    # Ganesha Kerberos owner mapping requires nss_wrapper preload unless explicitly disabled.
    if [ "${USE_NSS_WRAPPER:-1}" = "1" ] || [ "${USE_NSS_WRAPPER:-1}" = "true" ]; then
        if [ -z "${NSS_WRAPPER_SO:-}" ] || [ ! -f "$NSS_WRAPPER_SO" ]; then
            error "libnss_wrapper.so not found (set NSS_WRAPPER_SO or install libnss-wrapper)"
            missing=1
        fi
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
DBUS_PID=""
RPCBIND_PID=""
IDHELPER_PID=""

cleanup() {
    local reason="${1:-termination signal}"
    log "INFO" "Shutting down services (received ${reason})..."

    # Prevent re-entrancy on EXIT trap (avoids duplicate shutdown logs).
    trap - EXIT SIGTERM SIGINT

    # Terminate tracked child PIDs (rpcbind is only stopped via pkill fallback).
    for pidvar in WEBUI_PID GANESHA_PID SSSD_PID WATCHER_PID DBUS_PID RPCBIND_PID IDHELPER_PID; do
        local pid="${!pidvar:-}"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done

    # Broad fallback for restart races
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    pkill -TERM sssd 2>/dev/null || true
    pkill -TERM nfs-klldap-conf-watcher 2>/dev/null || true
    pkill -TERM dbus-daemon 2>/dev/null || true
    pkill -TERM rpcbind 2>/dev/null || true
    pkill -TERM nfs-klldap-idhelper 2>/dev/null || true

    # Give processes a moment to exit cleanly
    sleep 1

    log "INFO" "Shutdown complete."
    exit 0
}

trap 'cleanup "termination signal"' SIGTERM SIGINT
trap 'cleanup "exit"' EXIT

BULK_SEED_MARKER="/var/lib/nfs-klldap/.bulk_seed_done"

# Stop ganesha.nfsd before identity recycle (matches stable cold-boot ordering).
stop_ganesha() {
    if [ -n "${GANESHA_PID:-}" ] && kill -0 "$GANESHA_PID" 2>/dev/null; then
        kill -TERM "$GANESHA_PID" 2>/dev/null || true
    fi
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    sleep 0.3
    GANESHA_PID=""
}

# Append host/FQDN host/*@REALM principals to NFS_KLLDAP_IDHELPER_PRERESOLVE.
refresh_idhelper_preresolve() {
    local _H _R _PRE _V _P
    _H=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo "localhost")
    _R=$(awk '/default_realm/ {print $3; exit}' /etc/krb5.conf 2>/dev/null || echo "${NFS_KLLDAP_KERBEROS_REALM:-EXAMPLE.COM}")
    _PRE="${NFS_KLLDAP_IDHELPER_PRERESOLVE:-}"
    for _V in "$_H" "$(echo "$_H" | cut -d. -f1)"; do
        _P="host/${_V}@${_R}"
        case ",${_PRE}," in
            *",${_P},"*) ;;
            *) _PRE="${_PRE:+$_PRE,}$_P" ;;
        esac
    done
    export NFS_KLLDAP_IDHELPER_PRERESOLVE="$_PRE"
}

# SSSD restart + NSS pipe readiness (required before idhelper/Ganesha).
restart_sssd_and_wait() {
    if [ -n "${SSSD_PID:-}" ] && kill -0 "$SSSD_PID" 2>/dev/null; then
        kill -TERM "$SSSD_PID" 2>/dev/null || true
    fi
    pkill -TERM sssd 2>/dev/null || true
    sleep 0.5

    info "Starting SSSD..."
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} &
    SSSD_PID=$!

    info "Waiting for SSSD NSS responder..."
    local ready=0
    for _ in {1..60}; do
        if [ -S /var/lib/sss/pipes/nss ]; then
            info "SSSD ready"
            ready=1
            break
        fi
        sleep 0.3
    done

    if [ "$ready" -ne 1 ]; then
        warn "SSSD NSS pipe did not appear after reload — identity mapping may be degraded"
    fi
}

# idhelper restart + bulk LDAP preload before Ganesha (same gate as cold boot).
restart_idhelper_and_wait_bulk() {
    refresh_idhelper_preresolve

    if [ -n "${IDHELPER_PID:-}" ] && kill -0 "$IDHELPER_PID" 2>/dev/null; then
        kill -TERM "$IDHELPER_PID" 2>/dev/null || true
        sleep 0.2
    fi
    pkill -TERM nfs-klldap-idhelper 2>/dev/null || true
    sleep 0.2

    info "Starting nfs-klldap-idhelper (Kerberos ID translator)..."
    "$IDHELPER_BIN" daemon > >(tee -a /var/log/idhelper.log) 2>&1 &
    IDHELPER_PID=$!
    sleep 0.2
    if ! kill -0 "$IDHELPER_PID" 2>/dev/null; then
        warn "idhelper did not stay running; check /var/log/idhelper.log"
    else
        info "idhelper daemon started (pid $IDHELPER_PID)"
    fi

    info "Waiting for idhelper preload (bulk LDAP users + root + server host principals)..."
    local seeded=0
    for _ in $(seq 1 60); do
        if [ -f "$BULK_SEED_MARKER" ] && \
           grep -q '^root:' /var/lib/nfs-klldap/nss_passwd 2>/dev/null; then
            local _n
            _n=$(cat "$BULK_SEED_MARKER" 2>/dev/null | tr -d '[:space:]' || echo "?")
            info "idhelper preload ready (bulk-seeded ${_n} users + root uid0 in nss_passwd)"
            seeded=1
            break
        fi
        sleep 0.2
    done
    if [ "$seeded" -ne 1 ]; then
        warn "idhelper bulk-seed marker missing after reload; Ganesha may log principal2uid WARN on first user mount"
    fi
}

# rpcbind + dbus prerequisites for ganesha.nfsd (idempotent on reload).
ensure_ganesha_prereqs() {
    if command -v rpcbind >/dev/null 2>&1; then
        if ! pgrep -x rpcbind >/dev/null 2>&1; then
            info "Starting rpcbind..."
            rpcbind -w 2>/dev/null || rpcbind 2>/dev/null || true
        fi
    fi

    mkdir -p /run/dbus
    rm -f /run/dbus/pid

    if ! pgrep -x dbus-daemon >/dev/null 2>&1; then
        info "Starting dbus-daemon (system bus)..."
        dbus-daemon --system --nofork &
        DBUS_PID=$!
        sleep 0.5
    fi

    info "Waiting for D-Bus system bus socket..."
    local dbus_ready=0
    for _ in {1..50}; do
        if [ -S /run/dbus/system_bus_socket ]; then
            if dbus-send --system --print-reply --dest=org.freedesktop.DBus \
                /org/freedesktop/DBus org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
                info "D-Bus system bus is ready"
                dbus_ready=1
                break
            fi
        fi
        sleep 0.2
    done

    if [ "$dbus_ready" -ne 1 ]; then
        warn "D-Bus system bus socket did not appear; Ganesha may have limited management features."
    fi
}

restart_webui() {
    if [ -n "${WEBUI_PID:-}" ] && kill -0 "$WEBUI_PID" 2>/dev/null; then
        kill -TERM "$WEBUI_PID" 2>/dev/null || true
        sleep 0.3
    fi
    info "Starting WebUI on 0.0.0.0:9630 (HTTPS)..."
    NFS_KLLDAP_CONF="$NFS_CONFIG" \
    "$UI_BIN" --config "$NFS_CONFIG" \
        > >(tee -a /var/log/webui.log) 2>&1 &
    WEBUI_PID=$!
    sleep 0.8
    if ! kill -0 "$WEBUI_PID" 2>/dev/null; then
        warn "WebUI process exited quickly after reload — last log lines:"
        tail -n 20 /var/log/webui.log 2>/dev/null || true
    fi
}

# Shared recycle path: identity stack first, then Ganesha + WebUI (matches cold boot).
recycle_services_after_config() {
    mkdir -p /var/lib/nfs-klldap /var/run/nfs-klldap /var/lib/extrausers

    stop_ganesha
    restart_sssd_and_wait
    restart_idhelper_and_wait_bulk
    ensure_ganesha_prereqs

    info "Starting NFS-Ganesha (idhelper mappings via nss_wrapper preload)..."
    start_ganesha

    restart_webui
}

handle_sighup() {
    info "SIGHUP received — reloading configuration via Rust generator..."

    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || {
        error "Rust config generator failed during SIGHUP reload"
        return 1
    }

    fix_derived_permissions
    recycle_services_after_config

    info "Ganesha, SSSD, idhelper, and WebUI recycled after config apply."
    # Create the marker *after* the declaration. The /restart-status handler
    # (polled by restarting.html) will only return 200 for a recent marker.
    # This is the signal the client waits for before redirecting to /login.
    touch /tmp/.nfs-klldap-services-recycled
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

    # --- Start core services (order matters for stable Ganesha bring-up) ---
    mkdir -p /var/lib/nfs-klldap /var/run/nfs-klldap /var/lib/extrausers

    restart_sssd_and_wait
    if [ ! -S /var/lib/sss/pipes/nss ]; then
        die "SSSD NSS pipe did not appear. Check LLDAP connectivity and bind credentials."
    fi

    restart_idhelper_and_wait_bulk
    ensure_ganesha_prereqs

    info "Starting NFS-Ganesha (idhelper mappings via nss_wrapper preload)..."
    start_ganesha

    restart_webui

    info "All services launched. Supervisor (this process) remains as pid 1."
    # Ensure no stale apply marker from a previous container run (the button
    # handler also clears it when starting a restart, and the status handler
    # has an age check).
    rm -f /tmp/.nfs-klldap-services-recycled 2>/dev/null || true

    # Start config watcher last so early bring-up cannot race Ganesha/dbus readiness;
    # inotify → SIGHUP → generate + service recycle.
    info "Starting config watcher..."
    "$WATCHER_BIN" "$NFS_CONFIG" &
    WATCHER_PID=$!

    info "Container is ready."

    # Supervisor loop: reap children; do not auto-respawn crashed daemons (HUP = config reload; full restart = new container).
    while true; do
        wait -n 2>/dev/null || true   # wait -n reaps one child; sleep avoids tight spin when none exit
        sleep 5
    done
}

main "$@"

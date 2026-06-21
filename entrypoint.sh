#!/bin/bash
# pid-1 supervisor (thin). Rust bins do heavy lifting (startup TUI + generate). On HUP/watcher/config-apply we bounce Ganesha+SSSD+WebUI. Simple loop for traps; TERM does full cleanup. No complex child-death exit logic.
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
IDHELPER_BIN="${IDHELPER_BIN:-/usr/local/bin/nfs-klldap-idhelper}"
# nss_wrapper integration: the idhelper materializes /var/lib/nfs-klldap/nss_{passwd,group}
# containing classified machine (→ uid 0) and user principals. Only Ganesha is run under
# the preload so its getpwnam (used for Kerberos NFSv4 owner mapping) sees the idhelper's
# decisions. Regular processes continue to use real SSSD users.
NSS_PASSWD="${NSS_PASSWD:-/var/lib/nfs-klldap/nss_passwd}"
NSS_GROUP="${NSS_GROUP:-/var/lib/nfs-klldap/nss_group}"

# Path prefix so ganesha.nfsd finds our nfsidmap shim (which is a symlink to
# nfsidmap-idhelper installed by the Dockerfile). Ganesha's ID MAPPER does
# `Get uid ... using nfsidmap` for principals like testuser1@REALM.
# By putting /usr/local/bin first, the literal name 'nfsidmap' resolves to
# our script that delegates to the idhelper. This is the 9.6/trixie-specific
# mechanism to give the server the same principal->uid view as clients.
# Only affects the ganesha.nfsd process.
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

    # Prefer killing tracked PIDs when we have them
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

handle_sighup() {
    info "SIGHUP received — reloading configuration via Rust generator..."

    "$CONFIG_BIN" generate --config "$NFS_CONFIG" || {
        error "Rust config generator failed during SIGHUP reload"
        return 1
    }

    fix_derived_permissions

    # Ganesha restart (management via pkill + respawn from supervisor; system bus is now present
    # inside the container for any D-Bus features Ganesha itself may use).
    if [ -x "$GANESHA_CTL" ]; then
        "$GANESHA_CTL" reload 2>/dev/null || pkill -TERM ganesha.nfsd 2>/dev/null || true
    else
        pkill -TERM ganesha.nfsd 2>/dev/null || true
    fi
    sleep 0.3
    info "Starting NFS-Ganesha (idhelper mappings via wrapper/extrausers)..."
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

    # SSSD almost always needs a full restart when its config changes (bind DN,
    # search bases, schema/ignores, krb5 provider bits, etc.).
    pkill -TERM sssd 2>/dev/null || true
    sleep 0.5
    sssd -i --logger=files ${SSSD_DEBUG_LEVEL:+-d $SSSD_DEBUG_LEVEL} 2>/dev/null &
    SSSD_PID=$!
    info "SSSD restarted after config change"

    # Recycle idhelper so it picks up any realm/hostname changes from regeneration.
    if [ -n "${IDHELPER_PID:-}" ] && kill -0 "$IDHELPER_PID" 2>/dev/null; then
        kill -TERM "$IDHELPER_PID" 2>/dev/null || true
        sleep 0.2
    fi
    "$IDHELPER_BIN" daemon > >(tee -a /var/log/idhelper.log) 2>&1 &
    IDHELPER_PID=$!
    info "idhelper restarted"

    # WebUI cycle for share changes (FsManager allow roots loaded at start; shares need restart).
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

    info "Services (Ganesha + SSSD + WebUI) recycled in place for config apply."
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

    # Ensure directories used by idhelper for its cache + nss_wrapper/extrausers materialization.
    mkdir -p /var/lib/nfs-klldap /var/run/nfs-klldap /var/lib/extrausers

    # SSSD (provides NSS for POSIX identity from LLDAP). Start early; Ganesha
    # and the rest of the stack benefit from consistent UID/GID mapping.
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

    # Start the ID/Kerberos principal helper daemon.
    # It must be running for the lifetime of the container because it is consulted
    # (directly or via its fast cache file) for every mount to distinguish machine
    # principals (host/..., nfs/...) from regular LDAP users and to provide fast
    # uid/gid translation. This prevents the repeated mount collapse seen with
    # Fedora Immutable clients.
    info "Starting nfs-klldap-idhelper (Kerberos ID translator)..."
    "$IDHELPER_BIN" daemon > >(tee -a /var/log/idhelper.log) 2>&1 &
    IDHELPER_PID=$!
    sleep 0.2
    if ! kill -0 "$IDHELPER_PID" 2>/dev/null; then
        warn "idhelper did not stay running; check /var/log/idhelper.log"
    else
        info "idhelper daemon started (pid $IDHELPER_PID)"
    fi

    # Ganesha prerequisites in the required order: rpcbind, dbus, wait for socket, then ganesha.
    # rpcbind (tooling/compatibility; Ganesha itself is strict NFSv4+).
    if command -v rpcbind >/dev/null 2>&1; then
        if ! pgrep -x rpcbind >/dev/null 2>&1; then
            info "Starting rpcbind..."
            rpcbind -w 2>/dev/null || rpcbind 2>/dev/null || true
        fi
    fi

    # dbus system bus (Ganesha on Fedora builds uses it for monitoring/management features).
    mkdir -p /run/dbus

    # Clean stale pid file (very common cause of "Failed to start message bus")
    rm -f /run/dbus/pid

    if ! pgrep -x dbus-daemon >/dev/null 2>&1; then
        info "Starting dbus-daemon (system bus)..."
        dbus-daemon --system --nofork &
        DBUS_PID=$!
        sleep 0.5
    fi

    # Wait for the system bus socket + functional responsiveness
    info "Waiting for D-Bus system bus socket..."
    for _ in {1..50}; do
        if [ -S /run/dbus/system_bus_socket ]; then
            # Functional test — this catches the case where the socket exists but the daemon isn't ready
            if dbus-send --system --print-reply --dest=org.freedesktop.DBus \
                /org/freedesktop/DBus org.freedesktop.DBus.ListNames >/dev/null 2>&1; then
                info "D-Bus system bus is ready"
                break
            fi
        fi
        sleep 0.2
    done

    if [ ! -S /run/dbus/system_bus_socket ]; then
        warn "D-Bus system bus socket did not appear; Ganesha may have limited management features."
    fi

    # Ganesha (the actual NFS server). Start only after rpcbind + dbus readiness checks.
    # The idhelper materializes machine overrides (via nss_wrapper *and* extrausers).
    # nsswitch is configured with extrausers so LDAP users remain visible via sss.
    # The preload below is kept for environments that rely on it; it can be disabled
    # by setting USE_NSS_WRAPPER=0 if extrausers alone is sufficient.
    info "Starting NFS-Ganesha (idhelper mappings via wrapper/extrausers)..."
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

    # WebUI (HTTPS on 9630 via axum-server + rustls; self-signed unless NFS_KLLDAP_WEBUI_TLS_* set)
    info "Starting WebUI on 0.0.0.0:9630 (HTTPS)..."
    NFS_KLLDAP_CONF="$NFS_CONFIG" \
    "$UI_BIN" --config "$NFS_CONFIG" \
        > >(tee -a /var/log/webui.log) 2>&1 &
    WEBUI_PID=$!

    sleep 1.5
    if ! kill -0 "$WEBUI_PID" 2>/dev/null; then
        warn "WebUI process exited quickly — last log lines:"
        tail -n 30 /var/log/webui.log 2>/dev/null || true
    fi

    info "All services launched. Supervisor (this process) remains as pid 1."
    # Ensure no stale apply marker from a previous container run (the button
    # handler also clears it when starting a restart, and the status handler
    # has an age check).
    rm -f /tmp/.nfs-klldap-services-recycled 2>/dev/null || true

    # Config watcher (inotify on the mounted source nfs-klldap.conf). It signals
    # pid 1 (HUP) so the privileged supervisor can run the generator (ensuring
    # 0600 root:root sssd.conf etc.) and bounce services. We start it *late*
    # (after Ganesha + WebUI are up) so inotify events during the critical
    # early bring-up on container start / image rebuild cannot race with the
    # first ganesha.nfsd launch or the dbus/rpc readiness waits. Once running
    # it provides the documented live-edit experience for the source config.
    info "Starting config watcher..."
    "$WATCHER_BIN" "$NFS_CONFIG" &
    WATCHER_PID=$!

    info "Container is ready."

    # Supervisor loop (simple pid1): reaps, stays up. HUP path does bounces; only TERM/INT/EXIT exits us.
    # (No liveness false-positives, no "child death exits supervisor". Crashed services stay down until HUP/restart.)
    while true; do
        wait -n 2>/dev/null || true   # reap any exited children promptly
        sleep 5
    done
}

main "$@"

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
# NOTE: The 4-step guided setup TUI, reachability tests, banner, waiting loop,
# and runtime diagnostics (including hostname/keytab guidance based on --uts=host)
# now live in the Rust binary `nfs-klldap-startup`.
#
# Only thin orchestration + gosu daemon startup remains in this shell script.
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
    log "SIGHUP received — reloading configuration via Rust generator (as root)..."
    generate_configs

    # Fix perms again after regeneration (sssd.conf must stay root:root 0600).
    chown root:root /etc/sssd/sssd.conf 2>/dev/null || true
    chmod 600 /etc/sssd/sssd.conf 2>/dev/null || true
    chown root:root /etc/krb5.conf 2>/dev/null || true
    chmod 644 /etc/krb5.conf 2>/dev/null || true
    chown -R nfs:nfs /etc/ganesha 2>/dev/null || true
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
    log "=== Starting nfs-klldap-host (v0.3+ guided setup) ==="

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
    # Permission model (carefully tuned for both SSSD requirements and the
    # project's unprivileged ganesha goal)
    # -----------------------------------------------------------------------------
    # - /etc/sssd/sssd.conf MUST be root:root 0600. SSSD's internal
    #   access_check_file() explicitly rejects any other owner (even if the
    #   running user could read it via kernel perms). This is why we can no
    #   longer chown it to the 'nfs' user.
    # - sssd itself therefore runs as root (standard and required for its
    #   own config + pipe creation behavior).
    # - ganesha.nfsd and the config watcher run unprivileged as the 'nfs' user
    #   (via gosu). This is the important containment boundary for VFS access
    #   to user data.
    # - The root entrypoint shell stays as pid 1 (no final exec) so it can
    #   continue to handle SIGHUP, perform privileged regenerate, fix perms,
    #   and orchestrate child restarts. This gives us "permissions across the
    #   board" without needing sudo for the normal reload path.
    # - After sssd starts we fix up the responder pipes so the unprivileged
    #   'nfs' user (ganesha, getent, etc.) can still perform NSS lookups.
    # -----------------------------------------------------------------------------

    # Force correct ownership for the main SSSD config (non-negotiable).
    chown root:root /etc/sssd/sssd.conf 2>/dev/null || true
    chmod 600 /etc/sssd/sssd.conf 2>/dev/null || true

    # krb5.conf is public config; root-owned 0644 is fine and expected.
    chown root:root /etc/krb5.conf 2>/dev/null || true
    chmod 644 /etc/krb5.conf 2>/dev/null || true

    # Ganesha fragments and main config need to be readable by the nfs user
    # (ganesha runs as nfs). The directory is already prepared in the image.
    chown -R nfs:nfs /etc/ganesha 2>/dev/null || true
    chmod -R a+rX /etc/ganesha 2>/dev/null || true

    # Start SSSD as root (required by its strict config ownership validator and
    # how it creates responder sockets/pipes). This is the one daemon we run
    # privileged; everything else that touches user data stays as 'nfs'.
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

    # -----------------------------------------------------------------------------
    # Make SSSD responder pipes usable by the unprivileged 'nfs' user.
    # Even when sssd runs as root it often creates /var/lib/sss/pipes with
    # tight ownership (root or sssd group). Ganesha (as nfs) and tools like
    # getent/id need to talk to the NSS responder for UID/GID mapping.
    # We make the pipes directory group-readable by the nfs user (who is
    # a member of the sssd group when the image was built correctly).
    # -----------------------------------------------------------------------------
    log "    Fixing SSSD responder pipe permissions for unprivileged NSS access..."
    chown -R root:sssd /var/lib/sss/pipes 2>/dev/null || true
    chmod -R 0770 /var/lib/sss/pipes 2>/dev/null || true
    # Also ensure the broader cache area is traversable (some mc caches etc.)
    find /var/lib/sss -type d -exec chmod g+rx {} + 2>/dev/null || true
    chown -R root:nfs /var/lib/sss/mc /var/lib/sss/pubconf 2>/dev/null || true

    # Start config watcher (as the unprivileged nfs user).
    # The watcher now signals the root supervisor (pid 1) on changes instead of
    # calling the generator directly. This guarantees that regeneration of
    # sssd.conf always happens with root privileges → correct ownership.
    if [ -x /usr/local/bin/nfs-klldap-conf-watcher ]; then
        run_as_nfs /usr/local/bin/nfs-klldap-conf-watcher "$NFS_CONFIG" &
        WATCHER_PID=$!
        log "    Config watcher started (auto-reload on changes)."
    fi

    # Start Ganesha as the unprivileged nfs user (the important containment
    # boundary). We do NOT exec here — the root shell must remain as pid 1
    # so SIGHUP continues to work for privileged regeneration and so we can
    # reap children cleanly.
    log "[2/3] Starting NFS-Ganesha..."
    run_as_nfs ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log &
    GANESHA_PID=$!

    log "All services launched. Supervisor (this shell) remains as root for signal handling and privileged regen."

    # Wait for children. If any die the script exits and the container will
    # be restarted by the policy (unless-stopped etc.).
    wait
}

main

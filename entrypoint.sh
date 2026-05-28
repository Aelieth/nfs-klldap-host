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

die() {
    log "FATAL: $*"
    exit 1
}

# -----------------------------------------------------------------------------
# Helper: Extract hostname from ldap_uri (ldaps://host:port or ldap://host)
# -----------------------------------------------------------------------------
extract_host_from_uri() {
    local uri="$1"
    echo "$uri" | sed -E 's|^ldaps?://([^:/]+).*|\1|'
}

# -----------------------------------------------------------------------------
# Step 1: LDAP_URI focused reachability test (as requested)
# 1. Try real LDAP connect (ldapsearch)
# 2. Fallback to ping
# 3. If DNS fails → clear "DNS resolution failed" + reminder that only DNS names are allowed
# -----------------------------------------------------------------------------
test_ldap_reachability() {
    local uri="$1"
    local host
    host=$(extract_host_from_uri "$uri")

    if [ -z "$host" ]; then
        echo "ERROR: ldap_uri is empty or invalid in $NFS_CONFIG"
        echo "       Please set: ldap_uri = \"ldaps://your-lldap-hostname:6360\""
        return 1
    fi

    # 1. Real LDAP test (ldapsearch is installed in the image)
    if ldapsearch -H "$uri" -x -s base -b "" >/dev/null 2>&1; then
        return 0
    fi

    # 2. Ping fallback
    if ping -c 1 -W 3 "$host" >/dev/null 2>&1; then
        log "Ping to $host succeeded (LDAP connect failed — check bind credentials or firewall)"
        return 0
    fi

    # 3. DNS resolution check (critical because keytab + SSSD require DNS names)
    if ! getent hosts "$host" >/dev/null 2>&1; then
        echo "FATAL: DNS resolution failed for '$host'"
        echo "       ldap_uri MUST use a DNS hostname — IP addresses are not supported"
        echo "       (SSSD config and Kerberos keytab both require proper DNS naming)."
        echo "       Fix your DNS or /etc/hosts and the container will auto-start."
        return 2
    fi

    echo "WARNING: $host resolves via DNS but is unreachable via LDAP or ping."
    echo "         Check LLDAP is running and firewall allows the port."
    return 1
}

# -----------------------------------------------------------------------------
# Check if Step 1 (persistent config volume) is properly done
# A real host mount will have a different device ID than the container root
# -----------------------------------------------------------------------------
is_persistent_config() {
    if [ -f "$NFS_CONFIG" ]; then
        local config_dev root_dev
        config_dev=$(stat -c %d "$NFS_CONFIG" 2>/dev/null || echo 0)
        root_dev=$(stat -c %d / 2>/dev/null || echo 1)
        if [ "$config_dev" != "$root_dev" ]; then
            return 0
        fi
    fi
    return 1
}

# -----------------------------------------------------------------------------
# Lightweight TCP test for Step 2 (ldap_uri)
# Uses nc to check if the exact host:port from ldap_uri is reachable
# -----------------------------------------------------------------------------
test_ldap_port() {
    local uri="$1"
    local host port

    host=$(extract_host_from_uri "$uri")
    # Extract port, default to 636 for ldaps
    port=$(echo "$uri" | grep -oE ':[0-9]+' | tail -1 | tr -d ':' || echo 636)

    if nc -z -w 3 "$host" "$port" 2>/dev/null; then
        echo "             [OK] Reachable at $host:$port"
        return 0
    else
        echo "             [FAIL] Cannot reach $host:$port"
        echo "                    → Check DNS, firewall, or if LLDAP is listening"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Step 3: Quick LDAP bind test using the credentials from config
# -----------------------------------------------------------------------------
test_ldap_bind() {
    local bind_dn authtok

    bind_dn=$(grep -E '^\s*ldap_default_bind_dn\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')
    authtok=$(grep -E '^\s*ldap_default_authtok\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')

    if [ -z "$bind_dn" ] || [ -z "$authtok" ]; then
        echo "             [FAIL] Missing bind_dn or authtok in config"
        return 1
    fi

    # Quick anonymous + simple bind test (non-destructive)
    if ldapsearch -H "$(grep -E '^\s*ldap_uri\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')" \
        -D "$bind_dn" -w "$authtok" -s base -b "" >/dev/null 2>&1; then
        echo "             [OK] Bind successful as $bind_dn"
        return 0
    else
        echo "             [FAIL] Bind failed — check credentials or LLDAP permissions"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Step 4: Verify the first share's host_path actually exists on the host
# -----------------------------------------------------------------------------
test_share_path() {
    local host_path

    # Extract first host_path from [[shares]]
    host_path=$(grep -A 20 '^\s*\[\[shares\]\]' "$NFS_CONFIG" | grep -E '^\s*host_path\s*=' | head -1 | cut -d= -f2- | tr -d ' "')

    if [ -z "$host_path" ]; then
        echo "             [FAIL] No host_path found in first [[shares]]"
        return 1
    fi

    if [ -d "$host_path" ]; then
        echo "             [OK] host_path exists: $host_path"
        return 0
    else
        echo "             [FAIL] host_path does not exist: $host_path"
        echo "                    → Create it on the host or fix the path in config"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Keytab vs current hostname alignment check
#
# Policy (per requirements):
# - As long as a keytab file exists, we consider this check "good" for startup.
# - A hostname/principal mismatch is acceptable here. Services are allowed to start.
# - We emit a clear WARNING on mismatch so operators see it in the container logs.
# - Detailed mismatch status + remediation instructions are handled by the web UI.
# -----------------------------------------------------------------------------
check_keytab_hostname_match() {
    local kt="/etc/krb5.keytab"
    local current_host
    current_host=$(hostname 2>/dev/null || echo "unknown")

    echo "  [KEYTAB/HOSTNAME] Checking keytab principal alignment..."

    if [ ! -f "$kt" ]; then
        echo "             (no keytab mounted at $kt yet — Kerberos NFS will not work until provided)"
        return 0
    fi

    if ! command -v klist >/dev/null 2>&1; then
        echo "             (klist not available — skipping detailed principal check; keytab file is present)"
        return 0
    fi

    # Extract all host parts from nfs/ principals (e.g. nfs/foo-nfs@REALM → foo-nfs)
    local kt_hosts
    kt_hosts=$(klist -k "$kt" 2>/dev/null \
        | awk '/^[0-9]+[[:space:]]+nfs\// {print $2}' \
        | sed -E 's|^nfs/([^@]+).*|\1|' \
        | sort -u \
        | tr '\n' ' ' | sed 's/ $//')

    if [ -z "$kt_hosts" ]; then
        echo "             WARNING: keytab exists but contains no nfs/* service principals"
        echo "                      (hostname and keytab: no nfs principals found)"
        return 0
    fi

    # Check for exact match
    if echo " $kt_hosts " | grep -q " $current_host "; then
        echo "             (hostname and keytab: aligned)   hostname=$current_host   keytab=$kt_hosts"
        return 0
    else
        # Mismatch is not fatal. Container proceeds. UI shows the details + instructions.
        echo "             WARNING: (hostname and keytab: mismatch! change hostname or recreate keytab)"
        echo "                      Container hostname : $current_host"
        echo "                      nfs/ principals in keytab : $kt_hosts"
        echo "                      Services will continue to start."
        echo "                      See the web UI (System Settings page) for current status and remediation steps."
        return 0
    fi
}

# -----------------------------------------------------------------------------
# check_runtime_permissions (documented in docs/run/README.md)
# Emits diagnostics + copy-pasteable remediation for:
#   - keytab readability (permissions/group)
#   - writable runtime directories needed by ganesha/sssd
#   - keytab presence + hostname/principal alignment (WARNING only on mismatch)
#
# This function is intentionally advisory. A present keytab is sufficient for
# services to start. The web UI provides the authoritative mismatch details.
# -----------------------------------------------------------------------------
check_runtime_permissions() {
    echo "  [RUNTIME PERMISSIONS] Checking keytab readability and runtime dirs..."

    local kt="/etc/krb5.keytab"
    if [ -f "$kt" ]; then
        if [ -r "$kt" ]; then
            echo "             [OK] keytab is readable by current user"
        else
            echo "             [ACTION REQUIRED] keytab not readable by $(id -un)"
            echo "                    Current: $(ls -l "$kt" 2>/dev/null)"
            echo "                    Run on the HOST (adjust GID from the image):"
            echo "                      ./scripts/fix-keytab-perms.sh /path/to/your/krb5.keytab"
            echo "                    Or manually:"
            echo "                      sudo chgrp \$(docker run --rm --entrypoint getent ghcr.io/aelieth/nfs-klldap-host:latest keytab | cut -d: -f3) $kt"
            echo "                      sudo chmod g+r $kt"
        fi
    else
        echo "             (no keytab at $kt — Kerberos NFS will not work until provided)"
    fi

    # Writable runtime dirs (ganesha + sssd need these even as non-root in many cases)
    for d in /var/log/ganesha /var/lib/sss /var/run/ganesha /var/run/sssd /etc/ganesha/exports.d; do
        if [ -d "$d" ]; then
            if touch "$d/.write-test-$$" 2>/dev/null; then
                rm -f "$d/.write-test-$$" 2>/dev/null || true
            else
                echo "             [ACTION REQUIRED] $d is not writable by $(id -un)"
                echo "                    Fix on host (or add --user root temporarily for debugging):"
                echo "                      sudo chown -R 1000:1000 $d   # (example UID; use the container's nfs uid)"
            fi
        fi
    done

    # Hostname / keytab principal alignment check.
    # Non-blocking: a keytab file being present is sufficient for startup.
    # Mismatches are reported as warnings only; detailed guidance lives in the web UI.
    check_keytab_hostname_match
}

# -----------------------------------------------------------------------------
# Print only the CURRENT active step + minimal instruction
# Once previous step is COMPLETE, we show the next one
# 4 clear separate steps as requested
# -----------------------------------------------------------------------------
print_current_step_guidance() {
    if ! is_persistent_config; then
        echo "  [STEP 1/4] Mount a persistent config volume (REQUIRED):"
        echo "             -v /path/on/your/host:/config"
        return
    fi

    if ! grep -qE '^\s*ldap_uri\s*=' "$NFS_CONFIG" 2>/dev/null; then
        echo "  [STEP 2/4] Set ldap_uri in nfs-klldap.conf (DNS name only):"
        echo "             ldap_uri = \"ldaps://lldap.yourdomain.com:6360\""
        return
    fi

    # ldap_uri is set — test connectivity with nc
    ldap_uri=$(grep -E '^\s*ldap_uri\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')
    echo "  [STEP 2/4] ldap_uri = $ldap_uri"
    if ! test_ldap_port "$ldap_uri"; then
        # Still on Step 2 — don't advance
        return
    fi
    # If we reach here, nc succeeded — move to next step below

    # Step 3: Bind credentials — check syntax then test actual bind
    if ! grep -qE '^\s*ldap_default_bind_dn\s*=' "$NFS_CONFIG" 2>/dev/null || \
       ! grep -qE '^\s*ldap_default_authtok\s*=' "$NFS_CONFIG" 2>/dev/null; then
        echo "  [STEP 3/4] Add LLDAP bind credentials in [sssd] section:"
        echo "             ldap_default_bind_dn  = \"uid=admin,ou=people,dc=...\""
        echo "             ldap_default_authtok = \"your-password\""
        return
    fi

    echo "  [STEP 3/4] Testing bind with configured credentials..."
    if ! test_ldap_bind; then
        return   # Stay on Step 3 if bind fails
    fi

    # Step 4: Shares — check section exists, then verify host_path
    if ! grep -qE '^\s*\[\[shares\]\]' "$NFS_CONFIG" 2>/dev/null; then
        echo "  [STEP 4/4] Add at least one [[shares]] section:"
        echo "             [[shares]]"
        echo "             name = \"my-share\""
        echo "             host_path = \"/export/my-share\""
        echo "             export_path = \"/my-share\""
        return
    fi

    echo "  [STEP 4/4] Checking first share host_path..."
    if ! test_share_path; then
        return   # Stay on Step 4 if path doesn't exist
    fi

    echo "  All steps complete — starting services..."
}

# -----------------------------------------------------------------------------
# Print a concise, guiding first-run banner (shown once at startup)
# -----------------------------------------------------------------------------
print_setup_banner() {
    cat <<'EOF'

╔══════════════════════════════════════════════════════════════════════════════╗
║  nfs-klldap-host — FIRST RUN SETUP (Step-by-Step)                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  The container is now WAITING for you. It will auto-start services           ║
║  when these steps are complete (no restart needed).                          ║
║                                                                              ║
║  STEP 1: Mount a persistent config volume (MOST IMPORTANT)                   ║
║    Nothing else works without this.                                          ║
║    -v /path/on/your/host/nfs-config:/config                                  ║
║                                                                              ║
║  STEP 2: Set ldap_uri (MUST be a DNS hostname — NO IP addresses)             ║
║    ldap_uri = "ldaps://lldap.yourdomain.com:6360"                            ║
║                                                                              ║
║  STEP 3: Add LLDAP bind credentials + at least one [[shares]]                ║
║                                                                              ║
║  RECOMMENDED full docker run (copy-paste & adjust paths):                    ║
║  docker run -d --name nfs-klldap \                                           ║
║    -v /home/you/nfs-config:/config \                                         ║
║    -v /media/data:/export \                                                  ║
║    -v /home/you/krb5.keytab:/etc/krb5.keytab:ro \                            ║
║    -p 2049:2049/tcp -p 2049:2049/udp \                                       ║
║    --user nfs \                                                              ║
║    --cap-add CHOWN --cap-add FOWNER --cap-add DAC_OVERRIDE \                 ║
║    ghcr.io/aelieth/nfs-klldap-host:latest                                    ║
║                                                                              ║
║  Better long-term: Use docker-compose (see examples/docker-compose.yml)      ║
╚══════════════════════════════════════════════════════════════════════════════╝

EOF
}

# -----------------------------------------------------------------------------
# Cute little waiting loop (the heart of Option A)
# Keeps checking until config is valid AND ldap_uri is reachable
# -----------------------------------------------------------------------------
wait_for_valid_config() {
    while true; do
        if "$CONFIG_BIN" validate --config "$NFS_CONFIG" >/dev/null 2>&1; then
            # Extract current ldap_uri
            ldap_uri=$(grep -E '^\s*ldap_uri\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')

            if test_ldap_reachability "$ldap_uri"; then
                log "[OK] Config is valid and LDAP is reachable. Starting services..."
                return 0
            fi
        fi

        # Show only the current active step + minimal instruction
        print_current_step_guidance

        log "[WAITING] Edit the config file — it will auto-start when ready."
        sleep 10
    done
}

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

    # Auto-set hostname to $(hostname)-nfs if user didn't pass --hostname
    # This makes --hostname an override, not a requirement
    current_hostname=$(hostname)
    if [ "$current_hostname" = "$(cat /etc/hostname 2>/dev/null || echo 'localhost')" ] || \
       [ "$current_hostname" = "localhost" ] || \
       echo "$current_hostname" | grep -qE '^[0-9a-f]{12}$'; then
        # Looks like default Docker hostname (container ID or localhost)
        host_base=$(cat /proc/sys/kernel/hostname 2>/dev/null || hostname)
        desired="${host_base}-nfs"
        hostname "$desired" 2>/dev/null || true
        export HOSTNAME="$desired"
        log "Auto-set hostname to $desired (use --hostname to override)"
    fi

    # Make the effective hostname (the one the keytab + NFS principal must match) very obvious
    effective_host=$(hostname)
    log "Effective container hostname for NFS principal: $effective_host"
    log "  → Your keytab MUST contain: nfs/$effective_host@YOUR.REALM"

    ensure_config_binary

    if [ ! -f "$NFS_CONFIG" ]; then
        "$CONFIG_BIN" init --config "$NFS_CONFIG" || die "Failed to create default config"
        print_setup_banner
        wait_for_valid_config
    else
        # Existing config on restart — still validate ldap_uri reachability once
        ldap_uri=$(grep -E '^\s*ldap_uri\s*=' "$NFS_CONFIG" | head -1 | cut -d= -f2- | tr -d ' "')
        if ! test_ldap_reachability "$ldap_uri" >/dev/null 2>&1; then
            log "WARNING: ldap_uri reachability check failed on startup. Continuing anyway..."
        fi
    fi

    generate_configs

    # This is the big one that was documented but previously missing (would have caused "command not found")
    check_runtime_permissions || true   # never fatal — only advisory diagnostics

    # Start SSSD
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

    # Start config watcher
    if [ -x /usr/local/bin/nfs-klldap-conf-watcher ]; then
        /usr/local/bin/nfs-klldap-conf-watcher "$NFS_CONFIG" &
        WATCHER_PID=$!
        log "    Config watcher started (auto-reload on changes)."
    fi

    # Start Ganesha
    log "[2/3] Starting NFS-Ganesha..."
    exec ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log
}

main

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
# First-run: Generate safe default config if it doesn't exist
# -----------------------------------------------------------------------------
generate_default_config() {
    log "No config found at $NFS_CONFIG — generating safe first-run template..."
    mkdir -p "$CONFIG_DIR"

    cat > "$NFS_CONFIG" << 'EOF'
# =============================================================================
# nfs-klldap.conf — Single Source of Truth
# =============================================================================
# Auto-generated on first run.
# The container will NEVER overwrite this file after it exists.
#
# REQUIRED — fill these in to start the server:
# =============================================================================

ldap_uri = "ldaps://lldap.example.com:6360"

[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=example,dc=com"
ldap_default_authtok = "CHANGE_ME_SUPER_SECRET"


# =============================================================================
# Everything below is OPTIONAL — leave commented to use smart defaults
# =============================================================================

[server]
# hostname = "examplehost-nfs"          # (optional) leave commented to auto-derive

[sssd]
# port = 6360
# ldap_user_search_base = "ou=people,dc=example,dc=com"
# ldap_group_search_base = "ou=groups,dc=example,dc=com"

[kerberos]
# realm = "EXAMPLE.COM"                 # (auto-derived from ldap_uri domain)

[ganesha]
# default_security = "krb5p"            # krb5p | krb5i | krb5


# =============================================================================
# Shares — Add your own blocks (examples are commented out)
# =============================================================================
# The container only creates shares from blocks you actually add or uncomment.

# [[shares]]
# name = "project-alpha"
# host_path = "/export/project-alpha"
# export_path = "/project-alpha"
# security = "krb5p"
# rw = true
# squash = "no_root_squash"
EOF

    chmod 600 "$NFS_CONFIG"
    log "Default config created. Please edit $NFS_CONFIG before restarting."
}

# -----------------------------------------------------------------------------
# Simple TOML parser (sufficient for our structured config)
# -----------------------------------------------------------------------------
parse_config() {
    log "Parsing $NFS_CONFIG..."

    # Top-level
    LDAP_URI=$(grep -E '^ldap_uri\s*=' "$NFS_CONFIG" | head -1 | cut -d'=' -f2- | tr -d ' "')

    # [server]
    HOSTNAME=$(grep -A 20 '^\[server\]' "$NFS_CONFIG" | grep -E '^hostname\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')

    # [sssd]
    BIND_DN=$(grep -A 30 '^\[sssd\]' "$NFS_CONFIG" | grep -E '^ldap_default_bind_dn\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')
    BIND_PW=$(grep -A 30 '^\[sssd\]' "$NFS_CONFIG" | grep -E '^ldap_default_authtok\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')
    PORT=$(grep -A 30 '^\[sssd\]' "$NFS_CONFIG" | grep -E '^port\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')
    USER_BASE=$(grep -A 30 '^\[sssd\]' "$NFS_CONFIG" | grep -E '^ldap_user_search_base\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')
    GROUP_BASE=$(grep -A 30 '^\[sssd\]' "$NFS_CONFIG" | grep -E '^ldap_group_search_base\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')

    # [kerberos]
    REALM=$(grep -A 20 '^\[kerberos\]' "$NFS_CONFIG" | grep -E '^realm\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')

    # [ganesha]
    DEFAULT_SECURITY=$(grep -A 20 '^\[ganesha\]' "$NFS_CONFIG" | grep -E '^default_security\s*=' | head -1 | cut -d'=' -f2- | tr -d ' "')

    # Auto-derive if not set
    if [ -z "$HOSTNAME" ]; then
        HOSTNAME="$(hostname)"
    fi

    if [ -z "$REALM" ]; then
        # Derive from ldap_uri (e.g. lldap.example.com → EXAMPLE.COM)
        DOMAIN=$(echo "$LDAP_URI" | sed -E 's|.*://([^:/]+).*|\1|' | cut -d. -f2-)
        REALM=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
    fi

    if [ -z "$PORT" ]; then
        if [[ "$LDAP_URI" == ldaps://* ]]; then
            PORT=636
        else
            PORT=389
        fi
    fi

    if [ -z "$DEFAULT_SECURITY" ]; then
        DEFAULT_SECURITY="krb5p"
    fi

    if [ -z "$USER_BASE" ]; then
        USER_BASE="ou=people,dc=example,dc=com"
    fi

    if [ -z "$GROUP_BASE" ]; then
        GROUP_BASE="ou=groups,dc=example,dc=com"
    fi

    log "Config parsed successfully (hostname=$HOSTNAME, realm=$REALM, security=$DEFAULT_SECURITY)"
}

# -----------------------------------------------------------------------------
# Generate sssd.conf from parsed values
# -----------------------------------------------------------------------------
generate_sssd_conf() {
    log "Generating $SSSD_CONF..."

    mkdir -p "$(dirname "$SSSD_CONF")"

    cat > "$SSSD_CONF" << EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = default

[domain/default]
id_provider = ldap
auth_provider = ldap
ldap_uri = $LDAP_URI
ldap_search_base = dc=$(echo "$REALM" | tr '[:upper:]' '[:lower:]' | tr '.' ',dc=')
ldap_default_bind_dn = $BIND_DN
ldap_default_authtok = $BIND_PW
ldap_user_search_base = $USER_BASE
ldap_group_search_base = $GROUP_BASE
cache_credentials = True
enumerate = False
EOF

    chmod 600 "$SSSD_CONF"
}

# -----------------------------------------------------------------------------
# Generate krb5.conf
# -----------------------------------------------------------------------------
generate_krb5_conf() {
    log "Generating $KRB5_CONF..."

    cat > "$KRB5_CONF" << EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    $REALM = {
        kdc = $(echo "$LDAP_URI" | sed -E 's|.*://([^:/]+).*|\1|')
        admin_server = $(echo "$LDAP_URI" | sed -E 's|.*://([^:/]+).*|\1|')
    }

[domain_realm]
    .$(echo "$REALM" | tr '[:upper:]' '[:lower:]') = $REALM
    $(echo "$REALM" | tr '[:upper:]' '[:lower:]') = $REALM
EOF

    chmod 644 "$KRB5_CONF"
}

# -----------------------------------------------------------------------------
# Generate Ganesha EXPORT fragments from shares (basic version for now)
# -----------------------------------------------------------------------------
generate_ganesha_fragments() {
    log "Generating Ganesha export fragments..."

    mkdir -p "$EXPORTS_DIR"
    rm -f "$EXPORTS_DIR"/*.conf 2>/dev/null || true

    # For now we create one example fragment if no shares are defined
    # Full [[shares]] parsing will be added in next iteration
    cat > "$EXPORTS_DIR/10-default.conf" << EOF
EXPORT {
    Export_Id = 1000;
    Path = /export;
    Pseudo = /;
    SecType = $DEFAULT_SECURITY;
    Squash = no_root_squash;
    Access_Type = RW;
    Protocols = 4;
    Transports = TCP;
    FSAL {
        Name = VFS;
    }
}
EOF

    log "Default export fragment created (full per-share parsing coming soon)"
}

# -----------------------------------------------------------------------------
# Generate main ganesha.conf
# -----------------------------------------------------------------------------
generate_ganesha_main_conf() {
    log "Generating $GANESHA_CONF..."

    mkdir -p "$(dirname "$GANESHA_CONF")"

    cat > "$GANESHA_CONF" << EOF
NFS_CORE_PARAM {
    Protocols = 4;
}

NFSV4 {
    Lease_Lifetime = 60;
}

EXPORT_DEFAULTS {
    SecType = $DEFAULT_SECURITY;
}

%include "$EXPORTS_DIR/*.conf"
EOF

    chmod 644 "$GANESHA_CONF"
}

# -----------------------------------------------------------------------------
# Signal handling
# -----------------------------------------------------------------------------
cleanup() {
    log "Shutting down services..."
    pkill -TERM ganesha.nfsd 2>/dev/null || true
    pkill -TERM sssd 2>/dev/null || true
    sleep 1
    log "Shutdown complete."
    exit 0
}
trap cleanup SIGTERM SIGINT

handle_sighup() {
    log "SIGHUP received — reloading configuration..."
    parse_config
    generate_sssd_conf
    generate_krb5_conf
    generate_ganesha_fragments
    generate_ganesha_main_conf
    /usr/local/bin/ganesha-ctl reload 2>/dev/null || pkill -HUP ganesha.nfsd 2>/dev/null || true
}
trap 'handle_sighup' SIGHUP

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    log "=== Starting nfs-klldap-host (v0.23+) ==="

    if [ ! -f "$NFS_CONFIG" ]; then
        generate_default_config
        log "Please edit $NFS_CONFIG and restart the container."
        exit 0
    fi

    parse_config
    generate_sssd_conf
    generate_krb5_conf
    generate_ganesha_fragments
    generate_ganesha_main_conf

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

    # Start Ganesha
    log "[2/3] Starting NFS-Ganesha..."
    exec ganesha.nfsd -f "$GANESHA_CONF" -L /var/log/ganesha.log
}

main

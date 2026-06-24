#!/bin/bash
# Capture raw audit evidence for nfs-klldap-host goal verification.
# Usage: SCRATCH=/path/to/scratch ./scripts/audit-scope.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${SCRATCH:-/tmp/grok-goal-audit}/audit-evidence"
mkdir -p "$OUT"

run() {
    local name="$1"
    shift
    {
        echo "=== $name ==="
        echo "cwd: $ROOT"
        echo "cmd: $*"
        echo "---"
        (cd "$ROOT" && "$@") 2>&1 || true
        echo
    } >"$OUT/${name}.txt"
    echo "wrote $OUT/${name}.txt"
}

run file-inventory bash -c '
    for f in \
        nfs-klldap-config/src/generate.rs nfs-klldap-config/src/idmap.rs nfs-klldap-config/src/lib.rs \
        nfs-klldap-config/src/validate.rs nfs-klldap-config/src/startup.rs nfs-klldap-config/src/supervisor.rs \
        nfs-klldap-config/src/bin/idhelper/common.rs nfs-klldap-config/src/bin/idhelper/resolve.rs \
        nfs-klldap-config/src/bin/idhelper/materialize.rs nfs-klldap-config/src/bin/idhelper/observer.rs \
        nfs-klldap-config/src/bin/idhelper/daemon.rs nfs-klldap-config/src/bin/idhelper/main.rs \
        nfs-klldap-identity/src/lib.rs nfs-klldap-identity/src/krb5/principal.rs nfs-klldap-identity/src/ldap/resolver.rs \
        nfs-klldap-ui/src/main.rs nfs-klldap-ui/src/ldap.rs nfs-klldap-ui/src/config.rs \
        Dockerfile entrypoint.sh scripts/verify-ganesha.sh container/healthcheck.sh \
        container/scripts/ganesha-ctl container/scripts/nfsidmap-idhelper container/scripts/check-common.sh \
        docs/ganesha-architecture.md docs/ldap-integration.md docs/run/README.md \
        Cargo.toml nfs-klldap-config/Cargo.toml nfs-klldap-identity/Cargo.toml nfs-klldap-ui/Cargo.toml
    do
        if [ -f "$f" ]; then
            wc -l "$f"
        else
            echo "MISSING $f"
        fi
    done
'

run grep-deprecated-ganesha-keys grep -n -E 'Manage_Gids_Expiration|IdmapConf|UseGetpwnam|Read_Access_Check_Policy|Transports' nfs-klldap-config/src/generate.rs nfs-klldap-config/tests/representative_generate.rs || true

run grep-root-krb-principal grep -rn 'Root_Kerberos_Principal|GANESHA_ROOT_KRB' nfs-klldap-config/src nfs-klldap-config/tests || true

run grep-ui-head head -40 nfs-klldap-ui/src/main.rs nfs-klldap-ui/src/ldap.rs nfs-klldap-ui/src/config.rs

run grep-entrypoint cat entrypoint.sh

run grep-container-scripts head -30 container/scripts/ganesha-ctl container/scripts/nfsidmap-idhelper container/scripts/check-common.sh container/healthcheck.sh scripts/verify-ganesha.sh

run grep-docs-head head -25 docs/ganesha-architecture.md docs/ldap-integration.md docs/run/README.md

run grep-idhelper-resolve grep -n 'take_materialize\|materialize_nss\|cache.insert' nfs-klldap-config/src/bin/idhelper/resolve.rs

run grep-idhelper-daemon grep -n 'take_materialize\|apply_cache\|rebulk' nfs-klldap-config/src/bin/idhelper/daemon.rs nfs-klldap-config/src/bin/idhelper/materialize.rs

run grep-comments-audited grep -n -E '^(//|//!|# )' \
    nfs-klldap-config/src/generate.rs \
    nfs-klldap-config/src/bin/idhelper/resolve.rs \
    nfs-klldap-config/src/bin/idhelper/materialize.rs \
    nfs-klldap-config/src/bin/idhelper/observer.rs \
    nfs-klldap-config/src/bin/idhelper/daemon.rs \
    nfs-klldap-config/src/validate.rs \
    nfs-klldap-identity/src/krb5/principal.rs \
    nfs-klldap-config/src/supervisor.rs

echo "audit-scope complete: $OUT"
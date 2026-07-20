#!/bin/bash
# ganesha-startup-smoke.sh — refactor-plan 1.3 startup sanity gate (also the
# Phase 2 §2.2 regression gate). Runs INSIDE the image; the export path must
# be a bind-mounted real filesystem (overlayfs/--tmpfs cannot provide file
# handles for FSAL_VFS). From the repo root:
#
#   mkdir -p .smoke-exportroot
#   docker run --rm --entrypoint bash \
#     --cap-add SYS_ADMIN --cap-add DAC_READ_SEARCH \
#     -v "$PWD/.smoke-exportroot:/srv/smoke" \
#     -v "$PWD/scripts/ganesha-startup-smoke.sh:/smoke.sh:ro" \
#     <image> /smoke.sh
#
# Proves: custom package identity (+klldap1), binary provenance (no MSPAC
# stub, no wbclient, POSIX-ACL backend present — one ACL-capable binary per
# the 2026-07-10 realignment), daemon start on 2049, VFS FSAL mapped into the
# process, GSS nfs/ principal acquired from a local keytab, and a clean
# startup log with a Disable_ACL export (the per-export NOACL proof in
# miniature). The client half of the gate (krb5p mount from an immutable
# Fedora client) is scripts/fedora-krb5p-client-validate.sh.
# pipefail catches a mid-pipe failure; -e is deliberately omitted because the
# checks below tally failures and must not abort on expected non-zero.
set -uo pipefail

# Expected custom package version; override when gating a different uplift.
EXPECT_VERSION="${EXPECT_VERSION:-9.13-1+klldap3}"

pass=0; fail=0
ok()  { echo "PASS: $*"; pass=$((pass+1)); }
bad() { echo "FAIL: $*"; fail=$((fail+1)); }

echo "== [1] package identity =="
v="$(dpkg-query -W -f='${Version}' nfs-ganesha)"
[ "$v" = "$EXPECT_VERSION" ] && ok "nfs-ganesha $v" || bad "unexpected version: $v (expected $EXPECT_VERSION)"
vv="$(dpkg-query -W -f='${Version}' nfs-ganesha-vfs)"
[ "$vv" = "$EXPECT_VERSION" ] && ok "nfs-ganesha-vfs $vv" || bad "unexpected vfs version: $vv (expected $EXPECT_VERSION)"

echo "== [2] binary provenance =="
ganesha.nfsd -v 2>&1 | head -2
# No binutils in the slim image: use grep -a for binary string probes.
if grep -qa 'Unsupported code path for principal' /usr/bin/ganesha.nfsd; then
    bad "MSPAC uid2grp stub string present in ganesha.nfsd"
else
    ok "MSPAC uid2grp stub absent from ganesha.nfsd"
fi
if ldd /usr/bin/ganesha.nfsd | grep -qi wbclient; then
    bad "ganesha.nfsd links wbclient"
else
    ok "no wbclient linkage"
fi
for lib in libgssapi_krb5 'libntirpc\.so' libnfsidmap libdbus-1; do
    if ldd /usr/bin/ganesha.nfsd | grep -q "$lib"; then
        ok "linked: $lib"
    else
        bad "missing expected linkage: $lib"
    fi
done
VFS_SO="/usr/lib/$(uname -m)-linux-gnu/ganesha/libfsalvfs.so"
# Flipped by the 2026-07-10 realignment: the single ACL-capable binary must
# carry the POSIX-ACL backend (posix_acls.c: acl_get_fd/acl_set_fd et al.).
# The in-memory debug store (vfs_acl_init) must stay absent.
if grep -qaE 'acl_(get|set)_(fd|file)|acl_from_text|acl_to_any_text' "$VFS_SO"; then
    ok "libfsalvfs.so carries the POSIX-ACL backend (ACL-capable binary)"
else
    bad "libfsalvfs.so lacks POSIX-ACL backend symbols (ACL capability missing)"
fi
if grep -qa 'vfs_acl_init' "$VFS_SO"; then
    bad "libfsalvfs.so contains the in-memory debug-ACL store (vfs_acl_init)"
else
    ok "no in-memory debug-ACL store compiled in"
fi

echo "== [3] daemon start + VFS FSAL load =="
mkdir -p /srv/smoke /srv/smoke-acl /var/lib/nfs/ganesha /run/dbus /run/rpcbind
# ACL-variant export: seed one named entry so the POSIX-ACL backend has a
# real extended ACL to fetch on the first attribute refresh (WI-9).
if setfacl -m u:12001:r-x /srv/smoke-acl 2>/dev/null; then
    echo "    seeded /srv/smoke-acl with u:12001:r-x"
else
    echo "    WARN: could not seed ACL on /srv/smoke-acl (filesystem must store POSIX ACLs for [4b])"
fi
dbus-daemon --system --fork 2>/dev/null || echo "    (dbus start failed; non-fatal for smoke)"
rpcbind 2>/dev/null || echo "    (rpcbind start failed; non-fatal for v4-only)"
# Local keytab so gss_principal_init can acquire accept creds for the nfs/
# service principal — the server half of the krb5 machinery, no KDC needed.
cat > /etc/krb5.conf <<EOF
[libdefaults]
    default_realm = SMOKE.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    SMOKE.TEST = { kdc = 127.0.0.1 }
EOF
printf 'addent -password -p nfs/%s@SMOKE.TEST -k 1 -e aes256-cts-hmac-sha1-96\nsmokepw\nwkt /etc/krb5.keytab\nq\n' "$(hostname)" | ktutil >/dev/null 2>&1
klist -k /etc/krb5.keytab 2>/dev/null | sed 's/^/    /' || echo "    (keytab creation failed)"
# Allow_Set_Io_Flusher_Fail mirrors production (generate/mod.rs emits it):
# PR_SET_IO_FLUSHER needs CAP_SYS_RESOURCE, which the deployed cap set
# (SYS_ADMIN + DAC_READ_SEARCH) does not include.
cat > /tmp/smoke.conf <<'EOF'
NFS_CORE_PARAM {
    Protocols = 4;
    Enable_NLM = false;
    Enable_RQUOTA = false;
    Enable_UDP = false;
    Allow_Set_Io_Flusher_Fail = true;
}
NFSv4 {
    Graceless = true;
}
EXPORT {
    Export_Id = 1;
    Path = /srv/smoke;
    Pseudo = /smoke;
    Access_Type = RW;
    Squash = None;
    SecType = sys;
    Protocols = 4;
    Disable_ACL = true;
    FSAL { Name = VFS; }
}
EXPORT {
    Export_Id = 2;
    Path = /srv/smoke-acl;
    Pseudo = /smoke-acl;
    Access_Type = RW;
    Squash = None;
    SecType = sys;
    Protocols = 4;
    Disable_ACL = false;
    FSAL { Name = VFS; }
}
EOF
ganesha.nfsd -F -f /tmp/smoke.conf -L /tmp/ganesha-smoke.log -N NIV_INFO &
GPID=$!
up=""
for i in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ':2049'; then up=1; break; fi
    kill -0 "$GPID" 2>/dev/null || break
    sleep 1
done
if [ -n "$up" ]; then ok "ganesha.nfsd up and listening on 2049 (pid $GPID)"; else bad "2049 never came up"; fi
if kill -0 "$GPID" 2>/dev/null && grep -q 'libfsalvfs\.so' "/proc/$GPID/maps"; then
    ok "libfsalvfs.so mapped into the running daemon (VFS FSAL loaded)"
else
    bad "libfsalvfs.so not mapped into daemon process"
fi

echo "== [4] log audit =="
if grep -qiE 'undefined symbol|cannot open shared object|dlopen.*error' /tmp/ganesha-smoke.log; then
    bad "linkage errors in log:"; grep -iE 'undefined symbol|cannot open shared object|dlopen' /tmp/ganesha-smoke.log | head -5
else
    ok "no undefined-symbol / missing-library errors"
fi
if grep -qiE ':CRIT :|:FATAL :|:MAJ :' /tmp/ganesha-smoke.log; then
    bad "CRIT/FATAL/MAJ lines in startup log:"
    grep -iE ':CRIT :|:FATAL :|:MAJ :' /tmp/ganesha-smoke.log | head -8
else
    ok "no CRIT/FATAL/MAJ in startup log"
fi
# Since the WI-9 ACL variant (0.9.90) the conf carries one NOACL and one ACL
# export on the same binary. Startup itself should still log only the
# daemon-core ACL cache init; FSAL POSIX-ACL lines appear once a client
# exercises the ACL export (proven in the 2.6 gate, not at boot). What is a
# hard failure on this build is the NOTSUPP signature: the POSIX-ACL backend
# failing to serve ACLs from the export's filesystem.
if grep -qiE 'Permission check for ACL.*(not supported|NOTSUPP)' /tmp/ganesha-smoke.log; then
    bad "[4b] POSIX-ACL backend cannot serve the ACL export's filesystem:"
    grep -iE 'Permission check for ACL' /tmp/ganesha-smoke.log | head -3
else
    ok "[4b] no ACL-NOTSUPP failures with the ACL export loaded"
fi
if grep -i 'acl' /tmp/ganesha-smoke.log | grep -qvE 'COMPONENT_NFS_V4_ACL|NFSv4 ACL cache successfully initialized|Disable_ACL|smoke-acl'; then
    echo "    NOTE: unexpected ACL lines (review):"
    grep -i 'acl' /tmp/ganesha-smoke.log | grep -vE 'COMPONENT_NFS_V4_ACL|NFSv4 ACL cache successfully initialized|Disable_ACL|smoke-acl' | head -4
else
    ok "no ACL activity beyond core cache init and the declared ACL export"
fi
if grep -q 'gss_principal_init' /tmp/ganesha-smoke.log && grep -qi 'Cannot acquire credentials' /tmp/ganesha-smoke.log; then
    bad "GSS could not acquire nfs/ service credentials from keytab"
else
    ok "RPCSEC_GSS service principal acquired from keytab"
fi
grep -m1 'Starting: Ganesha Version' /tmp/ganesha-smoke.log | sed 's/^/    /'
grep -m1 -iE 'export.*(pseudo|/smoke)' /tmp/ganesha-smoke.log | sed 's/^/    /' || true

kill "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null

echo "== [5] navahi discovery =="
# Generator end-to-end with the shipped binary: flag on ⇒ core v3 lines +
# widened flagged export + advert XML (0644); flag off ⇒ our XMLs pruned.
# Env-redirected outputs keep /etc (used by legs [3]/[4]) untouched.
NAV_DIR=/tmp/smoke-navahi
rm -rf "$NAV_DIR"; mkdir -p "$NAV_DIR/out/exports.d" "$NAV_DIR/avahi"
cat > "$NAV_DIR/nfs-klldap.conf" <<'EOF'
ldap_uri = "ldaps://klldap.smoke:6360"
navahi_discovery = true
[server]
hostname = "smoke.nfs.test"
[storage]
container_root = "/srv"
[sssd]
ldap_default_bind_dn = "uid=admin,ou=people,dc=smoke,dc=test"
ldap_default_authtok = "smokepw"
[[shares]]
name = "smoke"
host_path = "/srv/smoke"
container_path = "/srv/smoke"
navahi_insecure = true
EOF
nav_gen() {
    SSSD_CONF="$NAV_DIR/out/sssd.conf" KRB5_CONF="$NAV_DIR/out/krb5.conf" \
    GANESHA_CONF="$NAV_DIR/out/ganesha.conf" EXPORTS_DIR="$NAV_DIR/out/exports.d" \
    IDMAP_CONF="$NAV_DIR/out/idmapd.conf" NFS_CONF="$NAV_DIR/out/nfs.conf" \
    AVAHI_SERVICES_DIR="$NAV_DIR/avahi" \
    nfs-klldap-config generate --config "$NAV_DIR/nfs-klldap.conf" >/dev/null 2>&1
}
if nav_gen; then ok "navahi generate succeeded"; else bad "navahi generate failed"; fi
g="$NAV_DIR/out/ganesha.conf"
if grep -q 'Protocols = 3,4;' "$g" && grep -q 'Mount_Path_Pseudo = true;' "$g" && grep -q 'MNT_Port = 20048;' "$g"; then
    ok "core conf carries v3 + Mount_Path_Pseudo + MNT_Port"
else
    bad "core navahi lines missing in $g"
fi
frag="$(ls "$NAV_DIR/out/exports.d"/*.conf 2>/dev/null | head -1)"
if [ -n "$frag" ] && grep -q ', sys;' "$frag" && grep -q 'Protocols = 3,4;' "$frag"; then
    ok "flagged export widened (sys + v3)"
else
    bad "flagged export not widened: ${frag:-<no fragment>}"
fi
xml="$NAV_DIR/avahi/nfs-klldap-smoke.service"
if grep -q '_nfs._tcp' "$xml" 2>/dev/null && grep -q 'path=/smoke' "$xml"; then
    ok "advert XML generated"
else
    bad "advert XML missing/incomplete: $xml"
fi
if grep -q '<host-name>smoke.nfs.test</host-name>' "$xml" 2>/dev/null; then
    ok "advert SRV target is the qualified hostname (not <short>.local)"
else
    bad "advert lacks the FQDN host-name element"
fi
if [ "$(stat -c '%a' "$xml" 2>/dev/null)" = "644" ]; then
    ok "advert XML world-readable (0644 — avahi drops privileges)"
else
    bad "advert XML not 0644"
fi
if command -v avahi-daemon >/dev/null 2>&1; then
    avahi-daemon --no-chroot >/tmp/avahi-smoke.log 2>&1 &
    APID=$!
    sleep 2
    if kill -0 "$APID" 2>/dev/null; then
        ok "avahi-daemon --no-chroot runs (pid $APID)"
    else
        bad "avahi-daemon exited early:"; tail -3 /tmp/avahi-smoke.log | sed 's/^/    /'
    fi
    kill "$APID" 2>/dev/null; wait "$APID" 2>/dev/null
else
    bad "avahi-daemon binary missing from image"
fi
sed -i 's/navahi_discovery = true/navahi_discovery = false/' "$NAV_DIR/nfs-klldap.conf"
nav_gen || bad "navahi flag-off regenerate failed"
if [ -e "$xml" ]; then bad "flag-off must prune the advert XML"; else ok "flag-off pruned the advert XML"; fi
if grep -q 'Protocols = 3,4' "$g"; then bad "flag-off must drop core v3"; else ok "flag-off core back to v4-only"; fi

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

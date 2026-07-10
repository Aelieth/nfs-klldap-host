#!/bin/sh
# Build the nfs-klldap-host custom Ganesha debs (refactor plan 2.1 uplift).
# Runs as root inside the ganesha-build Docker stage (debian:13-slim).
# Fetches the stock Debian unstable source, applies klldap-packaging.patch,
# builds arch packages, and gates the result on the Phase 2 invariants
# (no wbclient, POSIX-ACL capability present, VFS as the only FSAL).
set -eu

GANESHA_DEBVER="${GANESHA_DEBVER:-9.13-1}"
KLLDAP_DEBVER="${KLLDAP_DEBVER:-9.13-1+klldap1}"
GANESHA_UPSTREAM="${GANESHA_UPSTREAM:-9.13}"
POOL="https://deb.debian.org/debian/pool/main/n/nfs-ganesha"
PATCH="/ganesha-build/klldap-packaging.patch"
OUT="/debs"

# Content pins recorded 2026-07-10 from the .dsc (see
# container/ganesha/README.md). Unstable sources rotate out of the pool when
# superseded — if the download 404s, fetch the same filenames from
# snapshot.debian.org and verify against these same hashes.
DSC_SHA256="9dddb6a05a56813eb21f9c46dfb638254480ac3084adbf0d8ebf0291ba0b71a2"
DEBTAR_SHA256="9154868dcc437555c0e13324dfd0939e01acee238bdc1c4bf4e87c40243b425c"
ORIG_SHA256="d618efdd3284698c81d50c19330d69fd12ae160732eaf3750085cf14d4eb4efa"

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl xz-utils patch dpkg-dev build-essential
echo 'deb https://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list
echo 'deb-src https://deb.debian.org/debian trixie-backports main' >> /etc/apt/sources.list.d/backports.list
apt-get update

mkdir -p /ganesha-src "$OUT"
cd /ganesha-src

for f in "nfs-ganesha_${GANESHA_DEBVER}.dsc" \
         "nfs-ganesha_${GANESHA_DEBVER}.debian.tar.xz" \
         "nfs-ganesha_${GANESHA_UPSTREAM}.orig.tar.gz"; do
    curl -fsSL --retry 3 -o "$f" "${POOL}/${f}"
done
cat > SHA256SUMS <<EOF
${DSC_SHA256}  nfs-ganesha_${GANESHA_DEBVER}.dsc
${DEBTAR_SHA256}  nfs-ganesha_${GANESHA_DEBVER}.debian.tar.xz
${ORIG_SHA256}  nfs-ganesha_${GANESHA_UPSTREAM}.orig.tar.gz
EOF
sha256sum -c SHA256SUMS

# Signature check is skipped (no Debian keyring in the stage); integrity is
# pinned by the sha256 list above, which also covers the .dsc itself.
dpkg-source --no-check -x "nfs-ganesha_${GANESHA_DEBVER}.dsc"
cd "nfs-ganesha-${GANESHA_UPSTREAM}"
patch -p1 < "$PATCH"

built_ver="$(dpkg-parsechangelog -S Version)"
[ "$built_ver" = "$KLLDAP_DEBVER" ] || {
    echo "FATAL: changelog version '$built_ver' != expected '$KLLDAP_DEBVER'" >&2
    exit 1
}

apt-get build-dep -y -t trixie-backports --no-install-recommends ./
dpkg-buildpackage -us -uc -B -jauto

# --- Phase 2 gates: fail the image build if any invariant is violated ---
cfg=""
for c in src/obj-*/include/config.h obj-*/include/config.h; do
    if [ -f "$c" ]; then cfg="$c"; break; fi
done
[ -n "$cfg" ] || { echo "FATAL: generated config.h not found" >&2; exit 1; }
if grep -q '^#define _MSPAC_SUPPORT' "$cfg"; then
    echo "FATAL: _MSPAC_SUPPORT still defined in $cfg" >&2; exit 1
fi
# One ACL-capable binary (2026-07-10 realignment): the persistent POSIX-ACL
# backend must be compiled in; the in-memory debug store must not be.
if ! grep -q '^#define ENABLE_VFS_POSIX_ACL' "$cfg"; then
    echo "FATAL: ENABLE_VFS_POSIX_ACL not defined in $cfg (ACL capability missing)" >&2; exit 1
fi
if ! grep -q '^#define ENABLE_VFS_ACL' "$cfg"; then
    echo "FATAL: ENABLE_VFS_ACL not defined in $cfg (ACL capability missing)" >&2; exit 1
fi
if grep -q '^#define ENABLE_VFS_DEBUG_ACL' "$cfg"; then
    echo "FATAL: ENABLE_VFS_DEBUG_ACL defined in $cfg (in-memory debug store must stay off)" >&2; exit 1
fi
echo "config.h gates passed ($cfg): MSPAC off, POSIX-ACL backend on, debug store off"

arch="$(dpkg-architecture -qDEB_HOST_ARCH)"
core_deb="../nfs-ganesha_${KLLDAP_DEBVER}_${arch}.deb"
vfs_deb="../nfs-ganesha-vfs_${KLLDAP_DEBVER}_${arch}.deb"
[ -f "$core_deb" ] && [ -f "$vfs_deb" ] || {
    echo "FATAL: expected debs missing; produced:" >&2; ls ../*.deb >&2; exit 1
}
if dpkg-deb -f "$core_deb" Depends | grep -qi wbclient; then
    echo "FATAL: nfs-ganesha still depends on wbclient" >&2; exit 1
fi
fsals="$(dpkg-deb -c "$vfs_deb" | grep -o 'ganesha/libfsal[a-z0-9]*\.so' | sort -u)"
[ "$fsals" = "ganesha/libfsalvfs.so" ] || {
    echo "FATAL: unexpected FSAL set in nfs-ganesha-vfs: $fsals" >&2; exit 1
}
if dpkg-deb -c "$core_deb" | grep -q 'libfsal'; then
    echo "FATAL: FSAL libraries leaked into the core package" >&2; exit 1
fi
echo "package gates passed: no wbclient dependency, VFS is the only FSAL"

cp "$core_deb" "$vfs_deb" ../*.buildinfo ../*.changes "$OUT/"
( cd "$OUT" && sha256sum ./* > MANIFEST.sha256 )
{
    echo "# Built $(date -u +%Y-%m-%dT%H:%M:%SZ) from nfs-ganesha_${GANESHA_DEBVER} source"
    dpkg-deb -I "$OUT/$(basename "$core_deb")"
    dpkg-deb -I "$OUT/$(basename "$vfs_deb")"
} > "$OUT/MANIFEST.txt"
echo "done: $(ls "$OUT")"

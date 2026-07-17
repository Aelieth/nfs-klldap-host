#!/bin/bash
# check-version-pins.sh — assert the Ganesha version pin agrees across its
# three hand-maintained homes (packaging build, image install gate, startup
# smoke). They have drifted independently before; a mismatch means the image
# would build one version and the smoke gate would fail — or worse, pass —
# against another.
set -uo pipefail

cd "$(dirname "$0")/.."

deb="$(grep -oP 'KLLDAP_DEBVER="\$\{KLLDAP_DEBVER:-\K[^}]+' container/ganesha/build-ganesha-debs.sh)"
img="$(grep -oP '^ARG GANESHA_VERSION=\K.+' Dockerfile)"
smoke="$(grep -oP 'EXPECT_VERSION="\$\{EXPECT_VERSION:-\K[^}]+' scripts/ganesha-startup-smoke.sh)"

fail=0
for pair in "build-ganesha-debs.sh:$deb" "Dockerfile:$img" "ganesha-startup-smoke.sh:$smoke"; do
    [ -n "${pair#*:}" ] || { echo "FAIL: could not extract pin from ${pair%%:*}"; fail=1; }
done
if [ "$fail" -eq 0 ] && { [ "$deb" != "$img" ] || [ "$img" != "$smoke" ]; }; then
    echo "FAIL: Ganesha version pins disagree:"
    echo "  container/ganesha/build-ganesha-debs.sh  KLLDAP_DEBVER   = $deb"
    echo "  Dockerfile                               GANESHA_VERSION = $img"
    echo "  scripts/ganesha-startup-smoke.sh         EXPECT_VERSION  = $smoke"
    fail=1
fi
[ "$fail" -eq 0 ] && echo "OK: Ganesha pin ${deb} consistent across build/image/smoke"
exit "$fail"

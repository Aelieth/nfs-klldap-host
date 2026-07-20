#!/bin/sh
# Probe stub for ganesha-ctl id-resolve exercised by check_idhelper_sample_resolutions.
case "$1" in
  id-resolve)
    echo "[ganesha-ctl-stub] id-resolve $2"
    exit 0
    ;;
esac
echo "unknown: $1" >&2
exit 1
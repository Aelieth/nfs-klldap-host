#!/bin/sh
# Probe stub for nfsidmap -g exercised by check_idhelper_sample_resolutions.
while [ $# -gt 0 ]; do
  case "$1" in
    -g|--group)
      shift
      case "$1" in
        host/*) echo "0"; exit 0 ;;
        *) echo "3002"; exit 0 ;;
      esac
      ;;
    -u|--user)
      shift
      echo "3788"
      exit 0
      ;;
  esac
  shift
done
echo "usage" >&2
exit 1
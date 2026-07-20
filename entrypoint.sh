#!/bin/bash
# PID-1 entry: delegate all orchestration to the Rust supervisor.
set -euo pipefail
exec "${STARTUP_BIN:-/usr/local/bin/nfs-klldap-startup}" supervise
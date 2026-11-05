#!/usr/bin/env bash
# EUAG3-MANAGED v6.0
set -Eeuo pipefail
if [[ -f /usr/local/sbin/euag3ctl ]]; then
  exec python3 /usr/local/sbin/euag3ctl uninstall "$@"
fi
cd "$(dirname "$(readlink -f "$0")")"
exec python3 ./euag3ctl.py uninstall "$@"

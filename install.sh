#!/usr/bin/env bash
# EUAG3-MANAGED v6.0
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")"
exec python3 ./euag3ctl.py install "$@"

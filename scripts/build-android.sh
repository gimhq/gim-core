#!/usr/bin/env bash
# Builds the Android artifacts; see bindings/android/build.sh.
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/../bindings/android/build.sh" "$@"

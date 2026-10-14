#!/usr/bin/env bash
# Wrapper for bindings/apple/build-xcframework.sh.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/../bindings/apple/build-xcframework.sh" "$@"

#!/usr/bin/env bash
# Wrapper for bindings/apple/generate-swift.sh.
set -euo pipefail
exec bash "$(dirname "${BASH_SOURCE[0]}")/../bindings/apple/generate-swift.sh" "$@"

#!/usr/bin/env bash
# Compatibility shim (one minor release): moved to packages/node/bootnode/deploy/rolling-update.sh.
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../packages/node/bootnode/deploy/rolling-update.sh" "$@"

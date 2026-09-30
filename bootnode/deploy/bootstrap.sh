#!/usr/bin/env bash
# Compatibility shim (one minor release): moved to packages/node/bootnode/deploy/bootstrap.sh.
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../packages/node/bootnode/deploy/bootstrap.sh" "$@"

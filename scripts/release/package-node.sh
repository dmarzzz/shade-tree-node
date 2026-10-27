#!/usr/bin/env bash
# Package the `shadenet-node` binary of one release build (release.yml, ADR 0014).
#
#   bash scripts/release/package-node.sh <target> <version> [ext]
#
# Writes, under dist/: shadenet-node-<version>-<target><ext> and its .sha256, and appends
# `node=` plus a multi-line `node_artifacts` list to $GITHUB_OUTPUT.
set -euo pipefail

target="${1:?target}"
version="${2:?version}"
ext="${3-}"
dir="target/$target/release"
out="${GITHUB_OUTPUT:-/dev/stdout}"

src="$dir/shadenet-node$ext"
[ -f "$src" ] || {
  echo "no shadenet-node binary in $dir" >&2
  exit 1
}

mkdir -p dist
asset="shadenet-node-$version-$target$ext"
cp "$src" "dist/$asset"
if command -v sha256sum >/dev/null; then hex=$(cd dist && sha256sum "$asset"); else hex=$(cd dist && shasum -a 256 "$asset"); fi
printf '%s  %s\n' "${hex%% *}" "$asset" > "dist/$asset.sha256"
cat "dist/$asset.sha256"

{
  echo "node=dist/$asset"
  echo "node_artifacts<<PATHS"
  echo "dist/$asset"
  echo "PATHS"
} >> "$out"

#!/usr/bin/env bash
# Package the `shadenet-node` and `shadenet-elder` binaries of one release build (release.yml,
# ADR 0014, ADR 0015).
#
#   bash scripts/release/package-node.sh <target> <version> [ext]
#
# Writes, under dist/: shadenet-node-<version>-<target><ext>, shadenet-elder-<version>-<target><ext>
# and their .sha256, and appends `node=`, `elder=` plus a multi-line `node_artifacts` list to
# $GITHUB_OUTPUT.
set -euo pipefail

target="${1:?target}"
version="${2:?version}"
ext="${3-}"
dir="target/$target/release"
out="${GITHUB_OUTPUT:-/dev/stdout}"

mkdir -p dist
artifacts=()
for name in shadenet-node shadenet-elder; do
  src="$dir/$name$ext"
  [ -f "$src" ] || {
    echo "no $name binary in $dir" >&2
    exit 1
  }
  asset="$name-$version-$target$ext"
  cp "$src" "dist/$asset"
  if command -v sha256sum >/dev/null; then hex=$(cd dist && sha256sum "$asset"); else hex=$(cd dist && shasum -a 256 "$asset"); fi
  printf '%s  %s\n' "${hex%% *}" "$asset" > "dist/$asset.sha256"
  cat "dist/$asset.sha256"
  artifacts+=("dist/$asset")
  echo "${name#shadenet-}=dist/$asset" >> "$out"
done

{
  echo "node_artifacts<<PATHS"
  printf '%s\n' "${artifacts[@]}"
  echo "PATHS"
} >> "$out"

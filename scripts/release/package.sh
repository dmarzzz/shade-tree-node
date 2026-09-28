#!/usr/bin/env bash
# Package the CLI binaries of one release build (release.yml).
#
#   bash scripts/release/package.sh <target> <version> <suffix> [ext]
#
# suffix is "" for the default build or "-live". Writes, under dist/:
#   shadenet-<version>-<target><suffix><ext>     and its .sha256
#   shade-tree-<version>-<target><suffix><ext>   and its .sha256 (alias, kept for one minor)
# Each asset comes from the binary of the same name. Until the `shadenet` binary exists, the
# `shade-tree` bytes ship under both names so installers can move to shadenet-* assets now.
# Appends `shadenet=`, `shade_tree=` and a multi-line `artifacts` list to $GITHUB_OUTPUT.
set -euo pipefail

target="${1:?target}"
version="${2:?version}"
suffix="${3-}"
ext="${4-}"
dir="target/$target/release"
out="${GITHUB_OUTPUT:-/dev/stdout}"

mkdir -p dist
[ -f "$dir/shade-tree$ext" ] || [ -f "$dir/shadenet$ext" ] || {
  echo "no CLI binary in $dir" >&2
  exit 1
}

paths=()
for name in shadenet shade-tree; do
  src="$dir/$name$ext"
  if [ ! -f "$src" ]; then
    # Before the rename lands only one binary exists; ship its bytes under both names.
    if [ "$name" = shadenet ]; then src="$dir/shade-tree$ext"; else src="$dir/shadenet$ext"; fi
  fi
  asset="$name-$version-$target$suffix$ext"
  cp "$src" "dist/$asset"
  # sha256sum on linux + windows (git-bash); shasum -a 256 on macOS. Re-framed as
  # "<hex>  <file>" so the .sha256 format is byte-identical across targets.
  if command -v sha256sum >/dev/null; then hex=$(cd dist && sha256sum "$asset"); else hex=$(cd dist && shasum -a 256 "$asset"); fi
  printf '%s  %s\n' "${hex%% *}" "$asset" > "dist/$asset.sha256"
  cat "dist/$asset.sha256"
  paths+=("dist/$asset")
done
ls -l dist

{
  echo "shadenet=${paths[0]}"
  echo "shade_tree=${paths[1]}"
  echo "artifacts<<PATHS"
  printf '%s\n' "${paths[@]}"
  echo "PATHS"
} >> "$out"

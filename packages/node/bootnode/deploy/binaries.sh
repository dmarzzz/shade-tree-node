#!/usr/bin/env bash
# The Rust service binaries a deploy runs (ADR 0014, ADR 0015): shadenet-node and shadenet-elder
# from the GitHub release of the checkout's version, verified against a pinned sha256 and
# installed under /usr/local/bin. Sourced by bootstrap.sh and rolling-update.sh after the clone,
# so the pins come from the checked-out commit.
#
# Tunables (env):
#   SHADENET_VERSION        release to install        (default: the checkout's package.json version)
#   SHADENET_NODE_SHA256 / SHADENET_ELDER_SHA256   sha256 of the two release assets for this host's
#                           target; required for a version that is not pinned below
#   SHADENET_NODE_BIN / SHADENET_ELDER_BIN         local binaries to install instead of downloading
#                           (a build of this checkout; the e2e containers pass these)
#   SHADENET_RELEASES       release download base     (default: this repository's GitHub releases)
#
# Pinned sha256 of the release assets shadenet-<name>-<version>-<target>, computed from the
# downloaded assets after the release workflow published them. A version that is not here needs
# both SHADENET_*_SHA256 (no unpinned download, ever).
shadenet_pinned_sha256() {  # $1 = node|elder, $2 = version, $3 = target -> echoes sha256 or nothing
  case "$1:$2:$3" in
    *) ;;
  esac
}

shadenet_release_target() {  # the release target of this host, or failure
  case "$(uname -m)" in
    x86_64) echo x86_64-unknown-linux-musl ;;
    aarch64|arm64) echo aarch64-unknown-linux-musl ;;
    *) return 1 ;;
  esac
}

# $1 = checkout dir. Installs both binaries; one whose --version already reports the wanted
# version is left alone.
install_shadenet_binaries() {
  local checkout="$1" version target name upper local_bin want_sha installed asset tmp url
  version="${SHADENET_VERSION:-$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' "$checkout/package.json" | head -n 1)}"
  version="${version#v}"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] \
    || { echo "binaries.sh: SHADENET_VERSION must be a release version like 0.8.0 (got '$version')" >&2; return 1; }
  target="$(shadenet_release_target)" \
    || { echo "binaries.sh: no release build for $(uname -m); pass SHADENET_NODE_BIN and SHADENET_ELDER_BIN" >&2; return 1; }
  for name in node elder; do
    upper="$(echo "$name" | tr '[:lower:]' '[:upper:]')"
    installed="/usr/local/bin/shadenet-$name"
    local_bin="SHADENET_${upper}_BIN"; local_bin="${!local_bin:-}"
    if [ -n "$local_bin" ]; then
      [ -x "$local_bin" ] || { echo "binaries.sh: SHADENET_${upper}_BIN=$local_bin is not an executable file" >&2; return 1; }
      install -o root -g root -m 0755 "$local_bin" "$installed"
      "$installed" --version
      continue
    fi
    if [ -x "$installed" ] && "$installed" --version 2>/dev/null | grep -q "^shadenet-$name $version "; then
      echo "shadenet-$name $version already installed at $installed"
      continue
    fi
    want_sha="SHADENET_${upper}_SHA256"; want_sha="${!want_sha:-}"
    want_sha="${want_sha:-$(shadenet_pinned_sha256 "$name" "$version" "$target")}"
    [ -n "$want_sha" ] \
      || { echo "binaries.sh: no pinned sha256 for shadenet-$name $version ($target); pass SHADENET_${upper}_SHA256=<sha256 of the release asset> or SHADENET_${upper}_BIN=<a local build>" >&2; return 1; }
    [[ "$want_sha" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "binaries.sh: SHADENET_${upper}_SHA256 must be 64 hex chars" >&2; return 1; }
    asset="shadenet-$name-$version-$target"
    url="${SHADENET_RELEASES:-https://github.com/dmarzzz/shade-tree-node/releases/download}/v$version/$asset"
    tmp="$(mktemp)"
    curl -fsSL --proto '=https' --retry 3 "$url" -o "$tmp" \
      || { rm -f "$tmp"; echo "binaries.sh: could not download $url" >&2; return 1; }
    echo "${want_sha,,}  $tmp" | sha256sum -c --quiet - \
      || { rm -f "$tmp"; echo "binaries.sh: $asset sha256 mismatch (want $want_sha); refusing to install" >&2; return 1; }
    install -o root -g root -m 0755 "$tmp" "$installed"
    rm -f "$tmp"
    "$installed" --version
  done
}

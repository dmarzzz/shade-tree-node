#!/bin/sh
# install.sh: one-line installer for the prebuilt Rust `shade-tree` client (issue #64).
#
#   curl -q -fsSL --proto '=https' --proto-redir '=https' \
#     https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh | sh
#
# What it does, in order: detect OS/arch, resolve the release tag, refuse to replace a symlink
# at the destination (unless forced), download the matching release asset AND its .sha256,
# verify the checksum, and only then place the binary in ~/.local/bin (or
# $SHADE_TREE_INSTALL_DIR). It never uses sudo, never executes a byte it has not verified, and
# never fetches a binary over cleartext from the network.
#
# Knobs (environment; `curl | sh` cannot take flags):
#   SHADE_TREE_VERSION       release tag to install (`v0.6.0` or `0.6.0`); default: latest
#   SHADE_TREE_LIVE=auto     install the `-live` agent where published (default); use 0 for
#                            the verifier-only binary or 1 to require a live binary
#   SHADE_TREE_INSTALL_DIR   destination directory; default $HOME/.local/bin
#   SHADE_TREE_FORCE=1       replace a destination that is a symlink to a file
#   SHADE_TREE_TARGET        skip detection; one of the seven published targets
#   SHADE_TREE_LIBC=gnu|musl choose the Linux libc when it cannot be detected
#   SHADE_TREE_RELEASE_BASE  where releases live; default the GitHub Releases page. Must be
#                            https://; file:// / loopback http:// exist only for offline tests.
#
# Asset naming comes from .github/workflows/release.yml:
#   shade-tree-<version>-<target>[-live][.exe]   plus   <asset>.sha256   ("<hex>  <file>")
#
# POSIX sh only (dash, bash --posix, BusyBox ash, Git Bash): no arrays, no [[ ]], no
# pipefail, no local.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
# Single-quote a value for copy-paste into any POSIX shell (a path with spaces or quotes).
shquote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

usage() {
  cat <<'EOF'
usage: sh install.sh            (or: curl -q -fsSL --proto '=https' --proto-redir '=https' <https url> | sh)

Installs the prebuilt Rust `shade-tree` client from a GitHub Release into ~/.local/bin after
verifying its sha256 against the published .sha256 asset. No sudo, ever.

environment:
  SHADE_TREE_VERSION=v0.6.0     pin a release (default: latest)
  SHADE_TREE_LIVE=auto          default: -live agent where published, verifier otherwise;
                                1 requires -live, 0 installs the verifier-only binary
  SHADE_TREE_INSTALL_DIR=DIR    destination (default: $HOME/.local/bin)
  SHADE_TREE_FORCE=1            replace a destination that is a symlink to a file
  SHADE_TREE_TARGET=TRIPLE      skip OS/arch detection (one of the seven published targets)
  SHADE_TREE_LIBC=gnu|musl      choose the Linux libc when it cannot be detected
  SHADE_TREE_RELEASE_BASE=URL   https:// release base (local schemes are test-only)

Prefer to inspect before running? Download the script, read it, then `sh install.sh`.
Windows: works from Git Bash or MSYS2 (x86_64 only); see rust/INSTALL.md for PowerShell.
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) die "unknown argument '$1' (this installer is configured through SHADE_TREE_* variables; -h for help)" ;;
esac

REPO_BASE_DEFAULT="https://github.com/dmarzzz/shade-tree-node/releases"
BASE="${SHADE_TREE_RELEASE_BASE:-$REPO_BASE_DEFAULT}"
LIVE="${SHADE_TREE_LIVE:-auto}"
FORCE="${SHADE_TREE_FORCE:-0}"
if [ -n "${SHADE_TREE_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$SHADE_TREE_INSTALL_DIR"
else
  [ -n "${HOME:-}" ] || die "HOME is unset; set SHADE_TREE_INSTALL_DIR to choose a destination"
  INSTALL_DIR="$HOME/.local/bin"
fi

# A typo such as SHADE_TREE_LIVE=yes must not quietly install the wrong variant.
case "$LIVE" in auto|0|1) ;; *) die "SHADE_TREE_LIVE must be auto, 1, or 0 (got '$LIVE')" ;; esac
case "$FORCE" in 0|1) ;; *) die "SHADE_TREE_FORCE must be 1 or 0 (got '$FORCE')" ;; esac

# --- prerequisites -------------------------------------------------------------------------
command -v curl >/dev/null 2>&1 || die "curl is required (install it with your package manager, then rerun)"
command -v mktemp >/dev/null 2>&1 || die "mktemp is required"

# Pick a sha256 tool once. Which one exists differs by platform: sha256sum (coreutils, BusyBox,
# Git Bash), shasum (macOS, perl), openssl (almost everywhere). Each is only ever fed a path.
if command -v sha256sum >/dev/null 2>&1; then SHA_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then SHA_TOOL=shasum
elif command -v openssl >/dev/null 2>&1; then SHA_TOOL=openssl
else die "no sha256 tool found (need sha256sum, shasum, or openssl); refusing to install unverified"
fi

# Each tool prints the digest in a different frame: "<hex>  <file>" for the first two,
# "SHA256(<file>)= <hex>" for openssl. Only the hex is returned.
sha256_of() {
  case "$SHA_TOOL" in
    sha256sum) sha256sum "$1" | { read -r hex _; printf '%s' "$hex"; } ;;
    shasum)    shasum -a 256 "$1" | { read -r hex _; printf '%s' "$hex"; } ;;
    openssl)   openssl dgst -sha256 "$1" | sed 's/^.*= *//' | tr -d '\n' ;;
  esac
}

# --- release base: refuse cleartext from the network before touching it -------------------
# A binary fetched over plain http can be swapped in transit, and its .sha256 with it; the
# checksum then proves nothing. file:// and loopback http:// exist so the selftest can run
# offline against a fake release tree. The loopback authority is parsed strictly: no
# user-info (curl would connect to whatever follows the "@"), the exact host, an optional
# numeric port, nothing else.
case "$BASE" in
  https://*) PROTO="https" ;;
  file://*)  PROTO="file" ;;
  http://*)
    AUTHORITY="${BASE#http://}"
    AUTHORITY="${AUTHORITY%%/*}"
    case "$AUTHORITY" in
      *@*) die "SHADE_TREE_RELEASE_BASE must use https (got '$BASE'); cleartext http is allowed only to 127.0.0.1, localhost, or [::1], with no user-info" ;;
    esac
    HOSTPART="$AUTHORITY"
    PORTPART=""
    case "$AUTHORITY" in
      "[::1]")   ;;
      "[::1]:"*) HOSTPART="[::1]"; PORTPART="${AUTHORITY#\[::1\]:}" ;;
      *:*)       HOSTPART="${AUTHORITY%%:*}"; PORTPART="${AUTHORITY#*:}" ;;
    esac
    case "$HOSTPART" in
      127.0.0.1|localhost|"[::1]") ;;
      *) die "SHADE_TREE_RELEASE_BASE must use https (got '$BASE'); cleartext http is allowed only to 127.0.0.1, localhost, or [::1]" ;;
    esac
    case "$AUTHORITY" in *:) die "malformed port in SHADE_TREE_RELEASE_BASE ('$AUTHORITY')" ;; esac
    if [ -n "$PORTPART" ]; then
      case "$PORTPART" in *[!0-9]*) die "malformed port in SHADE_TREE_RELEASE_BASE ('$AUTHORITY')" ;; esac
      if [ "$PORTPART" -lt 1 ] || [ "$PORTPART" -gt 65535 ]; then
        die "port out of range in SHADE_TREE_RELEASE_BASE ('$AUTHORITY')"
      fi
    fi
    PROTO=http ;;
  *) die "SHADE_TREE_RELEASE_BASE must be an https:// URL (got '$BASE')" ;;
esac
BASE="${BASE%/}"

# Every fetch: fail on HTTP errors (-f), follow only https redirects (GitHub serves assets
# from objects.githubusercontent.com), allow exactly the scheme of the configured base, and
# never send a loopback request through an ambient http_proxy.
curl_get() {
  if [ "$PROTO" = http ]; then
    curl -q -fsSL --retry 2 --connect-timeout 20 --max-time 600 --proto "=$PROTO" --proto-redir "=https" --noproxy '*' "$@"
  else
    curl -q -fsSL --retry 2 --connect-timeout 20 --max-time 600 --proto "=$PROTO" --proto-redir "=https" "$@"
  fi
}
curl_head() {
  if [ "$PROTO" = http ]; then
    curl -q -fsSI --connect-timeout 20 --max-time 60 --proto "=$PROTO" --noproxy '*' "$@"
  else
    curl -q -fsSI --connect-timeout 20 --max-time 60 --proto "=$PROTO" "$@"
  fi
}
# Turn a curl exit code into the remedy the user actually needs. 22 is the only "the server
# answered and said no" code; everything else is transport, and "asset not found" would send
# someone to check their version instead of their network.
explain_curl() {
  case "$1" in
    22) printf 'HTTP error %s' "$2" ;;
    37) printf 'file not found' ;;
    6)  printf 'could not resolve host (DNS)' ;;
    7)  printf 'could not connect' ;;
    28) printf 'timed out' ;;
    35|60) printf 'TLS handshake or certificate failure' ;;
    *)  printf 'curl exit %s' "$1" ;;
  esac
}

# --- target ---------------------------------------------------------------------------------
detect_libc() {
  # Positive identification only. glibc's ldd says "GNU libc"; musl's says "musl libc" (on
  # stderr, exit 1). Without ldd, the dynamic loader's file name is the next best witness.
  # No guess otherwise: a GNU binary "installs fine" on a musl host and then fails to exec.
  if command -v ldd >/dev/null 2>&1; then
    case "$(ldd --version 2>&1 || true)" in
      *musl*) printf musl; return ;;
      *GNU*|*glibc*) printf gnu; return ;;
    esac
  fi
  if [ -f /etc/alpine-release ] || ls /lib/ld-musl-*.so* >/dev/null 2>&1; then printf musl; return; fi
  if ls /lib/ld-linux*.so* /lib64/ld-linux*.so* /lib/*/ld-linux*.so* >/dev/null 2>&1; then printf gnu; return; fi
  printf ''
}

if [ -n "${SHADE_TREE_TARGET:-}" ]; then
  TARGET="$SHADE_TREE_TARGET"
  say "target: $TARGET (SHADE_TREE_TARGET)"
else
  OS="$(uname -s 2>/dev/null || echo unknown)"
  ARCH="$(uname -m 2>/dev/null || echo unknown)"
  case "$ARCH" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported CPU architecture '$ARCH' (releases cover x86_64 and aarch64); see rust/INSTALL.md to build from source" ;;
  esac
  case "$OS" in
    Darwin)
      # An Apple Silicon Mac running an x86_64 shell under Rosetta reports x86_64 from uname.
      # Apple's sysctl flag is the authoritative way to distinguish that from an Intel Mac.
      if [ "$ARCH" = x86_64 ] && command -v sysctl >/dev/null 2>&1; then
        case "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" in
          1) ARCH=aarch64; say "note: Rosetta translation detected; selecting the Apple Silicon release" ;;
        esac
      fi
      TARGET="$ARCH-apple-darwin" ;;
    Linux)
      LIBC="${SHADE_TREE_LIBC:-}"
      [ -n "$LIBC" ] || LIBC="$(detect_libc)"
      [ -n "$LIBC" ] || die "cannot tell glibc from musl on this Linux host (no ldd, no known loader); set SHADE_TREE_LIBC=gnu or SHADE_TREE_LIBC=musl"
      case "$LIBC" in gnu|musl) ;; *) die "SHADE_TREE_LIBC must be gnu or musl (got '$LIBC')" ;; esac
      TARGET="$ARCH-unknown-linux-$LIBC" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      # Git Bash / MSYS2 give a POSIX sh with curl and sha256sum; the asset is the MSVC .exe.
      [ "$ARCH" = x86_64 ] || die "Windows releases cover x86_64 only (got '$ARCH'); see rust/INSTALL.md"
      TARGET="x86_64-pc-windows-msvc" ;;
    *) die "unsupported OS '$OS' (releases cover Linux, macOS, and Windows); see rust/INSTALL.md to build from source" ;;
  esac
  say "target: $TARGET (detected)"
fi
# The seven targets release.yml publishes. An exact allowlist means a typo, or a "-live"
# smuggled into the target to dodge SHADE_TREE_LIVE, fails here instead of naming an asset
# that happens to exist. A new target in release.yml needs a line here too.
case "$TARGET" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-unknown-linux-musl|x86_64-apple-darwin|aarch64-apple-darwin|x86_64-pc-windows-msvc) ;;
  *) die "'$TARGET' is not a published target; choose one of x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, x86_64-apple-darwin, aarch64-apple-darwin, x86_64-pc-windows-msvc (SHADE_TREE_LIVE=1 selects the -live variant)" ;;
esac
case "$TARGET" in *windows*) EXT=.exe ;; *) EXT= ;; esac

# --- version ---------------------------------------------------------------------------------
if [ -n "${SHADE_TREE_VERSION:-}" ]; then
  VERSION="${SHADE_TREE_VERSION#v}"
  TAG="v$VERSION"
  say "release: $TAG (SHADE_TREE_VERSION)"
else
  if [ "$PROTO" = file ]; then
    die "SHADE_TREE_VERSION is required with a file:// release base (no 'latest' redirect to follow)"
  fi
  # GitHub answers /releases/latest with a 302 to /releases/tag/<tag>. Reading the Location
  # header needs no API token and no JSON parser.
  LOCATION="$(curl_head -o /dev/null -w '%{redirect_url}' "$BASE/latest" || true)"
  TAG="${LOCATION##*/tag/}"
  if [ -z "$LOCATION" ] || [ "$TAG" = "$LOCATION" ]; then
    die "could not resolve the latest release from $BASE/latest (set SHADE_TREE_VERSION to pin one)"
  fi
  VERSION="${TAG#v}"
  say "release: $TAG (latest)"
fi
case "$TAG" in
  v[0-9]*) ;;
  *) die "unexpected release tag '$TAG'" ;;
esac
case "$VERSION" in
  ''|*[!0-9A-Za-z.+-]*) die "unexpected release version '$VERSION'" ;;
esac

# --- destination preflight (before any download) ------------------------------------------
# A symlink at the destination is refused unless explicitly forced. A symlink to a DIRECTORY is
# refused even then: `mv` would follow it and drop the binary inside. A regular file there is
# replaced with a note so rerunning the installer can upgrade it. Anything else (a directory,
# a device) is refused.
BIN_NAME="shade-tree$EXT"
DEST="$INSTALL_DIR/$BIN_NAME"
check_destination() {
  if [ -L "$DEST" ]; then
    [ ! -d "$DEST" ] || die "$DEST is a symlink to a directory; refusing to install through it. Remove it or choose another SHADE_TREE_INSTALL_DIR"
    [ "$FORCE" = 1 ] || die "$DEST is a symlink; refusing to replace it. Use another SHADE_TREE_INSTALL_DIR, or SHADE_TREE_FORCE=1 to replace it explicitly"
  elif [ -e "$DEST" ] && [ ! -f "$DEST" ]; then
    die "$DEST exists and is not a regular file; refusing to replace it"
  fi
}
check_destination
if [ -L "$DEST" ]; then say "note: will replace symlink $DEST (SHADE_TREE_FORCE=1)"
elif [ -f "$DEST" ]; then say "note: will replace existing $DEST"
fi
mkdir -p "$INSTALL_DIR" || die "cannot create $INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "$INSTALL_DIR is not writable (choose another SHADE_TREE_INSTALL_DIR; this installer never uses sudo)"

# --- asset ------------------------------------------------------------------------------------
TMP="$(mktemp -d "${TMPDIR:-/tmp}/shade-tree-install.XXXXXX")"
STAGE=""
# Whatever happens next (checksum mismatch, Ctrl-C, a failed download), the partial files go,
# including the staging file inside the destination directory once it exists.
cleanup() { rm -rf "$TMP"; [ -n "$STAGE" ] && rm -f "$STAGE"; return 0; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# `auto` probes the selected release instead of assuming every tag has the current target
# matrix. It falls back only for a genuine 404/file-not-found. Network, TLS, and integrity
# failures remain fail-closed. An explicit SHADE_TREE_LIVE=1 never falls back.
select_asset() {
  SUFFIX=
  [ "$LIVE" != 0 ] && SUFFIX=-live
  ASSET="shade-tree-$VERSION-$TARGET$SUFFIX$EXT"
  URL="$BASE/download/$TAG/$ASSET"
}
fetch_to() {
  FETCH_CODE="$(curl_get -w '%{http_code}' -o "$2" "$1" 2>/dev/null)"
}
fetch_variant() {
  FETCH_WHAT="$ASSET.sha256"
  if fetch_to "$URL.sha256" "$TMP/$ASSET.sha256"; then :; else FETCH_RC=$?; return "$FETCH_RC"; fi
  FETCH_WHAT="$ASSET"
  if fetch_to "$URL" "$TMP/$ASSET"; then :; else FETCH_RC=$?; return "$FETCH_RC"; fi
}
fetch_was_missing() {
  [ "$1" = 37 ] || { [ "$1" = 22 ] && [ "$FETCH_CODE" = 404 ]; }
}

select_asset
say "asset: $ASSET"
if fetch_variant; then
  [ "$LIVE" != auto ] || LIVE=1
else
  RC=$?
  if fetch_was_missing "$RC"; then
    if [ "$LIVE" = auto ]; then
      say "note: no -live asset for $TARGET in $TAG ($FETCH_WHAT not found);"
      say "      installing the verifier-only binary from that release"
      if [ "$TARGET" = x86_64-apple-darwin ]; then
        say "      (Intel macOS cannot use this release for live tunneling; see rust/INSTALL.md)"
      fi
      LIVE=0
      select_asset
      say "asset: $ASSET"
      if fetch_variant; then
        :
      else
        RC=$?
        if fetch_was_missing "$RC"; then
          die "release asset $FETCH_WHAT not found (wrong SHADE_TREE_VERSION or SHADE_TREE_TARGET?)"
        fi
        die "could not fetch $FETCH_WHAT: $(explain_curl "$RC" "$FETCH_CODE"). Check your network or SHADE_TREE_RELEASE_BASE and retry"
      fi
    elif [ "$LIVE" = 1 ]; then
      if [ "$TARGET" = x86_64-apple-darwin ]; then
        die "no -live asset for $TARGET in $TAG ($FETCH_WHAT not found); Intel macOS releases may be verifier-only. Set SHADE_TREE_LIVE=0 or see rust/INSTALL.md"
      fi
      die "no -live asset for $TARGET in $TAG ($FETCH_WHAT not found). Set SHADE_TREE_LIVE=0 for the verifier-only build or see rust/INSTALL.md"
    else
      die "release asset $FETCH_WHAT not found (wrong SHADE_TREE_VERSION or SHADE_TREE_TARGET?)"
    fi
  else
    die "could not fetch $FETCH_WHAT: $(explain_curl "$RC" "$FETCH_CODE"). Check your network or SHADE_TREE_RELEASE_BASE and retry"
  fi
fi

# --- verify (the whole point) -------------------------------------------------------------
# The .sha256 line is "<hex>  <file>" (release.yml frames it by hand so every target matches).
# Both halves are checked: the hex against the bytes, and the file name against the asset we
# asked for, so a .sha256 swapped in from another asset cannot vouch for this one.
read -r EXPECTED EXPECTED_NAME _ < "$TMP/$ASSET.sha256" || true
EXPECTED="$(printf '%s' "${EXPECTED:-}" | tr 'A-F' 'a-f')"
EXPECTED_NAME="${EXPECTED_NAME#\*}"
case "$EXPECTED" in
  ????????????????????????????????????????????????????????????????) ;;
  *) die "malformed $ASSET.sha256 (expected '<64 hex>  <file>'); refusing to install" ;;
esac
case "$EXPECTED" in *[!0-9a-f]*) die "malformed $ASSET.sha256 (non-hex digest); refusing to install" ;; esac
[ "$EXPECTED_NAME" = "$ASSET" ] || die "$ASSET.sha256 names '$EXPECTED_NAME', not '$ASSET'; refusing to install"
ACTUAL="$(sha256_of "$TMP/$ASSET" | tr 'A-F' 'a-f')"
[ "$ACTUAL" = "$EXPECTED" ] || die "checksum mismatch for $ASSET (expected $EXPECTED, got $ACTUAL); refusing to install"
say "verified transfer integrity: sha256 $ACTUAL"

# --- install (only now does the file get an executable bit) --------------------------------
# Stage in an exclusive temp file inside the destination directory (so the final rename is a
# same-filesystem replace and a reader never sees a half-written binary), never at a name an
# attacker could pre-create. The destination is re-checked right before the rename: the
# download took time, and an approved file symlink is removed explicitly so `mv` replaces the
# link itself rather than following it.
STAGE="$(mktemp "$INSTALL_DIR/.shade-tree.XXXXXX")" || die "cannot create a staging file in $INSTALL_DIR"
cp "$TMP/$ASSET" "$STAGE"
chmod 0755 "$STAGE"
check_destination
if [ -L "$DEST" ]; then rm -f "$DEST" || die "cannot remove symlink $DEST"; fi
mv -f "$STAGE" "$DEST"
STAGE=""
if [ ! -f "$DEST" ] || [ -L "$DEST" ] || [ ! -x "$DEST" ]; then
  die "$DEST is not the installed executable after the rename; refusing to report success"
fi
say "installed: $DEST ($TAG, $TARGET${SUFFIX:+, live})"

# --- after-care -------------------------------------------------------------------------------
QDEST="$(shquote "$DEST")"
QDIR="$(shquote "$INSTALL_DIR")"

# macOS only stamps a quarantine attribute on files saved by browsers, not by curl; mention
# the fix anyway if it is there, since the checksum already vouched for the bytes.
if command -v xattr >/dev/null 2>&1 && xattr -p com.apple.quarantine "$DEST" >/dev/null 2>&1; then
  say "note: macOS quarantined the file; the checksum verified, so you can clear it with:"
  say "  xattr -d com.apple.quarantine $QDEST"
fi

# Walk the whole PATH rather than asking `command -v`, which only reports the winner and would
# stay silent about another installation behind the directory we just installed into.
OTHERS=""
SAVED_IFS="$IFS"
IFS=:
set -f
for d in $PATH; do
  [ -n "$d" ] || continue
  for cand in "$d/shade-tree" "$d/shade-tree.exe"; do
    [ -x "$cand" ] && [ "$cand" != "$DEST" ] && OTHERS="$OTHERS $cand"
  done
done
set +f
IFS="$SAVED_IFS"
if [ -n "$OTHERS" ]; then
  FIRST="$(command -v shade-tree 2>/dev/null || true)"
  say "warning: other shade-tree executables are on PATH:$OTHERS"
  if [ "$FIRST" = "$DEST" ]; then
    say "         Your shell will run this Rust client first and shadow them."
  else
    say "         Your shell will run $FIRST first and shadow $DEST; call the Rust client by its"
    say "         full path, or put $INSTALL_DIR earlier in PATH."
  fi
fi

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: $INSTALL_DIR is not on your PATH. Add it for this shell with:"
     say "  export PATH=$QDIR:\"\$PATH\"" ;;
esac

say ""
say "warning: Shade Tree is a research preview with testnet-only, unaudited RLN setup artifacts;"
say "         do not use it as a production anonymity or security boundary."
say "note: the checksum establishes transfer integrity, not publisher provenance;"
say "      verify the GitHub build attestation when provenance matters (rust/INSTALL.md)."
say ""
say "next:"
say "  $QDEST --help"
if [ "$LIVE" = 1 ]; then
  say "  # Create the owner-only identity locally; send only public-leaf.txt to the operator:"
  say "  read -r SHADE_TREE_LIMIT"
  say "  $QDEST enroll --limit \"\$SHADE_TREE_LIMIT\" --out identity.json > public-leaf.txt"
  say "  # After admission, use the operator's member set, Elder onion, and signer pin:"
  say "  $QDEST proxy --bootnode-onion <elder.onion> --signer <canopy-signer-hex> \\"
  say "    --identity identity.json --members members.json --listen 127.0.0.1:8118"
  say "  # Slot allocation is automatic and safely coordinated by default; see rust/INSTALL.md."
else
  say "  $QDEST verify-directory directory.json --signer <canopy-signer-hex>"
  say "  (tunneling needs a -live build, which is not published for Intel macOS)"
fi

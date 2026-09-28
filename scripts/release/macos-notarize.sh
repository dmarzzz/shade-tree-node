#!/usr/bin/env bash
# Sign and notarize macOS release binaries in place (HYG-20), before packaging.
#
#   bash scripts/release/macos-notarize.sh <binary>...
#
# Needs these repository secrets, passed as env; without them it signs nothing, says so,
# and the binaries ship unsigned (provenance is still verifiable with
# `gh attestation verify`):
#   APPLE_CERT_P12_BASE64   Developer ID Application certificate + key, base64 .p12
#   APPLE_CERT_PASSWORD     its password
#   APPLE_SIGNING_IDENTITY  e.g. "Developer ID Application: Name (TEAMID)"
#   APPLE_NOTARY_KEY_P8_BASE64, APPLE_NOTARY_KEY_ID, APPLE_NOTARY_ISSUER_ID
#                           App Store Connect API key for notarytool
#
# Bare Mach-O binaries can't be stapled; Gatekeeper finds the ticket online.
set -euo pipefail

if [ -z "${APPLE_CERT_P12_BASE64:-}" ] || [ -z "${APPLE_NOTARY_KEY_P8_BASE64:-}" ]; then
  echo "::notice::macOS signing credentials are not configured; shipping unsigned binaries (verify with gh attestation verify)"
  exit 0
fi

here="$(cd "$(dirname "$0")" && pwd)"
tmp="${RUNNER_TEMP:?}"
keychain="$tmp/signing.keychain-db"
kpass="$(openssl rand -hex 24)"
cleanup() {
  security delete-keychain "$keychain" 2>/dev/null || true
  rm -f "$tmp/cert.p12" "$tmp/notary.p8"
}
trap cleanup EXIT

printf '%s' "$APPLE_CERT_P12_BASE64" | base64 --decode > "$tmp/cert.p12"
printf '%s' "$APPLE_NOTARY_KEY_P8_BASE64" | base64 --decode > "$tmp/notary.p8"
security create-keychain -p "$kpass" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$kpass" "$keychain"
security import "$tmp/cert.p12" -P "$APPLE_CERT_PASSWORD" -A -t cert -f pkcs12 -k "$keychain"
security set-key-partition-list -S apple-tool:,apple: -s -k "$kpass" "$keychain" >/dev/null
# shellcheck disable=SC2046
security list-keychains -d user -s "$keychain" $(security list-keychains -d user | tr -d '"')

for bin in "$@"; do
  [ -f "$bin" ] || continue
  # Hardened runtime with JIT allowed: the live prover runs circuits under wasmer.
  codesign --force --options runtime --timestamp \
    --entitlements "$here/macos-entitlements.plist" \
    --sign "$APPLE_SIGNING_IDENTITY" "$bin"
  codesign --verify --strict --verbose=2 "$bin"
  zip -j -q "$tmp/notarize.zip" "$bin"
  xcrun notarytool submit "$tmp/notarize.zip" \
    --key "$tmp/notary.p8" --key-id "$APPLE_NOTARY_KEY_ID" --issuer "$APPLE_NOTARY_ISSUER_ID" \
    --wait --timeout 30m
  rm -f "$tmp/notarize.zip"
done

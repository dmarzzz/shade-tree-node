#!/bin/sh
# curl through the local ShadeNet proxy.
#   shadenet proxy &      # once, or as a service
#   sh examples/curl.sh https://api.ipify.org?format=json
set -eu
URL="${1:-https://api.ipify.org?format=json}"
TOKEN_FILE="${SHADENET_PROXY_TOKEN_FILE:-$HOME/.config/shadenet/proxy-token}"
TOKEN="$(cat "$TOKEN_FILE")"

# -i shows the status line: a refusal is 403/429/502/503 with X-ShadeNet-Error and a JSON body.
curl -si -x "http://shadenet:$TOKEN@127.0.0.1:8118" "$URL"
echo
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8118/_shadenet/status

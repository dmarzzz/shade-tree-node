#!/usr/bin/env python3
"""Fetch through the local ShadeNet proxy with httpx.

    pip install 'httpx[http2]'
    shadenet proxy &                      # once, or as a service
    python3 examples/python-httpx.py 'https://api.ipify.org?format=json'

One httpx.Client keeps one tunnel open for many requests to the same host
(keep-alive and HTTP/2), which matters: every new tunnel spends one slot of a
small per-epoch budget.
"""

import json
import os
import sys

import httpx

token_file = os.environ.get(
    "SHADENET_PROXY_TOKEN_FILE", os.path.expanduser("~/.config/shadenet/proxy-token")
)
token = os.environ.get("SHADENET_PROXY_TOKEN") or open(token_file).read().strip()
proxy = f"http://shadenet:{token}@127.0.0.1:8118"
url = sys.argv[1] if len(sys.argv) > 1 else "https://api.ipify.org?format=json"

with httpx.Client(proxy=proxy, http2=True, timeout=60) as client:
    try:
        response = client.get(url)
    except httpx.ProxyError as error:
        # A refused CONNECT carries a JSON body with a stable code; httpx surfaces the status.
        sys.exit(f"proxy refused the tunnel: {error}")
    print(response.status_code, response.headers.get("content-type"))
    print(response.text[:2000])

# The proxy's own status, for budgeting:
status = httpx.get(
    "http://127.0.0.1:8118/_shadenet/status",
    headers={"Authorization": f"Bearer {token}"},
    timeout=60,
).json()
print(json.dumps({k: status[k] for k in ("state", "slotsLeft", "epochResetsInSeconds")}))

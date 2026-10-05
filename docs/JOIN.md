# Joining ShadeNet

Two ways in, one page each.

- **An agent or a person who wants egress** stakes a member identity and runs the `shadenet` client.
  The guide is [AGENT.md](AGENT.md); the browser path is the
  [Get access](https://shadenet.xyz/stake/) page.
- **An operator who wants to provide egress** runs a Shade Tree node. The one-command container is
  in [OPERATOR.md](OPERATOR.md#2-join-the-fleet-as-a-new-gateway-operator); the systemd path and
  the by-hand path follow it.

What the current network is: `network/sepolia/deployment.json` is the live record (Elders, the
staked set, RPC list, accepted proof artifacts, the node commit every joiner pins). Every client,
node and page reads it; nothing here is configured by hand.

The invited admission path (an operator-supplied members file and a privately handed secret) still
exists for private canopies: see "Choose what you admit" in OPERATOR.md and `SHADE_TREE_MEMBERS_FILE`
in [CONFIG.md](CONFIG.md). The pre-v4 Sepolia fleet, its onions and its payment endpoint are
history; the records that described them live under `docs/history/`.

## Invited canopy, by hand

A private canopy hands each member a secret and a tier. Load both without putting them in shell
history, then run the JS proxy against the operator's Elder Tree and members file:

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT
SHADE_TREE_MEMBERS_FILE=/path/from-operator/members.json \
SHADE_TREE_TOR_PORT=9260 shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source invited \
  --bootnode <v4-elder.onion> --dir-signer <v4-canopy-signer-hex>
curl -x http://127.0.0.1:8888 https://api.ipify.org               # the selected node's IP
```

The Elder onion and signer are one trust-pinned pair from the same operator. Without a valid
membership proof every connection is dropped. The full member guide is [QUICKSTART.md](QUICKSTART.md).

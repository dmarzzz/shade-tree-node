# you've been handed a key

Someone added you to a private reputation set. The key lets you prove membership to an egress
node without sending the node your leaf identity. The node still sees the destination, timing,
lifetime, and traffic volume.

Public docs call the local protocol client the **Proxy**, the egress gateway a **Shade Tree
node**, and the discovery bootnode the **Elder Tree**. Source paths, environment variables,
flags, and historical records retain `client`, `gateway`, and `bootnode` where compatibility
matters.

> **Current network status.** This checkout is envelope v4 only. Ask a v4 canopy operator for
> its discovery pins and admission path, or run the local canopy in [QUICKSTART.md](QUICKSTART.md).
> The legacy Sepolia contract/directory files and 2026-08-17 log describe the incompatible
> pre-v4 fleet. A separate `network/sepolia/deployment.json` records the live disposable v4
> research canopy behind the public aggregate map. Since 2026-09-03 its explicit staked path is a
> Sepolia testnet access offer; invited members still need private operator-supplied membership
> material. Never substitute the legacy `bootnode.json` or directory files.

The historical Sepolia and June PoC details remain below as experiment records. Do not use
their onions, payment endpoint, or `sepolia` network preset with the current Proxy. The live
`deployment.json` explicitly reuses only the compatible staking set and gateway registry and
publishes the active archival RPC and deploy block beside them.

## connect to an operator's v4 canopy: what you need

- Node.js 20 or newer, then `npm install` in this repo (`npm link` if you want `shade-tree-node` on PATH,
  otherwise `node bin/shade-tree.mjs` everywhere)
- tor installed locally (`brew install tor`, or `apt install tor`); `bash scripts/start-tor-client.sh`
  starts one on SOCKS 9260, or use a system tor with `SHADE_TREE_TOR_PORT=9050`
- your secret, sent to you privately and loaded through a hidden shell read
- your exact enrolled tier from the operator
- either one v4 node onion, or the operator's v4 Elder Tree onion plus pinned canopy signer
- for invited admission, the operator's current member list
- for paid or staked admission, the registrar, chain, and contract values supplied by that operator

## connect to an operator's v4 canopy: run it

```bash
npm install && npm link
bash scripts/start-tor-client.sh                                  # laptop tor, SOCKS 9260
```

Load the secret without putting it in shell history or process arguments:

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT
```

Paste the secret at the hidden prompt and enter the operator-supplied tier at the second prompt.
For invited admission, run:

```bash
SHADE_TREE_MEMBERS_FILE=/path/from-operator/members.json \
SHADE_TREE_TOR_PORT=9260 shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source invited \
  --bootnode <v4-elder.onion> --dir-signer <v4-canopy-signer-hex>
curl -x http://127.0.0.1:8888 https://api.ipify.org               # the selected node's IP
```

The Elder Tree onion and signer are one trust-pinned pair; get both from the same v4 operator.
The Proxy fetches that operator's signed canopy directory over Tor and selects from the nodes it
lists. The gate is fail-closed: without a valid membership proof every connection is dropped,
and the canopy address buys nothing on its own. If the operator gives you one node instead,
replace discovery with `--onion <v4-node.onion>`. Full member guide:
[`docs/QUICKSTART.md`](QUICKSTART.md).

## use it

Point a proxy-aware tool at the Proxy on port 8888:

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org            # shows the node's IP
curl -x http://127.0.0.1:8888 "https://www.google.com/search?q=zk+proofs"
```

The Proxy opens a Tor onion connection to the node. The node application receives the Tor-side
connection rather than your source IP, verifies the proof, and connects to the destination from
its public IP. TLS continues to the destination, so the node does not see the plaintext URL path
or query. It does see the hostname and port plus timing, lifetime, and traffic volume.

To restrict admission policy, add `--max-anon`. The Proxy then uses only nodes that admit
**invited** members and no staked or paid population, and refuses to run if your own leaf is
staked or paid. If no node in the canopy is invited-only, it refuses the connection. This is a
policy filter, not a defense against timing or application-level correlation. Without
`--max-anon` the Proxy routes to nodes that admit your leaf source (`docs/CLIENTS.md`
"Leaf source"; `--leaf-source paid` pins the set if you hold more than one leaf).

## buy access, when the v4 operator offers it

Paid admission is optional. Get the v4 Elder Tree onion, signer, registrar details, settle asset, and
paid-set address from the operator. With an EIP-3009 rail you hold the settle asset but need no
gas: you sign and the operator submits. Do not substitute values from the historical Sepolia
record.

Before any payment or Proxy command below, load the matching member secret into
`SHADE_TREE_SECRET` with a hidden read. If you need a new identity, generate it at the
operator's tier and copy only the secret value into the prompt:

```bash
shade-tree enroll --commitment-only --limit "$SHADE_TREE_LIMIT"
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
shade-tree-node pay --bootnode <v4-elder.onion> --limit "$SHADE_TREE_LIMIT" \
  --key-file buyer.key  # x402 (default) or --protocol mpp; reads SHADE_TREE_SECRET
# -> paid (x402): settleTx 0x…  insertTx 0x…  leafIndex N  root …
shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source paid \
  --bootnode <v4-elder.onion> --dir-signer <v4-canopy-signer-hex> \
  --paid-access-contract <v4-paid-set-address>
```

A node operator chooses what it admits (`invited`, `staked`, `paid`) and what it sells (which
402 rails); the operator's `/health` `pay.protocols` (or the node's `caps.pay` in the canopy directory)
lists the rails you can pay with. `shade-tree-node pay --protocol mpp` against an x402-only registrar tells
you to retry with `--protocol x402`.

`--dry-run` shows the operator's 402 challenge and the exact authorization you would sign, and
signs nothing. Tier 32 = a bigger per-epoch budget (`--limit 32`, priced higher). Both rails
were exercised on the pre-v4 Sepolia research deployment on 2026-08-17; that is historical
evidence, not a claim that its registrar is compatible with v4.

Read this before you pay: **the payment is public.** On chain, your wallet address pays the
operator's address the tier's price, and the operator inserts your leaf right after. The proof
does not expose the leaf or a stable identifier across private slots, but timing, destinations,
accounts, cookies, and payment timing can still correlate activity. “This address bought access
from this operator” is visible to anyone. If that matters to you, pay from a **fresh address** funded
through a large shared pool (Railgun, Privacy Pools, a CEX withdrawal; your call, the protocol
does not pick one). `docs/PAYMENTS.md` has the whole leak ledger.

## stake instead, when the v4 operator offers it

```bash
shade-tree enroll --commitment-only --limit "$SHADE_TREE_LIMIT"
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -s SHADE_TREE_REGISTER_KEY
SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" \
shade-tree register-member <commitment> --limit "$SHADE_TREE_LIMIT" \
  --rpc-url <operator-rpc-url> --group-contract <v4-staked-set-address>
unset SHADE_TREE_REGISTER_KEY
shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source staked \
  --bootnode <v4-elder.onion> --dir-signer <v4-canopy-signer-hex> \
  --rpc-url <operator-rpc-url> --group-contract <v4-staked-set-address>
```

Paste the funded member-registration key at the second hidden prompt. The one-shot environment
assignment keeps it out of argv, and `unset` removes it before the long-running Proxy starts.

Reuse a private slot on a different tunnel signal in one epoch and a node can reconstruct the RLN
identity secret and attempt to slash the bond on chain. A failed slash submission is not a
guaranteed slash (`docs/ONCHAIN.md`).

## what your key actually is

It is a bearer credential. Whoever holds it can use the membership until the set is rotated or
the leaf is slashed, so keep it local. The proof does not contain your name, but enrollment,
payment, accounts, and traffic metadata can create links outside the proof.

Your tier sets a private message-slot budget per epoch. Each slot produces a different
nullifier. Reusing one slot on a different tunnel signal in the same epoch repeats its nullifier, which
a node can detect. One proof admits one CONNECT tunnel, not each HTTP request inside it.

## stop it

Ctrl-C the Proxy; `pkill -f torrc.client` if you started the laptop Tor with `start-tor-client.sh`.

Want to see exactly what happens to your bytes? Open `docs/walkthrough.html` in a browser and step through it (recorded on the June PoC; the request path is the same).

---

# legacy: the June 2026 PoC bundle

> **Read first.** This is the original single-gateway PoC path (`scripts/join.sh`, a pinned
> onion, the committed `group/members.json`). **It does not work since 2026-08-17.** The PoC box
> was reused for the live fleet's bootnode + gateway-1 (`docs/GO-LIVE-LOG-2026-08-17.md`,
> Phase 1.1): the PoC gateway process was killed at go-live and, for a few hours, the PoC onion
> mapped to the new gateway on the same box; then the "Box-1 tidy" stopped the PoC tor that
> published that onion, so the PoC onion is dark (the PoC checkout and its HS keys were left in
> place, not deleted). A PoC secret may identify a leaf in the historical
> `group/members.json`, but that does not grant access to a current v4 canopy. Ask a current
> operator for admission. `scripts/join.sh` and `scripts/run-client.sh` (code, unchanged)
> still default to the PoC onion. Do not replace it with the pre-v4 Sepolia preset; use a v4
> operator's explicit `--onion`, or `--bootnode` plus `--dir-signer`, instead. The rest of this
> page is kept as a record.

## what you need (legacy)

- node 18 or newer
- tor installed locally (`brew install tor`, or `apt install tor`)
- the bundle you were sent (`shade-tree-gateway-deploy.tgz`), unpacked
- the historical bearer credential, which must never be put in argv or shell history

## historical command (legacy)

The retired `scripts/join.sh` helper accepted the secret as a positional argument. Do not run
or reconstruct that form: it leaks the credential to process listings and shell history, and it
no longer establishes a tunnel. This section records only the old topology.
For the record, its built-in gateway onion was:

```
ezguggje6sbldhw4pl5nudwg2mrwkb5zzyu3a26qc4eka2ur24bv3eqd.onion
```

Historically, `scripts/join.sh` started a local Tor process and Proxy, then compared the IP
seen by `api.ipify.org` with `SHADE_TREE_EXPECT_IP`. The address and IP are experiment records,
not current v4 connection values.

## use it (legacy)

The original Proxy accepted proxy-aware tools on port 8888:

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org            # historical node IP
curl -x http://127.0.0.1:8888 "https://www.google.com/search?q=zk+proofs"
```

In that design, the Proxy opened a Tor onion connection to the node. The node application saw
the Tor-side connection, the target hostname and port, timing, lifetime, and traffic volume.
TLS protected the plaintext path and query from the node.

## stop it (legacy)

```bash
bash scripts/stop.sh
pkill -f torrc.client
```

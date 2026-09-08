# Quickstart

Shade Tree has a local **Proxy** (protocol client), an access-gated **Shade Tree node**
(protocol gateway), and an **Elder Tree** (discovery bootnode). Source paths, environment
variables, flags, and service units retain `client`, `gateway`, and `bootnode` where
compatibility matters.

Connect to an operator's v4 Grove, or stand up your own. Three paths follow: connect with
configuration from an operator, run a local loop to understand the pieces, or run your own
node or Grove on a host.

> **Current network status.** This checkout speaks envelope v4 only. The committed
> [`network/sepolia/`](../network/sepolia/README.md) legacy contract and directory files describe
> the earlier incompatible pre-v4 deployment; they are not runnable defaults for this Proxy or
> payments. The directory's separate `deployment.json` records the disposable v4 research Grove,
> supplies its Elder+Canopy-signer discovery default and the public Sepolia staking path. The
> bundled client defaults are tier 1 (0.1 Sepolia ETH), a fixed 60-second epoch, and a 40 MiB
> combined tunnel ceiling. Invited credentials remain private; alternate Groves require explicit
> membership and discovery inputs.

Everything is one CLI: `shade-tree <command> [--flags]`. Install it:

```bash
npm install
npm link           # puts `shade-tree` on PATH; or just use `node bin/shade-tree.mjs` everywhere
shade-tree doctor        # checks node, tor, deps, keys
```

Common `--flags` map to `SHADE_TREE_*` variables; command-specific flags pass through to the
underlying module (see [CONFIG.md](CONFIG.md)).
Agent developers who do not need the repository can use the shorter
[agent install](AGENT.md#1-install-the-agent-cli).

## Path A: connect to an operator's v4 Grove

The bundled public Sepolia path needs a locally generated member secret plus 0.1 Sepolia ETH and
gas in a separate registration wallet. An alternate Grove must supply its exact tier, membership
input, Elder Tree onion, and matching Canopy signer. You need a Tor SOCKS port:
`bash scripts/start-tor-client.sh` starts one on 9260 (or use `--tor-port 9050` with a system Tor).

For the public path, the contract, RPC, deployment block, tier, and rate policy need no flags:

```bash
commitment="$(shade-tree enroll --commitment-only)"  # copy the secret shown on stderr into the hidden prompt below
read -s SHADE_TREE_REGISTER_KEY
SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree register-member "$commitment"
unset SHADE_TREE_REGISTER_KEY
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
shade-tree proxy --tor-port 9260
```

Load the bearer secret without putting it in shell history or process arguments. Enter the
operator-supplied tier at the second prompt:

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT
```

For an invited profile pinned to one node:

```bash
SHADE_TREE_MEMBERS_FILE=/path/from-operator/members.json \
shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source invited \
  --tor-port 9260 --onion <v4-node.onion>
curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json     # the node's IP
```

For signed discovery and rotation through the current Sepolia Grove, omit discovery flags:

```bash
SHADE_TREE_MEMBERS_FILE=/path/from-operator/members.json \
shade-tree proxy --limit "$SHADE_TREE_LIMIT" --leaf-source invited --tor-port 9260
```

For an alternate Grove, add `--bootnode <v4-elder.onion> --dir-signer
<matching-v4-canopy-signer-hex>` from the same operator.

If another operator enables paid or staked admission, they must also supply the v4 registrar,
chain, and contract addresses. Generate an
identity at their tier, then copy only its secret value into the hidden prompt:

```bash
shade-tree enroll --commitment-only --limit "$SHADE_TREE_LIMIT"
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET

# paid admission, when offered by the v4 operator
shade-tree pay --bootnode <v4-elder.onion> --limit "$SHADE_TREE_LIMIT" \
  --protocol x402 --key-file buyer.key

# staked admission, when offered by the v4 operator
read -s SHADE_TREE_REGISTER_KEY
SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" \
shade-tree register-member <commitment> --limit "$SHADE_TREE_LIMIT" \
  --rpc-url <operator-rpc-url> --group-contract <v4-staked-set-address>
unset SHADE_TREE_REGISTER_KEY
```

Paste the funded registration key at the hidden prompt. It is passed only to the registration
process and cleared before the Proxy starts. A non-loopback RPC refuses the public Anvil key and
requires this explicit key.

The Proxy fetches the signed Canopy over Tor, verifies it against the pinned signer, and
selects a node per tunnel. Member page: [JOIN.md](JOIN.md); buying: [PAYMENTS.md](PAYMENTS.md).
Research preview and untrusted ZK artifacts: see the README warning and Boundaries.

## Path B: the local loop (understand the pieces)

You need a local Tor daemon and access to the public Tor network; "local" describes where
the processes run, not an offline transport. On restricted or unreliable networks, start with
`npm run test:fast` for local checks. This loop publishes two onion services from one Tor process. The
checked-in `tor/torrc` and `scripts/start-tor.sh` publish one standalone node only, so do not use
that single-node config unchanged here. Below, each role is a separate terminal.

### 1. Mint onion identities

```bash
shade-tree keygen tor/hs-bootnode --label bootnode   # Elder Tree identity; internal path/label
shade-tree keygen tor/hs-gateway  --label gateway    # node identity; internal path/label
```

Each writes Tor HS key files plus `identity.local.json` (the announce-signing seed). In another
terminal, start the exact two-service local configuration. This command stays in the foreground:

```bash
mkdir -p tor/data-local-loop
chmod 700 tor/data-local-loop tor/hs-bootnode tor/hs-gateway
tor --DataDirectory ./tor/data-local-loop \
  --SocksPort 9250 \
  --HiddenServiceDir ./tor/hs-bootnode \
  --HiddenServicePort "80 127.0.0.1:8877" \
  --HiddenServiceDir ./tor/hs-gateway \
  --HiddenServicePort "80 127.0.0.1:8443" \
  --Log "notice stdout"
```

This is the local-loop equivalent of two `HiddenServiceDir` blocks: the Elder Tree is onion port
80 to loopback 8877, and the node is onion port 80 to loopback 8443. Wait for Tor to report
`Bootstrapped 100%` before continuing. Tor may warn that these paths are relative; they
are intentionally relative to the repository root where this command runs.

### 2. Run the Elder Tree

```bash
shade-tree elder --port 8877 --admission open
```

It prints its **pinned signer pubkey**. Proxies need it. (`--admission open` means onion
control is the only requirement; `--admission stake` also requires an on-chain node bond, see
[BOOTNODE.md](BOOTNODE.md).)

### 3. Enroll one local invited member

For this local loop, choose tier 8. The command automatically appends the commitment to
`group/members.json`; no manual edit is needed. Live bootstrap never accepts this file:

```bash
shade-tree enroll --limit 8
```

Copy only the printed secret value into the hidden prompt in step 5.

### 4. Run a Shade Tree node and announce it

```bash
SHADE_TREE_MEMBERS_FILE=./group/members.json shade-tree node
shade-tree heartbeat --bootnode <elder-onion> \
  --identity tor/hs-gateway/identity.local.json
```

The heartbeat announces the node to the Elder Tree every few minutes and keeps it live.
Confirm it is listed:

```bash
curl --socks5-hostname 127.0.0.1:9250 http://<elder-onion>/directory
```

### 5. Connect a Proxy

Load the member secret without putting it in shell history or process arguments:

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
```

Paste the member secret at the hidden prompt, then run:

```bash
SHADE_TREE_MEMBERS_FILE=./group/members.json \
shade-tree proxy --limit 8 --leaf-source invited --tor-port 9250 \
  --bootnode <elder-onion> \
  --dir-signer <elder-signer-pubkey>
```

The Proxy fetches the signed Canopy over Tor, verifies it, and listens on
`127.0.0.1:8888`. It selects a node for each CONNECT tunnel. Use it:

```bash
curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json
```

The returned IP belongs to the node. The node application receives a Tor onion connection,
not the Proxy's source IP. It still sees the target, timing, lifetime, and traffic volume.
One RLN proof admits one CONNECT tunnel, not each HTTP request carried inside it.

## Path C: your own Grove on a droplet (one command)

> **Deployment blocked.** The private-target guard is now closed by default, but the
> development ZK setup and the other [`DEPLOYMENT-PLAN.md`](DEPLOYMENT-PLAN.md) gates remain.
> Keep this path limited to disposable research infrastructure until they are closed.

After those gates clear, the bootstrap target is a fresh Ubuntu 24.04 host:

```bash
ssh root@<droplet>
curl -fsSL https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/bootnode/deploy/bootstrap.sh \
  | sudo env SHADE_TREE_MEMBERS_FILE=/root/operator-members.json bash
```

It installs Tor + Node.js, mints the onions, starts the internal bootnode + gateway + heartbeat
systemd units, and prints the Elder Tree onion, its pinned signer, and a Proxy template. Opt-ins:
`SHADE_TREE_BOOTNODE_ONION=<onion>` (node-only host joining an existing Elder Tree), `SHADE_TREE_REGISTRAR=1`
(sell access over 402), `SHADE_TREE_HELIOS=1` (light-client root anchor). See
[bootnode/deploy/README.md](../bootnode/deploy/README.md). Then connect as in [step 5](#5-connect-a-proxy), pointing `--bootnode` / `--dir-signer` at what it printed and using the operator-supplied member values.

## On-chain mode (optional)

To source membership from the on-chain `StakedReputationSet` and require staked gateways:

```bash
# deploy locally
anvil &
forge script script/Deploy.s.sol:Deploy --rpc-url http://127.0.0.1:8545 --broadcast \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

shade-tree register-member <commitment> --limit 8 # stake a tier-8 member from `shade-tree enroll --commitment-only --limit 8`
shade-tree register-gateway                      # stake a node operator; command retains wire name
shade-tree elder --admission stake --stake-mode onchain \
  --gateway-registry <addr> --rpc-url http://127.0.0.1:8545
```

See [CONFIG.md](CONFIG.md) for every variable and [ONCHAIN.md](ONCHAIN.md) for the design.

## Verify everything works

```bash
npm run test:fast        # quick first check; slow proof/onchain suites + Foundry skipped
npm test                 # full pre-PR check: all selftests + Foundry
npm run test:contracts   # forge test (StakedReputationSet + GatewayRegistry)
```

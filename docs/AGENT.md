# Agent guide

Use the checksummed Rust `-live` binary when one local agent should use Shade
Tree and the rest of the machine should not. Its Proxy listens on loopback,
embeds Arti, and mints one RLN proof for every CONNECT tunnel. `shade-tree run`
gives the Proxy settings to one child process. The agent path needs neither
Node.js nor a system Tor daemon.

> [!WARNING]
> Research preview. The bundled public Sepolia profile uses untrusted testnet ZK
> artifacts and links the staking wallet to the public member commitment. It is
> not suitable for real funds or sensitive use. Retired pre-v4 records remain unusable.

## 1. Install the live binary

Download the `-live` binary and matching `.sha256` for your platform from the
[latest release](https://github.com/dmarzzz/shade-tree-node/releases/latest).
This example installs the v0.6.0 x86_64 GNU/Linux asset; change `TARGET` to the
published target for your machine when needed:

```sh
VERSION=0.6.0
TARGET=x86_64-unknown-linux-gnu
ASSET="shade-tree-$VERSION-$TARGET-live"
curl -LO "https://github.com/dmarzzz/shade-tree-node/releases/download/v$VERSION/$ASSET"
curl -LO "https://github.com/dmarzzz/shade-tree-node/releases/download/v$VERSION/$ASSET.sha256"
sha256sum -c "$ASSET.sha256"
chmod +x "$ASSET"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$ASSET" "$HOME/.local/bin/shade-tree"
shade-tree --version
```

Use `shasum -a 256 -c` on macOS. See the Rust
[installation guide](../rust/INSTALL.md) for platform targets, Windows
verification, source builds, attestations, and the current macOS notarization
limitation.

## 2. Create an identity and obtain admission

For the bundled public Sepolia Grove, tier 1 costs exactly 0.1 Sepolia ETH and
permits one CONNECT tunnel per fixed 60-second epoch, capped at 40 MiB combined
payload. Create the identity locally and register its public leaf with a separately
funded testnet wallet:

```sh
shade-tree enroll --out identity.json
chmod 600 funded-sepolia.key
shade-tree register-member --identity identity.json --key-file funded-sepolia.key
shade-tree member-status --identity identity.json --json
```

The CLI reads the current contract, RPC, deployment block, tier, Elder, signer,
and rate policy from its bundled deployment record. The wallet signs locally;
the private key never goes to the RPC. The receipt confirms mining; wait for that
block to reach Sepolia finality before starting the Proxy, because client and
gateway membership snapshots both default to the finalized tree.

The identity is also the recovery credential. To leave, run `shade-tree exit-member
--identity identity.json --key-file gas.key`, wait until `member-status` reports that
the 24-hour deadline has passed, then run `shade-tree withdraw-member --identity
identity.json --recipient 0xFRESH_ADDRESS --key-file gas.key`. Both proofs are generated
locally; the gas wallet may be unrelated to the original funder or recipient.

For an invited, paid, or alternate Grove, ask its operator for:

- the exact rate tier (`limit`) your new leaf should use;
- an invited, staked, or paid admission process;
- an alternate Elder trust pair or pinned node only when not using the bundled default;
- the member-set input matching the root its nodes verify.

An overridden Elder onion and signer are one trust-pinned pair; get both from
the same operator. Then create a new owner-only identity locally:

```sh
read -r SHADE_TREE_LIMIT
shade-tree enroll --limit "$SHADE_TREE_LIMIT" --out identity.json > public-leaf.txt
```

`identity.json` contains the member secret. Do not send it anywhere. Submit only
`public-leaf.txt` through the operator's admission process.

Identity generation and admission are separate operations. `enroll` does not
change a remote Grove or submit an on-chain transaction. Its optional
`--members <file>` updates only an explicit local version-2 demo set. Wait for
the operator to confirm that the public leaf is present in the exact root its
nodes use. For invited access, save the corresponding operator-supplied
`members.json` beside the identity.

If you are migrating an existing Shade Tree secret, derive its identity rather
than generating a new one:

```sh
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
shade-tree identity --limit "$SHADE_TREE_LIMIT" --out identity.json
unset SHADE_TREE_SECRET
```

The tier must match admission. A different `limit` derives a different leaf and
membership verification fails.

## 3. Start the local Proxy

For bundled public staked access through its Elder Tree:

```sh
(umask 077; set -C; shade-tree proxy-token > proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree proxy --identity identity.json --listen 127.0.0.1:8118
```

For invited access, add the operator's member set:

```sh
(umask 077; set -C; shade-tree proxy-token > proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree proxy \
  --identity identity.json \
  --members members.json \
  --listen 127.0.0.1:8118
```

The Proxy requires an unpredictable URL-safe token of at least 32 characters,
even on loopback: loopback is host-local, not user-local, and another OS account
must not be able to spend this member's slots. It verifies the signed Canopy and
reuses one successfully bootstrapped base Arti client. Each logical CONNECT gets
an isolated Arti view that is reused only for that tunnel's gateway failover, so
separate tunnels do not share circuits. Successive tunnels rotate across healthy
gateways with smooth weighted round-robin by default; `--no-rotation-spread`
restores independent weighted-random first choices. Use
`--directory directory.json --signer <hex>` for a static signed Canopy, or
`--bootnode-onion <elder.onion> --signer <hex>` to override the bundled Elder,
or `--onion <node.onion>:80` for one pinned node. Alternate staked or paid profiles
use the operator's `--contract` and `--rpc-url` values instead of `--members`.

RLN slot allocation is default-on, durable, and atomic across Rust and
JavaScript clients using the same public leaf. It stores no bearer secret and
fails closed on corrupt, unavailable, or locked state. A crash or local proof
failure burns the already-reserved slot, so restart is safe but may reach the
epoch budget sooner. Do not delete or edit the state to reclaim capacity inside
an epoch.

## 4. Launch one agent through it

Open another terminal:

```sh
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree run -- your-agent
```

The default Proxy URL is `http://127.0.0.1:8118`. An explicit equivalent is:

```sh
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree run --proxy http://127.0.0.1:8118 -- your-agent
```

For Hermes:

```sh
shade-tree run -- hermes
```

`run` authenticates its Proxy preflight before spawning the agent and fails
closed if the Proxy is unavailable or rejects the token. It gives uppercase and
lowercase HTTP, HTTPS, and WSS URLs containing `shade-tree:<token>` only to the
child, removes inherited `ALL_PROXY`, the raw token, and other `SHADE_TREE_*`
secrets/operator settings, and leaves the parent shell unchanged. Use
`--no-proxy <hosts>` to add child-only bypasses or
`--check-timeout-ms <milliseconds>` to change the 2000 ms preflight timeout.

If an agent ignores standard proxy variables, point its HTTP proxy setting at
`http://shade-tree:$SHADE_TREE_PROXY_TOKEN@127.0.0.1:8118`. The Proxy accepts
HTTP CONNECT only, and nodes permit target port 443. TLS continues to the
destination.

Token-file creation refuses to overwrite an existing path. Reuse that file only
for the same running Proxy, and remove it after the Proxy stops before generating
a replacement.

## Library integration

Rust applications that own their networking can use the `shade-tree-egress`
workspace crate directly through a Git or path dependency; it is not currently
published on crates.io. Its long-lived async client shares the same proving,
failover, transport, and slot-state paths as the CLI Proxy. Generic
applications should prefer the loopback Proxy unless they need an in-process
Rust stream API.

JavaScript applications can still install the Git dependency and import
`ShadeTreeClient` from `shade-tree-node/client`:

```sh
npm install git+https://github.com/dmarzzz/shade-tree-node.git
```

Read the [SDK reference](SDK.md) and the tested
[`examples/agent-egress.mjs`](../examples/agent-egress.mjs) example. This npm
path is for JavaScript SDK users and repository contributors; it is not part of
the binary agent quickstart.

## Contributor integration test

Repository contributors can exercise a disposable local Grove, the
embedded-Arti Rust Proxy, and a real Hermes one-shot. This gated live test needs
a configured model, server-side Tor for the temporary onion, Rust, Node.js for
the operator/test harness, and one public HTTPS request:

```sh
npm run test:hermes
```

The test requires both the agent's success marker and an accepted-tunnel metric
from the ephemeral node. It can also keep the Grove local while running an
existing Hermes installation over a loopback-only SSH reverse tunnel; see
[`test/HERMES-E2E.md`](../test/HERMES-E2E.md).

## Current boundary

- The node sees the target hostname, port, timing, lifetime, and traffic volume.
- TLS hides the application path and body from the node when the agent uses HTTPS.
- Tor does not prevent timing correlation by an observer who can watch both ends.
- One proof admits one CONNECT tunnel, not every HTTP request inside it.
- RLN slot state is local and fail-closed; back it up only as opaque state and never rewind it inside an epoch.

Read [Adapters](ADAPTERS.md) for proxy-aware tools and the
[threat model](THREAT-MODEL.md) for the exact guarantees.

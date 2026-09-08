# Shade Tree for Rust

The Rust workspace contains the distributable `shade-tree` client and the
trust-critical protocol implementation behind it.

> Research preview. The bundled RLN artifacts are suitable for testing, not a
> production trusted setup. See [`../circuits/rln/ARTIFACTS.md`](../circuits/rln/ARTIFACTS.md).

The JavaScript client in [`../client/shade-tree-client.mjs`](../client/shade-tree-client.mjs)
is the reference implementation. Golden vectors in
[`../testdata/vectors.json`](../testdata/vectors.json) keep both implementations
on the same v4 wire format.

## Workspace

```text
rust/
├── shade-tree-proto/   canonical bytes, signatures, selection, receipts
├── shade-tree-client/  the `shade-tree` binary
├── shade-tree-egress/  reusable async admission, proving, Tor, and tunnel client
└── shade-tree-rln/     RLN proving, verification, and artifact bindings
```

The default binary verifies directories and receipts, selects gateways, and
maintains a last-known-good directory cache. The optional `live` feature adds
identity creation, RLN proof generation, the reusable egress crate, embedded
Arti, the loopback Proxy, and the agent `run` wrapper.

```sh
cd rust

# Fast deterministic client
cargo build --release -p shade-tree-client

# Live egress client with embedded Tor and RLN artifacts
cargo build --release -p shade-tree-client --features live

# Complete workspace checks
cargo test --workspace --all-features
cargo check --workspace --all-targets --all-features
bash shade-tree-rln/interop/proxy-run.sh
```

The binary is written to `target/release/shade-tree`. Release binaries and
checksums are attached to tagged GitHub releases; see [`INSTALL.md`](INSTALL.md).

## Trust boundary

`shade-tree-proto` owns deterministic security decisions and deliberately has
no I/O or JSON serializer dependency. The client parses untrusted input into
local data structures, then hands it to that crate for canonicalization and
verification.

The conformance suite covers:

- signed directory and onion/public-key binding verification;
- capability and admission-aware gateway selection;
- explicit protocol-v4 negotiation and v3 rejection;
- request signal and receipt domain separation;
- JavaScript/Rust byte parity for the checked-in vectors.

The `live` path also validates the embedded ZK artifact lock before proving.
It does not make the artifact ceremony more trustworthy: provenance remains a
separate deployment requirement.

Live RLN slots are allocated through the same default-on `{version, epoch,
nextSlot}` file and directory-lock protocol as the JavaScript Proxy/SDK. The
file is keyed by the public member leaf, contains no secret, never wraps at K,
and fails closed on corrupt, unavailable, or locked state.

## Client commands

```text
shade-tree verify-directory …
shade-tree fetch-directory …
shade-tree select …
shade-tree verify-receipt …
shade-tree proxy-token …       # requires --features live; generates local Proxy auth
shade-tree enroll …            # requires --features live; creates a new identity
shade-tree identity …          # requires --features live; derives from an existing secret
shade-tree register-member …   # requires --features live; stakes a public leaf on chain
shade-tree member-status …     # requires --features live; reads bond/exit state
shade-tree exit-member …       # requires --features live; local ZK exit authorization
shade-tree withdraw-member …   # requires --features live; private refund to a recipient
shade-tree leaves …            # requires --features live; reconstructs an on-chain set
shade-tree egress …            # requires --features live
shade-tree proxy …             # requires --features live
shade-tree run -- <agent>      # process-scoped use of an existing Proxy
```

Run `shade-tree --help` for the complete option set. The live binary's `proxy`
command is the language-neutral agent boundary: it listens on loopback for HTTP
CONNECT and embeds Arti, so the client host needs no system Tor daemon or SOCKS
port. One successfully bootstrapped base Arti client is reused across CONNECT
tunnels, while each logical tunnel gets a separate isolation view. Proof
generation runs outside the async network executor.

```sh
(umask 077; set -C; ./target/release/shade-tree proxy-token > proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
./target/release/shade-tree proxy \
  --onion <gateway.onion>:80 \
  --identity identity.json \
  --members members.json \
  --listen 127.0.0.1:8118
```

The Proxy requires this unpredictable local token. The process-scoped wrapper
performs an authenticated, fail-closed preflight and puts Basic credentials
only in the child proxy URLs:

```sh
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree run --proxy http://127.0.0.1:8118 -- your-agent
```

Create a new identity with `shade-tree enroll --limit N --out identity.json`,
then send only its printed public leaf through a Grove operator's admission
process. `enroll` does not change a remote member root or submit an on-chain
transaction; its optional `--members` flag updates only a local version-2 demo
set. Use `shade-tree identity` only when deterministically deriving
from an existing secret. In both cases, `identity.json` contains the member
secret and must remain local. Omitting `--limit` uses the bundled staked
`defaultLimit` (1 in the public profile); `SHADE_TREE_LIMIT` or an explicit
flag selects a custom tier. New identity files always record the exact tier so
their leaves cannot later be interpreted under a different default.

The live Rust binary can stake that public leaf without Node.js. It defaults to
the current bundled Sepolia staking contract and RPC, reads the exact tier bond
from the contract, signs locally, broadcasts only the signed EIP-1559
transaction, and waits for a successful receipt:

```sh
shade-tree enroll --limit 1 --out identity.json
chmod 600 funded-sepolia.key
shade-tree register-member --identity identity.json --key-file funded-sepolia.key
shade-tree member-status --identity identity.json --json
```

`register-member --identity` recomputes the public leaf from the secret and tier
before its first network request. The public identity leaf is derived at limit 1
explicitly; `register-member` reads the bundled profile's matching `defaultLimit=1`
when `--limit` is omitted.
For a custom Grove, pass its tier explicitly to both commands—the enrolled and
registered limits must match.

`SHADE_TREE_REGISTER_KEY` is also supported for parity with the JavaScript CLI;
no raw-key command-line flag is accepted. A key file must be owner-only on Unix,
and a missing key fails before the first public RPC request. Explicit
`--contract`/`--rpc-url` flags (or `SHADE_TREE_GROUP_CONTRACT`/
`SHADE_TREE_RPC_URL`) select another Grove. If receipt lookup fails after
broadcast, the command retains the locally computed transaction hash in its
error and requires checking that hash before retrying.

The same private file authorizes a complete exit without revealing its secret:

```sh
shade-tree exit-member --identity identity.json --key-file gas.key
shade-tree member-status --identity identity.json
shade-tree withdraw-member --identity identity.json \
  --recipient 0xFRESH_SEPOLIA_ADDRESS --key-file gas.key
```

Each action creates and locally verifies a fresh Groth16 proof, checks chain and
contract bytecode, reads current member state, simulates the exact call, and signs
locally. The withdrawal proof binds its recipient. Any separately funded wallet
can pay gas; it need not be the registration payer or refund recipient.

With no transport or explicit membership source, dynamic discovery uses the
current v4 Sepolia Elder, signer, staked contract, RPC, deployment block,
60-second epoch, and `defaultLimit=1` embedded in
`network/sepolia/deployment.json`. Each eligible gateway must carry the exact
matching `caps.rate` in its onion-signed capabilities; a missing or different
policy fails before proof construction. An RPC-only override retains this public
profile while changing how the bundled contract is read. Explicit membership,
contract, or leaf-source configuration keeps the custom-Grove defaults of a
120-second epoch and limit 8. Override discovery with
`--directory <file> --signer <hex>`, `--bootnode-onion <onion> --signer <hex>`,
or `--onion <node.onion>`; see `shade-tree --help` for all egress options.
Directory-backed tunnels use smooth weighted round-robin for their first gateway
by default. Pass `--no-rotation-spread` or set `SHADE_TREE_ROTATION_SPREAD=0` to
restore independent weighted-random first choices.

Rust applications that need an in-process stream API can use the
`shade-tree-egress` workspace crate through a Git or path dependency. It is not
currently published on crates.io. The CLI `egress` and `proxy` paths consume
the same client rather than maintaining a second implementation. Other
languages should use the loopback Proxy.

## Protocol changes

Shade Tree v4 is a clean boundary. Old v3 envelopes and request proofs are not
accepted under the new name. Operators must regenerate operator-authorization,
capability, and receipt signatures; domain-neutral signatures over unchanged
canonical bytes are unaffected. Deployments using the changed exit and
withdrawal domains require new contracts. See
[`../docs/MIGRATING-TO-SHADE-TREE.md`](../docs/MIGRATING-TO-SHADE-TREE.md).

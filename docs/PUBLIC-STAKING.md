# Public Sepolia staking profile

The public Protocol v4 profile is deliberately narrow:

- stake exactly **0.1 Sepolia ETH** at tier `1`;
- receive **one new HTTPS `CONNECT` tunnel per fixed 60-second epoch**;
- relay at most **40 MiB (41,943,040 bytes) of combined payload** through that slot;
- recover the stake after the ZK-authorized 24-hour exit window unless the member is slashed.

The deployed proof artifacts are explicitly untrusted testnet material. This is a disposable
research Grove, not a production anonymity system.

## What “one request” means

TLS remains end to end. A node can count the admitted `CONNECT` tunnel and its opaque bytes, but it
cannot see or count Google queries, HTTP requests, or HTTP/2 streams inside that tunnel. The epoch
is `floor(unixSeconds / 60)`, not a rolling window, so uses immediately before and after a minute
boundary are possible.

The v4 external nullifier is Grove-wide, not egress-specific. Honest JavaScript and Rust clients
therefore allocate one tier-1 slot total and reuse the identical proof only for gateway failover.
Using the same private slot for two different target-bound requests produces slash evidence.

Nodes also exchange spent-nullifier notices. That fleet tally closes ordinary sequential replay,
but it is asynchronous and fail-open: simultaneous requests, a partition, or a dropped notice can
still race. The accurate claim is **one honest-client allocation per fixed minute, with best-effort
Grove-wide replay suppression**. A hard per-egress entitlement would require an egress-scoped
external nullifier and a new protocol version.

## Protocol parameters

| parameter | public value |
|---|---:|
| network | Sepolia (`11155111`) |
| tier-1 bond | `0.1 ETH` |
| tier-8 bond | `0.8 ETH` |
| allowed limits | `[1, 8]` |
| default member limit | `1` |
| epoch | fixed `60 seconds` |
| previous epochs accepted | `1` |
| superseded-root lifetime | `60 seconds` |
| combined payload per slot | `40 MiB` (`41,943,040` bytes) |
| slash confirmation allowance | `3,600 seconds` |
| contract minimum safety window | `3,720 seconds` (`F + E + C`) |
| deployed unbonding | `86,400 seconds` (24 hours) |

Tier 8 is priced linearly so the compatibility tier cannot buy eight slots for the tier-1 price.
The 40 MiB payload is the 4 MiB text-oriented search-and-fetch estimate from
[ADR 0009](adr/0009-epoch-bandwidth-envelope.md), multiplied by the chosen `10×` safety factor.
Both relay directions spend one shared allowance. The boundary chunk is truncated and both sockets
close with reason `payload-limit`.

## Member flow

The privacy-first browser flow is available at
[shade-tree-node.vercel.app/stake](https://shade-tree-node.vercel.app/stake/). It generates the
identity entirely in the tab, requires a plaintext recovery download before staking, and calls the
pinned contract through the user's injected wallet. The static page has no identity or commitment
API and stores neither in browser storage. Loading any website can still expose an IP address to its
host, and the injected wallet/RPC sees the public transaction.

For agents and terminals, the released Rust client uses the bundled live Sepolia record by default:

```bash
shade-tree enroll --out identity.json
chmod 600 funded-sepolia.key
shade-tree register-member --identity identity.json --key-file funded-sepolia.key
shade-tree member-status --identity identity.json --json
shade-tree proxy --identity identity.json
```

`register-member --identity` validates that the private secret, public leaf, and exact tier match
before the first RPC call. The file stays local; the locally signed registration transaction contains
only its already-public leaf and tier. The payer can instead sponsor an agent by registering only the
agent's public decimal leaf, but the sponsor bears the slashing risk and does not control the later
refund.

The JavaScript SDK and Rust client both read the Elder, signer, current staking contract, RPC,
deployment block, tier, and rate policy from the bundled deployment record. Explicit flags and
environment variables still win.

Membership proofs use the finalized Sepolia tree by default, matching the gateways' pinned root
snapshot. A newly mined registration is therefore not usable until its block is finalized; this
deliberate delay prevents client and gateway RPCs from racing on different tip roots. Every
superseded root the gateway observes remains accepted for the full 60-second freshness window.

The staking wallet, commitment, tier, amount, and timing are public forever. Only the identity
secret stays local. Use a separately funded wallet when address-graph separation matters.

The second local allocation in one epoch fails with
`SHADE_TREE_EPOCH_BUDGET_EXHAUSTED`; the client does not intentionally manufacture slash evidence.

## Exit and recovery

The identity file is the recovery credential. Losing it makes the stake unrecoverable; anyone who
obtains it can use the membership and choose the eventual refund recipient. Keep it in encrypted,
recoverable storage.

The live Rust binary implements the complete ZK-authorized lifecycle:

```bash
# Any separately funded Sepolia wallet may pay gas; it need not be the staking wallet.
shade-tree exit-member --identity identity.json --key-file gas.key
shade-tree member-status --identity identity.json

# After the reported 24-hour unbonding deadline:
shade-tree withdraw-member --identity identity.json \
  --recipient 0xFRESH_RECIPIENT --key-file gas.key
```

Both actions create a fresh Groth16 proof locally. The exit proof removes the leaf from admission and
starts the clock. The withdrawal proof is bound to the exact recipient, so a captured transaction
cannot redirect the refund. The identity secret is never sent to the RPC or written into calldata.
The public commitment necessarily links registration, exit, and withdrawal as one pseudonymous
membership; a fresh payer and fresh recipient separate the surrounding address graph, not those
public lifecycle events. The bond remains slashable throughout unbonding.

## Operator invariants

The live deployment record is the source of truth. Its `ratePolicy` and public staking root pin the
contract receipt, hasher, real testnet exit verifier, tier table, deployment block, clock, payload,
root lifetime, and unbonding relationship. A manifest in the pinned service commit binds normalized
runtime bytecode for the set, hasher, exit wrapper, Groth16 verifier, and both linked Poseidon
libraries. Deployment preflight checks that complete graph through both the public record RPC and
the operator's exact runtime RPC before changing a host.

Every node must run the same values and advertise the rate policy in its onion-signed capabilities.
Clients fail closed before proving when a signed node policy is absent or differs from their
expected epoch/payload profile. Operators must keep the fleet tally enabled on public-profile nodes
and retain the explicit caveat that it is not an atomic distributed reservation system.

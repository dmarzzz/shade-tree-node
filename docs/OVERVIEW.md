# Overview: how it works, what is and is not anonymous, what is not done

The long-form companion to the [README](../README.md): the request path, the anonymity
ledger per admission path, the open caveats and why they matter, the exit-blocking numbers,
the Rust binary, the local loop, and the repository layout. Everything here is also in the
per-topic docs; this page is the one-screen-per-topic version. Index: [`README.md`](README.md).

> **v4 network status.** This checkout speaks envelope v4. There is no repo-maintained public
> v4 network profile yet; obtain explicit discovery and contract values from a v4 operator or
> run the local loop below. The legacy Sepolia runtime records are incompatible pre-v4 history.
> A separate `network/sepolia/deployment.json` records the invited-and-staked v4 research Grove behind
> the public aggregate map, but does not contain the membership inputs required to connect.

## How it works

The gate is an application-layer protocol on top of Tor, not a Tor modification. Tor cannot
carry a reputation proof natively (cells are opaque, v3 client-auth is a static linkable
allowlist), but onion services give the part that matters: each gateway is a `.onion` reached
by rendezvous, so there is no exit node and the gateway never learns the client IP.

```
  curl / SearXNG / your agent
        |
        v
  client ──── 1. pull the live gateway set from the bootnode (over Tor), verify it
        |     2. keep the gateways whose signed `admits` cover my leaf source
        |     3. build ONE RLN membership proof for this request (fresh per-tunnel nullifier)
        |     4. pick a gateway (weighted rotation + failover)
        |  SOCKS to Tor, no exit node
        v
  Tor rendezvous  (3 + 3 hops; client IP never revealed to the gateway)
        |
        v
  gateway.onion ── verify RLN proof · root in the union it admits (invited ∪ staked ∪ paid),
        |          within the freshness window? · nullifier fresh?
        |          a 2nd distinct signal on one nullifier reconstructs the secret and SLASHES
        v
  clean egress IP ──> destination   (TCP CONNECT :443 only; TLS stays end to end)
```

- **The proof is real RLN.** The set is a [Semaphore](https://semaphore.pse.dev/) /
  [RLN](https://rate-limiting-nullifier.github.io/rln-docs/) group; each request carries a
  fresh nullifier and a Shamir share inside one circom-rln Groth16 proof (`lib/rln.mjs`,
  `circuits/rln/`). One share per slot egresses; a second distinct signal on the same
  nullifier is a provable over-spend, so the gateway reconstructs the identity secret and
  slashes on whichever contract holds the leaf (`gateway/gateway.mjs:makeRoutingSlasher`).
  Proof transcripts carry no stable member identifier across slots. A gateway can still
  correlate tunnels through destination, timing, volume, or application metadata. A member's
  per-epoch budget is a tier
  baked into its leaf (`Poseidon2(Poseidon1(secret), limit)`, 8 or 32), proven in the same
  circuit and invisible on the wire ([ADR 0006](adr/0006-reputation-tiers.md)).
- **The root is a union of on-chain sets.** Members self-enroll (only a commitment leaves the
  machine). A gateway reads one root per source it admits, `group/members.json` (invited),
  `StakedReputationSet` (staked, `contracts/StakedReputationSet.sol`) and `PaidAccessSet`
  (paid, `contracts/PaidAccessSet.sol`, [ADR 0007](adr/0007-paid-access.md)), through a
  `RootProvider` (`lib/root-provider.mjs`: node, or an EIP-1186 light client, optionally
  Helios-anchored) and trusts their union. `GatewayRegistry` (`contracts/GatewayRegistry.sol`)
  holds operator bonds; an operator can configure the bootnode to admit staked operators only.
  The values in [`network/sepolia/contracts.json`](../network/sepolia/contracts.json) are
  historical and must not be substituted for current v4 contract inputs.
- **Payment is a leaf, not a token.** `shade-tree pay` speaks HTTP 402 in x402 v2 or MPP to the
  provider's registrar (`payments/registrar.mjs`), signs one EIP-3009 authorization, the
  operator settles it and inserts the commitment; egress is the same RLN proof
  ([`PAYMENTS.md`](PAYMENTS.md)).
- **The fleet is discovered live.** Gateways heartbeat to a bootnode (`bootnode/`) that
  serves a signed directory with per-gateway signed caps (`admits`, `pay`, region); the client
  pulls it over Tor, verifies it, re-derives each onion's key, keeps a last-known-good copy,
  and rotates per tunnel. The onion is never on chain; the bootnode is a cache, not a trust
  root ([`BOOTNODE.md`](BOOTNODE.md), [ADR 0002](adr/0002-onion-never-on-chain.md),
  [ADR 0003](adr/0003-bootnode-is-a-cache-not-a-trust-root.md)).

## Which gateways you use

`SHADE_TREE_LEAF_SOURCE=auto|invited|staked|paid` (default `auto`: the
set that holds your leaf) and the client only picks gateways whose signed `admits` include
that source (a gateway advertising no policy is assumed to admit every path during the
rollout). `--max-anon` (`SHADE_TREE_MAX_ANON=1`) goes further: it uses only gateways whose signed
`admits` is exactly `invited`, so a gateway that also sells or stakes access, or advertises no
policy, is refused, and it refuses to run at all with a paid or staked leaf (those paths leave
an on-chain footprint, so "max anon" would be a lie). If an operator offers no invited-only
gateway, the client refuses and names each advertised policy. Order of the paths, most to least
anonymous: invited, staked, paid.

## The Rust binary

`shade-tree-0.6.0-<target>-live` needs no Node and no tor daemon; the default non-live binary
verifies, selects and fetches directories but does not egress ([`rust/INSTALL.md`](../rust/INSTALL.md)):

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT                           # exact enrolled tier
./shade-tree-0.6.0-<target>-live enroll --limit "$SHADE_TREE_LIMIT" --out identity.json
shade-tree leaves --contract <v4-member-set-address> --rpc-url <operator-rpc-url> --out members.json
./shade-tree-0.6.0-<target>-live egress \
  --identity identity.json --members members.json --target api.ipify.org:443
```

That uses the bundled current-v4 Sepolia Elder+signer. Add `--bootnode-onion <elder.onion>
--signer <matching-signer-hex>` to select an alternate Grove.

## The local loop

One box can run the Elder Tree, one node, and one Proxy. It needs two onion-service mappings,
while the checked-in `tor/torrc` is intentionally the single-node helper. Follow
[`QUICKSTART.md`](QUICKSTART.md) Path B for the copyable two-service Tor command, exact tier,
member list, heartbeat, and Proxy steps.

Watch the gate drop non-members with `node scripts/probe.mjs {noproof|garbage|wronggroup}`.

## What is and is not anonymous

The proof hides the leaf; the request hides the IP. What differs is how you got the leaf.

| path | on-chain footprint | who can link what | default admitted? |
|---|---|---|---|
| invited | none | the operator knows it handed you a secret; nobody can tell which requests are yours from the proof alone | yes (`SHADE_TREE_ADMIT=invited`) |
| staked | `register(commitment, limit)` from your wallet, `bondFor(limit)` posted | wallet ↔ commitment ↔ tier bucket, public; requests still unlinkable to the leaf from the proof alone | operator opt-in (`staked`) |
| paid | your address → operator transfer (tier price) and the operator's `insert(commitment, limit)` a block or two later | "this address bought from this operator" and the tier, public; the operator learns commitment ↔ payer; requests still unlinkable from the proof alone | operator opt-in (`paid`) |

Facts that hold for all three: the gateway sees a rendezvous circuit, never your IP; which
root a proof opens (invited / staked / paid) is a public signal, so your crowd is that set's
size (the paid set is warned below `SHADE_TREE_PAID_MIN_LEAVES`, never refused); TLS is end to end,
the gateway sees `host:443`. Prepaid access is trust in the operator: a valid proof the
operator refuses to honor, or a payment it never inserts, has no on-chain recourse, only
public evidence. Full ledger: [`THREAT-MODEL.md`](THREAT-MODEL.md) §4.14b, §5.

## Not done, and why it matters

- **No trusted-setup ceremony.** `circuits/rln/` is circom-rln's dev phase-2 (two hard-coded
  contributions, a fixed beacon); anyone can recompute the toxic waste and forge a membership
  proof under any root or an exit-auth proof against any bond. `testdata/zk-artifacts.lock.json`
  says so (`trust: "UNTRUSTED-TESTNET"`) and CI verifies the pins; the runbook is
  [`CEREMONY.md`](CEREMONY.md), the reasoning is
  [issue #6](https://github.com/dmarzzz/shade-tree-node/issues/6).
- **No audit.** Trust boundaries, per-party threat model and review order:
  [`AUDIT.md`](AUDIT.md), [`CONTRACTS-AUDIT.md`](CONTRACTS-AUDIT.md),
  [`adversarial-review.md`](adversarial-review.md). `npm test` runs every
  `*selftest.mjs` plus the Foundry suite.
- **One operator, one provider.** Two regions, same AS14061; every asset is Sepolia testnet;
  onion PoW is off (`SHADE_TREE_ENABLE_POW=0`, most client tors lack the module), so rendezvous DoS
  is unmitigated; gateway slashing is owner-gated ([ADR 0005](adr/0005-governed-gateway-slash.md)).
- **Why bother.** [`exit-blocking-benchmark.md`](exit-blocking-benchmark.md): over 51
  Tor exits, web destinations blocked 315 of 1,812 requests (17%), and 98% of those blocks were
  403 / CAPTCHA / JS challenge, 2% rate limits; search engines blocked 2,217 of 6,024 (37%),
  62% reputation, 38% rate limit. Sites behind commercial anti-bot vendors block Tor in the
  90 to 100 percent range, the open web roughly zero. Clean IPs stay clean by being gated and
  scarce; this gates on membership instead of identity.

## Layout

| Path | What it is |
|------|------------|
| `bin/shade-tree.mjs` | The unified CLI (every role, `--flag` → `SHADE_TREE_*` env) |
| `lib/rln.mjs`, `circuits/rln/` | circom-rln Groth16: prove, verify, reconstruct, slash |
| `lib/directory.mjs`, `lib/root-provider.mjs`, `lib/helios-root.mjs` | Signed fleet directory + caps; on-chain root read (node / light client); Helios anchor |
| `lib/gateway-registry.mjs`, `lib/zk-artifacts.mjs` | Gateway-stake verifier; ZK artifact-set lock + negotiation |
| `contracts/` | `StakedReputationSet.sol`, `PaidAccessSet.sol`, `GatewayRegistry.sol` |
| `gateway/gateway.mjs` | Onion-side egress: admit set, verify, dedup/slash, tunnel, drop |
| `bootnode/` | Discovery server, announce, keygen, heartbeat, fetch; `deploy/` = the one-command droplet |
| `client/` | The fleet client library (`shade-tree-client.mjs`), HTTP-CONNECT proxy (`shim.mjs`), selection |
| `payments/` | The 402 registrar, both wire dialects, EIP-3009 typed data, test-asset deploy |
| `group/` | Self-enrollment, `shade-tree pay`, `shade-tree leaves`, on-chain register (member / gateway), the committed `members.json` |
| `network/` | Committed deployment records per network; `SHADE_TREE_NETWORK` reads them |
| `rust/` | The distributable client: `shade-tree-proto` (wire), `shade-tree-rln` (prover + tree), `shade-tree-client` (embedded arti, `-live`) |
| `test/`, `testdata/`, `scripts/test-all.mjs` | Foundry suite + cross-module selftests; golden vectors + artifact lock; the audit entrypoint |
| `docker/`, `monitoring/`, `examples/`, `web/`, `smithers/` | Local container fleet; Prometheus/Grafana; agent examples; fleet map page; the roadmap as a Smithers workflow |

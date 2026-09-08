# Payments: anonymous, cheap, ergonomic, scalable access funding

## Shipped 2026-08-17: 402 rails

**Status: Layer 1 is built and live on Sepolia** (T-FEAT-7). Access is *purchased* over HTTP 402
using the two machine-payment protocols, settled in a stablecoin on the chain the fleet is
deployed on, and the operator inserts the buyer's leaf into the on-chain `PaidAccessSet`.
Redemption is unchanged: the buyer egresses with the ordinary RLN proof and the gateway trusts
the paid set's root next to the staked set's. The design below ("The architecture", Layer 1)
described a native-ETH `deposit(commitment) payable` / `sweep()` contract; **that Layer 1 is
superseded by the 402 rails** (payment settles off the tree contract, in a stablecoin, straight
to the operator). The on-chain tree, the off-chain redemption, Layer 0 and Layer 2 stand as
written.

Code: `payments/registrar.mjs` (the operator's 402 service), `payments/wire.mjs` (both wire
formats), `payments/eip3009.mjs` (the settlement typed data), `group/pay.mjs` (`shade-tree pay`),
`contracts/PaidAccessSet.sol` (the tree, PR #50), `test/Eip3009Token.sol` (a test stablecoin).
Tests: `payments/wire.selftest.mjs` (fast, chainless; includes the x402 spec's worked-example
signature as a cross-implementation golden), `payments/registrar.selftest.mjs` (anvil: both
rails end to end via `shade-tree pay`, replay/idempotency, the adversarial matrix, slow-loris, crash
recovery), `test/Eip3009Token.t.sol` (Foundry). Live receipts: `docs/GO-LIVE-LOG-2026-08-17.md`
"(payments)".

### The flow

```
 buyer (shade-tree pay)                registrar (operator, on the bootnode onion :8878)          chain
   |                                   |                                                     |
   | GET /pay/quote?limit=8            |                                                     |
   |---------------------------------->|                                                     |
   | 402  PAYMENT-REQUIRED (x402)      |                                                     |
   |      WWW-Authenticate: Payment (MPP)                                                    |
   |      body: {pay:{asset, chain, tiers, payTo}}                                            |
   |<----------------------------------|                                                     |
   | sign EIP-712 TransferWithAuthorization (EIP-3009) with the BUYER wallet: no gas needed |
   | POST /pay {commitment, limit}     |                                                     |
   |   + PAYMENT-SIGNATURE   (x402)    |                                                     |
   |   | Authorization: Payment (MPP)  |  verify shape/offer/window/signature/nonce/balance   |
   |---------------------------------->|  token.transferWithAuthorization(...)  (operator pays gas)
   |                                   |---------------------------------------------------->|
   |                                   |  wait 1 conf                                        |
   |                                   |  PaidAccessSet.insert(commitment, limit)            |
   |                                   |---------------------------------------------------->|
   | 200  PAYMENT-RESPONSE (x402) / Payment-Receipt (MPP)                                    |
   |      {settleTx, insertTx, leafIndex, root}                                              |
   |<----------------------------------|                                                     |
   | now: shade-tree proxy …  (secret from env; RLN proof against the paid root; the gateway sees a proof, not a leaf)
```

x402 uses `GET /pay/quote` for the challenge; MPP uses `POST /pay` *without* a credential for
the challenge, so the challenge is digest-bound (RFC 9530) to the exact body the buyer then
pays for. Both are the same route with the same body; the registrar answers with **both**
challenges every time, so a client speaks whichever it prefers.

### Headers (both rails, exact)

| rail | server → client (challenge) | client → server (payment) | server → client (result) |
|---|---|---|---|
| x402 v2 | `402` + `PAYMENT-REQUIRED: base64(PaymentRequired)` — `{x402Version:2, resource, accepts:[{scheme:"exact", network:"eip155:<chainId>", amount, asset, payTo, maxTimeoutSeconds, extra:{name, version, assetTransferMethod:"eip3009", limit}}]}` (one entry per tier) | `PAYMENT-SIGNATURE: base64(PaymentPayload)` — `{x402Version:2, resource, accepted, payload:{signature, authorization:{from,to,value,validAfter,validBefore,nonce}}}` | `200` + `PAYMENT-RESPONSE: base64({success:true, transaction:<settleTx>, network, payer})`; failure = `402` + fresh `PAYMENT-REQUIRED` + `PAYMENT-RESPONSE {success:false, errorReason}` (400 for a malformed payload) |
| MPP | `402` + `WWW-Authenticate: Payment id="…", realm="<onion>", method="evm", intent="charge", request="<b64url JCS {amount, currency, recipient, description, externalId:"limit=8", methodDetails:{chainId, permit2Address, credentialTypes:["authorization"], decimals, eip712Domain}}>", expires="<RFC3339>", opaque="…"[, digest="sha-256=:…:"]` (one header per tier) + RFC 9457 body | `Authorization: Payment <base64url({challenge:{…echoed…}, payload:{type:"authorization", from,to,value,validAfter,validBefore,nonce,signature}, source:"did:pkh:eip155:<chainId>:<addr>"})>` with `nonce == keccak256(id ‖ realm)` | `200` + `Payment-Receipt: base64url({status:"success", method:"evm", challengeId, reference:<settleTx>, timestamp, chainId})`; failure = `402` + fresh challenge + `application/problem+json` (`malformed-credential` / `invalid-challenge` / `verification-failed` / `payment-expired` / `payment-insufficient`; `method-unsupported` = 400) |

x402 **v1** (`X-PAYMENT` / `X-PAYMENT-RESPONSE`, `x402Version:1`) is *not* served; a v1 payload
gets `invalid_x402_version`. The current version (v2, `PAYMENT-*` headers) is what the
registrar speaks (specs fetched 2026-08-17: `coinbase/x402 specs/x402-specification-v2.md`,
`specs/transports-v2/http.md`, `specs/schemes/exact/scheme_exact_evm.md`; `tempoxyz/mpp-specs
specs/core/draft-httpauth-payment-00.md`, `specs/intents/draft-payment-intent-charge-00.md`,
`specs/methods/evm/draft-evm-charge-00.md`).

The MPP challenge `id` is the core draft's recommended stateless binding: `base64url(
HMAC-SHA256(secret, realm|method|intent|request|expires|digest|opaque))` (seven fixed slots,
absent optionals as `""`); the secret is random per registrar and persisted in the order store
so a restart keeps unexpired challenges valid. Editing any challenge parameter (amount, recipient,
expiry, digest…) breaks the id; the wire selftest and the anvil selftest both prove that.

### One settlement primitive: EIP-3009, submitted by the operator

Both rails carry the same signed object: an EIP-712 `TransferWithAuthorization(address from,
address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)` over the
**token's** domain (`{name, version, chainId, verifyingContract}` — USDC is `{"USDC","2"}`;
the registrar probes `name()`/`version()` and *proves* its computed domain equals the token's
on-chain `DOMAIN_SEPARATOR()` at boot, or refuses to start). The buyer's wallet needs the
stablecoin and **nothing else** — no ETH, no approval, no on-chain action: the operator submits
`transferWithAuthorization(from,to,value,validAfter,validBefore,nonce,v,r,s)` and pays the gas,
then `insert(commitment, limit)` (gas again). The token contract burns `(from, nonce)` on use
(`authorizationState`), which is the replay primitive both protocols lean on; x402 uses a fresh
random nonce, MPP binds it to the challenge (`keccak256(id ‖ realm)`).

**What the registrar verifies before it spends any gas** (`payments/registrar.mjs`
`makeEngine.verifyAndSettle`, in order): wire shape (version/scheme/network/asset/payTo/amount
→ tier; MPP: HMAC id, realm, expiry, digest, `type=authorization`, nonce binding); the body's
`limit` equals the tier paid for and the `commitment` is a field element; `validAfter ≤ now <
validBefore − settleBuffer` (default 20 s of headroom so the tx can still mine); the signature
recovers to `from` over the token domain; on chain: `authorizationState(from,nonce) == false`,
`balanceOf(from) ≥ value`, `PaidAccessSet.limitOf(commitment) == 0` (never take money for a
leaf that cannot be inserted); an `eth_call` simulation of `transferWithAuthorization`. Then,
serialized on the operator key: settle → wait `SHADE_TREE_PAY_CONFIRMATIONS` (1) → insert → wait.
Each receipt wait also has the wall-clock `SHADE_TREE_TX_RECEIPT_TIMEOUT_MS` deadline (180 s).

**Idempotency + crash safety.** Every order is keyed by `(asset, from, nonce)` in a small JSON
store (`SHADE_TREE_REGISTRAR_STORE`, atomic tmp+rename like the bootnode's). An identical replay of a
finished order returns the stored receipt (`200`, `replayed:true`, no second insert); the same
nonce with a different commitment is `409 nonce-used`; a nonce already consumed on chain that
the store never saw is `402`. A settle that mined but whose insert did not is resumed on the
next identical POST and on boot (`recover()`). If a receipt deadline expires, the order remains
`settling` or `inserting` with its broadcast hash. A null receipt is ambiguous, so the registrar
reports `503 in-progress` and never resubmits until a receipt or active leaf resolves the state.
`GET /pay/status/<nonce>` shows an order's public state.

### No facilitator: the operator IS the facilitator

x402 defines a "facilitator" role (verify + settle, typically hosted). Here **the operator's own
registrar is that facilitator**: it verifies the typed-data signature and submits the transfer
itself, on its own key, against its own RPC. No hosted facilitator is called, none is needed, and
using one is optional (an operator could point a Coinbase-style facilitator at the same
`accepts` — nothing in the wire format changes). MPP's "server" role is the same process. So the
"no facilitator party" rule of this document holds exactly: the buyer touches the chain (to
hold the stablecoin) and the operator (to buy), nobody else. There is no x402 SDK dependency:
the wire format is ~300 lines implemented straight from the specs (`payments/wire.mjs`), which
keeps `ethers` the only crypto dependency, avoids pulling a facilitator client into an onion
service, and lets the same parse surface serve both rails and be fuzzed in one place.

### Leak ledger (as shipped)

| link | what is public | mitigation |
|---|---|---|
| buyer address → operator | the stablecoin transfer is on chain: `from` (buyer) → `payTo` (operator), amount = the tier's price; the insert tx (operator → set) follows within a block or two | **Layer 0 is the user's choice**: pay from a fresh address funded through a shared pool (Railgun / Privacy Pools / a CEX withdrawal…). `shade-tree pay` prints this advice every run. Nothing in the protocol mandates a pool. |
| tier | public: the transfer amount *is* the tier price, and `insert(commitment, limit)` names the tier | by design (a tier bucket is a public anonymity set, as with the staked set); prices are fixed per tier so amounts never fingerprint within a tier |
| payer ↔ leaf | the **operator** learns `commitment ↔ from` (it inserts the leaf right after that payment); a chain observer can correlate the transfer with the next `Inserted` event by timing | the gateway never learns it — it verifies an RLN proof against the root, not a leaf; batching inserts (`insertBatch`) and a dwell time between settle and insert would blur the chain-timing link and are a one-flag operator choice later |
| client IP → anything | the quote/pay round trip rides the bootnode onion (`http://<onion>:8878`); the registrar sees a rendezvous circuit, never the buyer's IP | standard Tor caveats only |
| operator linking payment to *use* | it cannot: redemption is a Semaphore/RLN proof over the paid root | timing correlation between an insert and a first use — dwell time (user's choice) |
| the operator taking money and not inserting | the buyer holds the settle tx hash and the order key; the registrar's store retries the insert on boot; a refusal is visible (payment on chain, no `Inserted`) | buyer–seller trust, irreducible for any prepaid service (as stated below); public evidence makes it reputational |

### Per-provider choice: what a gateway sells, and on which rails (T-FEAT-9, ADR [0008](adr/0008-per-gateway-admission-and-payment-choice.md))

Selling access is EACH provider's decision, not the fleet's:

- **Rails.** `SHADE_TREE_PAY_PROTOCOLS=x402,mpp` (default both when the registrar is enabled; any non-empty
  subset) is what THIS registrar serves. A disabled rail gets no challenge in any 402 (`GET /pay/quote`,
  the bodied `POST /pay`), is absent from the 402 body's `pay.protocols` and from `/health`, and a
  `POST /pay` carrying its header (`PAYMENT-SIGNATURE` / `Authorization: Payment`) is refused
  `400 { err:"protocol-disabled", protocol, protocols:[enabled] }` before any parsing. `shade-tree pay
  --protocol mpp` against an x402-only registrar says so: "this registrar does not serve mpp (it
  sells via: x402); retry with --protocol x402". x402 and MPP are EQUAL on the anonymity axis (one
  EIP-3009 transfer either way); the choice is fees, tooling, and the buyer's client.
- **Where.** A registrar rides an onion the box already runs: the bootnode's (as shipped 2026-08-17)
  or — a gateway-only box — the GATEWAY's own onion (`bootstrap.sh SHADE_TREE_REGISTRAR=1` with
  `SHADE_TREE_BOOTNODE_ONION` set: `HiddenServicePort 8878` in the gateway HS block, `SHADE_TREE_REGISTRAR_ONION`
  = the gateway onion). Every provider may therefore run its own registrar + its own `PaidAccessSet`
  and sell on its own terms; nothing requires a bootnode.
- **Advertised where.** The offer (`{protocols, onion?, port, asset, chain, tiers}`) rides in the
  gateway's SIGNED caps as `caps.pay` (heartbeat `SHADE_TREE_REGISTRAR_ADVERTISE=1`; `onion` names the
  registrar's onion when it is not the gateway's own, e.g. the bootnode's) — and, on a bootnode box,
  in the bootnode's `/health` `pay` as before. Both may coexist; the caps form is what a client
  learns from `/directory` and cannot be forged by the bootnode (`docs/WIRE-SPEC.md` §3.0.1).
- **Admit what you sell.** A gateway must ADMIT paid leaves to sell them: `SHADE_TREE_ADMIT` must include
  `paid` (`bootstrap.sh` refuses `SHADE_TREE_REGISTRAR=1` otherwise), and the default policy is `invited`
  ALONE — a provider that never opts in never admits a paid leaf, whoever inserted it. Conversely a
  buyer's client routes ONLY to gateways whose `caps.admits` include `paid` (`docs/CLIENTS.md`
  "Leaf source"): on the sepolia demo fleet that is gateway-1 (`invited,staked,paid`), not gateway-2
  (`invited,staked`) — `network/sepolia/README.md`.

### Settle asset on Sepolia

Circle's Sepolia USDC (`0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`) implements EIP-3009 (checked
2026-08-17: `TRANSFER_WITH_AUTHORIZATION_TYPEHASH()`, `authorizationState()`, `DOMAIN_SEPARATOR()
== keccak(EIP712Domain{"USDC","2",11155111,0x1c7D…})`), but its faucet is captcha-gated, so the
live run uses the test stablecoin `test/Eip3009Token.sol` ("Test USD"/tUSD, 6 decimals, same
EIP-3009 surface) deployed at `network/sepolia/contracts.json` `payAsset`. **Real USDC is a
one-env swap**: `SHADE_TREE_PAY_ASSET=0x1c7D…7238` (the registrar probes the domain and adapts).
`payments/deploy-test-asset.mjs` deploys/mints the test token.

---

## Shipped 2026-08-17: the gateway / root / slash / client half (T-FEAT-7 2/3, ADR [0007](adr/0007-paid-access.md))

The registrar above sells the leaf; this is what happens to it afterwards — how the fleet trusts the paid set next to the staked and static ones, how a paid over-spender is slashed, and how a buyer's client finds its leaf.


| Layer | What it is now | Code |
|---|---|---|
| **0 — identity decorrelation** | Unchanged: the buyer's choice of hop into a fresh address / account (Railgun, Privacy Pools, a CEX, a bridge; none mandated), now applied to the 402 payment as well as to any on-chain footprint. Nothing to build; documented in the leak ledger + THREAT-MODEL §5. | — |
| **1 — payment + binding** | 402-settled off-chain payment (x402/MPP) → operator inserts the buyer's rateCommitment `Poseidon2(Poseidon1(identitySecret), limit)` into `PaidAccessSet`: the structural sibling of `StakedReputationSet` (T-DEV-9 on-chain depth-20 Poseidon tree, `currentRoot()` at storage slot 3, tiered leaf, `limitOf` / `leafCount` / `allowedLimits` / `DEFAULT_LIMIT`, `slash(commitment, secret, limit, receiver)` zeroes the leaf — no bond, no exit/withdraw). Contract: `contracts/PaidAccessSet.sol` (T-FEAT-7 1/3, PR #50; live on Sepolia at `0x4e8C2Bf5d3c5454A04837401095fce2646484111`). Off-chain readers: `lib/root-provider.mjs:TOPIC.inserted / TOPIC.deposit / TOPIC.paidSlashed` (the paid events, `(commitment indexed, limit, index, root)`), `reconstructGroup`, `loadGroupFromContract`. | `contracts/PaidAccessSet.sol`, `lib/root-provider.mjs` |
| **2 — access** | Unchanged envelope + proof. The gateway trusts the UNION of its root sources — `members.json` (static), each `SHADE_TREE_GROUP_CONTRACT` (now a comma list) and `SHADE_TREE_PAID_ACCESS_CONTRACT` (sugar that appends) — one `RootProvider` per contract, node or light, unioned by `CompositeRootProvider`; `SHADE_TREE_ROOTS=static,onchain` selects (default = both when configured). Slashing ROUTES to the contract that holds the leaf. Anonymity floor `SHADE_TREE_PAID_MIN_LEAVES` (default 8) is logged + gauged, never enforced. Client: leaf discovery across the same sources; Rust bridge `shade-tree leaves`. | `gateway/gateway.mjs:initRoots / resolveRootSources / describeRootSources / makeRoutingSlasher / makeOnchainSlasher.holds / PAID_MIN_LEAVES`, `lib/root-provider.mjs:CompositeRootProvider / configuredContracts / parseContractList / makeRootProvider`, `client/shade-tree-client.mjs:makeLeafSourceLoader`, `group/leaves.mjs`, `lib/config.mjs:isEthAddressList / isRootSourceList` |

Startup lines (ABI-of-record for scripts): `roots: members.json + staked(0x…) + paid(0x…)`,
`paid-access anonymity set: N leaves (floor K=SHADE_TREE_PAID_MIN_LEAVES)` (WARN below the floor,
never refuse), `slash: routing over primary(0x…) + staked(0x…) + paid(0x…)`, and on a slash
`slash: routed to paid(0x…)` / `SLASH tx … via=0x…`. Metrics use source-only labels:
`shade_tree_gateway_trusted_roots{source}` where `source` is `invited`, `staked`, or `paid`;
`shade_tree_gateway_paid_access_leaves` has no labels. Contract addresses are not metric labels.

**Decisions on the four open items** (below, "Buildable today vs open"):

1. *Live root vs pinned per-epoch snapshot* → **live**, exactly as the staked set: the gateway reads the confirmed root (`finalized`, or `head - SHADE_TREE_CONFIRMATIONS`) and keeps the freshness ring (`SHADE_TREE_FRESHNESS_ROOTS`, current + 2 prior), so a proof built against a just-superseded root still verifies and a reorg is bounded by the confirmation depth. No separate pin was needed (`lib/root-provider.mjs:NodeRootProvider / LightClientRootProvider`, unchanged; the paid set is just one more child).
2. *One deposit = one access period vs an ongoing budget* → **subscription**: nullifier scoped to the epoch, fresh `limit` budget every epoch, for as long as the leaf lives (until slashed). Expiry is a follow-up (the contract could zero a leaf after N epochs; nothing in the gateway changes).
3. *Anonymity-set floor K* → **logged, not enforced**: `SHADE_TREE_PAID_MIN_LEAVES` (8). `leafCount()` (total leaves ever inserted; slashed slots never reused) is read at startup and on every root refresh; below the floor the gateway WARNs and keeps serving. It is a deployment parameter, not a proven bound — say it, do not hide it.
4. *Wiring the Layer-0 hop and the payment to one decorrelated address* → **a wiring note, unchanged by the pivot**: pay the 402 from a fresh address / account funded through the hop; the registrar's insert tx carries only the commitment + tier, never the payer. THREAT-MODEL §5 lists the residual (payment-side) linkability.

**Leak ledger, updated:** in addition to the rows below — the **tier bucket is public** at insertion (the `limit` in the `Inserted` event; the same is already true of a stake's `bondFor(limit)`), the insert tx is public (it names the commitment, not the payer), the 402 payment is visible to its rail, and **which root a proof opens (static / staked / paid) is visible to the gateway** (the root is a public signal) — the paid crowd is `leafCount()`, hence the floor.

**Verified by:** `test/paid-access.selftest.mjs` (anvil: the real staked set + the real `PaidAccessSet` from its forge artifact, the REAL gateway, REAL proofs — static, staked and paid members all egress with three roots trusted at once; unknown root → `gate:wrong-group-root`; a paid over-spender is slashed on the PAID contract, leaf zeroed, root changed, staked set untouched; the floor WARN; `shade-tree leaves` round-trips the root), `gateway/root-sources.selftest.mjs`, `client/leaf-source.selftest.mjs`, `group/leaves.selftest.mjs`, `lib/root-provider.selftest.mjs`.

## Design of record (2026-08, pre-402): the four requirements and the three layers

**Status: design; Layer 1 below is superseded by the 402 rails above (the tree + off-chain redemption stand).** This supersedes the earlier four-pass design. The access layer it builds on (Semaphore membership proof + epoch nullifiers) is live.

## What we are solving

Today membership is granted by a local `enroll` command. We want access to be **purchased**, under four requirements and one sharpened constraint.

1. **Anonymous.** Cryptographic unlinkability between who paid and who used. Not "no-KYC." Actual unlinkability.
2. **Cheap**, in dollars and in resources. Per-message verify cost and server-side double-spend state both stay small.
3. **Ergonomic.** Hard constraint: no expensive operation per message. A fresh zk proof, an on-chain transaction, or a Lightning payment on every request is disqualified. A Semaphore proof is 240ms on a laptop and 800ms on the 2 vCPU gateway (see `experiments/`), so anything per-message must be a cheap token check.
4. **Scalable.** Cost and state grow with active users on hardware we control, not with block space we rent. Throughput is bounded by gateway CPU, not by L1 throughput.

The sharpened constraint, which the earlier design missed:

**No facilitator party.** The protocol must not assume interaction with any specific third party. Not a relayer, not an association-set curator, not a mint. The only parties a user touches are the permissionless chain (many nodes, no single operator) and the operator they are buying access from. The operator is irreducible: you are paying them. So the operator must be cryptographically unable to link payer to user, and nobody else gets to be in the loop at all.

## Why Ethereum L1 is the no-single-party choice

This is the reason to insist on L1, and it is an anonymity argument, not a tax we pay for one. Every L2 today runs a single sequencer operated by one company. A single sequencer is exactly a "one specific party" that can censor, reorder, and observe your transaction. L1 has no single sequencer. Insisting on L1 is not the price of anonymity. It is the anonymity move. We keep it.

## The architecture: three layers, three independent anonymity properties

Only the middle layer is new code.

**Layer 0: identity decorrelation. Optional. User's choice. No fixed party.**
If you do not want your funding address publicly known as a customer of a privacy-egress service, route the money through any large shared pool into a fresh address first. The protocol does not mandate which pool. Railgun, Privacy Pools, a CEX withdrawal, a bridge: all fine. It is a replaceable commodity hop. This is how we honor "no one specific party." The protocol assumes none, and where a big anonymity set is wanted, you pick the rail. If you want a named default that best fits the constraint, it is Railgun: client-side proof-of-innocence instead of a curator, and a decentralized broadcaster set rather than one relayer. Privacy Pools works too, but its association-set provider is a curator-party, so it is the weaker fit for this exact requirement.

**Layer 1: payment and binding. New. One small immutable contract.**

> **Superseded rail (2026-08-17, ADR 0007):** the payable `deposit(commitment)` / `sweep()` below is NOT what shipped. Payment settles off chain over HTTP 402 rails and the operator inserts the commitment (`insert(commitment, limit)`, operator only). The tree, the leaf and the redemption are exactly as described.

```
deposit(commitment) payable
    require msg.value == D            // one fixed denomination, so amounts never fingerprint
    append commitment to Merkle tree  // commitment = Poseidon(secret, nullifierSecret)
    emit Deposit(commitment, leafIndex)

sweep() onlyOperator
    transfer contract balance to operator   // this is how the operator gets paid
```

There is no on-chain user withdrawal. Funds accumulate and the operator sweeps them. The sweep is an operator-to-operator transaction that says nothing about depositors beyond a count. The commitment's preimage is never spent on chain. It is spent off chain, to the gateway.

**Layer 2: access. Already shipped. Unchanged.**
The cached epoch-proof and the per-nullifier rate budget in `gateway/gateway.mjs`.

## The redemption is the proof you already verify

This is the elegant part. The payment redemption is the exact same proof shape the gateway runs today.

`lib/semaphore.mjs` `checkProof` already does Merkle-membership-in-a-group, plus an epoch nullifier, plus a trusted-root match. The payment redemption is identical, with one swap: the group is the **on-chain deposit tree** instead of the enrolled `members.json`.

Over the existing onion, the client sends the gateway a zk proof: "my commitment is a leaf under the current on-chain deposit root, I know its preimage, and here is the nullifier `N = Poseidon(nullifierSecret, epoch)`," revealing nothing about which leaf. The gateway reads the root from its own node, or from many RPC endpoints (no single party), checks `N` is unspent in the per-epoch `Map`, and grants the access budget. You are swapping "membership in the enrolled set" for "membership in the paid-deposit set." Same circuit, same nullifier machinery, same rate-limit map.

The literature name for this is zk-creds, "insertion equals issuance" (Rosenberg, White, Garman, Miers, IEEE S&P 2023). A credential is issued by becoming a leaf in a public Merkle list, gated on a zk proof, with no issuer signing key. The paper explicitly describes Sybil-resistant tokens issued by making a blockchain payment. The one twist we add: redeem the leaf **off chain**, so the user never needs a gas-funded fresh address, which is what otherwise forces a relayer into the design.

## Why off-chain redemption, stated plainly

We spend the proof off chain. The alternative, spending it on chain so the contract only pays the operator when a valid proof lands, would make payment-for-access trustless. It would also force the user to submit a gas-paying transaction from a fresh address, which drags a relayer or a 4337 bundler back into the loop and adds a second L1 transaction per redemption. That breaks the no-facilitator rule and breaks scalability at the same time.

The cost of off-chain redemption is one honest line: the operator could take a deposit and refuse to honor a valid proof. That is buyer-seller trust, the same trust Cashu places in its mint to redeem a token, and it is irreducible for any prepaid service. It is not facilitator trust. No third party is added. You decided this tradeoff is the right one, and on cheap, ergonomic, and scalable it is not close.

## Leak ledger, redone for the single-party lens

| Link | Where it breaks | Residual to mitigate |
|---|---|---|
| payer address to use | off-chain zk membership over the deposit set: the gateway sees a proof, not a depositor | anonymity set = deposits under the redeemed root; thin at low volume, so batch and hold a dwell time |
| funding identity to the customer set | Layer 0 hop through any large shared pool into a fresh address | set bounded by the chosen pool; unique amounts and timing shrink it, so use the pool's fixed denomination |
| deposit amount fingerprint | single fixed denomination `D` for everyone | none if `D` is universal; a tiered price reintroduces it |
| client IP to anything | the redemption rides the existing Tor onion | standard Tor caveats only |
| operator linking payment to use | it cannot: the redemption proof hides which leaf | timing correlation between a deposit and a first use, so add dwell time and batch per epoch |

Two facilitator-parties from the old design are now gone by construction. There is no relayer, because nothing is submitted on the user's behalf. There is no association-set curator, because the gateway is its own verifier of its own deposit set, and it learns nothing about which depositor. There is no mint, because value settles on chain.

## Scalability

- **Per message:** unchanged. A cached proof, ~10 to 32ms verify, ~27 to 31 verifies per second per core measured on the 2 vCPU box. Horizontal across cores and gateways.
- **L1 footprint:** one deposit transaction per user per top-up period, and zero per-message on-chain cost. The operator amortizes one `sweep` across many deposits. This is the minimum possible L1 usage, so throughput is bounded by gateway CPU, not by block space.
- **Gateway state:** the per-epoch nullifier map is O(active members) and is already swept. No growth with history.
- **Proof generation:** scales with deposit-tree depth, which is logarithmic in total deposits. A LeanIMT keeps this cheap.

## Rejected, and why

- **A relayer for withdrawal.** One party that sees your withdrawal, can censor it, and can time-correlate it. Removed: off-chain redemption needs no submitter.
- **Privacy Pools association-set provider as a mandated step.** A curator that can exclude you. Removed from the protocol: decorrelation is Layer 0, user's choice, and Railgun's client-side proof-of-innocence is the curator-free default.
- **Cashu and any single mint.** One party that sees every payment, can refuse you, and holds your float. This is the single-party dependency the whole design exists to avoid.
- **On-chain redemption.** Trustless, but needs a gas-funded fresh address, so it reintroduces a relayer or bundler and an L1 transaction per redemption. Loses cheap, ergonomic, and scalable at once.
- **Payment channels, including zk channels (BOLT, zkChannels).** Rejected in an earlier pass and worth restating here because it is the cleanest statement of our core constraint. BOLT (Green and Miers, ACM CCS 2017) requires a channel to "be established with a counter-party before being used," treats the merchant as "a known identity," and its own Tor example concedes that "establishing a channel to pay for Tor bandwidth implicitly links each payment on a given channel to all of her other payments." A channel is a persistent counterparty, which is exactly the payer-to-use link we destroy. Production zk channels are also dead (libzkchannels archived February 2023) and run 7 to 9 seconds per payment, four orders of magnitude over our cached hot path.
- **GNU Taler.** Income-transparent by design and the exchange most likely needs a bank license. Wrong for a solo Tor operator.
- **L402.** The macaroon embeds the invoice payment hash plus a persistent user id, and the operator is both issuer and verifier, so it trivially links payment to use.

## Buildable today vs open

**Buildable now from shipping primitives:** Semaphore v4 (the circuit and nullifier machinery we already run), a minimal deposit/sweep contract, an on-chain Merkle root the gateway reads, the Tor onion we already operate, and for Layer 0 any of Railgun, Privacy Pools, a CEX, or a bridge.

**Open engineering decisions, not blockers:**

1. Whether the redemption proof verifies against the live on-chain root every time, or against a periodically pinned root the gateway snapshots per epoch. Pinning is simpler and bounds reorg edge cases. Likely yes.
2. Whether one deposit buys one access period (nullifier scoped to the deposit, single redemption ever) or an ongoing rate budget (nullifier scoped to the epoch, fresh budget each epoch). The first is pay-as-you-go, the second is a subscription. Both are a one-line scope change in the circuit.
3. Minimum deposits per epoch before redemptions are honored, the anonymity-set floor `K`. A deployment parameter, not a proven bound. Log it, do not hide it.
4. Proving the Layer 0 hop and the Layer 1 deposit can share one decorrelated address cleanly, so the deposit is never linkable to the user's main funds. A wiring detail.

## Recommendation

Build Layer 1 as a fixed-denomination deposit/sweep contract, redeem the deposit off chain to the gateway with the existing Semaphore proof shape against the on-chain deposit root, and leave identity decorrelation as a user-chosen Layer 0 hop through any large shared pool. The result touches no facilitator, costs one L1 transaction per top-up, reuses the entire access stack unchanged, and scales with gateway CPU. The only trust is the operator-honors-a-valid-proof trust that any prepaid service carries, and the only cryptography is primitives we already ship.

## Sources

- zk-creds, "insertion equals issuance": Rosenberg, White, Garman, Miers, IEEE S&P 2023 (eprint 2022/878).
- Payment-channel counterparty linkage: BOLT, Green and Miers, ACM CCS 2017.
- Semaphore v4 and LeanIMT: Semaphore v4.0.0 release notes.
- RLN rate-limiting nullifier: rln.waku.org, rate-limiting-nullifier docs.
- Stealth addresses and account abstraction, for the rejected on-chain-redeem path: ERC-5564, ERC-4337.
- Layer 0 pools: Railgun (proof-of-innocence, broadcaster network); Privacy Pools, Buterin/Soleimani et al. (SSRN 4563364).
- Rejected rails: GNU Taler exchange manual; L402 macaroon spec; zkChannels/libzkchannels status.

Claims marked as costs, gas figures, and library maturity should be re-verified against current sources before this design is built. The architecture does not depend on any single number above.

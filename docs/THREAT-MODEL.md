# Threat model

This is the consolidated, auditor-facing threat model for the ShadeNet
system. It names the assets, the actors and adversary classes, states what each party is trusted
for and — more importantly — what it is *not* trusted for, and maps each security property to the
exact code that enforces it (`file:function`). It ends with the known residual risks (honestly, and
cross-referenced to the tracked tasks) and a short "where to start" for a review.

Ground rules for this document:

- Every enforced property below cites the function that enforces it. Where a property is designed
  but the enforcement path is not fully wired in the shipped code, it is marked **claimed,
  unverified** rather than asserted.
- This is a reference implementation, **unaudited**, with **testnet-only ZK artifacts** from an
  untrusted phase-2 ceremony (`circuits/rln/ARTIFACTS.md`, `SECURITY.md`). Nothing here is a
  production security guarantee. Read `docs/AUDIT.md` first; this page is its threat-model companion.

---

## 1. Assets

| Asset | What it is | Where it lives | Compromise impact |
|---|---|---|---|
| Member identity secret | The app field-element secret behind a Semaphore v3 / RLN identity | Client only, never on the wire | Full impersonation of that member |
| `identitySecret` | `Poseidon2(nullifier, trapdoor)` of the identity; the value a slash reveals | Derived client-side (`packages/node/lib/rln.mjs:identitySecretOf`) | Two different shares under one nullifier reconstruct it, deliberately revealing the slashable leaf |
| RLN transcript unlinkability | Distinct slots do not expose a shared leaf or stable cryptographic identifier | Enforced by the RLN nullifier structure | Loss creates a cryptographic link across a member's uses; timing and traffic metadata are separate correlation channels |
| Gateway onion identity key | The ed25519 seed behind a v3 `.onion` (a `.onion` **is** this pubkey) | Operator host (`tor/hs/`, `packages/node/bootnode/keygen.mjs`) | Lets an attacker impersonate that gateway in the directory/announce |
| Directory signer key | The pinned ed25519 key that signs the fleet directory | Bootnode / offline signer | Lets an attacker sign a poisoned fleet list — but see the layered onion↔key check below |
| On-chain bonds | Member bonds (`StakedReputationSet`) and operator bonds (`GatewayRegistry`) | Ethereum (Sepolia) | Fund-custody / slash-authorization bugs |
| Target metadata | The `host:port` a member egresses to | Encrypted in transit through Tor; plaintext to the serving gateway | A gateway can correlate destinations, timing, tunnel lifetime, and volume for the tunnels it serves |

---

## 2. Actors and adversary classes

**Honest actors**

- **Member (client).** Holds a membership secret, proves membership per tunnel, selects a gateway
  per tunnel, and egresses over a Tor rendezvous with no exit node. The onion transport hides the
  member's source IP from the gateway; it does not prevent traffic or application-layer correlation.
- **Gateway / operator.** Runs an onion service that proxies member egress to a public IP. Optionally
  stakes an operator address on chain. Pays the gas to slash a member over-spender.
- **Bootnode.** Publishes its own v3 onion, collects gateway announces, and serves a *signed*
  directory of live gateways. Signs the directory with the pinned signer key.
- **On-chain registry.** `StakedReputationSet` (members) and `GatewayRegistry` (operators): canonical,
  public, tamper-evident stake + membership state.

**Adversary classes** (each is addressed in §4/§5):

- **A1 — Malicious gateway.** A gateway a member dials. Wants to deanonymize the member, redirect a
  member's proof to a different target, replay/amplify a captured envelope, or forge a receipt.
- **A2 — Malicious / replaying bootnode.** Wants to steer a client to a hostile gateway, inject an
  onion, resurrect a dropped/slashed gateway with an old-but-validly-signed directory, or paste a
  fake `staked` label.
- **A3 — Network observer, member end.** Sees the member's local traffic into Tor. (Out of scope to
  the same degree Tor itself is: a global passive adversary.)
- **A4 — Network observer, gateway end.** Sees the gateway's egress to the public destination.
  Knowing a gateway's own exit is explicitly *not* the threat (`docs/ROADMAP.md` #3).
- **A5 — Over-spending / tier-forging member.** A member that tries to exceed its rate budget, reuse
  a slot, or claim membership it does not hold.
- **A6 — Sybil operator.** An entity that spins up many gateways (and/or many stakes) to raise its
  odds of being the operator a given member rotates onto.

---

## 3. Trust assumptions — what each party is and is NOT trusted for

**The Tor network / v3 onion addressing.**
Trusted for: rendezvous confidentiality and the fact that a v3 `.onion` *is* an ed25519 public key,
so reaching the service at all requires it to hold that key. NOT trusted for: hiding a member's own
exit from the member (it never does; path selection is client-side by design), nor for enumerating
gateways (blinded HSDir descriptors deliberately prevent that — hence the app-layer directory).

**The bootnode.**
Trusted for: *availability* of a fresh fleet view and, unless the client independently re-verifies,
the operator↔onion and `staked` labels. A serving bootnode without the directory signing key can
omit entries or replay a previously signed view, but cannot change signed bytes. An attacker with
the signing key can sign any syntactically valid onion/pubkey entry and attach false labels,
including an attacker-controlled onion. Onion↔pubkey verification prevents a mismatched address
and key; it does not prove control of a compact-directory entry. Optional stake re-verification
narrows the label trust. The bootnode is not a substitute for a protected signing key.

**The pinned directory signer (`SHADE_TREE_DIR_SIGNER`).**
Trusted for: authenticating and choosing *which list* is the fleet. The bundled Sepolia client
profile pins the current v4 signer. An explicit Elder or static-directory source must supply its
matching pin (`packages/node/client/selection.mjs:parsePinnedSigners`); it is never accepted through trust on
first use. A compromised signer can add any internally consistent entry, including an
attacker-controlled onion/key pair. The independent onion↔pubkey check only prevents a mismatched
pair (see §5).

**The on-chain registry / RPC.**
Trusted like any node read. Stake/root reads default to `latest` (dev-chain friendly) and can be
pinned to a confirmation depth for reorg safety (`SHADE_TREE_CONFIRMATIONS`,
`packages/node/lib/gateway-registry.mjs:blockTag`, `packages/node/lib/root-provider.mjs`). NOT trusted to be reorg-safe at
default settings — that is an operator config. The **onion is never on chain**
(`contracts/GatewayRegistry.sol`): only an operator *address* stakes, so the fleet stays
un-enumerable and one stake can rotate across many onions.
*Lever: the RPC lies about the admission root.* With `SHADE_TREE_ROOT_PROVIDER=node` the RPC is
trusted for the root outright (event reconstruction; the solo-staker's own node). With
`SHADE_TREE_ROOT_PROVIDER=light` the root's slot **value** is proven by EIP-1186 proofs, so the only
remaining lie is the block `stateRoot` the proof is anchored to (a fake header + a proof
consistent with it admits the attacker's tree). **That lever is closed when `SHADE_TREE_HELIOS_RPC_URL`
is set** (T-DEV-9b, `packages/node/lib/helios-root.mjs`): the header comes from a local Helios verifying RPC
(beacon sync-committee signed), the RPC's header is cross-checked and a divergence is rejected
with a precise `stateRoot mismatch` reason; Helios unreachable / wrong chain fails closed. The
RPC can then only withhold (the last-known-good root keeps gating). Residual trust: the sync
committee (2/3-honest, ~512 validators / ~27h) and Helios' weak-subjectivity checkpoint —
`docs/LIGHT-CLIENT.md`. Unset, the gateway logs `stateRootSource: rpc header (TRUSTED, …)`.

**The admission ceremony.**
Trusted as the Sybil-resistance root (whatever adds a leaf). The RLN proof *gates* membership; it
does not *create* reputation. NOT trusted to provide anonymity of enrollment beyond what the chosen
admission policy inherently leaks (enrollment is publicly timestamped; `docs/ROADMAP.md` #2).

**The gateway operator.**
Trusted for: nothing cryptographic about the member. It sees each routed `host:port` in plaintext,
plus tunnel timing, lifetime, and traffic volume. RLN prevents the proof transcript from exposing a
stable member identifier across slots; it does not prevent a gateway or colluding fleet from using
network or application metadata to correlate tunnels. Rotation spreads observation rather than
removing it.

---

## 4. Security properties and where they are enforced

Each row cites the enforcing function. "Enforced" means verified present in the shipped source;
"claimed, unverified" flags a designed-but-not-fully-wired path.

### 4.1 Source-IP hiding from the gateway
The gateway terminates a Tor rendezvous; there is no Tor exit node and the client source IP is not
present on the application connection. **Enforced** by the onion transport (the shim /
`packages/node/client/shade-tree-client.mjs`), not by app crypto. This property does not hide targets or defeat
traffic analysis. Adversary A1/A4.

### 4.2 Membership soundness
A request carries a real RLN Groth16 proof of membership in a `rateCommitment` leaf of the depth-20
tree, checked against the currently-accepted root set. **Enforced** by
`packages/node/lib/rln.mjs:verifyEnvelope` (check 3 root membership + check 4 Groth16 verify) over
`recentRoots`. A forged set fails the root check; a bad proof fails verification. Adversary A5.

### 4.3 Per-tunnel proof unlinkability + rate cap (RLN)
The RLN nullifier is a function of the identity, the per-epoch `externalNullifier`, and a **private
`messageId` (slot)**; a member rotates the slot per tunnel, yielding distinct, mutually-unlinkable
nullifiers, capped at `K` per epoch (`K_SLOTS`, default 8). **Enforced** by
`packages/node/lib/rln.mjs:proveForSlot` (`messageId = i`, range-checked in the circuit) and the top-of-file RLN
semantics comment; the gateway keys its spent-set on the proof's *public-signal* nullifier
(`packages/node/lib/rln.mjs:verifyEnvelope` returns `nullifier` from `publicSignals`, never the envelope's copy),
so a lying envelope cannot desync accounting. At the proof layer the gateway learns a fresh
nullifier per slot and no stable leaf identifier. Target, timing, volume, account, and cookie data
may still correlate uses. Adversary A1 (including a colluding set).

The client allocates each slot through `packages/node/client/slot-state.mjs` before proving.
The versioned `{epoch,nextSlot}` state is serialized by an atomic directory lock
shared with the Rust client, durably replaced, and namespaced by the public
identity commitment Poseidon1(identitySecret) -- the same file for every leaf of
one secret, so two leaves can never both issue messageId 0 in an epoch; no bearer
secret is written. Restart, local proof failure, and a
crash after allocation therefore burn capacity rather than reuse a nullifier.
Missing state is accepted only as first use; corrupt, unavailable, locked, or
future-epoch state is refused, and the cursor resets only on a strictly newer
protocol epoch. The sole bypass deliberately wraps slots and is explicitly
named `unsafeAllowSlotReuseForTests` /
`--unsafe-allow-slot-reuse-for-slashing-tests` for isolated slashing tests.

**Reputation tiers (T-FEAT-8, `docs/adr/0006-reputation-tiers.md`).** `K` is per LEAF, not
global: the leaf is `Poseidon2(Poseidon1(identitySecret), userMessageLimit)` and the circuit
range-checks `messageId < userMessageLimit` with both PRIVATE, so a tier-32 member gets 32
unlinkable nullifiers per epoch from the same tree, and the tier itself never reaches the wire
  (the public signals, envelope, and `verifyEnvelope` result use the same schema and carry no
  explicit tier field — `test/reputation-tiers.selftest.mjs` UNLINKABLE). **Tier forgery (A5) is leaf forgery:** a
member proving with a limit its leaf does not carry has no Merkle path (`proveForSlot` "not in
group"), and a real proof over a self-made tree with the wished-for leaf is rejected
`wrong-group-root` before any SNARK work (`packages/node/lib/rln.mjs:verifyEnvelope` check 3); a tier-8
member at slot 8 has no valid proof at all (client pre-check + circuit RangeCheck assert), so
exceeding its tier forces a nullifier reuse => `over-spend-slashed`. Residual: `LessThan(16)`
is unsound for a limit >= 2^16, so admission MUST refuse such leaves (`MAX_LIMIT`, `normLimit`
— an admission-time rule, not a circuit one), and the on-chain hasher pins `K = 8`, so tiered
leaves staked on chain are unslashable there until `docs/ONCHAIN.md` "Tiers on chain" ships.

### 4.4 Message-to-target binding
A captured proof cannot be redirected to a different destination. The committed public `x` is
`calculateSignalHash(requestSignal(target, nonce))`; the gateway recomputes it from the envelope's
`target`+`nonce` and requires it to equal `ps.x`. **Enforced** by `packages/node/lib/rln.mjs:verifyEnvelope`
check **2b**, gated by `packages/node/lib/rln.mjs:signalFieldSafe` (rejects newline/oversize fields that could
make the newline-delimited `requestSignal` non-injective) and failing closed (`unbound-target`) when
`nonce`/`target` are absent. The invariant note in the code is explicit that 2b is only meaningful
*with* check 4 (`ps.x` is attacker-supplied until the Groth16 proof verifies). Adversary A1.
(Tracked history: T-DEV-3, now built.)

### 4.5 Over-spend detection and slashing
Two distinct public `x` values under the *same* nullifier are two points on the degree-1 line, so
the `identitySecret` is Shamir-reconstructed and the gateway attempts to slash the leaf at most once
per in-memory nullifier. **Enforced** by
`packages/node/gateway/gateway.mjs:makeSpentSet` (`admit` → the "distinct public x under the same nullifier"
branch → `reconstruct`/`derive`/`slash`), `packages/node/lib/rln.mjs:reconstructSecret` +
`packages/node/lib/rln.mjs:deriveCommitment`, and on chain `contracts/StakedReputationSet.sol:slash`
(**permissionless** — the secret is a cryptographic proof of over-spend; `slash` re-derives
`commitmentOf(secret)` and reverts `BadSecret` on mismatch). The spent set marks the attempt before
calling the slasher; a failed call is logged but is not automatically retried, so successful
on-chain slashing is not guaranteed. Adversary A5.

### 4.6 Per-gateway replay handling
An exact-envelope resend to the *same* gateway is accepted within a short window without counting
as an over-spend, and rejected after it. The current handler can open another upstream tunnel for
that accepted replay, so this is not side-effect idempotence. **Enforced** by `packages/node/gateway/gateway.mjs:makeSpentSet`:
the `seenEnv` fingerprint `nullifier|share.x|nonce` plus `replayWindowMs` (default 5s) →
`replay` (accept) vs `replayed-envelope` (drop). **Scope limit:** this is per-process, per-gateway
only; there is no shared spent-set across non-colluding gateways (residual T-FEAT-20, §5). Adversary
A1.

### 4.7 Directory authenticity, signer pinning, rotation allowlist
The whole list is ed25519-signed by a pinned signer, and the pinned argument is an **allowlist**
(single key, or an overlap set for rotation). **Enforced** by `packages/node/lib/directory.mjs:verifyDirectory`
(+ `normalizePinnedSigners`): the signature must verify under *some* pinned key AND the declared
`dir.signer`, when present, must itself be pinned — this is an allowlist, not "trust any signer"; an
unpinned or wrong signer is rejected (`signer-not-pinned` / `bad-signature`). Rotation without a
flag day: `SHADE_TREE_DIR_SIGNER` accepts a comma-separated `{old,new}` overlap set
(`packages/node/client/selection.mjs:parsePinnedSigners`; T-HARD-5, built). Adversary A2.

### 4.8 Onion↔key self-authentication (poisoned-directory defense)
Each directory/announce entry's `pubkey` must equal the ed25519 key encoded in its own v3 `.onion`
address. A v3 address *is* that key, so a mismatched or swapped pair is rejected. This is an
internal-consistency check, not proof that the directory signer controls the onion. **Enforced** by
`packages/node/lib/directory.mjs:onionToPubkey` (checksum-validated recovery) inside `verifyDirectory`
(per-entry `pubkey-onion-mismatch` / `bad-onion` rejection). At announce admission, control is
separately proven by `packages/node/bootnode/announce.mjs:verifyAnnounce` (`onionSig` verified via
`packages/node/lib/directory.mjs:verifyOnionControl` over `canonicalAnnounceBytes`, freshness-bounded by `ts`/skew
and optional `seenNonce`). The onion is never on chain (`contracts/GatewayRegistry.sol`). Adversary
A1/A2.

*Note (claimed, unverified):* `packages/node/lib/directory.mjs:verifyOnionControl` also exists as a **live per-dial
challenge**, but the code comment says to "wire the challenge/response into the gateway envelope
handshake" — the shipped per-dial handshake was not confirmed to call it. Connection-time onion
control is instead provided by Tor itself (you cannot reach a v3 onion without the service holding
its key); the announce signature provides it at directory-build time.

### 4.9 Directory rollback / stale-replay defense
An ed25519 directory signature is valid forever, so a hostile/replaying bootnode could serve an
*old* validly-signed directory to resurrect a dropped or slashed gateway, and stateless
`verifyDirectory` would accept it clean. Two guards close this in `packages/node/client/selection.mjs:ensureLoaded`:

- **Monotonic issued floor** (`lastAcceptedIssued`): a *fresh* directory whose `issued` predates the
  newest already accepted is rejected (`directory rollback rejected`); the last-known-good cache is
  exempt but still raises the floor. Stops *in-session* rollback.
- **Absolute max-age bound** (`SHADE_TREE_DIRECTORY_MAX_AGE_MS` + skew grace): a *fresh* directory older
  than the bound is rejected (`directory too stale`). **OFF by default** (T-FEAT-21), so a cold-start
  client with no prior state has *no* staleness bound unless configured — see §5. Both fail closed to
  the last-good in-memory fleet / cache. Adversary A2.

### 4.10 Client-side weight clamp (traffic-concentration defense)
Selection weight is gateway-attested, so a poisoned static directory or compromised signer could
try to concentrate a member's traffic on one gateway (a deanonymization lever). **Enforced** on the
client by `packages/node/lib/directory.mjs:clampWeight` (`MAX_WEIGHT = 1000`, negatives floored, NaN → 1),
independent of the bootnode's own announce-time clamp (`packages/node/bootnode/server.mjs` `MAX_WEIGHT`). Adversary
A1/A2/A6.

### 4.11 Operator↔onion binding + live stake (stake mode)
In `admission=stake`, an announce carries a durable operator ECDSA authorization binding
operator↔onion plus a live on-chain stake check. **Enforced** by
`packages/node/bootnode/announce.mjs:verifyAnnounce` (`verifyOperatorSig` recovers the operator from
`operatorAuthMessage` and confirms it equals `operator`; `isStaked` gated by `requireStake`, with a
chain-read failure hard-rejecting rather than silently passing) against
`contracts/GatewayRegistry.sol:isStaked` via `packages/node/lib/gateway-registry.mjs:makeStakeVerifier`. Revocation
= unstaking (`isStaked` flips false, entry drops next refresh). Adversary A2/A6.

### 4.12 Client zero-trust operator re-verification
The signed directory carries a bootnode `staked`/`operator` label the client cannot check from the
entry alone. With `SHADE_TREE_VERIFY_STAKE=1` the client refuses to take the label on faith: for every
entry claiming stake it fetches `GET /gateway/<onion>` and re-runs the same two proofs
(`verifyAnnounce` sigs + live `isStaked`), dropping any that fail. **Enforced** by
`packages/node/client/selection.mjs:reverifyGateway` / `filterReverified` (T-DEV-5). **OFF by default**, so the
default path still trusts the bootnode's pairing label — flagged as a residual in `SECURITY.md`.
Adversary A2.

### 4.13 Receipt privacy (no linkability channel)
A gateway's signed egress-success receipt is a per-*gateway* liveness attestation carrying **zero**
request-linkable data: only a schema version, the gateway's own `.onion` (self-authenticating via
`onionToPubkey`), a **coarse epoch bucket**, and a constant `ok:true`. **Enforced** by
`packages/node/lib/receipt.mjs:canonicalReceiptBytes` / `buildReceipt` / `verifyReceipt`, with a receipt-only
domain tag (`RECEIPT_DOMAIN`) providing domain separation so a receipt signature can never be
confused with an announce/directory signature by the same onion key. Deliberately absent: member
identity, nullifier (or any prefix), share, target `host:port`, request nonce, fine timestamp, or a
counter. Consequence stated honestly in-code: two receipts from one gateway in one epoch are
byte-identical, so a receipt proves gateway liveness, not that *your* request egressed — the missing
per-tunnel binding is exactly the linkability channel refused. The client-side tally that consumes
receipts is local-only, off by default, never transmitted
(`packages/node/client/selection.mjs:reportReceipt`, `SHADE_TREE_RECEIPT_SCORING`). Adversary A1.

### 4.14 On-chain stake / root reorg-safety
Stake and root reads can be pinned to a confirmation depth to reduce the chance that a reorg flips
an admission decision under the gateway. **Enforced** by `packages/node/lib/gateway-registry.mjs:blockTag` (reads at
`head - SHADE_TREE_CONFIRMATIONS`, or `finalized`) and `packages/node/lib/root-provider.mjs` (confirmation-depth
`eth_getLogs` up to `head - N` / `finalized`). **Default is `latest`** (dev-chain friendly), so
reorg risk reduction is opt-in via `SHADE_TREE_CONFIRMATIONS`. Reorgs deeper than the configured
depth, or failures in finalized-header assumptions, remain possible.
Adversary A2.

### 4.14b Multi-root admission: static + staked + paid sets (T-FEAT-7)
The gateway admits a proof under ANY root in the union of its configured sources — the static
`members.json`, each `StakedReputationSet` in `SHADE_TREE_GROUP_CONTRACT`, the `PaidAccessSet` in
`SHADE_TREE_PAID_ACCESS_CONTRACT` (`packages/node/gateway/gateway.mjs:initRoots`, `packages/node/lib/root-provider.mjs:
CompositeRootProvider`). Soundness per source is unchanged (§4.2: the proof still opens a leaf under
one trusted root); what the union changes is WHO can add a leaf: the operator (members.json, and the
paid set's operator-only `insert` after an off-chain 402 payment) and anyone who posts a bond
(staked). So the paid set is exactly as trustworthy as the operator's insert key — a stolen
registrar key mints admissions (never money: the contract holds none). Anonymity within the union:
a proof reveals which ROOT it opens (the root is a public signal), i.e. whether the member is a
static, staked or paid member, and nothing finer — the paid set's crowd is its live leaf count,
logged against `SHADE_TREE_PAID_MIN_LEAVES` (WARN, never refuse; the floor is a parameter, not a bound).
Slashing routes to the contract that holds the leaf (`limitOf`), so a paid over-spender loses its
leaf on the paid set and a staked one its bond; a members.json member is only ever dry-run/primary
slashed as before. **Enforced** in `packages/node/gateway/gateway.mjs:makeRoutingSlasher`; tested in
`test/paid-access.selftest.mjs`, `packages/node/gateway/root-sources.selftest.mjs`. Adversaries A1, A2, A4.

### 4.14c Per-gateway admission policy + `--max-anon` (T-FEAT-9, ADR [0008](adr/0008-per-gateway-admission-and-payment-choice.md))
What each admission path REVEALS is not the same, so §4.14b's "which ROOT the proof opens" leak has
three different weights (the ANONYMITY ORDER, most → least):

| leaf source | on-chain footprint of BEING a member | what a proof reveals to the gateway |
|---|---|---|
| `invited` (members.json) | none — a leaf in a file only the operator holds | "one of the operator's invited set" |
| `staked` (`StakedReputationSet`) | the staking wallet ↔ commitment (+ tier bond) is public and permanent; a bonded wallet is linkable to whatever funded it | "one of the staked set" — and the crowd is enumerable on chain |
| `paid` (`PaidAccessSet`) | the buyer address → operator transfer (amount = the tier price) and the following `Inserted(commitment, limit)` are public; the OPERATOR learns `commitment ↔ payer` (§4.17); x402 and MPP are equal here | "one of the paid set" — enumerable, and each leaf has a payer behind it |

Consequences and what is enforced:
- A gateway that admits several paths MIXES these crowds; a member's proof still shows only its
  root, but a member who wants the strongest guarantee should route only to gateways whose whole
  population is invited. Hence `SHADE_TREE_ADMIT` on the gateway (`packages/node/gateway/gateway.mjs:resolveAdmission`;
  the DEFAULT is `invited` ALONE, even when contract addresses are configured; a named path whose
  contract is missing fails CLOSED at startup) and the client's `--max-anon` (`packages/node/client/selection.mjs
  filterByAdmission`: keep ONLY gateways whose SIGNED `admits` is exactly `["invited"]`; a
  policy-less gateway cannot prove it and is EXCLUDED; and the client REFUSES to run with a staked or
  paid leaf, saying which linkability that leaf carries — an invited-only gateway would reject the
  proof `wrong-group-root` anyway). Default `--max-anon` OFF: a member routes to whatever admits its
  leaf source (a leaf source it cannot hide from the gateway either way — the root is public).
- The policy is a SIGNED cap (`caps.admits`, onion `capsSig` + announce `onionSig`), so a directory
  signer cannot rewrite a present policy without invalidating `capsSig`. It can omit the gateway or
  strip the optional caps and sign a legacy-looking entry. A client that sees no admitting gateway
  fails closed naming every advertised policy. Rollout caveat: an ABSENT `admits` is
  treated as "may admit any path" (except under `--max-anon`), so during the window a paid member may
  still meet one `wrong-group-root` + failover — exactly the pre-T-FEAT-9 worst case, never worse.
- What the client's CHOICE leaks: nothing new to the gateway (it already sees the root); to the
  bootnode nothing (the client fetches the whole directory and filters locally); the leaf-source
  label appears only in the client's own log/events (`SELECT … leaf=paid`).
- The registrar's rail choice (`SHADE_TREE_PAY_PROTOCOLS`) is a business knob with no anonymity delta
  (both rails settle the same EIP-3009 transfer, §4.17); a disabled rail's payload is refused
  `400 protocol-disabled` before any parsing (one less parser reachable by an unauthenticated peer).
- Slashing routes only over ADMITTED contracts (`makeSlasher({ rootContracts })`): a leaf in an
  un-admitted set could never have egressed here.
**Enforced** in `packages/node/gateway/gateway.mjs:resolveAdmission/initRoots`, `packages/node/client/selection.mjs:
filterByAdmission`, `packages/node/client/shade-tree-client.mjs:_admission`, `packages/node/lib/directory.mjs:canonicalAdmits`;
tested in `packages/node/gateway/admission.selftest.mjs`, `packages/node/client/admission-filter.selftest.mjs`,
`packages/node/lib/admission-caps.selftest.mjs`, `test/paid-access.selftest.mjs` §7. Adversaries A1, A2, A4.

### 4.15 Version-negotiation downgrade resistance
The gateway declares an inclusive envelope-version range and checks the incoming `v` **before any
field is read**, so a garbage or out-of-range version never reaches `verifyEnvelope`. **Enforced** by
`packages/node/gateway/gateway.mjs:acceptEnvelopeVersion` (sole version authority; `bad-version` for
non-integers, `unsupported-version` for out-of-range; absent `v` == legacy v3). The advertised range
rides back on rejection so a client can re-select. Capability advertisement (incl. the proto
range) is signed into the announce and directory entry with an onion-bound `capsSig`
(`packages/node/lib/directory.mjs:verifyCapsSig`; T-FEAT-10/10b), so a bootnode or MITM cannot rewrite an
advertised range without the gateway's onion key. **Limit:** the range that rides back on a
*rejection* is unsigned, but a forged one can only cause a re-select or a fail-closed
`no-mutual-version`, and version choice cannot forge §4.2/§4.3.
Adversary A1.

### 4.16 Endpoint DoS levers (slow-loris, connection pinning, verify floods) — CLOSED (T-HARD-4)
Both listeners bound what an *unauthenticated* peer can cost before it has proven anything, and
what a member can cost with one proof. **Enforced** by:
- `packages/node/gateway/gateway.mjs:readEnvelope` — absolute envelope deadline (`SHADE_TREE_ENVELOPE_TIMEOUT_MS`,
  30 s from connect, not re-armed by dribbled bytes) => drop `envelope-timeout`; size cap =>
  `envelope-too-large`.
- `packages/node/gateway/gateway.mjs:makeHandler` — relay idle timeout on both sockets (`SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS`,
  5 min; either socket idle == no bytes in either direction) => `tunnel_closes{idle-timeout}`; a
  black-holed upstream connect is bounded by the same timer (`upstream-timeout`); a permanent
  socket error sink closes the **half-close crash** (a partial envelope + FIN used to raise an
  unhandled `EPIPE` on the error reply and kill the whole gateway process — one connection, full
  outage; found by the T-HARD-4 selftest, confirmed against `main` before the fix).
- `packages/node/gateway/gateway.mjs:makePayloadBudget` — both opaque relay directions share a 40 MiB
  `(externalNullifier, nullifier)` allowance (`SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES`); same-node
  retries cannot reset it, and the exact boundary closes both sockets with `payload-limit`.
  Cross-node concurrency remains subject to the asynchronous, fail-open fleet-tally residual.
- `packages/node/gateway/gateway.mjs:makeConnLimiter` — `SHADE_TREE_MAX_CONNS` (1024) concurrent sockets, refused at
  accept before any read (`too-many-connections`); `SHADE_TREE_MAX_CONNS_PER_NULLIFIER` (8) concurrent
  tunnels per nullifier (`nullifier-conn-limit`), checked *after* `spentSet.admit` so a slashable
  second distinct share is never hidden by the cap. Slots released on close; the per-nullifier map
  is bounded by open sockets.
- `packages/node/bootnode/server.mjs:makeAnnounceBucket` — GLOBAL announce token bucket, the last gate before
  `verifyAnnounce` (`SHADE_TREE_BOOTNODE_ANNOUNCE_RATE`/`_BURST`, default 66.7/s, burst 1000 = 2×maxEntries/
  heartbeat and maxEntries/10): an attacker minting fresh onions gets at most `burst` ed25519 verifies
  in an instant, then `rate`/s (was: up to `maxEntries` in one burst); `429` + `Retry-After`; cheap
  per-onion/full rejects are checked first and consume no token; legit heartbeats at default cadence
  never hit it (`docs/BOOTNODE.md` "Endpoint hardening" for the math).
- `packages/node/bootnode/server.mjs:HTTP_LIMITS` — headers 10 s / request 30 s (`408`), keep-alive idle 5 s,
  headers <= 8 KiB (`431`), enforced every 1 s (Node defaults 60 s / 300 s / 16 KiB / 30 s).
Proven in `packages/node/gateway/hardening.selftest.mjs`, `packages/node/bootnode/hardening.selftest.mjs` (real sockets, verify
spy) and `test/adversarial.selftest.mjs` scenarios 6–7. **Limit:** these bound *this process*; Tor
rendezvous/onion-service DoS remains an operator concern (§5, `docs/TOR-HARDENING.md`). Adversaries
A1 (as a client of peers), A5, and any unauthenticated network peer.

---

### 4.17 Paid admission over HTTP 402 (T-FEAT-7): the registrar as a trust surface

**Property.** The payment authorization is bound to one commitment and tier, and replay checks
prevent the same authorization from settling twice or minting a second leaf. The registrar checks
the transfer before insertion and simulates transactions before spending gas. Settlement and leaf
insertion are not atomic: after payment, the buyer trusts the operator to complete insertion. The
payer↔leaf link does not reach the gateway through the proof protocol.

**Where enforced.** `packages/node/payments/registrar.mjs` `makeEngine.verifyAndSettle` (order: wire shape via
`packages/node/payments/wire.mjs` `parseX402Payment` / `parseMppCredential`; body `limit` == paid tier;
commitment is a field element; time window with a settle buffer; EIP-712 recovery over the
token domain proven at boot against `DOMAIN_SEPARATOR()`; on-chain `authorizationState`,
`balanceOf`, `PaidAccessSet.limitOf == 0`; `eth_call` simulation) → serialized settle → wait →
`insert` → wait. Replay: the token burns `(from, nonce)`; the store keys orders by `(asset, from,
nonce)` (identical replay → stored receipt, different commitment → `409`, chain-consumed nonce →
`402`). MPP challenges are HMAC-bound (7-slot, core draft) so a tampered challenge fails
`invalid-challenge`; the MPP nonce is `keccak256(id ‖ realm)` so a credential binds to one
challenge; a bodied challenge is digest-bound (RFC 9530). Endpoint DoS: the bootnode's token
bucket in front of paid POSTs and quotes, an in-flight cap, 4 KiB body cap, the T-HARD-4 slow-
client limits, and the operator key never rendered into a unit (0600 drop-in). Proof:
`packages/node/payments/wire.selftest.mjs` (parse matrix, spec golden), `packages/node/payments/registrar.selftest.mjs`
(both rails end to end on anvil, replay/idempotency, adversarial matrix, slow-loris, crash
recovery), `test/Eip3009Token.t.sol`.

**Trust.** The buyer trusts the operator to insert after settlement (buyer–seller trust,
irreducible for any prepaid service; the settle tx and `GET /pay/status/<nonce>` are the public
evidence). The operator trusts its RPC as everywhere else. **The operator learns
`commitment ↔ payer`** (it must, to insert), and a chain observer sees `payer → operator` plus the
tier: Layer 0 (a fresh, pool-funded address) is the buyer's mitigation, stated in `shade-tree pay`'s
output and `docs/JOIN.md`. The gateway is unchanged: it sees an RLN proof over the paid root,
never a leaf or a payer.

## 5. Known residual risks and out-of-scope

These are documented limitations, not new findings. Cross-referenced to `docs/history/SHIP-PLAN.md`,
`docs/ROADMAP.md`, and `SECURITY.md`.

**Residual (tracked, will change the security surface when built):**

- **Paid access (T-FEAT-7, `docs/PAYMENTS.md`, ADR 0007) is prepaid trust in the operator.** The
  payment settles OFF chain (HTTP 402 rails) and the operator inserts the leaf; a paying member
  who is refused a valid proof, or never inserted, has no on-chain recourse — the same
  buyer-seller trust any prepaid service carries, and NOT a facilitator: no third party is added.
  Linkability lives at the payment, not at use: the 402 payment (its rail, its payer address /
  account, its timing) and the on-chain `insert` tx are visible to the rail and to the chain
  respectively; the TIER BUCKET (which `limit` was bought) is public in the insert event; a use does
  not reveal the leaf or payer through the proof, although timing and application metadata can still
  correlate it. Mitigations are the buyer's Layer-0 hop (a fresh
  address / account funded through a pool of their choice), the operator batching inserts (dwell
  time between payment and insert), and a healthy paid crowd (`SHADE_TREE_PAID_MIN_LEAVES`). Which
  root a proof opens (static / staked / paid) is public to the gateway (§4.14b).

- **Cross-fleet replay / rate is fleet-wide only when the tally is on (T-FEAT-20/20b, ROADMAP-v1
  #1/#3).** §4.6 defends *one* gateway. The shared per-epoch nullifier tally
  (`packages/node/gateway/fleet-tally.mjs`, `SHADE_TREE_FLEET_TALLY_PEERS`, authenticated by
  `SHADE_TREE_FLEET_TALLY_TOKEN`) rejects a replay at a second gateway and
  shares only `(nullifier, epoch)` (RLN's per-tunnel nullifiers keep it from being a linkability
  channel), but it is **opt-in and fail-open**: a fleet without it lets a malicious gateway fan a
  captured envelope to peers (each accepts it once), and a member spreading requests across `N`
  gateways gets up to `N`× its intended budget.
- **Exit-auth verifier — real in the Sepolia rln-v4-tiers set (2026-08-17).** The set
  (`0xFe48De8b…9d25`), explicitly reused by the live v4 research canopy since 2026-09-03, wires the real Groth16 `WithdrawVerifier` (`contracts/WithdrawVerifier.sol`,
  taking the member's recorded tier); only its VK is still the untrusted dev phase-2 (T-HARD-1),
  and the superseded rln-v3 set (`0xdAE242AE…20FC`, the experiment's earlier slash target) keeps the
  mock.
- **RLN leaf-removal parity (T-DEV-2) — closed.** `reconstructRoot` now follows the contract's
  zero-in-place convention (`packages/node/lib/root-provider.mjs`, three-way JS/Solidity/Rust proof); listed so
  the history of the caveat is not lost.
- **Trusted-setup provenance (T-HARD-1, P0).** The ZK artifacts came from an **untrusted testnet
  phase-2 ceremony** (`circuits/rln/ARTIFACTS.md`). Their hashes are now pinned and CI-verified
  (`testdata/zk-artifacts.lock.json`, `test/zk-artifacts.selftest.mjs`), which fixes *which* untrusted
  artifacts run, not their provenance: no real anonymity or funds until the human-gated ceremony
  (`docs/CEREMONY.md`) or pinned audited artifacts land. This is the single biggest caveat.
- **Cold-start directory staleness (T-FEAT-21).** The rollback floor (§4.9) only bounds staleness
  *within* a session; the absolute max-age bound is **off by default**, so a brand-new client can
  accept a validly-signed but months-old directory from a replaying bootnode. Set
  `SHADE_TREE_DIRECTORY_MAX_AGE_MS` to close it.
- **Stale `staked` label by default (T-DEV-5).** Client zero-trust operator re-verification (§4.12)
  exists but is **off by default**; the default path trusts the bootnode's operator↔onion pairing
  label.
- **Reorg safety off by default (§4.14).** `latest` reads unless `SHADE_TREE_CONFIRMATIONS` is set.
- **Capability/version advertisement is opt-in on the gateway side (T-FEAT-10/10b, §4.15).** Signed
  and onion-bound when present; a gateway that advertises nothing is treated as default-capable
  only, and the version range echoed on a rejection is unsigned (fail-closed either way).
- **Deploy bootstrap runs as root.** `packages/node/bootnode/deploy/bootstrap.sh` is exercised end to end in CI
  (`.github/workflows/bootstrap-e2e.yml`, T-TEST-8) but runs as root on a fresh box; read it before
  running it (`docs/AUDIT.md`, `SECURITY.md`).

**Explicitly out of scope (design boundaries, not bugs):**

- **Global passive network adversary (A3).** Same posture as Tor itself; not defended here.
- **Knowing your own exit.** A member knowing which gateway it egresses through is not the threat
  (`docs/ROADMAP.md` #3); multi-hop gateways are deliberately not the plan.
- **Payments, sourcing clean egress IPs, rendezvous/onion DoS.** Operator responsibilities / out of
  scope per the README `Boundaries` section, `docs/OVERVIEW.md` and `SECURITY.md`.
- **Sybil operators inflating rotation odds (A6).** Rotation spreads a member across the live fleet;
  a Sybil that runs many gateways raises its share of any one member's traffic. Staking
  (`admission=stake`) raises the cost but does not eliminate it; the proof-level argument rests on
  RLN's per-slot transcript unlinkability (§4.3) holding even against a *colluding* set, not on any single
  operator being honest. RLN transcript unlinkability does not defeat traffic analysis by that
  colluding set.

---

## 6. Audit checklist — where to start

Highest-value review targets, roughly in order of trust concentration:

1. **`packages/node/lib/directory.mjs`** — the trust core. Confirm `verifyDirectory` rejects: unsigned, wrong
   signer, non-pinned declared signer, tampered field, grafted onion, pubkey↔onion mismatch. Confirm
   `onionToPubkey` checksum validation and `clampWeight`. Read alongside `packages/node/lib/directory.selftest.mjs`.
2. **`packages/node/lib/rln.mjs:verifyEnvelope`** — walk checks 1→4 in order and confirm 2b (target binding) is
   never trusted without 4 (Groth16 verify), and that `nullifier`/`share` come from `publicSignals`,
   not the envelope. Confirm `signalFieldSafe` runs before hashing. Beside `packages/node/lib/rln.selftest.mjs`.
3. **`packages/node/gateway/gateway.mjs:makeSpentSet`** — the over-spend/slash and replay control flow. Confirm
   slash-exactly-once, the `seenEnv` replay window, and that failures don't crash the path. Confirm
   `acceptEnvelopeVersion` is the sole version gate. In `makeHandler`, confirm the socket error sink,
   the envelope deadline, the connection caps and the idle timeout (§4.16) bracket every exit path.
4. **`packages/node/bootnode/announce.mjs:verifyAnnounce`** — the discovery loop's admission. Confirm onion-sig +
   operator-sig + `isStaked` ordering, freshness/skew, nonce replay, and that a chain-read failure
   hard-rejects under `requireStake`. Beside `packages/node/bootnode/selftest.mjs`. In `packages/node/bootnode/server.mjs`,
   confirm the global announce bucket is the last gate before verify and reload is its only exemption
   (§4.16).
5. **`packages/node/client/selection.mjs:ensureLoaded`** — the rollback floor + max-age bound + last-known-good
   fallback; and `reverifyGateway`/`filterReverified` for the zero-trust stake path.
6. **`contracts/StakedReputationSet.sol` + `contracts/GatewayRegistry.sol`** — stake lifecycle, the
   permissionless member `slash` vs the governed gateway `slash`, fund custody, the mock exit
   verifier (T-DEV-1). Beside `test/*.t.sol` and `docs/CONTRACTS-AUDIT.md`.

For the full attack matrix run against live code, see `test/adversarial.selftest.mjs`. For the
per-component trust boundaries and suggested reading order, see `docs/AUDIT.md`.

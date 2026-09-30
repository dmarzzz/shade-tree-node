# Light-client integration: trust-minimized reads of the reputation root

**Status: built (option A, sidecar), opt-in.** `LightClientRootProvider`
(`packages/node/lib/root-provider.mjs`, `SHADE_TREE_ROOT_PROVIDER=light`) verifies the contract's `currentRoot`
storage slot against a block header's `stateRoot` via an EIP-1186 `eth_getProof` MPT proof
(SHIP-PLAN T-DEV-9), and since T-DEV-9b the `stateRoot` itself can be anchored to the beacon
sync committee instead of the RPC's header: set `SHADE_TREE_HELIOS_RPC_URL` to a LOCAL
[a16z/helios](https://github.com/a16z/helios) verifying JSON-RPC and the provider takes the
header from it (`packages/node/lib/helios-root.mjs`, `makeHeliosTrustedStateRoot`), cross-checks the RPC's
header against it, and rejects with a precise reason if they differ. Then the whole chain
sync-committee → stateRoot → account proof → storage proof → root is verified end to end and
the RPC is a dumb pipe. Unset, behaviour is unchanged (RPC-trusted stateRoot) and the gateway
logs so at startup. The **Decision, how-to and receipt** section below is the operator part;
the default is still the trusted-node provider (`SHADE_TREE_ROOT_PROVIDER=node`), which is the right
default for a solo operator; the rest of this doc is the design for the *other* provider, so an
operator who does not run a full node can still read the reputation-set root without trusting
an RPC. It is written to be reviewed by someone who knows the Helios internals, so it
front-loads the trust model and collects the open questions at the end.

## Decision, how-to and receipt (T-DEV-9b)

**Decision: option A, Helios as a local verifying RPC sidecar**, feeding the existing
`trustedStateRoot(blockTag)` hook of `LightClientRootProvider`. Not B (embedding the Rust
crate into a Node process is not on the table today; it becomes the natural home only under
the Rust rewrite) and not C (hand-rolled sync-committee verification: maximal surface for no
gain). The pieces:

| piece | where |
|---|---|
| the hook implementation | `packages/node/lib/helios-root.mjs` — `makeHeliosTrustedStateRoot({ rpcUrl, chainId?, upstreamRpcUrl? })` → `trustedStateRoot(tag)` = Helios `eth_getBlockByNumber(tag,false)` → `{ stateRoot, number, hash }`; first use checks Helios `eth_chainId` against `SHADE_TREE_HELIOS_CHAIN_ID` (else the RPC's own `eth_chainId`); unreachable / mismatch / null block / malformed header all **throw** (fail closed, reason names `helios`) |
| wiring | `packages/node/lib/root-provider.mjs` — `SHADE_TREE_HELIOS_RPC_URL` set ⇒ `LightClientRootProvider` installs the hook, anchors the proof to Helios' `stateRoot`, and **cross-checks** the RPC's header for the same block number: `stateRoot mismatch at block N: RPC (…) claims X but the anchor (helios (sync-committee verified)) attests Y` ⇒ rejected before any proof is fetched. `describe().stateRootSource` and the gateway startup log say `helios (sync-committee verified)` vs `rpc header (TRUSTED, not verified; …)`. Results carry `stateRootVerified: true|false`. `SHADE_TREE_HELIOS_RPC_URL` with `SHADE_TREE_ROOT_PROVIDER=node` is refused (would look verified without being so) |
| tests | `packages/node/lib/helios-root.selftest.mjs` (fake Helios + fake RPC in-process: hook honoured, chainId mismatch, unreachable, RPC-lies-about-stateRoot both stale-honest and self-consistent-fake, tag mapping, "Helios lies" boundary, node-mode guard), `packages/node/lib/root-provider-light.selftest.mjs` §8 |
| sidecar | `packages/node/bootnode/deploy/bootstrap.sh` `SHADE_TREE_HELIOS=1` (opt-in, default render unchanged): installs the **pinned** release `helios 0.11.1` (`helios_linux_{amd64,arm64}.tar.gz`, sha256 `339bf4ce…62ddb` / `20132e1f…5dab6`, verified before install; other versions need `SHADE_TREE_HELIOS_SHA256`), renders `shade-tree-helios.service` (loopback `127.0.0.1:8546`, endpoints via `EXECUTION_RPC`/`CONSENSUS_RPC` env, same sandbox as the other units + `MemoryDenyWriteExecute`), and points the gateway unit at it (`SHADE_TREE_ROOT_PROVIDER=light`, `SHADE_TREE_HELIOS_RPC_URL`, `SHADE_TREE_RPC_URL`, `SHADE_TREE_GROUP_CONTRACT`, ordered after the sidecar). `packages/node/bootnode/deploy/README.md` has the tunables |

**How-to (by hand, any box).** Helios 0.11.1 CLI (checked against the README and
`helios ethereum --help` on 2026-08-17):

```bash
# 1. install the pinned release (linux; darwin_{arm64,amd64} tarballs exist too) and verify it
curl -fsSLo helios.tgz https://github.com/a16z/helios/releases/download/0.11.1/helios_linux_amd64.tar.gz
echo "339bf4ce73073c53790e41e3217b6d91f0e5d8571132b9e88689997613162ddb  helios.tgz" | sha256sum -c
tar xzf helios.tgz && install -m 0755 helios /usr/local/bin/helios      # tarball = the single `helios` binary
# 2. run it: consensus (beacon API with the light-client endpoints) + execution (must serve eth_getProof)
helios ethereum --network sepolia \
  --consensus-rpc https://lodestar-sepolia.chainsafe.io \
  --execution-rpc "$SHADE_TREE_RPC_URL" \
  --rpc-bind-ip 127.0.0.1 --rpc-port 8546 --data-dir /var/lib/shade-tree-helios \
  --checkpoint 0x<recent FINALIZED beacon block root>     # or --load-external-fallback
# 3. point the gateway at it
export SHADE_TREE_ROOT_PROVIDER=light SHADE_TREE_HELIOS_RPC_URL=http://127.0.0.1:8546 SHADE_TREE_GROUP_CONTRACT=0x… SHADE_TREE_RPC_URL=…
```

Flags: `-n/--network mainnet|sepolia|holesky`, `-c/--consensus-rpc`, `-e/--execution-rpc`,
`-w/--checkpoint`, `-p/--rpc-port` (default 8545), `-b/--rpc-bind-ip` (default 127.0.0.1),
`-d/--data-dir`, `-f/--fallback`, `-l/--load-external-fallback`, `-s/--strict-checkpoint-age`;
each URL/checkpoint flag also reads an env var of the same name (`EXECUTION_RPC`,
`CONSENSUS_RPC`, `CHECKPOINT`, …), which is what the systemd unit uses so keys stay out of
`ps`. Notes from the live run that an operator will hit:

- **Sepolia has no default consensus RPC in Helios**; you must pass one. On 2026-08-17
  `https://lodestar-sepolia.chainsafe.io` synced; `https://ethereum-sepolia-beacon-api.publicnode.com`
  failed with `sync failed err=invalid sync committee period` (its light-client `updates`
  endpoint did not satisfy Helios). Mainnet defaults to lightclientdata.org.
- **Checkpoint.** `--load-external-fallback` lets Helios fetch a checkpoint from public
  services; a pinned `--checkpoint` (a recent *finalized* beacon block root, e.g.
  `GET <beacon>/eth/v1/beacon/headers/finalized` → `data.root`, cross-checked against a second
  source) is the more trust-minimized bootstrap. `SHADE_TREE_HELIOS_CHECKPOINT` in bootstrap.sh.
- **Public execution RPCs have short `eth_getProof` windows.** The provider proves the root at
  the *finalized* block (≥64 slots behind head); publicnode / tenderly / 1rpc serve proofs only
  ~32 blocks back (publicnode inconsistently across backends), so `eth_getProof: distance to
  target block exceeds maximum proof window` is what you get most of the time. `SHADE_TREE_RPC_URL`
  for the light provider must be an RPC that serves proofs at finalized (own node, or an
  archive-capable provider such as Alchemy/Infura). This is an availability limit of the RPC,
  not a trust issue; the last-known-good root keeps gating meanwhile.
- **Helios' own head lags** (`latest` errors `out of sync: N seconds behind` while it catches
  up; "inconsistent block history detected" warnings on the public consensus endpoint). Read
  at **finalized** (`SHADE_TREE_CONFIRMATIONS=0`, the default); a `head-N` hex tag is served only
  inside Helios' recent window.
- **After a good read, a lying RPC does not stall the gate.** `withCache` returns the
  last-known-good verified root flagged `stale:true` with the mismatch reason in `error`; a
  provider with no good read yet throws (gateway start fails closed). The lying value is never
  surfaced either way.

**Receipt (live, 2026-08-17, this Mac).** `helios 0.11.1` (`helios_darwin_arm64.tar.gz`,
sha256 `fc88981c7fe12e1010115b7bfe61909cfae36f65177325562c57daa0eb30ae8c`) run for ~20 min
against Sepolia with `--consensus-rpc https://lodestar-sepolia.chainsafe.io`,
`--execution-rpc https://ethereum-sepolia-rpc.publicnode.com`, checkpoint
`0x79c0ea030b4f2ba9bf03f1188c4bdc8a263e6b8f1c4bc3bd1d24c1274552ceac` (that moment's
finalized header root); it reported `consensus client in sync with checkpoint` and followed
four finality advances (11510059 → 11510090 → 11510122 → 11510152). The real
`makeRootProvider()` (`SHADE_TREE_ROOT_PROVIDER=light`, `SHADE_TREE_HELIOS_RPC_URL=http://127.0.0.1:8546`,
`SHADE_TREE_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com`,
`SHADE_TREE_GROUP_CONTRACT=0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC`) returned, e.g.:

```
describe: {"provider":"light","mode":"proof","stateRootSource":"helios (sync-committee verified)","stateRootVerified":true,…}
currentRoots: {"roots":[],"observedAtBlock":11510152,"finalized":true,"verified":true,"stateRootVerified":true}
helios chainId: 11155111 | helios finalized: 11510152
  hash      0xc63b49eb3e10b8c9491e630442b02e7e70437f7de37c7e8ac8c2e6136611c7de
  stateRoot 0xe49f49e70514365cc36433bdcd38ffc1cbc8e5f7b1c87367023435c52ccf4d43   (RPC header for 11510152: identical)
```

(also at 11510090 / stateRoot `0xcb0a4fba…7d8c3b` and 11510122 / `0xc9a8f412…3a50a`; each
succeeded only on the retries where publicnode's backend served the finalized-block proof, see
above). `roots: []` is correct and is itself a finding: the account + storage proof verified
against the sync-committee-attested stateRoot proves slot 3 of the **live rln-v3 contract is
0** — that deployment (block 11279842, 2026-07-15) predates T-DEV-9's on-chain incremental
tree, so it has no `currentRoot` slot yet. The light provider is end-to-end verified against
Sepolia; it will surface a real root once `StakedReputationSet` is redeployed with the
T-DEV-9 contract (not tracked as a task at the time of writing; flagged in the T-DEV-9b PR).

**Receipt 2 (live, 2026-08-17, T-DEV-9c — the REAL root).** After the rln-v4-tiers redeploy
(`network/sepolia/contracts.json`, `StakedReputationSet 0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`,
which carries the T-DEV-9 on-chain tree) and its live two-tier integration
(`network/sepolia/integration-report-rln-v4.md`: ALICE tier 8 + BOB tier 32 staked, BOB slashed
at block 11510548), the same `helios 0.11.1` sidecar (fresh run, checkpoint
`0x73aa8e286e4a520bd5c3d437e84098540801742501b829ddea901a20421522a9` = that moment's finalized
header root from lodestar-sepolia, cross-checked equal on publicnode's beacon API;
`consensus client in sync with checkpoint`; finality followed 11510496 → 11510528 → 11510558)
and the real `makeRootProvider()` (`SHADE_TREE_ROOT_PROVIDER=light`,
`SHADE_TREE_HELIOS_RPC_URL=http://127.0.0.1:8546`, `SHADE_TREE_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com`,
`SHADE_TREE_GROUP_CONTRACT=0xFe48De8b…9d25`) returned:

```
describe: {"provider":"light","mode":"proof","stateRootSource":"helios (sync-committee verified)","stateRootVerified":true,"contract":"0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25"}
currentRoots: {"roots":["8610802244115318239575829157501362221923553955100605581936806202597950014363"],"observedAtBlock":11510558,"finalized":true,"verified":true,"stateRootVerified":true}
helios chainId: 11155111 | helios finalized: 11510558
  hash      0xefa2c6aa64c6d098c686e1e01a59ebca2c42f63c34fb0a8c9b74842499ac6ca9
  stateRoot 0x435ab830c49e06e210c69e97dd2c16e803072515770161272ba51e2f9d66be6b   (RPC header for 11510558: identical)
light root 8610802244115318239575829157501362221923553955100605581936806202597950014363
  == JS root AFTER the slash: newGroup([leafALICE, leafBOB]) with index 1 zeroed in place
  == NodeRootProvider (rln-v4 event reconstruction from the deploy block): same root
  == on-chain currentRoot() (cast call)
```

The chain of custody is now complete end to end on Sepolia: sync committee → Helios
`stateRoot` → account proof → storage proof of slot 3 → a **non-empty** membership root that
equals the root the JS computes from the staked members' leaves. Two side notes from the run:
(1) while Helios' finalized block was still BEFORE the deploy block (11510496 / 11510528 <
11510538) the provider returned `account absent in state proof` — correct: the contract did not
exist yet at that finalized state, and the provider refuses rather than guessing; (2) as in
receipt 1, publicnode served the finalized-block `eth_getProof` only intermittently
(`distance to target block exceeds maximum proof window` on the other attempts), so an
operator needs a proof-serving RPC that keeps `eth_getProof` at finalized (own node /
archive-capable provider); the last-known-good root bridges the gaps.

Context: the gateway is a Tor onion-service egress that admits only members of a
reputation set, where membership is an on-chain Semaphore/RLN group (docs/ONCHAIN.md).
The gateway's only on-chain read is **the group's current Merkle root, plus the recent
roots inside a freshness window `F`.** Everything downstream (proof verification, the
per-nullifier rate budget, slashing) is local. So the entire chain-trust question
reduces to: *how does the gateway learn the canonical root without trusting whoever
served it?*

## Why not the obvious two

- **Third-party RPC (Infura/Alchemy).** A lying RPC is not just a staleness problem: it
  can feed a root whose tree contains attacker commitments, so the attacker's own proofs
  verify and they egress for free, or a root that still contains a member you slashed.
  This is trusting exactly the party the rest of the system refuses. Disqualified for the
  admission root.
- **Own full node.** Correct and fully trust-minimized, and for a solo staker already
  running a validator it is *free* (they have the node). But it is the thing an operator
  who wants to run many gateways will not do per gateway. That is the gap this doc fills.

## What a sync-committee light client gives us, and what it costs

A Helios-style client validates the beacon chain's **sync committee** signatures to
obtain a validated execution-layer header, and therefore a trusted `stateRoot`, without
replaying the chain. Given a trusted `stateRoot`, the group contract's root is read with
an `eth_getProof` account+storage proof verified against that `stateRoot`; a hostile data
source then cannot forge the root, because it cannot fabricate a valid Merkle-Patricia
proof for a slot value that is not in state. It can only withhold (unavailability), not
lie.

The trust you take on, stated plainly for review:

- **Sync-committee honesty.** ~512 validators per ~27h period, 2/3-honest assumption. A
  majority-malicious committee can sign a false header. This is weaker than a full node's
  execution-validity guarantee and stronger than trusting a named RPC company. For an
  admission root that changes slowly and whose abuse is bounded by the unbonding window,
  this is a reasonable trade, but it is the load-bearing assumption and it belongs at the
  top.
- **Weak-subjectivity checkpoint.** The client must bootstrap from a recent trusted
  block root (a weak-subjectivity checkpoint) to avoid long-range attacks. *Who supplies
  the checkpoint, and how the operator verifies it, is the single biggest open question
  below.* A bad checkpoint at bootstrap undermines everything after it.
- **Connectivity, not validity.** The light client still needs a consensus data source
  (a beacon API) and an execution data source (for `eth_getProof` / `eth_call`). Helios
  removes the *trust* in those endpoints, not the *dependency* on reaching some endpoint.
  Liveness still requires a reachable source.

## Integration options

Three, in the order I would reach for them.

**A. Helios as a local verifying RPC proxy (recommended default).** Helios already runs
as a local JSON-RPC server that only returns consensus-verified results, executing
`eth_call` locally against light-client-verified state. So the integration is almost
nothing on our side: run Helios as a local process and point `SHADE_TREE_RPC_URL` at its
endpoint. The existing `NodeRootProvider` (docs/ONCHAIN.md, `packages/node/lib/root-provider.mjs`) then
reads `root()` and gets light-client security for free, because the "node" it is talking
to is a verifying client rather than a trusted upstream. This collapses "trusted vs
light" into *which endpoint the provider points at* — own node, a bad third-party RPC, or
a local Helios — and the cleanest version of the whole abstraction is exactly that. The
separate `LightClientRootProvider` with hand-rolled `eth_getProof` verification is only
needed if we deliberately avoid running Helios in-process.

**B. Helios embedded as a Rust library (the single-binary path).** If the gateway is
rewritten in Rust (docs/ONCHAIN.md, "On a Rust rewrite"), embed Helios as a crate rather
than shell out to a sidecar: one process, one supervised lifecycle, no local RPC socket to
secure, and the RLN verify sits in the same binary. This is the tightest deployment and
the reason the Rust question and the light-client question are really one question. It is
strictly more work than A and only pays off once the light-client path is the one being
run at scale.

**C. Hand-rolled verification (avoid unless there is a reason).** A raw sync-committee
client plus our own `eth_getProof` MPT verification. Maximum control, maximum surface to
get wrong, and it reimplements what Helios already does well. Listed for completeness; not
recommended.

## The on-chain-root requirement (this constrains the contract)

A consequence worth stating because it changes the contract choice. State proofs
(`eth_getProof` over a storage slot) are clean and well-supported. **Log/receipt proofs
are not** — verifying `eth_getLogs` results under a light client is materially harder and
less supported. So a light-client gateway must read the root from an **on-chain storage
slot**, i.e. the group must maintain its root on chain (an on-chain incremental Merkle
tree, e.g. Semaphore's on-chain group), *not* have the gateway reconstruct the tree from
`MemberAdded` events. Event reconstruction is fine only for the trusted-node provider,
where you already trust the node's log view. **If the light-client path matters at all,
build the on-chain-root contract; it serves both providers.** (Same conclusion as
docs/ONCHAIN.md, reached here from the light-client side, and it is a firmer reason than
the one there.)

## Read at finalized

Read the root at the **finalized** checkpoint, not head. On L1 finality is real (Casper
FFG, ~2 epochs, ~13 min), so a reorg can never retroactively change the admission set out
from under an in-flight slash. The cost is ~13 min of enrollment latency (a new member
waits for finality before egressing), which is nothing for a slowly-changing set. This is
the same `C ≈ 13 min` slash-confirmation margin that sizes the unbonding bound
`U ≥ F + E + C` in docs/ONCHAIN.md; the light client and the exit time-lock agree on
"one finality period," which is a reason L1 is cleaner here than an L2 would be.

## Tradeoffs

| Axis | Third-party RPC | Own full node | Light client (Helios) |
|---|---|---|---|
| Trust | the RPC company | none (self) | sync committee 2/3 + WS checkpoint |
| Can a bad source forge the root? | **yes** | no | no (only withhold) |
| Runs a full node? | no | yes | no |
| Resource cost | ~0 | high (validator-class) | low (seconds to sync, small memory) |
| Bootstrap trust | none extra | none | weak-subjectivity checkpoint |
| Best fit | never (for the root) | solo staker w/ a validator | run-many operator |
| Enrollment latency | provider-dependent | finalized ~13 min | finalized ~13 min |
| Needs on-chain root slot? | no (can reconstruct) | no (can reconstruct) | **yes** (state proofs, not log proofs) |
| Liveness dependency | RPC reachable | self | a beacon + execution source reachable |

## Failure modes

- **Data source unreachable.** Degrade to the last-known-good root (both providers cache
  it) and keep gating; only *slashing* stalls, because it must land a transaction. This is
  the one caveat: an extended outage means "still gating, temporarily cannot slash." Size
  the unbonding window with that in mind.
- **Stale checkpoint / long offline.** A client offline past the weak-subjectivity period
  must re-bootstrap from a fresh checkpoint. Operationally the same concern as any
  light-client wallet; the checkpoint-source question below covers it.
- **Sync committee majority-malicious.** Out of scope to defend cryptographically; the
  mitigation is that the damage is bounded by the unbonding window and that the operator
  can cross-check the finalized root against any second source (a friend's node, a block
  explorer) out of band, since the root is a single public value.

## Open questions for review

1. **Checkpoint source.** What is the right weak-subjectivity checkpoint source for an
   unattended gateway — a pinned checkpoint at bundle time, a checkpoint-sync endpoint, a
   small set cross-checked? This is the biggest residual trust and the thing most worth an
   expert opinion. *As shipped:* `SHADE_TREE_HELIOS_CHECKPOINT` (operator-pinned finalized root)
   or, unset, Helios' `--load-external-fallback`; still open which to make the default.
2. **Sidecar vs embedded.** For the Rust gateway, is embedding Helios as a crate the
   intended integration, or is the local-RPC-proxy deployment (option A) preferred even
   in-process? Any gotchas running Helios headless/long-lived next to a Tor daemon.
   *As shipped:* sidecar (option A); the ~20-min live run showed head lag and cache-reset
   warnings on a public consensus endpoint but finality advanced cleanly.
3. **`eth_call` vs explicit `eth_getProof`.** Is executing `root()` via Helios's local
   verified execution sufficient, or is an explicit storage-slot `eth_getProof` preferable
   for auditability (a single proof against a known slot vs trusting local EVM execution)?
   *As shipped:* explicit `eth_getProof` from the RPC, anchored to Helios' header — Helios
   is used only for the header, so its execution path is not in the trust chain at all.
4. **Finalized-state read latency and freshness.** Any reason the freshness window `F`
   should be sized around light-client head-follow lag rather than just the epoch, e.g. if
   finalized state lags enough to matter for enrollment UX.
5. **Log verifiability.** Confirm the premise: is verifying `MemberAdded` logs under a
   light client actually impractical enough to justify mandating the on-chain-root slot,
   or is there a receipts-proof path that makes event reconstruction viable? This decides
   whether the on-chain-root contract is truly required or merely convenient.

## Recommendation

Ship the trusted-node provider now (solo-staker path, no light client, gets the on-chain
gate working end to end). Treat this doc as the design for the run-many path, land the
on-chain-root contract when that path is needed, and prefer integration option A (Helios
as a local verifying RPC proxy) unless and until the Rust rewrite makes option B the
natural home. Reconcile the open questions above with review before building it.

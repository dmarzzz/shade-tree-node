# Live Sepolia integration — rln-v4-tiers (on-chain tiers + on-chain root)

> **Historical pre-v4 receipt.** “Live” below records the result on 2026-08-17. The Sepolia
> profile is retired and no longer supplies current Shade Tree runtime defaults.

**Result: PASS.** Two members stake on live Sepolia at DIFFERENT reputation tiers; the
on-chain `currentRoot()` equals the JS-computed root; the real gateway runs in ON-CHAIN ROOT
MODE against the new contract; the tier-8 member uses the gateway within its budget, the
tier-32 member proves a slot only its tier can prove and then over-spends and is reconstructed
+ slashed on-chain **at its tier** (`slash(leaf, secret, 32, receiver)`, burning the tier-32
bond) — all with real circom-rln Groth16 proofs. Date: 2026-08-17. Tasks: T-DEV-9c + T-FEAT-8b
(`docs/history/SHIP-PLAN.md`), ADR `docs/adr/0006-reputation-tiers.md`, `docs/ONCHAIN.md` "Tiers on chain".

## What changed vs. rln-v3 (`integration-report-rln.md`)

- The `StakedReputationSet` now keeps the **depth-20 Poseidon tree on chain** (`currentRoot`
  at storage slot 3, T-DEV-9), so `LightClientRootProvider` proves a REAL root (rln-v3 predated
  it: slot 3 = 0, `roots: []`, see `docs/LIGHT-CLIENT.md`).
- **Tiers on chain** (T-FEAT-8b): `register(commitment, limit)` at `bondFor(limit)` from an
  immutable table (8 => 0.001 ETH, 32 => 0.004 ETH), a tiered `RateCommitmentHasher`
  (`commitmentOf(secret, limit)`), `slash(commitment, secret, limit, receiver)` recomputing the
  leaf at the CLAIMED limit, `MemberRegistered`/`MemberSlashed` events carrying the limit, and
  the REAL Groth16 exit-auth `WithdrawVerifier` taking the recorded limit (rln-v3 wired the
  revealed-secret mock).
- The gateway ran in **on-chain root mode** (`SHADE_TREE_GROUP_CONTRACT`, `NodeRootProvider`
  reconstructing from the rln-v4 events) instead of `members.json`, and its slasher detected
  the tiered ABI and resolved the tier ON CHAIN (`limitOf`) before submitting.

## Deployment (fresh, this run)

| Item | Value |
|---|---|
| StakedReputationSet | [`0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`](https://sepolia.etherscan.io/address/0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25) |
| RateCommitmentHasher (tiered) | `0x29e9D6ae8d46A9D86D6A92a43307850e0FA06586` |
| WithdrawVerifier (REAL Groth16 exit-auth) | `0x522409038aA03FFF998d33C60A37486975695351` over `WithdrawGroth16Verifier` `0x6B26a9B6BEdcB711C35947f988fdFF168AFD507E` |
| PoseidonT2 / PoseidonT3 (linked, reused from rln-v3) | `0xA20D550b5b3b99c0abB6E51d68d2a39955E69b55` / `0x82Cb42c70208a92DD5938b5f4D67C7d2313bE022` |
| GatewayRegistry | UNCHANGED `0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868` (not redeployed: `SHADE_TREE_DEPLOY_REGISTRY=0`) |
| deploy blocks | 11510538 (hasher) · 11510539 (groth16) · 11510540 (verifier) · 11510541 (set) |
| deploy tx (set) | `0xa565fd7769ddfdd79abaff6e0a5f40159bb77604c531ec631941b52f2953ba03` |
| deployer / slasher / slash receiver | `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` (fleet operator hot key) |
| params | tiers {8: 0.001 ETH, 32: 0.004 ETH} · unbonding 300s (min 270) · `DEFAULT_LIMIT` 8 · `MAX_LIMIT` 65535 |
| deploy gas | 3,370,335 total (223,624 + 364,342 + 370,042 + 2,412,327) at ~1.0 gwei ≈ 0.0036 ETH |
| receipt bundle | [`rln-v4-broadcast.json`](rln-v4-broadcast.json); recorded with `shade-tree record-deploy --network sepolia --all --force --from-broadcast …` |

Verified with `cast call` right after the broadcast: `currentRoot()` ==
`10354334201938752428558948798274962999644820234654929486063894213598717249307` (the empty
depth-20 tree root — nonzero by construction; `test/StakedReputationSet.t.sol EMPTY_ROOT`),
`allowedLimits() == [8, 32]`, `bondFor(8) == 1e15`, `bondFor(32) == 4e15`, `DEFAULT_LIMIT() == 8`,
`ROOT_STORAGE_SLOT() == 3`, `withdrawVerifier()` / `hasher()` as above,
`hasher.commitmentOf(111, 32) == 15363698809722346745616993869789510363416645981863858152379739283427647190637`
(== `poseidon2([poseidon1([111n]), 32n])`, the JS golden in `test/StakedReputationSet.tiers.t.sol`).

## Members (fresh identities for this run; secrets never recorded)

| Role | Tier | Leaf (rateCommitment) |
|---|---|---|
| ALICE (honest) | 8 (0.001 ETH) | `16866272126161412576533177922000484242664187860651988211192006420365926155987` |
| BOB (abuser) | 32 (0.004 ETH) | `5443169668595253035126407516438306525977849927774428418330863046649288788866` |

Both staked from the operator hot key via the real CLI:
`shade-tree register-member <leaf> --limit N --rpc-url … --group-contract 0xFe48…9d25`
(`group/register-onchain.mjs`, which probes `bondFor(limit)` and calls
`register(uint256,uint256)`).

## Timeline (`node scripts/integration-tiers.mjs`, +seconds from start)

```
[+   0.1s] setup   StakedReputationSet 0xFe48…9d25 chainId=11155111 tiers=[8,32] bond(8)=0.001 ETH bond(32)=0.004 ETH epoch 14891666 (120s)
[+   0.1s] ok      contract admits tiers 8 and 32 (bondFor nonzero)
[+   9.4s] ok      ALICE staked at tier 8  via `shade-tree register-member --limit 8`   tx 0xe1f82c62…c68b  block 11510544  (1,283,077 gas)
[+  22.7s] ok      BOB   staked at tier 32 via `shade-tree register-member --limit 32`  tx 0xbc1910c4…1a4e  block 11510545  (  921,848 gas)
[+  22.8s] ok      ALICE on-chain: bond == bondFor(8),  limit 8 recorded
[+  22.8s] ok      BOB   on-chain: bond == bondFor(32), limit 32 recorded
[+  22.9s] stake   activeCount=2 limitOf(A)=8 limitOf(B)=32
[+  23.0s] ok      currentRoot() == JS groupFromIdentities([{A,8},{B,32}]).root  (20021925659736805426…)
[+  56.7s] gateway root source: on-chain RootProvider provider=node recentRoots=1  (SHADE_TREE_GROUP_CONTRACT=0xFe48…9d25, SHADE_TREE_CONFIRMATIONS=1)
[+  56.8s] gateway slash: on-chain via=0xFe48…9d25 receiver=0xc860…7f02 abi="rln-v4 tiered" tiers=[8,32]
[+  56.8s] gateway gateway up on 127.0.0.1:8443 epoch=14891666
[+  58.0s] alice   req 1 slot 0  -> {"ok":true}  (gateway: egress target=example.com:443)
[+  59.2s] alice   req 2 slot 1  -> {"ok":true}  (egress target=api.ipify.org:443)
[+  60.0s] alice   req 3 slot 2  -> {"ok":true}  (egress target=cloudflare.com:443)
[+  74.3s] ok      BOB (tier 32) built a slot-20 proof (a budget tier 8 cannot have)
[+  74.3s] bob     slot 20 -> {"ok":true}  (egress target=example.com:443)
[+  75.9s] bob     over-spend 1/2 slot 0 first signal  -> {"ok":true}
[+  75.9s] bob     over-spend 2/2 slot 0 SECOND distinct signal (same nullifier) -> the violation -> sending
[+  76.5s] gateway SLASH tx 0xfff760a614f0aecb73ddb13e0985a1cd3c5ee2beddef45d2584ce39c5bb3494c (waiting) commitment=544316966859525303.. limit=32
[+  80.6s] gateway SLASH mined block 11510548 commitment=544316966859525303.. limit=32   (919,847 gas)
[+  80.6s] gateway drop reason=over-spend-slashed
[+  80.6s] bob     over-spend 2/2 -> {"ok":false,"err":"over-spend-slashed"}
[+  80.6s] ok      the slash named tier 32 (resolved via limitOf on chain, not the default tier)
[+  81.0s] ok      BOB's tier-32 bond is gone (slashed)      ok  ALICE's tier-8 bond is intact      ok  activeCount == 1
[+  81.1s] ok      currentRoot() == JS tree with BOB's leaf zeroed in place  (8610802244115318239…)
[+  81.2s] ok      wrong-limit slash of ALICE (limit 32 for a tier-8 leaf) reverts BadLimit   (eth_call)
[+  81.3s] ok      control: the same slash at limit 8 simulates fine (not broadcast)
[+  81.3s] result  PASS — tier-8 member intact, tier-32 over-spender slashed at its tier on chain
```

## What this proves

- **Two tiers, one tree, one root, on chain.** ALICE (limit 8) and BOB (limit 32) are leaves
  of the same on-chain tree; `currentRoot()` equals `groupFromIdentities([{A,8},{B,32}]).root`
  before the slash and the zero-in-place tree after it — the T-DEV-9 root is real and the JS
  reconstruction agrees event for event (rln-v4 events carry the limit; the provider reads
  both generations).
- **The gateway enforces the proven tier from the chain alone.** It held roots, not leaves
  (`SHADE_TREE_GROUP_CONTRACT`), accepted BOB's slot-20 proof (a messageId a tier-8 leaf cannot
  prove) and ALICE's slots 0..2, and — after BOB's over-spend — reconstructed his
  `identitySecret`, asked the contract `limitOf` for the candidate leaves and slashed at
  **limit 32**, burning the **0.004 ETH tier-32 bond** to the receiver (`0xfff760a6…494c`).
- **Wrong tier cannot slash.** `slash(leafA, secretA, 32, …)` on ALICE's tier-8 leaf reverts
  `BadLimit`; the same call at 8 simulates (not sent). ALICE's bond is intact.
- **Per-tier stake, fixed per tier.** 0.001 / 0.004 ETH exactly (`BadBond` otherwise;
  `test/StakedReputationSet.tiers.t.sol`); the amount reveals the tier (public at registration
  anyway), never the member.

## Spend (this task, from the operator hot key)

Balance 0.05086 → 0.04300 ETH: deploy ≈ 0.0036 ETH, two stakes 0.005 ETH (0.004 came back
as BOB's slashed bond, 0.001 remains staked as ALICE), stake + slash gas ≈ 0.0033 ETH.
Net ≈ 0.0079 ETH including the 0.001 ETH still staked; well under the 0.02 ETH cap. (The same
key was concurrently used by another agent for `shade-tree register-gateway`; that spend is not
separated here.)

## Honesty / scope

- Local TCP transport to the gateway (the exact bytes Tor delivers), as in the rln-v3 run;
  the fleet-over-Tor path was proven in `integration-report-rln.md` P4 and is unchanged.
- The fleet's slashing still pointed at rln-v3 (`SHADE_TREE_SLASH_CONTRACT` in agent-devops)
  and gated on `members.json`; the fleet units were deliberately not flipped in this change
  (`docs/ONCHAIN-DEPLOY.md` §8). At the time, `SHADE_TREE_NETWORK=sepolia` resolved
  `SHADE_TREE_GROUP_CONTRACT` to the new set. The retired profile no longer does.
- Circuit + withdraw-verifier VK are still the **untrusted dev phase-2** (T-HARD-1) —
  testnet-only.
- The tier is DECLARED at registration (the contract cannot see inside a leaf); a mismatched
  declaration locks the bond forever and never buys extra budget (`docs/CONTRACTS-AUDIT.md` §3).
- The T-DEV-9b light-client receipt against this contract (Helios-anchored
  `LightClientRootProvider` returning the real root) is in `docs/LIGHT-CLIENT.md`.

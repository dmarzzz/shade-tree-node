# Live Sepolia integration — RLN release (real circom-rln circuit)

**Result: PASS.** Two members stake on live Sepolia; one uses the gateway within its
per-epoch rate cap; one over-spends and is reconstructed + slashed on-chain — all with
**real Rate-Limiting-Nullifier Groth16 proofs** (circom-rln v1.0.0), not the prior
PoC-fidelity share. Date: 2026-07-15.

## What changed vs. the previous live run

The earlier live integration (`integration-report.md`) ran the two-view PoC: a Semaphore
membership proof plus a hand-rolled Shamir share bound only by a cheap check, and an
on-chain leaf of `Poseidon(secret)`. This run uses the **RLN circuit**: one Groth16 proof
carries membership *and* the slashing share, the Merkle leaf is
`rateCommitment = Poseidon(Poseidon(identitySecret), 8)`, and a slash reveals the
`identitySecret` which the contract re-hashes to the leaf. Seams 1–3 from
`E2E-REPORT.md §9` are closed.

## Deployment (fresh, this run)

| Item | Value |
|---|---|
| StakedReputationSet | `0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC` |
| RateCommitmentHasher | `0x08F9a754D2cBdfB7805cFF2475632BEC4612ae6D` |
| MockWithdrawVerifier (exit-auth) | `0x5A6FD01d009989ff9E567fa2bC55253500ddbDB2` |
| deploy block | 11279842 |
| deploy tx (set) | `0xace20aff70f087d2752869bf4e63bae3105d2ddcad58179d224415b398342831` |
| bond | 0.001 ETH · unbonding 300s · limit K=8 |

On-chain hasher verified against `poseidon-lite` and the P3 pinned vector:
`commitmentOf(111) = 11302006078516901731073162965056551612114122314181142374993834332168998510316`.

## Wallets

| Role | Address |
|---|---|
| deployer | `0x3261DaF3672Dc8E6063b6960C161Fdc8a6Fc2ff7` |
| slasher (gateway hot key + slash receiver) | `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` |
| member ALICE (honest) staking wallet | `0x2ec9838Ea920Dc33D2771F4d29CBF6e7784929F9` |
| member BOB (abuser) staking wallet | `0xaaa30436B0710F918A2Cd63adF3878275b21325c` |

Leaves (rateCommitments): ALICE `835981380137162055943001…`, BOB `221825739623075315261028…`.

## Timeline (each step timestamped, +seconds from start)

```
[+0.1s]  setup   StakedReputationSet 0xdAE2…20FC  bond=0.001 ETH  epoch 14867867 (120s)
[+~5s]   stake   ALICE register+bond  tx 0x242d… (approx; see chain) block ~11279843
[+22.2s] stake   BOB   register+bond  tx 0xe1b73e91…67a9  block 11279844
[+22.2s] stake   on-chain activeCount = 2 (both bonds held)
[+22.9s] gateway up on 127.0.0.1:8443  (members.json fallback root, 8 members; slash wired)
[+23.6s] alice   req 1 built  slot 0  nullifier 184482051601…  (781ms prove)
[+23.9s] gateway PASS  egress->example.com:443   null 1844820516…  extNull 2202734630…   (rt 250ms)
[+24.8s] alice   req 2 built  slot 1  nullifier 172506278991…  (934ms prove)
[+24.9s] gateway PASS  egress->api.ipify.org:443  null 1725062789…  extNull 2202734630…  (rt 107ms)
[+25.5s] alice   req 3 built  slot 2  nullifier 443236961253…  (586ms prove)
[+25.7s] gateway PASS  egress->cloudflare.com:443 null 4432369612…  extNull 2202734630…  (rt 160ms)
[+25.7s] alice   3/3 within budget — normal use OK, no slash
[+26.3s] bob     over-spend 1/2  slot 0 first signal   nullifier 247408205118…
[+26.5s] gateway PASS  egress->example.com:443 (first share recorded, egresses)
[+27.0s] bob     over-spend 2/2  slot 0 SECOND distinct signal (same nullifier) — the violation
[+27.6s] gateway SLASH tx 0xc0f99e96…39efb  commitment 221825739623075315…  (submitted, waiting)
[+39.9s] gateway SLASH mined block 11279845
[+39.9s] gateway DROP  over-spend-slashed  null 2474082051…
[+39.9s] bob     ack {"ok":false,"err":"over-spend-slashed"}
[+40.5s] verify  ALICE bond on-chain = 0.001 ETH  (intact) ✓
[+40.5s] verify  BOB   bond on-chain = 0.0 ETH    (slashed) ✓
[+40.6s] verify  slasher balance = 0.05176… ETH  (received BOB's bond) ✓
[+40.6s] result  PASS — honest member intact, over-spender slashed on-chain
```

## What this proves

- **Real RLN membership** — each tunnel carries a circom-rln Groth16 proof against the depth-20
  rateCommitment tree; the gateway verifies it with the deployed `verification_key.json`.
- **Rotation / unlinkability** — ALICE's three tunnels carry three distinct nullifiers
  under one per-epoch external nullifier; no shared key links them.
- **Rate cap = K enforced by construction** — BOB reusing slot 0 (messageId 0) in one epoch
  yields the *same* nullifier; a second distinct signal is the (K+1)-th point.
- **Real slashing** — the gateway reconstructs BOB's `identitySecret` from the two shares,
  and the on-chain contract re-derives the rateCommitment leaf from it and burns the bond
  (`slash` tx `0xc0f99e96…39efb`, block 11279845). Honest ALICE is untouched.

## P4 — live fleet over Tor (2026-07-15)

All three DO gateways were re-provisioned onto the RLN branch (`git HEAD 8bd7b62`, `rlnjs`
installed, wired to the new contract `0xdAE242AE…20FC`, PoW off). A local shim built **real
RLN proofs** and routed over Tor to the fleet; every tunnel returned a **gateway** IP, never
the laptop's (`<laptop IP, redacted>`), rotating across all three:

| req | egress IP | gateway | onion |
|---|---|---|---|
| 1,2 | <retired IP> | shade-tree-03 | spoe2hmw… |
| 3,4,5,7 | <retired IP> | egress-01 | kjeyt2gt… |
| 6 | <retired IP> | egress-02 | oi73ktti… |

Gateway logs: RLN `PASS egress` on all three (egress-01 ×4, shade-tree-03 ×2, egress-02 ×1);
the laptop's public IP appears **0 times** across every gateway — Tor rendezvous never
reveals the client. The signed directory (`directory.json`, signer `189f4511…1321`) already
carried the three current onions, so no re-sign was needed.

### Full combined e2e — over-spend + slash THROUGH a live gateway over Tor

The happy-path run above proves membership + egress over Tor; this proves the *slash* path
end to end, with nothing local. A fresh member (**carol**, `keys[2]`, leaf `1145183029…`)
was staked on the live contract (register `0x2c2dd605…`, block 11280717). A driver then sent
**two same-slot / same-epoch / different-signal envelopes** to ONE pinned gateway (egress-01)
over Tor:

```
[+3.7s]  envelope 1/2 -> egress-01 over Tor -> ack {"ok":true}          (first share, egressed)
[+14.1s] envelope 2/2 -> SAME gateway over Tor -> ack {"ok":false,"err":"over-spend-slashed"}
```

egress-01's own log:

```
PASS  egress->example.com:443  null=1137054579..
SLASH tx 0x917e4a6083f30d2db2ce1c7b90f8593f905c2bcba1e98699d05acd33a0f1d159 commitment=114518302995674202..
SLASH mined block 11280727
DROP  over-spend-slashed  null=1137054579..
```

Carol's on-chain bond went `0.001 → 0`. So a **live fleet gateway**, reached **over Tor**,
verified the RLN proofs, collected the two shares, reconstructed carol's `identitySecret`, and
submitted the slash itself (its own hot key) — **live on Sepolia** (`0x917e4a60…d159`, block
11280727). Nothing in this run was local: real client proofs, real Tor transport, real fleet
gateway, real chain. Note the over-spend must hit the **same** gateway (the spent-set is
per-gateway, in-memory) — hence the pinned onion; cross-gateway detection would need shared
share state (a known follow-up).

One operator note (not a fault): a freshly started **client** tor has marginal onion-connect
success for the first several minutes (measured ~1/10 at one point); the shim's directory
mode requires `SHADE_TREE_DIR_SIGNER` set or it silently falls back to a stale local
`tor/hs/hostname`. With the signer set and tor warm, round-trips are reliable.

## Honesty / scope

- The on-chain integration above uses local TCP (the exact bytes Tor delivers to a fleet
  gateway), isolating the stake/use/over-spend/slash protocol from onion-descriptor
  propagation; the P4 section proves the same code over live Tor.
- Circuit artifacts are from a **local untrusted phase-2 ceremony** — testnet-only. Mainnet
  needs a real ceremony + audit and a real Groth16 exit-auth verifier (exit is still mock).
- Two client-side bugs were found and fixed *during* this live run (they had slipped past
  every offline gate): a shared-snarkjs reentrancy race (serialized behind a mutex) and a
  stale `lib/semaphore.mjs` `loadGroup` that built a depth-3 Semaphore-v4 tree instead of
  the depth-20 RLN tree (now delegates to the RLN loader). See the commit log.
```

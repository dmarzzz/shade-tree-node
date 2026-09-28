# Key rotations

Public record of key rotations for the Sepolia research canopy. Addresses only;
private keys live SOPS-encrypted in the operator's infrastructure repository.

## 2026-09-28: fleet hot key split by role (OPS-1)

**Why.** The fleet hot key `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` was echoed
into a session log on 2026-08-17. It also served every role at once: contract
deployer, GatewayRegistry owner, staked gateway operator, member slasher and
paid-access operator.

**New keys.**

| Role | Address | Holds |
|---|---|---|
| gateway operator | `0x16c9F91c38669850f192fbfBbd22DE7946b30b63` | GatewayRegistry stake; signs node announces |
| slasher | `0xF4E1bDfF6C5046Fb2026C190163FF154C5F68922` | gas for permissionless member slashes |
| registrar | `0xA1bb185443C6f51c32930F0cFECA41161594f676` | unused while paid admission is off |
| registry owner | `0xf014266aa00421A0bb49613C78dbb321387598eA` | GatewayRegistry `owner` (governed gateway slash); never on a host |

**Steps** (Sepolia transactions):

1. Funded the four keys from the old key (`0x27adc210…`, `0x627f7018…`, `0xbdbabe4a…`, `0x4b798bb8…`).
2. New gateway operator `register()` on GatewayRegistry `0x94ECeD0C…A868` (`0x2e958696…`).
3. Rolled nodes `-04`, `-05`, `-06` one at a time; each heartbeat was accepted with
   the new operator before the next host. A hash check confirmed the old key is on
   no host.
4. Old operator `initiateExit()` (`0x53179d19…`), `withdraw()` to the registry owner
   after the 300 s unbonding (`0x08b2c82d…`).
5. `transferOwnership()` of GatewayRegistry to the registry owner (`0x06df38a4…`).
6. Drained the old key's balance to the registry owner (`0xf1867b36…`).

**Still pointing at the old key.** `PaidAccessSet` `0x4e8C…4111` names it as insert
operator. Paid admission is retired (`paid: null` in the record), so nothing
accepts those roots; the ShadeNet launch deploys fresh contracts.

**Verification.** `GatewayRegistry.owner()` returns the registry owner;
`isStaked(0x16c9…0b63)` is true; the old operator's stake is deleted; the Elder's
signed Canopy lists all three nodes under the new operator; invited proof-gated
egress passes through each node.

## Pending

- DigitalOcean API token used for the 2026-08-17 deploy: rotate in the DigitalOcean
  console (the scoped automation token cannot manage tokens) and record it here.

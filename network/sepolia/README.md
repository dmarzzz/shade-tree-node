# Sepolia deployment records

This directory contains two deliberately separate generations:

- [`deployment.json`](deployment.json) records the live disposable Protocol v4 research Grove
  deployed on 2026-08-25 and upgraded to staking on 2026-09-03: one stake-gated Elder Tree and
  three Shade Tree nodes admitting invited and staked members, with explicitly untrusted testnet
  contracts and proof artifacts. Its original execution record is
  [`docs/GO-LIVE-LOG-2026-08-25-v4.md`](../../docs/GO-LIVE-LOG-2026-08-25-v4.md).
- [`contracts.json`](contracts.json), [`bootnode.json`](bootnode.json), the signed directory files,
  and the integration reports below record the earlier pre-v4 Sepolia experiment. The bundle is not
  a current client preset; `deployment.json` explicitly reuses only its compatible staking set,
  gateway registry, RPC, and deploy-block metadata.

> **Live discovery and testnet staking.** The current v4 Elder onion and Canopy signer in
> `deployment.json` are the bundled client discovery default. The same record publishes its explicit
> staking set, archival RPC, and deploy block.
> Invited membership material remains private; a staked member self-enrolls with Sepolia test ETH
> and supplies the
> staking/RPC values explicitly because the retired legacy preset stays disabled.

Unless a sentence refers to `deployment.json` or the 2026-08-25 v4 log, “live” below records what
was verified during the retired 2026-08-17 experiment. It does not mean that the older service is
current or compatible with envelope v4. The release name `rln-v4-tiers` referred to an earlier
contract/proof iteration, not envelope v4.

## Staking contracts

Status at deployment: **live** — release `rln-v4-tiers`, deployed 2026-08-17 (blocks 11510538–11510541) by
the fleet operator hot key `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` (retired 2026-09-28; see
[`docs/KEY-ROTATIONS.md`](../../docs/KEY-ROTATIONS.md)). Params: tiers
{8: 0.001 ETH, 32: 0.004 ETH} (`bondFor(limit)`), unbonding 300s (min 270), `DEFAULT_LIMIT` 8,
on-chain root at storage slot 3. [`contracts.json`](contracts.json) is the source of truth.
Live integration (two tiers, on-chain root mode, tier-32 slash):
[`integration-report-rln-v4.md`](integration-report-rln-v4.md).

| Contract | Address |
|---|---|
| StakedReputationSet (tiered, on-chain tree) | [`0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`](https://sepolia.etherscan.io/address/0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25) — tx `0xa565fd77…3ba03`, block 11510541 |
| RateCommitmentHasher (`hasher`, tiered `commitmentOf(secret, limit)`) | `0x29e9D6ae8d46A9D86D6A92a43307850e0FA06586` |
| WithdrawVerifier (`withdrawVerifier`, REAL Groth16 exit-auth) | `0x522409038aA03FFF998d33C60A37486975695351` over `WithdrawGroth16Verifier` `0x6B26a9B6BEdcB711C35947f988fdFF168AFD507E` (untrusted dev VK, T-HARD-1) |
| PoseidonT2 / PoseidonT3 (linked libraries) | `0xA20D550b5b3b99c0abB6E51d68d2a39955E69b55` / `0x82Cb42c70208a92DD5938b5f4D67C7d2313bE022` (from the rln-v3 deploy, reused) |
| PaidAccessSet (T-FEAT-7 paid-access membership tree; operator-inserted, no funds) | [`0x4e8C2Bf5d3c5454A04837401095fce2646484111`](https://sepolia.etherscan.io/address/0x4e8C2Bf5d3c5454A04837401095fce2646484111) — deployed 2026-08-17 at block 11510873, tx `0x9835d062…4086`, operator `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` (registrar / insert key), `allowedLimits() == [8, 32]`, same hasher + Poseidon libraries as the staked set, `currentRoot` at slot 3. Payment settles OFF chain (HTTP 402 rails, x402 / MPP); the operator inserts after settlement; `slash` zeroes the leaf and pays nothing. Smoke (one insert at tier 8, root == JS, negatives revert): [`integration-report-paid-access.md`](integration-report-paid-access.md); receipt: [`paid-access-broadcast.json`](paid-access-broadcast.json). The pre-v4 network preset formerly supplied this address. |
| GatewayRegistry | [`0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868`](https://sepolia.etherscan.io/address/0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868) — deployed 2026-08-17 at block 11509783, tx `0x1ae812c1…3ad5dc`, owner `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` (fleet operator hot key); BOND 0.001 ETH, unbonding 300s / min 270s (verified via `cast`: `BOND()`, `owner()`). Receipt bundle: [`gateway-registry-broadcast.json`](gateway-registry-broadcast.json); recorded with `shade-tree record-deploy --network sepolia --from-broadcast …`. The pre-v4 network preset formerly supplied this address (`docs/ONCHAIN-DEPLOY.md` §7). Unchanged by the rln-v4 redeploy. |

Receipt bundle: [`rln-v4-broadcast.json`](rln-v4-broadcast.json). The retired network preset
formerly resolved `SHADE_TREE_GROUP_CONTRACT` to this set. The current v4 research Grove now
explicitly reuses it; use the Elder, signer, staking set, archival RPC, and deploy block named by
`deployment.json` rather than enabling the retired preset (`docs/CLI.md`).

**Superseded (history only, do not stake there):**

- **rln-v3** (2026-07-15, block 11279842, deployer `0x3261DaF3…2ff7`): StakedReputationSet
  `0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC`, RateCommitmentHasher (K pinned to 8)
  `0x08F9a754D2cBdfB7805cFF2475632BEC4612ae6D`, MockWithdrawVerifier
  `0x5A6FD01d009989ff9E567fa2bC55253500ddbDB2`. No on-chain tree (slot 3 = 0, so the light
  provider yielded no root — the finding that filed T-DEV-9c) and no tiers. Superseded by
  rln-v4-tiers; during the experiment the fleet gateways' slashing (`SHADE_TREE_SLASH_CONTRACT`)
  pointed here until their units were flipped (`docs/ONCHAIN-DEPLOY.md` §8). Its integration record:
  [`integration-report-rln.md`](integration-report-rln.md); kept under `superseded.rln-v3` in
  `contracts.json`.
- the pre-RLN deployment at block 11274471 — StakedReputationSet
  `0x35719A477655A5Aaac7A2aAA11A3167eFa3398EC`, MockCommitmentHasher
  `0xB9c051d12750395e7541Da149e216B1542b343d2`, MockWithdrawVerifier
  `0xac506585D70F8DA91C38CF271938Ee956f7CB862` — whose hasher was `Poseidon(secret)` rather than
  the real RLN rateCommitment. An intermediate RLN deploy `0x7c5bcfD3…8c6E` was abandoned mid-test
  (see `contracts.json` `superseded.rln-v3.note`).

## Payments: settle asset + registrar (T-FEAT-7)

| what | value |
|---|---|
| settle asset (`payAsset`) | **tUSD** "Test USD" (`test/Eip3009Token.sol`, EIP-3009, 6 decimals, version `"1"`) at [`0xCe0C9F8822e4841e735d2eDe3a1Db57CfE55a3A8`](https://sepolia.etherscan.io/address/0xCe0C9F8822e4841e735d2eDe3a1Db57CfE55a3A8) — deployed 2026-08-17 by the fleet operator key, tx `0x9561fa31…b234`, block 11511028. Circle's Sepolia USDC `0x1c7D4B19…7238` was verified EIP-3009-capable (`TRANSFER_WITH_AUTHORIZATION_TYPEHASH`, `authorizationState`, `DOMAIN_SEPARATOR == EIP712{USDC,2}`), but its faucet is captcha-gated; real USDC was the one-env swap `SHADE_TREE_PAY_ASSET`. The retired preset formerly supplied this asset. |
| registrar (`registrar`) | `http://<bootnode onion>:8878/` (the bootnode onion in `bootnode.json`, virtual port 8878), protocols `x402` (v2: `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`) + `mpp` (`WWW-Authenticate: Payment` / `Authorization: Payment` / `Payment-Receipt`, method `evm`, intent `charge`, `type=authorization`), prices tier 8 = `100000` (0.10 tUSD), tier 32 = `400000` (0.40 tUSD), payTo = the operator `0xc8606C75…7f02`. It was advertised in the bootnode `/health` `pay` block and (from 2026-08-18, T-FEAT-9) in gateway-1's signed `caps.pay` in `/directory`; gateway-2 sold nothing. These are retained deployment facts, not a current payment endpoint. Receipts: `docs/GO-LIVE-LOG-2026-08-17.md` "(payments)". |

## Bootnode

[`bootnode.json`](bootnode.json) is the retired discovery record (`{onion, signer,
admission, staticDirectory}`; schema in `network/README.md`). It was verified **live** from
2026-08-17 (T-DEPLOY-1 + T-DEPLOY-2 + stake admission,
[`docs/GO-LIVE-LOG-2026-08-17.md`](../../docs/GO-LIVE-LOG-2026-08-17.md)).

| field | value |
|---|---|
| bootnode onion | `kssrk54kb5kngr4jjdzjouecwjh5ayzbzhamwmvju4kz63vno7hy4uyd.onion` |
| pinned signer (`SHADE_TREE_DIR_SIGNER`) | `d79f78c369bd9c7b74575eae0c5068e6921f90bfdc97d43af9adc0039f953a73` |
| admission | **`stake`** since 2026-08-17 (later): `SHADE_TREE_STAKE_MODE=onchain` against `GatewayRegistry` `0x94ECeD0C…A868` (bond 0.001 ETH); the fleet operator `0xc8606C75…7f02` is staked and both heartbeats sign the onion↔operator auth (`announced (staked=true)`), one stake backs both onions (`docs/BOOTNODE.md` "The onion is never on chain") |
| gateway-1 onion (region `na`, NYC) | `yaxo4ywgoizk4yiylx66k3vjsgcj5waruumgi6dgds4fgaihd2eh7yqd.onion` |
| gateway-2 onion (region `na`, SFO) | `av4m256h4wwgwdmg74wnqem7s7l333h6755sroydlbcq62ptkmawtwid.onion` (gateway-only box, `bootstrap.sh` `SHADE_TREE_BOOTNODE_ONION` mode, T-DEPLOY-2) |
| gateway slashing | on-chain, routed: primary `SHADE_TREE_SLASH_CONTRACT` = rln-v4 `StakedReputationSet` `0xFe48De8b…9d25` (flipped from rln-v3 2026-08-17 21:28 UTC), plus `PaidAccessSet` for paid leaves (`makeRoutingSlasher`) |
| onion PoW | off (`SHADE_TREE_ENABLE_POW=0`; a `pow: no` client tor could not reach a PoW onion) |
| membership roots / admission policy (`SHADE_TREE_ADMIT`, T-FEAT-9, `docs/adr/0008`) | **heterogeneous on purpose** since 2026-08-18 06:37 UTC (`docs/GO-LIVE-LOG-2026-08-17.md` "per-gateway admission policy rolled"): **gateway-1** `admits: invited,staked,paid` — committed `group/members.json` (8 invited) ∪ rln-v4 `StakedReputationSet` `0xFe48De8b…9d25` (staked, tiers 8/32) ∪ `PaidAccessSet` `0x4e8C2Bf5…4111` (bought over 402) — and it SELLS (registrar, `SHADE_TREE_PAY_PROTOCOLS=x402,mpp`, advertised as signed `caps.pay`); **gateway-2** `admits: invited,staked` — members.json ∪ the staked set only, no paid leaves, no registrar. Both advertise their policy as signed `caps.admits` in `/directory`. Consequences: a paid buyer's client routes ONLY to gateway-1; an invited member with `--max-anon` is refused by BOTH (neither is invited-only) with a precise error naming each gateway's policy — the intended outcome. (`SHADE_TREE_ROOTS=static,onchain`, the pre-T-FEAT-9 union spelling, is a deprecated alias.) |
| ref deployed | both `main` @ `c6be15e` (2026-08-18 06:36 UTC, T-FEAT-9 per-gateway admission; earlier `6c4940c` / `cb237e07` / `d8a6530` / `af225c2`) |

Before retirement, the network preset resolved the bootnode onion and signer above. Current v4
clients receive their defaults from `deployment.json`, never from this retired record. Its cold-path
[`directory-bootnode.json`](directory-bootnode.json) remains as the bootnode's signed
`/directory` export and research evidence; its valid signature does not make the listed nodes
v4-compatible. The box hosting bootnode + gateway-1 was a
DigitalOcean droplet in NYC and gateway-2 is a DigitalOcean droplet in SFO (same AS14061,
different regions — `docs/GO-LIVE-LOG-2026-08-17.md` names them); their clearnet IPs are
operational metadata and are not recorded here. The client rotates across both
(`SHADE_TREE_ROTATION_SPREAD=1` for strict round-robin).

## Legacy gateway fleet (static directory)

Three earlier Shade Tree gateways on DigitalOcean (nyc3), provisioned via
`~/agent-devops` (`shade_tree_gateway` role). Membership gates on the committed
`group/members.json`; the client rotates across all three per tunnel. **All three
were reported **live at the time of this record** (Tor + gateway systemd units active, onions published). The signed
[`directory.json`](directory.json) is the machine-readable source of truth.

| Gateway | DO droplet | Onion | Recorded status |
|---|---|---|---|
| gateway-1 | egress-01 | `kjeyt2gtzcvnbshedns5wvtahtqbqwlmw4e56ku3iuqiykf5mwwdqdad.onion` | live then |
| gateway-2 | egress-02 | `oi73kttiriqhfmoxo42pstfobrhbjxko3gzzs54bovwhs2ayuw64imad.onion` | live then |
| gateway-3 | shade-tree-03 | `spoe2hmwp62w5bg74by7plx54rn4rzjro4bq6qzv5q6ewi4lqlovlbqd.onion` | live then |

Onions are the member-facing discovery handles (they are what `directory.json` publishes).
The droplets' clearnet IPs are operational metadata and are not listed here; they live in
the agent-devops inventory. (The signed `directory.json` `note` fields from July still carry
them; that file is left byte-identical because editing it would break its signature.) A
member learns a gateway's egress IP as the result of a tunnel anyway
(`curl -x … https://api.ipify.org`).

Directory signer (pinned in the client as `SHADE_TREE_DIR_SIGNER`):
`189f4511bad18f7d9e1fa1339b8b7ac27a7920ddf27b9a9c286b599bc0b21321`. The signer's secret
half (`group/directory-signer.key`) is gitignored. Per-droplet SSH keys are tracked in
`~/agent-devops/ansible/files/secrets/*.enc` (SOPS) + the fleet ledger; shade-tree-03 was
created by OpenTofu, egress-01/02 retrofitted via the Ansible role.

## Connect a current v4 client

Do not use the legacy `bootnode.json`, signed directories, contracts, registrar, or signer with a
current checkout. A signed historical directory can still be authentic while every node in it
speaks an incompatible protocol. The current `deployment.json` Elder onion and signer are public
deployment metadata. Invited access still needs the operator's matching member-set input; staked
access is permissionless on Sepolia at one of the contract's published tiers and keeps the member
secret local.

For a local v4 fleet, follow [`../../docs/QUICKSTART.md`](../../docs/QUICKSTART.md) Path B. The
current research Grove needs no explicit discovery flags; an alternate operator-run fleet supplies
an Elder onion and pinned directory signer as an override pair:

```bash
bash scripts/start-tor-client.sh
read -s SHADE_TREE_SECRET
SHADE_TREE_SECRET="$SHADE_TREE_SECRET" shade-tree proxy --limit <operator-tier> --tor-port 9260
# Alternate fleet: add --bootnode <v4-elder.onion> --dir-signer <matching-signer-hex>
unset SHADE_TREE_SECRET
```

For this v4 Grove, use the staked contract, archival RPC, and deploy block recorded together in
`deployment.json`; do not use the legacy `bootnode.json` or directory files.
[`../../docs/JOIN.md`](../../docs/JOIN.md) shows the explicit self-enroll, register, and Proxy forms.

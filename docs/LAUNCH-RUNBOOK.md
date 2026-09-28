# ShadeNet launch runbook

For Dan. Everything before this page is built and rehearsed; these are the gates only you can
open, in order: **H2** set the economics, **H3** adopt the trusted setup, **M8** deploy and launch.
(H1, reviewing the new pages, happens before H2 on the staging site.) Every command also runs
against staging: replace `sepolia` with `sepolia-staging`, or add `--fork` to run on an anvil fork
of Sepolia that sends nothing.

Prerequisites on the machine you run this from: a checkout of `main`, `npm ci`, Foundry
(`forge`, `anvil`, `cast`), `sops`, and the agent-devops age key:

```sh
export SOPS_AGE_KEY_FILE=~/agent-devops/keys.txt
export SHADENET_DEPLOYER_SOPS=~/agent-devops/secrets/shadenet/deployer.sops.yml
```

The deployer is `0x62c448057273fceE5785dd5b57e40d0ff19554b1`. It owns nothing after a deploy.

---

## H2: set the economics

**The one file:** `network/sepolia/economics.json`. Every price in the product comes from it:
the contract's constructor, the deployment record, the Get access page, `@shadenet/sdk`, the Rust
client's bundled profile and the docs tables.

| Field | Unit | Rule the deploy script enforces |
|---|---|---|
| `tiers[]` | `{ limit, bondWei }` | `limit` 1..65535, strictly ascending; `bondWei` a positive decimal wei string; **tier 8 must be present** (the contract always admits it) |
| `defaultLimit` | tier limit | must be one of `tiers[].limit`; what the site and CLI stake by default |
| `unbondingSeconds` | seconds | ≥ 3720 (root freshness 60 + epoch 60 + slash confirmation 3600) |
| `slash.rewardDivisor` | integer | 2..1000; the slasher gets `floor(bond / d)`, the rest is burned (10 = 90% burn) |
| `sponsorSeats.count`, `sponsorSeats.bondWeiEach` | seats, wei | what M8 funds for agent preview seats (below) |
| `sessionTickets` | boolean | turns on multi-target session tickets (#103) in the node and clients |
| `status` | `"placeholder"` \| `"final"` | **production refuses to deploy until this is `"final"`** |
| `decisionRef` | text | who set these numbers and when |

What a slot buys is fixed by the rate policy, not by this file: one new HTTPS tunnel per 60-second
epoch per slot, up to 40 MiB combined traffic. A tier's `limit` is its slots per epoch.

**Steps:**

```sh
$EDITOR network/sepolia/economics.json           # set the numbers, status "final", decisionRef
node scripts/deploy-contracts.selftest.mjs        # validates the shape; PASS expected
node scripts/deploy-contracts.mjs --network sepolia --fork
```

Expected: `read back OK: 0x… bytecode matches the pinned manifest`, the staking smoke's twelve
`ok` lines, then `fork rehearsal passed; nothing written under network/`. The fork run deploys
with your exact numbers against a copy of Sepolia and runs register → exit with a real proof →
24 h → withdraw → slash, so a price that breaks anything fails here, not on chain.

Rehearse on real Sepolia once by copying the same values into
`network/sepolia-staging/economics.json` (smaller bonds are fine) and running
`scripts/staging-up.sh`. Open a PR with the economics change; nothing else regenerates until M8
writes the production record.

---

## H3: adopt the trusted setup

Decision D3 is settled by test (`docs/ceremony/PSE-ADOPTION.md`): PSE's finalized RLN ceremony
covers both circuits (RLN: 60 contributions; withdraw: 62; each closed by a beacon) and passes
every interop check. The path:

**1. Confirm.** Comment on the adoption PR (or tell the agents): "adopt PSE's RLN setup for both
circuits". The fallback, your own ceremony, is below.

**2. Independent verification.** Ask one person outside the core team to run, on their own machine:

```sh
git clone https://github.com/dmarzzz/shade-tree-node && cd shade-tree-node
npm ci --prefix scripts/ceremony --ignore-scripts
git clone https://github.com/iden3/circom && (cd circom && git checkout v2.1.5 && cargo build --release)
git clone https://github.com/Rate-Limiting-Nullifier/circom-rln && (cd circom-rln && git checkout 17f0fed && npm ci --omit=dev)
node scripts/ceremony/pse-check.mjs --work /tmp/pse --circom circom/target/release/circom --circom-rln circom-rln
```

Expected: eight `ok` lines ending `pse-check: PASS`. They also relate the chain's beacon generator
(`003089a0…0203`) to PSE's published beacon value (`0xa894a3f9…bb9d`), then publish a signed
statement ("I reproduced the PSE RLN setup check at commit X; hashes …"). Link the statement in
the adoption PR.

**3. The adoption PR** (an agent prepares it; you review): the `circuits/rln/` WASM, zkeys and
verification keys swapped for the PSE set (WASM built with circom 2.1.5 `--O2`), regenerated
`contracts/RlnGroth16Verifier.sol` and `contracts/WithdrawGroth16Verifier.sol`, the withdraw
fixture, `deploy/v4/public-stake-v1-bytecode.json`, the Rust embedded artifacts, and
`testdata/zk-artifacts.lock.json` with `ceremony.status: "complete"`, the PSE hashes and the
verifier statement. Check before merging:

```sh
node scripts/zk-artifacts-lock.mjs --check        # lock matches files
npm test                                          # full suite incl. contracts and on-chain tiers
bash crates/shadenet-rln/interop/run.sh           # Rust prover -> JS verifier
node scripts/deploy-contracts.mjs --network sepolia-staging --fork
```

All green means production deploys will embed the new keys; `scripts/deploy-contracts.mjs`
refuses production until the lock records the completed ceremony.

**Fallback: your own ceremony** with the kit in `scripts/ceremony/` (rehearsed with real
crypto on 2026-09-28). Fill `docs/ceremony/EVENT.md` (date, roster of at least 3 contributors, at
least 2 outside the team, independent builder and verifier, mirrors), then follow
`docs/CEREMONY.md`: `prepare`, serial `contribute` with signed receipts, `close` (publish the
closed state hash before the beacon round), `finalize` with the drand round, independent
`verify`, archive on two mirrors. The adoption PR is the same as step 3 with your ceremony's
outputs. Rehearse first: `node scripts/ceremony/rehearse.mjs --inputs <build-inputs.json> --out <new dir>`.

---

## M8: deploy and launch

**Inputs that change:** only `network/sepolia/economics.json` (H2) and the adopted artifacts and
lock (H3). The script, contracts and checks are the ones staging already ran.

**1. Fund the deployer** with enough for gas (about 0.005 ETH at 1 gwei) plus the launch cohort
and sponsor seats (step 5). Check: `cast balance --ether 0x62c448057273fceE5785dd5b57e40d0ff19554b1 --rpc-url https://ethereum-sepolia-rpc.publicnode.com`.

**2. Deploy, verify, smoke:**

```sh
node scripts/deploy-contracts.mjs --network sepolia --fork          # last rehearsal
SHADE_TREE_DEPLOYER_KEY="0x$(sops -d --extract '["vault_shadenet_deployer_key"]' "$SHADENET_DEPLOYER_SOPS")" \
ETHERSCAN_API_KEY=… node scripts/deploy-contracts.mjs --network sepolia --broadcast --verify
SHADE_TREE_SMOKE_KEY="$SHADE_TREE_DEPLOYER_KEY" \
node scripts/smoke-staking.mjs --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --contract "$(node -p 'require("./network/sepolia/deployment.json").admission.roots.staked.contract')"
```

Expected: `read back OK`, `sourcify … verified` and `etherscan … verified` for the hasher, both
verifiers and the set, then the smoke's register/exit/slash lines and `a is unbonding until …`.
Rerun the smoke with `--resume` after 24 h for the withdraw.

The deploy writes `network/sepolia/deployment.json` (new set, `registerInput:
"identityCommitment"`, your tiers) and `network/sepolia/contracts-deploy.json` (audit trail).

Then record the canopy that will serve it (the Elders keep their onions; the commit is the
release the fleet rolls to in step 4):

```sh
node scripts/record-canopy.mjs --network sepolia --commit <release commit> --elders-from sepolia-staging
```

**3. Retire the v4 set in the records.** In `network/sepolia/contracts.json` add
`0xEB67Abf066c11D78856BccC63476ed14d51e4275` to the retired history with the date. It holds no
members or funds. Rebuild what reads the record and commit it all in one PR:

```sh
node scripts/build-stake-site.mjs && node docs-site/build.mjs
npm test && (cargo test --workspace --all-features)
```

**4. Release and fleet roll.** Merge the records PR, then tag: `git tag -s vX.Y.Z -m "ShadeNet vX.Y.Z" && git push origin vX.Y.Z`.
The release workflow builds the Rust binaries, `@shadenet/sdk` and the images with the new record
and keys embedded. Roll the fleet onto the tag (the ops track's OPS-3 pin: the record's
`services.*.commit` is the tag's commit, and `/health` reports it):

```sh
cd ~/agent-devops && task shade-tree:deploy && task shade-tree:e2e
curl -s <elder>/health | jq .build.commit          # must equal the tag's commit
```

Nodes accept only the new verification key after this roll.

**5. Seed the launch cohort and sponsor seats**, so the anonymity set is not empty on day one.
Amounts come from `economics.json`:

- launch cohort: `N members × bondWei of defaultLimit` (N = the cohort you invite, e.g. 20)
- agent preview seats: `sponsorSeats.count × sponsorSeats.bondWeiEach`

Stake each with `shadenet register-member <identity-commitment> --limit <tier>` from the funding
key, or from the Get access page's sponsor mode. Check the count on the canopy page
(`/canopy`) and with `shadenet status`.

**6. Announce checklist:**

- [ ] `network/sepolia/deployment.json` on main names the new set; contracts verified on Etherscan and Sourcify
- [ ] smoke withdraw finished (`--resume`) after 24 h
- [ ] release `vX.Y.Z` published; fleet `/health` on that commit; `task shade-tree:e2e` green
- [ ] Get access page shows the H2 tiers and live member count ≥ the cohort
- [ ] Hermes on orbital-one and the SearXNG recipe egress through the canopy
- [ ] alerts reaching Matrix; status page green
- [ ] then post the announcement

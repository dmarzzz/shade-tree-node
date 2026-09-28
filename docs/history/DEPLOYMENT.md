# Deployment runbook: testnet contracts + DO gateway fleet

Status: **historical record (July 2026), kept for the decisions and the live-Tor evidence.**
This was the plan + runbook for deploying the next version (docs/history/NEXT-VERSION.md) to an
Ethereum testnet and a DigitalOcean gateway fleet, using the `~/agent-devops` OpenTofu +
Ansible repo. Grounded in live recon, not aspiration. The current bring-up path is the
one-command `bootnode/deploy/bootstrap.sh` (see `docs/OPERATOR.md`, `docs/QUICKSTART.md`)
and the human-gated first deployment record is `docs/history/GO-LIVE.md`; the retired historical contract
addresses are in `network/sepolia/contracts.json` (release `rln-v4-tiers`, 2026-08-17; rln-v3 under `superseded`), which supersedes the
addresses this file's checklist was written against.

## Topology

```
  Sepolia (testnet)                         DigitalOcean fleet (nyc3)
  ─────────────────                         ─────────────────────────
  StakedReputationSet  ← staking/slash      egress-01  ┐
  MockCommitmentHasher    /withdraw          egress-02  ├ tor onion + gateway.mjs
  MockWithdrawVerifier                       shade-tree-03    ┘  (loopback:8443, :443 egress)
        ▲                                        │
        │ (optional) gateway slash tx            │ each publishes a .onion
        └──────────── SHADE_TREE_SLASH_KEY ────────────┤
                                                 ▼
  members.json (identity leaves, committed)  signed group/directory.json (3 onions)
```

Membership gating uses `members.json` (Plan-B identity view, committed to the repo);
the testnet contract is the staking/slashing/withdraw economic layer. The gateways run
without the contract by default (membership-only mode); set the on-chain env to enable
slashing once the contract is funded + deployed.

## Part A — Testnet contracts (Sepolia)

Deployer: `0x3261DaF3672Dc8E6063b6960C161Fdc8a6Fc2ff7` (key in scratchpad, never
committed). **BLOCKED on funding** — it has 0 Sepolia ETH. Fund it from a faucet (e.g.
sepoliafaucet.com / a PoW faucet / a transfer), then:

```bash
export SHADE_TREE_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
export SHADE_TREE_BOND_WEI=1000000000000000     # 0.001 ETH (testnet-frugal)
export SHADE_TREE_UNBONDING=300 SHADE_TREE_MIN_UNBONDING=270
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$SHADE_TREE_RPC_URL" --broadcast \
  --private-key <deployer-key>
# writes contracts/deployed.local.json {stakedReputationSet, hasher, verifier, rpcUrl}
```

Deploy cost is a few M gas (~well under 0.05 Sepolia ETH). The Deploy script is
env-parameterized (foundry.toml has a `sepolia` rpc endpoint). Contracts are
byte-identical to the 22-test-green anvil build.

## Part B — Gateway fleet (DigitalOcean via agent-devops)

### Fleet decision

Droplet limit 15, 13 in use. Three gateways = **retrofit egress-01 + egress-02**
(created for exactly this, currently bare base boxes) **+ one new `shade-tree-03`**. This
reuses infra and adds only one droplet (14/15).

### SAFETY: targeted applies only

`tofu plan` shows one pending change that is NOT part of this work — a
`digitalocean_spaces_bucket "amis-blobs"` from the `amis-01-provisioning` branch. **Do
not run a blanket `tofu apply`** or it will create that bucket. Apply only the new
gateway droplet with `-target`, and retrofit the two existing boxes via Ansible only
(no tofu droplet change). The DO token comes from `doctl`'s config (or export
`DIGITALOCEAN_TOKEN` manually); `SOPS_AGE_KEY_FILE=./keys.txt` must be set so per-server
key tracking runs.

### Steps

1. **New droplet (shade-tree-03)** — append to `terraform.tfvars` `servers` map (gitignored;
   re-bundle `fleet-secrets.tar.gpg` after):
   ```hcl
   shade-tree-03 = {
     role       = "egress"                       # s-1vcpu-2gb, anon_egress, SSH-only firewall
     purpose    = "Shade Tree gateway"
     dev_tools  = { shade_tree_gateway = true }        # runs the new role
     extra_host_vars = { shade_tree_git_ref = "deploy/onchain-staked-fleet" }
   }
   ```
   ```bash
   export DIGITALOCEAN_TOKEN=<from doctl config>  SOPS_AGE_KEY_FILE=./keys.txt
   tofu -chdir=tofu/environments/dev apply -target='module.droplet["shade-tree-03"]'
   task bootstrap HOST=shade-tree-03
   ```

2. **Retrofit egress-01/02 (Ansible only, no tofu droplet change)** — set
   `dev_tools.shade_tree_gateway: true` + `shade_tree_git_ref` in their host_vars (and in tfvars for
   persistence), then:
   ```bash
   task provision HOST=shade-tree-03    -- -t shade_tree_gateway
   task provision HOST=egress-01  -- -t shade_tree_gateway
   task provision HOST=egress-02  -- -t shade_tree_gateway
   ```
   The `shade_tree_gateway` role installs Tor (Tor Project apt repo, PoW-capable), clones the
   `deploy/onchain-staked-fleet` branch to the box, drops `members.json`, writes the
   onion torrc + systemd units, and starts the gateway loopback-only behind the onion.
   The final task prints each box's `.onion`.

3. **Collect onions + build the directory.**
   ```bash
   # gather the three hostnames from the provision output (or /var/lib/tor-shade-tree/hs/hostname)
   node group/sign-directory.mjs <onion1> <onion2> <onion3>   # signs group/directory.json
   ```
   Commit `group/directory.json` + the onion list to the repo (the "Now" distribution
   stage from docs/FLEET.md — git as the directory channel).

### Identity + key tracking

Every new droplet's ed25519 key is auto-generated by the tofu droplet module, written
to `~/.ssh/shade-tree-03_ed25519` (0600), SOPS-encrypted to
`ansible/files/secrets/shade-tree-03_ed25519.enc` (committed), and logged to
`tofu/environments/dev/generated/fleet-ledger.md`. No manual key handling. Onion
addresses are tracked in this repo's `group/directory.json` (agent-devops has no onion
field; the app repo owns onion truth).

## Verification (per gateway)

```bash
# from a laptop holding an enrolled SHADE_TREE_SECRET (see demo-keys.local.md) + the directory:
curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json   # returns the gateway IP
# rotates across the 3 gateways per tunnel; each sees ~1/3 under distinct nullifiers
```

## Status checklist

- [x] Contracts Sepolia-ready (env-parameterized deploy, public RPC wired)
- [x] Deployer funded → **contracts deployed to Sepolia** (first deploy: StakedReputationSet `0x35719A47…98EC`, block 11274471 — **superseded** by the `rln-v3` release `0xdAE242AE…20FC`, block 11279842; see `network/sepolia/contracts.json` + `network/sepolia/README.md`)
- [x] `members.json` re-seeded (identity leaves) + proof round-trip verified
- [x] Next-version code committed + pushed (`deploy/onchain-staked-fleet`)
- [x] `shade_tree_gateway` Ansible role (agent-devops)
- [x] **shade-tree-03 provisioned + egress-01/02 retrofitted — all 3 gateways live, onions published**
- [x] 3 onions collected → `network/sepolia/directory.json` signed (signer `189f4511…1321`)
- [x] **Contracts deployed to Sepolia + integration test PASS** (stake→use→over-spend→slash, all on-chain; see `network/sepolia/integration-report.md`)
- [x] **Client hang bug fixed** (`verifyEnvelope` Set/Array; gateway never hangs; shim readLine timeout)
- [x] **On-chain slashing enabled fleet-wide** via `group_vars/egress` (SHADE_TREE_SLASH_CONTRACT decoupled from membership; slasher key SOPS-encrypted)
- [ ] fleet-ledger + `fleet-secrets.tar.gpg` re-bundled (agent-devops; needs your passphrase)
- [x] **live curl through the fleet over Tor — CONFIRMED end to end** (see below)

## Live Tor round-trip: CONFIRMED

Full path verified: laptop → shim (builds a Semaphore proof) → Tor rendezvous → fleet
gateway (verifies the proof, gates) → clearnet, returning the **gateway's** clean IP, not
the laptop's. Requests rotate across gateways and slots per tunnel:

| req | egress IP (gateway) | onion | slot (nullifier) |
|---|---|---|---|
| 1 | `<egress-02 droplet IP>` | oi73ktti… | 0 |
| 2 | `<egress-02 droplet IP>` | oi73ktti… | 1 |
| 3 | `<shade-tree-03 droplet IP>` | spoe2hmw… | 2 |

(Droplet IPs are operational metadata and are elided here; the onions are the member-facing
handles, published in `network/sepolia/directory.json`.)

Privacy check: the laptop's public IP appears **0 times** in the gateways' logs — Tor
rendezvous never reveals the client to the gateway.

### What had blocked it (three real issues, none an "environment fault")

Getting here required fixing three things, and my first read ("Tor network / environment
issue") was wrong — nothing that worked before had broken:

1. **`.onion` double-suffix (client bug).** Directory entries carry the full
   `<addr>.onion`; `dialOnion` re-appends `.onion`, so fleet mode dialed
   `<addr>.onion.onion` → SOCKS `HostUnreachable`. The single-onion path already stripped
   it. This is why fleet (rotation) mode never connected. Fixed in `client/shim.mjs`.
2. **PoW capability mismatch.** The gateways ran with `HiddenServicePoWDefensesEnabled 1`
   (Tor Project build); the laptop's Homebrew tor reports `pow: no` and **cannot connect
   to a PoW-enabled onion**. Proof: laptop reached DuckDuckGo's non-PoW onion (200) but
   not ours. The original PoC "worked before" precisely because Homebrew tor can't enable
   PoW, so it was always off. Fixed by defaulting PoW off (`shade_tree_enable_pow: false`);
   `bootnode/deploy/bootstrap.sh` now matches that default (`SHADE_TREE_ENABLE_POW=0`; set `1`
   to opt back in once every client runs a pow-capable tor).
3. **Onion cold-start.** Each re-provision restarts `shade-tree-tor`, and a freshly restarted
   v3 onion needs a few minutes to republish its descriptor to the HSDir hashring. My
   repeated re-provisions kept the tests landing in that window. Not a fault — just
   latency; the `dialOnion` retry covers the steady state.

The old *silent hang* on this path (the very first client bug) is also fixed — the shim
now reports the Tor error cleanly instead of hanging.

## Membership: does staking on-chain make you a recognized member? (resolved by the RLN release)

**Update:** the RLN circuit described below has since shipped (`docs/history/RLN-MIGRATION.md`,
`lib/rln.mjs`, `circuits/rln/`) and is what the live `rln-v3` contracts use: the on-chain leaf
is the real circom-rln `rateCommitment = Poseidon(Poseidon(secret), limit)` and a gateway
in on-chain root mode (`SHADE_TREE_GROUP_CONTRACT`, `lib/root-provider.mjs`) reads the admission
root from that same contract, so staking on chain is membership. (`bootstrap.sh` still
defaults to the committed `members.json`; see `docs/CONFIG.md` profiles.) The paragraph below is the pre-RLN reasoning that motivated it.

At the time: no. Gateways gated membership on the committed `members.json` (Semaphore *identity* leaves,
`Poseidon(EdDSA-pubkey(secret))`); the on-chain stake leaf is `Poseidon(secret)` (so the
contract can recompute it from a revealed secret to authorize a slash). These are
different leaf functions and cannot be unified by registering both, because nothing binds
the two commitments to the *same* secret without a ZK proof — a member could stake a junk
commitment and be un-slashable while proving membership with a real one. **RLN resolves it
by making `Poseidon(secret)` serve as both the membership leaf and the slashable identity
in one circuit.** So "stake → automatically a recognized member" is the RLN-circuit
follow-up, not a config change. Today: stake + `members.json` membership are bridged
off-chain (both derived from one secret); slashing is fully on-chain (proven).
